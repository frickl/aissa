import json
import unittest
from unittest.mock import patch, MagicMock
from aissa.analyzer import extract, validate, classify, MAX_MAIL


class AnalyzerTests(unittest.TestCase):
    def test_html_link_and_script(self):
        raw = b'Content-Type: text/html\n\n<script>secret</script><a href="https://evil.invalid">Verify account</a>'
        result = extract(raw)
        self.assertNotIn('secret', result['text'])
        self.assertIn('Verify account', result['text'])
        self.assertEqual(result['urls'], ['https://evil.invalid'])

    def test_attachment_excluded(self):
        raw = b'Content-Type: text/plain\nContent-Disposition: attachment\n\nprivate attachment'
        self.assertEqual(extract(raw)['text'], '')

    def test_bounds(self):
        with self.assertRaises(ValueError):
            extract(b'x' * (MAX_MAIL + 1))
        result = extract(b'Content-Type: text/plain\n\n' + b'x' * 5000)
        self.assertTrue(result['text_truncated'])
        self.assertEqual(len(result['text']), 1000)

    def test_configurable_text_budget(self):
        raw = b'Content-Type: text/plain\n\n' + b'x' * 1500
        self.assertEqual(len(extract(raw, 1200)['text']), 1200)
        self.assertFalse(extract(raw, 2000)['text_truncated'])
        for budget in (True, 99, 4001, '1000', 1000.5):
            with self.assertRaises(ValueError):
                extract(raw, budget)

    def test_invalid_confidence_and_fields(self):
        for value in [True, float('nan'), float('inf'), -1, 2, '0.9']:
            with self.assertRaises(ValueError):
                validate({'classification': 'ham', 'confidence': value, 'reason': 'test'})
        with self.assertRaises(ValueError):
            validate({'classification': 'ham'})

    def test_backend_contract(self):
        verdict = {'classification': 'phishing', 'confidence': 0.8, 'reason': 'Password theft'}
        response = MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps({'done': True,
            'message': {'content': json.dumps(verdict)},
            'prompt_eval_duration': 2000000000, 'eval_duration': 500000000,
            'prompt_eval_count': 80, 'eval_count': 12}).encode()
        with patch('urllib.request.build_opener') as factory:
            factory.return_value.open.return_value = response
            result = classify(b'Subject: Hello\n\nBonjour')
            request = factory.return_value.open.call_args.args[0]
            payload = json.loads(request.data)
            self.assertEqual(request.full_url, 'http://127.0.0.1:11434/api/chat')
            self.assertFalse(payload['stream'])
            self.assertEqual(payload['options']['num_thread'], 2)
            self.assertEqual(result['mode'], 'observe')
            self.assertEqual(result['classification'], 'phishing')
            self.assertEqual(result['prompt_eval_duration_seconds'], 2)
            self.assertEqual(result['eval_duration_seconds'], .5)
            self.assertEqual(result['input_text_chars'], 7)

    def test_backend_failure_not_ham(self):
        with patch('urllib.request.build_opener') as factory:
            factory.return_value.open.side_effect = TimeoutError()
            with self.assertRaises(TimeoutError):
                classify(b'Subject: Hello\n\ntext')


if __name__ == '__main__':
    unittest.main()
