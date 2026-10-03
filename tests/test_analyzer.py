import base64
import json
from email.message import EmailMessage
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

    def test_base64_utf8_plain_text_decodes_before_truncation(self):
        text = 'Grüße, unser Treffen ist morgen. ' * 50
        raw = (b'Content-Type: text/plain; charset=utf-8\r\n'
               b'Content-Transfer-Encoding: base64\r\n\r\n'
               + base64.encodebytes(text.encode('utf-8')))
        result = extract(raw, 1000)
        self.assertEqual(result['text'], text[:1000])
        self.assertTrue(result['text_truncated'])

    def test_quoted_printable_utf8_decodes(self):
        raw = (b'Content-Type: text/plain; charset=utf-8\r\n'
               b'Content-Transfer-Encoding: quoted-printable\r\n\r\n'
               b'Gr=C3=BC=C3=9Fe, morgen um 14 Uhr.')
        self.assertEqual(extract(raw)['text'], 'Grüße, morgen um 14 Uhr.')

    def test_base64_html_decodes_before_visible_text_and_links(self):
        html = '<p>Grüße</p><script>hidden</script><a href="https://example.org/">Termin</a>'
        raw = (b'Content-Type: text/html; charset=utf-8\r\n'
               b'Content-Transfer-Encoding: base64\r\n\r\n'
               + base64.encodebytes(html.encode('utf-8')))
        result = extract(raw)
        self.assertIn('Grüße', result['text'])
        self.assertIn('Termin', result['text'])
        self.assertNotIn('hidden', result['text'])
        self.assertEqual(result['urls'], ['https://example.org/'])

    def test_multipart_base64_attachment_stays_out_of_model_input(self):
        msg = EmailMessage()
        msg.set_content('Hallo, unser Treffen ist morgen.', cte='base64')
        msg.add_attachment(b'PK\x03\x04not a real archive', maintype='application',
                           subtype='zip', filename='test.zip', cte='base64')
        sample = extract(msg.as_bytes())
        self.assertEqual(sample['text'].strip(), 'Hallo, unser Treffen ist morgen.')
        self.assertNotIn('PK', sample['text'])
        self.assertNotIn('UEsD', sample['text'])

    def test_undeclared_base64_is_not_silently_decoded(self):
        body = base64.b64encode(b'PK\x03\x04test')
        sample = extract(b'Subject: test\r\n\r\n' + body)
        self.assertEqual(sample['text'], body.decode('ascii'))

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
