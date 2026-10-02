import base64
import contextlib
import http.client
import io
import json
import threading
import unittest
from http.server import HTTPServer
from unittest.mock import patch

from aissa.bridge import Bridge, bridge_handler
from aissa.service import metadata


class BridgeScoringTests(unittest.TestCase):
    def setUp(self):
        self.engine = Bridge(dict(max_pending=2, max_results=3,
                                  max_requests_per_minute=10, model='test', llm_timeout=60))
        self.meta = metadata(dict(event_id='node:queue:digest', account='user', ip='192.0.2.1'))

    def finish(self, **fields):
        verdict = dict(classification='phishing', confidence=.95,
                       elapsed_seconds=.1, model='test')
        verdict.update(fields)
        with patch('aissa.bridge.classify', return_value=verdict), contextlib.redirect_stdout(io.StringIO()):
            self.engine.process(b'mail', self.meta)

    def test_collector_ack_does_not_consume_live_verdict(self):
        self.assertEqual(self.engine.submit(b'mail', self.meta)[0], 202)
        self.finish()
        result = self.engine.pending_results()[0]
        self.assertEqual(self.engine.acknowledge([result['id']]), 1)
        self.assertEqual(self.engine.acknowledge([result['id']]), 0)
        self.assertEqual(self.engine.outstanding, 0)
        self.assertEqual(self.engine.verdict(self.meta['event_id'])['classification'], 'phishing')
        self.assertNotIn('meta', self.engine.verdict(self.meta['event_id']))

    def test_error_never_becomes_ham(self):
        self.engine.submit(b'mail', self.meta)
        with patch('aissa.bridge.classify', side_effect=TimeoutError), contextlib.redirect_stdout(io.StringIO()):
            self.engine.process(b'mail', self.meta)
        result = self.engine.verdict(self.meta['event_id'])
        self.assertEqual((result['status'], result['classification']), ('error', 'uncertain'))
        self.assertNotIn('confidence', result)
        self.assertEqual(len(self.engine.pending_results()), 1)

    def test_pending_missing_and_duplicate(self):
        self.assertEqual(self.engine.verdict('unknown')['status'], 'missing')
        self.assertEqual(self.engine.submit(b'mail', self.meta), (202, 'queued'))
        self.assertEqual(self.engine.verdict(self.meta['event_id'])['status'], 'pending')
        self.assertEqual(self.engine.submit(b'mail', self.meta), (200, 'duplicate'))
        self.assertEqual(self.engine.outstanding, 1)
        self.assertEqual(self.engine.jobs.qsize(), 1)

    def test_cache_expiry_keeps_unacknowledged_result(self):
        self.engine.submit(b'mail', self.meta)
        self.finish()
        with patch('aissa.bridge.time.monotonic', return_value=10**12):
            self.assertEqual(self.engine.verdict(self.meta['event_id'])['status'], 'missing')
        self.assertEqual(self.engine.verdicts, {})
        self.assertEqual(len(self.engine.pending_results()), 1)

    def test_cache_capacity_keeps_collection_rows(self):
        self.engine.VERDICT_LIMIT = 1
        self.engine.submit(b'mail', self.meta)
        self.finish()
        self.meta = metadata(dict(event_id='other', ip='192.0.2.2'))
        self.engine.submit(b'mail', self.meta)
        self.finish()
        self.assertEqual(len(self.engine.verdicts), 1)
        self.assertEqual(len(self.engine.pending_results()), 2)

    def test_completion_timestamp_is_after_classification(self):
        self.engine.submit(b'mail', self.meta)
        clock = {'now': 100}
        def classify(*args):
            clock['now'] = 200
            return dict(classification='ham', confidence=.9, elapsed_seconds=.1, model='test')
        with patch('aissa.bridge.time.time', side_effect=lambda: clock['now']), patch('aissa.bridge.classify', side_effect=classify), contextlib.redirect_stdout(io.StringIO()):
            self.engine.process(b'mail', self.meta)
        self.assertEqual(self.engine.pending_results()[0]['completed_at'], 200)

    def test_capacity_and_confirmation_are_separate(self):
        self.engine.max_results = 1
        self.assertEqual(self.engine.confirm(self.meta)[0], 202)
        self.assertEqual(self.engine.submit(b'mail', self.meta), (429, 'results_full'))
        self.assertEqual(self.engine.verdict(self.meta['event_id'])['status'], 'missing')
        self.assertEqual(self.engine.pending_results()[0]['status'], 'confirmed')

    def test_http_auth_validation_submit_verdict_and_ack(self):
        token = 'x' * 64
        server = HTTPServer(('127.0.0.1', 0), bridge_handler(self.engine, token))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def post(path, value, auth=True, headers=None):
            conn = http.client.HTTPConnection(*server.server_address, timeout=2)
            hdr = dict(headers or {})
            if auth:
                hdr['Authorization'] = 'Bearer ' + token
            body = value if isinstance(value, bytes) else json.dumps(value).encode()
            conn.request('POST', path, body, hdr)
            response = conn.getresponse()
            answer = (response.status, json.loads(response.read()))
            conn.close()
            return answer
        try:
            self.assertEqual(post('/verdict', {}, auth=False)[0], 401)
            self.assertEqual(post('/verdict', [1])[0], 400)
            self.assertEqual(post('/verdict', {'event_id': ''})[0], 400)
            encoded = base64.b64encode(json.dumps(self.meta).encode()).decode()
            self.assertEqual(post('/submit', b'mail', headers={'X-Aissa-Meta': encoded})[0], 202)
            self.assertEqual(post('/verdict', {'event_id': self.meta['event_id']})[1]['status'], 'pending')
            self.finish()
            row = self.engine.pending_results()[0]
            self.assertEqual(post('/ack', {'ids': [row['id']]})[1]['removed'], 1)
            self.assertEqual(post('/verdict', {'event_id': self.meta['event_id']})[1]['classification'], 'phishing')
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)
