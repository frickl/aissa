import base64
import io
import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import HTTPServer
from unittest.mock import Mock, patch
from aissa.service import Engine, handler, metadata
from aissa.state import Redis, State


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.state = Mock()
        self.state.observe.return_value = {'account_600': 1}
        self.engine = Engine({'max_pending': 1, 'max_requests_per_minute': 10}, self.state)
        self.meta = metadata({'event_id': 'Q:hash', 'account': 'u', 'ip': '192.0.2.1'})

    def test_queue_and_dedup(self):
        self.assertEqual(self.engine.submit(b'mail', self.meta), (202, 'queued'))
        self.assertEqual(self.engine.submit(b'mail', self.meta), (200, 'duplicate'))
        self.assertEqual(self.engine.submit(b'mail', {**self.meta, 'event_id': 'other'}), (429, 'queue_full'))

    def test_rate(self):
        self.engine.cfg['max_requests_per_minute'] = 1
        self.engine.submit(b'mail', self.meta)
        self.engine.jobs.get_nowait()
        self.assertEqual(self.engine.submit(b'mail', {**self.meta, 'event_id': 'other'}), (429, 'rate_limited'))

    def test_metadata(self):
        for value in [{'event_id': ''}, {'event_id': 'ok', 'ip': 'invalid'},
                      {'event_id': 'ok', 'rspamd_score': float('nan')}]:
            with self.assertRaises(ValueError):
                metadata(value)

    def test_http_auth_observe_submit(self):
        server = HTTPServer(('127.0.0.1', 0), handler(self.engine, 'a'*32))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = 'http://127.0.0.1:'+str(server.server_port)
        def request(path, body, headers):
            req = urllib.request.Request(url+path, data=body, headers=headers)
            try:
                with urllib.request.urlopen(req) as response:
                    return response.status, json.load(response)
            except urllib.error.HTTPError as exc:
                return exc.code, json.load(exc)
        try:
            self.assertEqual(request('/observe', b'{}', {})[0], 401)
            headers = {'Authorization': 'Bearer '+'a'*32}
            self.assertEqual(request('/observe', json.dumps(self.meta).encode(), headers)[0], 200)
            self.state.observe.assert_called_once()
            headers['X-Aissa-Meta'] = base64.b64encode(json.dumps(self.meta).encode()).decode()
            self.assertEqual(request('/submit', b'Subject: test\n\nhello', headers)[0], 202)
            self.assertEqual(self.engine.jobs.qsize(), 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_resp(self):
        self.assertEqual(Redis.read(io.BytesIO(b'*2\r\n:2\r\n$1\r\n3\r\n')), [2, '3'])
        with self.assertRaises(OSError):
            Redis.read(io.BytesIO(b'-ERR rejected\r\n'))

    def test_redis_lanes_separate(self):
        redis = Mock()
        state = State(redis)
        state.suspect(self.meta)
        suspect_args = redis.command.call_args.args
        self.assertIn(':ai_suspect:', suspect_args[-1])
        state.confirm('account', 'u', 'incident-1')
        confirm_args = redis.command.call_args.args
        self.assertIn(':confirmed:', confirm_args[-1])
        self.assertNotEqual(suspect_args[-1], confirm_args[-1])
