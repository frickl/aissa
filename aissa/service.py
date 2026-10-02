"""Bounded, loopback-only observation service. No SMTP decisions."""
import argparse
import base64
import collections
import hashlib
import hmac
import ipaddress
import json
import math
import queue
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from .analyzer import MAX_MAIL, classify
from .state import Redis, State


def metadata(value):
    if not isinstance(value, dict):
        raise ValueError('Invalid metadata')
    result = {}
    for key, limit in [('event_id', 256), ('queue_id', 128), ('account', 320), ('ip', 64), ('country', 2)]:
        item = value.get(key, '')
        if not isinstance(item, str) or len(item) > limit or any(ord(c) < 32 for c in item):
            raise ValueError('Invalid metadata field')
        result[key] = item
    if not result['event_id']:
        raise ValueError('Missing event ID')
    if result['ip']:
        result['ip'] = str(ipaddress.ip_address(result['ip']))
    if result['country'] and not (len(result['country']) == 2 and result['country'].isalpha()):
        raise ValueError('Invalid country')
    score = value.get('rspamd_score', 0)
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score):
        raise ValueError('Invalid score')
    result['rspamd_score'] = score
    return result


class Engine:
    def __init__(self, cfg, state):
        self.cfg, self.state = cfg, state
        self.jobs = queue.Queue(maxsize=cfg['max_pending'])
        self.lock = threading.Lock()
        self.stats = collections.Counter()
        self.minute = -1
        self.admitted = 0
        self.recent = {}  # bounded in-memory submission dedup, not durable

    def count(self, key):
        with self.lock:
            self.stats[key] += 1

    def submit(self, raw, meta):
        with self.lock:
            now = time.monotonic()
            self.recent = {k: v for k, v in self.recent.items() if now-v < 3600}
            key = hashlib.sha256(meta['event_id'].encode()).hexdigest()
            if key in self.recent:
                self.stats['duplicate'] += 1
                return 200, 'duplicate'
            minute = int(now // 60)
            if minute != self.minute:
                self.minute, self.admitted = minute, 0
            if self.admitted >= self.cfg['max_requests_per_minute']:
                self.stats['rate_limited'] += 1
                return 429, 'rate_limited'
            if len(self.recent) >= 10000:
                self.stats['dedup_full'] += 1
                return 429, 'dedup_full'
            try:
                self.jobs.put_nowait((raw, meta))
            except queue.Full:
                self.stats['queue_full'] += 1
                return 429, 'queue_full'
            self.recent[key] = now
            self.admitted += 1
            self.stats['queued'] += 1
            return 202, 'queued'

    def worker(self):
        while True:
            raw, meta = self.jobs.get()
            try:
                verdict = classify(raw, self.cfg['model'], self.cfg['llm_timeout'])
                self.count('completed')
                if verdict['classification'] in ('spam', 'phishing'):
                    try:
                        self.state.suspect(meta)
                    except Exception:
                        self.count('redis_verdict_error')
                # No mail body, displayed From, account/IP or model reason in logs.
                print(json.dumps({'event': 'verdict', 'event_id': meta['event_id'],
                    'queue_id': meta['queue_id'], 'classification': verdict['classification'],
                    'confidence': verdict['confidence'], 'elapsed_seconds': verdict['elapsed_seconds'],
                    'model': verdict['model'], 'rspamd_score': meta['rspamd_score'], 'mode': 'observe'}), flush=True)
            except Exception as exc:
                self.count('inference_error')
                print(json.dumps({'event': 'error', 'event_id': meta['event_id'],
                    'queue_id': meta['queue_id'], 'error_type': type(exc).__name__, 'mode': 'observe'}), flush=True)
            finally:
                self.jobs.task_done()


def handler(engine, token):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def setup(self):
            super().setup()
            self.connection.settimeout(1)

        def reply(self, code, value):
            body = json.dumps(value).encode()
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def authorized(self):
            return hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer '+token)

        def do_GET(self):
            if not self.authorized():
                return self.reply(401, {'status': 'unauthorized'})
            if self.path != '/metrics':
                return self.reply(404, {'status': 'not_found'})
            with engine.lock:
                stats = dict(engine.stats)
            self.reply(200, {'counters': stats, 'pending': engine.jobs.qsize(), 'mode': 'observe'})

        def do_POST(self):
            if not self.authorized():
                return self.reply(401, {'status': 'unauthorized'})
            if self.path not in ('/observe', '/submit'):
                return self.reply(404, {'status': 'not_found'})
            try:
                if self.headers.get('Transfer-Encoding'):
                    raise ValueError('Chunked body unsupported')
                length = int(self.headers.get('Content-Length', '-1'))
                limit = 4096 if self.path == '/observe' else MAX_MAIL
                if not 0 <= length <= limit:
                    return self.reply(413, {'status': 'oversized'})
                body = self.rfile.read(length)
                if len(body) != length:
                    raise ValueError('Incomplete request')
                if self.path == '/observe':
                    meta = metadata(json.loads(body))
                    counts = engine.state.observe(meta)
                    engine.count('observed')
                    return self.reply(200, {'status': 'observed', 'counts': counts})
                encoded = self.headers.get('X-Aissa-Meta', '')
                if len(encoded) > 6000:
                    raise ValueError('Oversized metadata')
                meta = metadata(json.loads(base64.b64decode(encoded, validate=True)))
                code, status = engine.submit(body, meta)
                self.reply(code, {'status': status})
            except (ValueError, TypeError, KeyError, UnicodeError):
                engine.count('bad_request')
                self.reply(400, {'status': 'bad_request'})
            except Exception:
                engine.count('service_error')
                self.reply(503, {'status': 'service_error'})
    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True, type=Path)
    args = parser.parse_args()
    cfg = json.loads(args.config.read_text())
    for key, upper in [('max_pending', 100), ('max_requests_per_minute', 10000), ('llm_timeout', 300)]:
        if type(cfg.get(key)) is not int or not 1 <= cfg[key] <= upper:
            raise ValueError('Invalid '+key)
    token = Path(cfg['token_file']).read_text().strip()
    if len(token) < 32:
        raise ValueError('Use a token of at least 32 characters')
    state = State(Redis(db=cfg.get('redis_db', 6)))
    state.redis.command('PING')  # fail visibly on invalid Redis configuration
    engine = Engine(cfg, state)
    threading.Thread(target=engine.worker, daemon=True).start()
    # Serial HTTP handling bounds handler count/memory. Redis uses short timeouts.
    HTTPServer(('127.0.0.1', 8765), handler(engine, token)).serve_forever()


if __name__ == '__main__':
    main()
