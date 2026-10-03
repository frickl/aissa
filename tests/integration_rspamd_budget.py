"""Explicit isolated scan test; never loads /etc/rspamd or the production bridge.

Requires an extracted official rspamd package plus Redis and its shared libraries.
Run: python3 tests/integration_rspamd_budget.py --runtime-root /path/to/runtime
This tests real scanner/HTTP self-scan APIs, not SMTP or production History.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def await_listener(proc, port):
    for _ in range(100):
        if proc.poll() is not None:
            raise RuntimeError(f'Process exited during startup: {proc.returncode}')
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError('Test listener did not start')


def stop(proc):
    if proc is not None and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-root', required=True, type=Path)
    args = parser.parse_args()
    runtime = args.runtime_root.resolve()
    repo = Path(__file__).resolve().parent.parent
    binary = runtime / 'usr/bin/rspamd'
    redis_binary = runtime / 'usr/bin/redis-server'
    share = runtime / 'usr/share/rspamd'
    env = dict(os.environ)
    env['LD_LIBRARY_PATH'] = ':'.join([
        str(runtime / 'usr/lib/rspamd'),
        str(runtime / 'usr/lib/x86_64-linux-gnu'),
        env.get('LD_LIBRARY_PATH', ''),
    ])
    print(subprocess.check_output([str(binary), '--version'], env=env, text=True).strip())

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get('Content-Length', 0)))
            data = json.dumps({'status': 'pending'}).encode()
            self.send_response(202 if self.path == '/submit' else 200)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    redis = proc = None
    try:
        with tempfile.TemporaryDirectory(prefix='aissa-budget-') as directory:
            root = Path(directory)
            (root / 'token').write_text('x' * 64)
            source = (repo / 'rspamd/aissa.lua').read_text()
            original_endpoint = "local endpoint = 'http://127.0.0.1:8765'"
            assert source.count(original_endpoint) == 1
            # Only the isolated copy points at this random-port fake bridge.
            (root / 'aissa.lua').write_text(source.replace(
                original_endpoint,
                f"local endpoint = 'http://127.0.0.1:{server.server_port}'"))
            redis_port = free_port()
            with (root / 'redis.log').open('w') as redis_log:
                redis = subprocess.Popen([
                    str(redis_binary), '--port', str(redis_port), '--bind',
                    '127.0.0.1', '--save', '', '--appendonly', 'no'],
                    env=env, stdout=redis_log, stderr=redis_log)
                await_listener(redis, redis_port)
                for worker in ('normal', 'rspamd_proxy'):
                    for wait, expected in ((10, 7), (2, 6.324)):
                        port = free_port()
                        proxy = ('milter=false; upstream { local {self_scan=true; default=true;} }'
                                 if worker == 'rspamd_proxy' else '')
                        (root / 'config.conf').write_text(f'''
logging {{type="file"; filename="{root}/rspamd.log"; level="info";}}
options {{task_timeout=8; filters=""; cache_file="{root}/cache-{worker}-{wait}";
  tempdir="{root}"; url_tld="{share}/effective_tld_names.dat";}}
worker "{worker}" {{bind_socket="127.0.0.1:{port}"; count=1; {proxy}}}
actions {{reject=15;}}
redis {{servers="127.0.0.1:{redis_port}";}}
aissa {{enabled=true; token_file="{root}/token"; scoring_enabled=true;
  sample_percent=100; score_wait_seconds={wait}; redis_timeout=0.2;}}
lua="{root}/test.lua";
''')
                        (root / 'test.lua').write_text(f'''
package.path='{share}/lualib/?.lua;'..package.path
rspamd_config:register_symbol({{name='TEST_SLOW',type='prefilter',score=0,
  callback=function(task) task:add_timer(4.324,function() return false end) end}})
dofile('{root}/aissa.lua')
''')
                        command = [str(binary), '-f', '-i', '-T', '-c', str(root / 'config.conf')]
                        for key, value in dict(LUALIBDIR=share / 'lualib', SHAREDIR=share,
                                              RULESDIR=share / 'rules', CONFDIR=runtime / 'etc/rspamd').items():
                            command.extend(['--var', f'{key}={value}'])
                        with (root / 'stderr.log').open('w') as output:
                            proc = subprocess.Popen(command, env=env, stdout=output, stderr=output)
                            try:
                                await_listener(proc, port)
                                request = urllib.request.Request(
                                    f'http://127.0.0.1:{port}/checkv2',
                                    data=b'From: a@example.com\r\nTo: b@example.net\r\nSubject: test\r\n\r\nHello\r\n',
                                    headers={'Queue-Id': f'{worker}-{wait}', 'Content-Type': 'message/rfc822'})
                                started = time.monotonic()
                                with urllib.request.urlopen(request, timeout=15) as response:
                                    result = json.load(response)
                                elapsed = time.monotonic() - started
                                status = result.get('symbols', {}).get('AISSA_STATUS', {}).get('options', [])
                                assert status == ['score_timeout'], result
                                assert expected - 0.3 <= elapsed < expected + 0.5, elapsed
                                print(f'{worker}: requested={wait}s, elapsed={elapsed:.3f}s, status={status[0]}')
                            except Exception:
                                print((root / 'stderr.log').read_text())
                                print((root / 'rspamd.log').read_text())
                                raise
                            finally:
                                stop(proc)
                assert 'post-processing of task time out' not in (root / 'rspamd.log').read_text()
                stop(redis)
    finally:
        stop(proc)
        stop(redis)
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == '__main__':
    main()
