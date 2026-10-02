"""Small local RESP2 client; no pip dependencies. One connection per atomic script."""
import hashlib
import socket
import time


class Redis:
    def __init__(self, host='127.0.0.1', port=6379, db=6):
        if host != '127.0.0.1':
            raise ValueError('Redis must be local')
        self.host, self.port, self.db = host, port, db

    @staticmethod
    def read(f):
        line = f.readline(65537)
        if not line.endswith(b'\r\n'):
            raise OSError('Invalid Redis response')
        kind, value = line[:1], line[1:-2]
        if kind == b'-':
            raise OSError('Redis command failed')
        if kind == b'+':
            return value.decode()
        if kind == b':':
            return int(value)
        if kind == b'$':
            length = int(value)
            if length == -1:
                return None
            if not 0 <= length <= 65536:
                raise OSError('Oversized Redis response')
            data = f.read(length + 2)
            if len(data) != length + 2 or not data.endswith(b'\r\n'):
                raise OSError('Incomplete Redis response')
            return data[:-2].decode()
        if kind == b'*':
            length = int(value)
            if not 0 <= length <= 100:
                raise OSError('Invalid Redis array')
            return [Redis.read(f) for _ in range(length)]
        raise OSError('Unknown Redis response')

    def command(self, *args):
        def send(sock, f, parts):
            encoded = [str(p).encode() for p in parts]
            sock.sendall(b'*%d\r\n' % len(encoded) + b''.join(
                b'$%d\r\n' % len(p) + p + b'\r\n' for p in encoded))
            return self.read(f)
        with socket.create_connection((self.host, self.port), timeout=0.3) as sock:
            with sock.makefile('rb') as f:
                send(sock, f, ['SELECT', self.db])
                return send(sock, f, args)


def identity(kind, value):
    return 'aissa:v1:' + kind + ':' + hashlib.sha256(value.encode()).hexdigest()


OBSERVE = """
local fresh = redis.call('SET', KEYS[1], '1', 'NX', 'EX', 86400)
local result = {}
for i=2,#KEYS do
  local n
  if fresh then
    n=redis.call('INCR',KEYS[i])
    redis.call('EXPIRE',KEYS[i],tonumber(ARGV[i-1])*2)
  else n=tonumber(redis.call('GET',KEYS[i]) or '0') end
  result[#result+1]=n
end
return result
"""
SUSPICION = """
if not redis.call('SET',KEYS[1],'1','NX','EX',86400) then return 0 end
for i=2,#KEYS do
  redis.call('INCR',KEYS[i]); redis.call('EXPIRE',KEYS[i],172800)
end
return 1
"""


class State:
    def __init__(self, redis):
        self.redis = redis

    def observe(self, meta):
        now = int(time.time())
        keys = [identity('observed', meta['event_id'])]
        labels, windows = [], []
        for kind in ('account', 'ip'):
            if meta.get(kind):
                base = identity(kind, meta[kind])
                for seconds in (60, 600, 3600):
                    keys.append(base + ':count:' + str(seconds) + ':' + str(now // seconds))
                    labels.append(kind + '_' + str(seconds))
                    windows.append(seconds)
        values = self.redis.command('EVAL', OBSERVE, len(keys), *keys, *windows)
        result = dict(zip(labels, values))
        day = now // 86400
        for kind in ('account', 'ip'):
            if meta.get(kind):
                base = identity(kind, meta[kind])
                for lane in ('ai_suspect', 'confirmed'):
                    scores = self.redis.command('MGET', base+':'+lane+':'+str(day),
                                                base+':'+lane+':'+str(day-1))
                    result[kind+'_'+lane] = sum(int(v or 0) for v in scores)
        return result

    def suspect(self, meta):
        day = int(time.time()) // 86400
        keys = [identity('judged', meta['event_id'])]
        for kind in ('account', 'ip'):
            if meta.get(kind):
                keys.append(identity(kind, meta[kind]) + ':ai_suspect:' + str(day))
        self.redis.command('EVAL', SUSPICION, len(keys), *keys)

    def confirm(self, kind, value, event_id):
        if kind not in ('account', 'ip') or not value or not event_id:
            raise ValueError('Specify account/ip, identity and unique confirmed event ID')
        keys = [identity('confirmed_event', kind+':'+value+':'+event_id),
                identity(kind, value)+':confirmed:'+str(int(time.time())//86400)]
        return self.redis.command('EVAL', SUSPICION, len(keys), *keys)
