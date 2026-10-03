# Installation and operations

These instructions assume an existing Linux mail server with Rspamd, Redis and
local Ollama, Python 3.11+, and a checkout at `/opt/aissa`. Rspamd 4.2.1 was used
for the reported real-daemon tests. Validate on your own installation.

## Python bridge

As root, create the service identity and token once. Existing installations
must preserve their token and local JSON values; see migration below.

```bash
cd /opt/aissa
id aissa || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin aissa
getent group _rspamd
# On distributions with a different Rspamd group, use that group below.
test -f deploy/aissa.token || python3 -c 'import secrets; print(secrets.token_hex(32))' > deploy/aissa.token
chown root:aissa deploy/aissa.token
chmod 0640 deploy/aissa.token
install -m 0640 -o root -g _rspamd deploy/aissa.token /etc/rspamd/local.d/aissa.token
test -f deploy/service.local.json || install -m 0640 -o root -g aissa deploy/service.json deploy/service.local.json
find /opt/aissa/aissa -type f -name '*.py' -exec chmod a+r {} +
install -m 0644 deploy/aissa.service /etc/systemd/system/aissa.service
systemctl daemon-reload
systemctl enable --now aissa
systemctl status aissa --no-pager
ss -ltnp 'sport = :8765'
```

All parent directories must permit traversal by the service user. Model inference
runs in Ollama, outside the Python service's memory limit. Keep Ollama bound to
loopback (`127.0.0.1:11434`). The bridge listens on `127.0.0.1:8765`.

`deploy/service.local.json` and `deploy/aissa.token` are untracked local files.
Defaults are one worker, 20 queued messages, 10 admissions per fixed minute,
1,000 outstanding jobs/results, 60-second model network timeout, 1,000 text
characters and 1,800 seconds of Ollama model retention. Retention can help
prompt-prefix reuse but does not guarantee a cache hit or prewarm the model.

## Rspamd integration

Install `rspamd/aissa.lua` as **`/etc/rspamd/local.d/aissa.lua`**. Merge once into
`/etc/rspamd/rspamd.local.lua`:

```lua
dofile('/etc/rspamd/local.d/aissa.lua')
```

Merge once into `/etc/rspamd/rspamd.conf.local`:

```ucl
aissa {
  .include "$LOCAL_CONFDIR/local.d/aissa.conf"
}
```

Review the repository's `rspamd/aissa.conf` rather than copying it unchanged.
For initial observation, use one unambiguous set of values:

```ucl
enabled = true;
token_file = "/etc/rspamd/local.d/aissa.token";
node_id = "your-unique-node-name";
sample_percent = 100;
combine = "all";
min_rspamd_score = 3;
max_rspamd_score = 15;
max_message_bytes = 2097152;
redis_timeout = 0.2;
result_poll_seconds = 2;
scoring_enabled = false;
score_wait_seconds = 20;
scan_finish_reserve_seconds = 1;
.include "$LOCAL_CONFDIR/local.d/aissa-scores.conf"
```

Merge these into `/etc/rspamd/local.d/aissa.conf`; avoid duplicate keys. Install
`rspamd/aissa-scores.conf` as `/etc/rspamd/local.d/aissa-scores.conf`. It is
included inside the AISSA section. Repository weights are phishing +3, spam +1,
and zero for ham/bulk/uncertain; live weights on your server may differ.

The example selects scores at least 3 and below 15; it misses suspicious content
with a low/negative score. Sampling applies after criteria. No criteria means
all suitable messages are eligible, still subject to admission and capacity.
Country refers to Rspamd's supplied ASN country, not verified physical location.

A controller worker must load AISSA for independent result collection. Redis
credentials remain in Rspamd's effective Redis configuration; Python does not
connect directly to Redis. Account identity must come from authenticated MTA
metadata and connection IP must survive any trusted proxy handoff correctly.

```bash
rspamadm configtest
# Continue only if configtest succeeds.
systemctl reload rspamd
rspamadm configdump aissa
journalctl -u aissa -n 30 --no-pager
```

Observation submits eligible mail without waiting for inference or adding class
points. Confirm both the submission and later result in logs. Before enabling
live scoring, read [the deadline limitations](aissa-scoring.md), check effective
MTA/worker/task settings, and test actual SMTP acknowledgements and History.

## API and diagnostics

Every endpoint requires `Authorization: Bearer <local token>`.

| Endpoint | Purpose |
|---|---|
| `POST /submit` | Selected raw MIME with Base64 JSON metadata in `X-Aissa-Meta` |
| `POST /verdict` | Current live result for an event ID |
| `GET /results` | Up to eight completed, unacknowledged results |
| `POST /ack` | Acknowledge collected result IDs |
| `POST /confirm` | Independently established abuse event |
| `GET /metrics` | Counters, queue/results and outstanding capacity |

The bridge journal's `mode: observe` does not describe whether Rspamd scored a
verdict. Inspect Rspamd class symbols and `AISSA_STATUS` for the scan outcome.
Journal results omit mail text and model explanations; CLI output contains an
explanation and can disclose sensitive content.

For independently confirmed abuse only:

```bash
python3 -m aissa.reputation account ACCOUNT_ID --event-id UNIQUE_INCIDENT_ID \
  --token-file /opt/aissa/deploy/aissa.token
```

This records a separate confirmed lane; it does not suspend an account. Identity
arguments may remain in shell history. AI suspicion must not be treated as
independently confirmed abuse.

## Existing /etc/aissa installation

Preserve the installed JSON values and token. Copy them to
`/opt/aissa/deploy/service.local.json` and `/opt/aissa/deploy/aissa.token`, changing
only `token_file` in the copied JSON. Both should be root:aissa mode 0640.
Keep the matching Rspamd token under `/etc/rspamd/local.d`.

Preserve existing service hardening/local overrides. A systemd drop-in can clear
the old ExecStart and replace it:

```ini
[Service]
ExecStart=
ExecStart=/usr/bin/python3 -m aissa.bridge --config /opt/aissa/deploy/service.local.json
```

After daemon-reload, restart during an idle period: RAM jobs/results are lost.
Verify effective ExecStart, status, listener and authenticated submission before
removing obsolete files. Do not overwrite local configuration during later pulls.
