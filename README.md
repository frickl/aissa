# AISSA — AI Sample Spam Analyzer

Experimental, locally operated multilingual email analysis for rspamd.
Maintainer: Gunther Nitzsche (`frickl`). MIT licensed.
If this helps you and we meet, buy me a beer.

## Status

Version 0.3 is an observation prototype, not an enforcement filter.
The Qwen 1.5B smoke test already produced a false positive on legitimate French
correspondence. Model confidence is not a calibrated probability.

Both MX and Submission are supported without a direction filter. Existing
rspamd/MTA settings must actually scan both paths. No account locking, SMTP
rejection, Bayes training, virus scanning, OCR or campaign similarity is added.

This version moves active Redis operations to rspamd Lua. Python does not read
Redis passwords or connect to Redis. The legacy state.py and service.py helpers
remain for compatibility/tests; start the new aissa.bridge entry point.

## Who checks what

| Component | Responsibility |
|---|---|
| MTA | Supplies trusted connection IP and authenticated account, if available |
| Existing rspamd modules | Existing spam, URL and authentication checks and SMTP actions |
| AISSA Lua postfilter | Counts scans, reads reputation, applies selection and sampling |
| Local Python bridge | Enforces queue/rate/result limits; accepts selected raw MIME |
| Python analyzer | Extracts bounded text/URLs and validates model JSON |
| Local Ollama model | Classifies message content; no tools or link fetching |
| rspamd controller Lua | Collects results, writes reputation to Redis, acknowledges results |
| Operator | Independently confirms abuse through the explicit confirmation command |

The model receives extracted message content, not verified account history.
Account/IP metadata is used for counting and selection in Lua.
Displayed From is never used as an authenticated account identity.

## Data flow

1. Lua obtains account/IP from trusted MTA metadata.
2. An atomic Redis script increments fixed-window counters and reads reputation.
3. Configured conditions, random sampling and size limits select messages.
4. Only selected full MIME is sent over authenticated loopback HTTP.
5. A single worker analyzes messages; SMTP does not wait for inference.
6. Results remain in RAM until rspamd confirms successful Redis processing.
7. Redis deduplication prevents repeated collection from increasing reputation.

The controller polls independently of new mail. A controller worker must be
running and load the AISSA Lua configuration. Collection by multiple controllers
is safe because result application is idempotent.

RAM queues and unacknowledged results are lost on Python restart. There is no
disk spool or durable delivery guarantee. While the service remains running,
a Redis outage retains completed results. Once result capacity is exhausted,
new samples are refused instead of deleting older results.

## Configuration

Selection: /etc/rspamd/local.d/aissa.conf.
Service: /etc/aissa/service.json.
Shared local API token: /etc/aissa/token.

Sampling applies after conditions:
* 100: every eligible message, subject to capacity.
* 0.2: about one in 500 eligible messages.
* 0: count metadata but submit no message content.

Conditions use all (AND) or any (OR). No conditions means all mail is eligible.
Available criteria: URL presence, rspamd score/symbols, country exclusion,
account/IP fixed-window counts, AI suspicion and independently confirmed events.

Country currently means the ASN owner's country reported by rspamd, not reliable
client GeoIP location. Unknown-country behavior is explicitly configurable.

Account keys use the exact authenticated ID. IP must be correct through the
Postfix/HAProxy chain. Header From/Received values are not identity sources.
node_id must distinguish independent MTAs sharing the same Redis namespace.

## Redis and reputation

lua_redis parses the effective rspamd Redis configuration, including credentials
and server configuration. No grepping, password copying or Python AUTH is needed.
AISSA uses the inherited Redis DB with the new aissa:v2: namespace.

Only AISSA's parameter copy gets redis_timeout=0.2 seconds and expand_keys=false:
its keys are built explicitly. Existing rspamd modules keep their own settings.
Writes and atomic snapshots use the configured write server. Read replicas are
not used for these read-modify-write operations.

This PoC routes all AISSA scripts through one shard key. It targets one logical
Redis writer and does not claim native Redis Cluster compatibility or automatic
cluster-wide scaling. Multi-key scripts require appropriate EVAL permissions.

Identity components are Base64-encoded, NOT anonymized. Protect Redis accordingly.

Counters:
* Aligned 60/600/3600-second buckets, TTL twice the bucket length.
* Counts are scan attempts, not accepted or delivered messages.
* These are fixed buckets, not rolling windows.
* Observation dedup: node ID + queue ID + message digest, TTL 48 hours.
* Without queue ID, identical content on the same node can collapse.

Reputation:
* ai_checked: successful model classifications.
* ai_suspect: spam/phishing model classifications.
* confirmed: explicit independent operator confirmation only.
* Daily buckets expire after 48 hours; selection reads today and yesterday.
* This is coarse expiration, not exponential decay or a calibrated risk score.
* AI and confirmed result dedup keys are separate, with 48-hour TTL.
* Delayed results are assigned to their completion day, not collection day.
* Errors never count as ham or confirmed abuse.

## Service setup on Debian 12

Assumptions: /opt/aissa, Python 3.11, existing rspamd and local Ollama.
No additional Python dependencies are required.

As root, create the service user and shared-token directory once:

```bash
getent group _rspamd
id aissa || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin aissa
usermod -a -G _rspamd aissa
install -d -m 0750 -o root -g _rspamd /etc/aissa
test -f /etc/aissa/token || python3 -c 'import secrets; print(secrets.token_hex(32))' > /etc/aissa/token
chown aissa:_rspamd /etc/aissa/token
chmod 0640 /etc/aissa/token
cat >> /opt/aissa/t.py <<'AISSA_UPDATE_END'

```

Copy the example service configuration, preserving intentional local changes:

```bash
install -m 0640 -o root -g _rspamd deploy/service.json /etc/aissa/service.json
install -m 0644 deploy/aissa.service /etc/systemd/system/aissa.service
systemctl daemon-reload
systemctl enable --now aissa
systemctl status aissa --no-pager
```

Defaults: 20 queued messages, one worker, 10 admissions per fixed minute,
1000 outstanding jobs/results. MemoryMax applies to Python, not Ollama.
Ollama must remain on 127.0.0.1:11434.

## rspamd setup

Copy rspamd/aissa.lua to /etc/rspamd/aissa.lua. Merge the example configuration
into /etc/rspamd/local.d/aissa.conf, preserving your selected criteria.

Merge once into /etc/rspamd/rspamd.conf.local:

```ucl
aissa {
  .include "$LOCAL_CONFDIR/local.d/aissa.conf"
}
```

Merge once into /etc/rspamd/rspamd.local.lua:

```lua
dofile('/etc/rspamd/aissa.lua')
```

Check configuration before reloading:

```bash
rspamadm configtest
# Only after a successful configuration test:
systemctl reload rspamd
journalctl -u aissa -n 30 --no-pager
```

A controller worker must load the module for result collection.
For a controlled synthetic test, temporarily set sample_percent=100,
leave conditions unset, then configtest/reload:

```bash
rspamc < samples/phish-fr.eml
journalctl -u aissa -n 20 --no-pager
```

Expect AISSA_STATUS(queued), followed by a Python result.
Restore the intended sampling afterwards.

## Operator confirmation

Only use for independently established abuse:

```bash
python3 -m aissa.reputation account ACCOUNT_ID --event-id incident-unique-id
```

This uses the local API token, not Redis credentials. The controller records
the event in the confirmed lane. No account is disabled. Reusing an event ID
within the deduplication period does not add another event.
Identity arguments can appear in shell history.

## API and diagnostics

All endpoints require Authorization: Bearer <local token>.

* POST /submit: raw MIME; Base64 JSON metadata in X-Aissa-Meta.
* GET /results: up to eight completed, unacknowledged results.
* POST /ack: {"ids": ["result-id"]}.
* POST /confirm: operator metadata including identity and event_id.
* GET /metrics: counters, pending queue/results and outstanding capacity.

Redis and HTTP acknowledgements add a bounded wait to the rspamd scan.
Inference runs asynchronously and cannot change a completed SMTP decision.
AISSA_STATUS has zero weight. Redis/service errors do not override existing
rspamd actions. Results remain in RAM until acknowledged; restarting Python
loses queued messages and unacknowledged results.

## Content limits and privacy

Raw MIME is limited to 2 MiB, extracted body to 4000 characters, and URLs to
12 x 300 characters. Attachments are not analyzed. Full MIME temporarily exists
in memory; only extracted content is sent to the local model.
HTML extraction is basic. Truncation can hide attacks.
No URL is fetched. Prompt injection remains a model-quality risk.

Redis contains identity-related counters, not mail bodies.
Journal entries omit account/IP, body and model explanation.
CLI output does include explanations and may contain sensitive text.
Protect the API token and Redis. Swap, core dumps, Ollama logging and journal
retention remain operator-controlled.

## Verification

```bash
python3 -m unittest discover -s tests -v
python3 -m aissa samples/phish-fr.eml
```

Tests cover retained results, acknowledgements, capacity, error results,
operator confirmation and existing extraction/validation behavior.
They do not certify live Redis or rspamd compatibility.

This update was generated without a working execution environment.
Local tests, rspamadm configtest and a synthetic end-to-end scan are required
before observing real traffic. Known model false positives remain.

References:
https://docs.rspamd.com/lua/lua_redis/
https://docs.rspamd.com/lua/rspamd_config/
https://docs.rspamd.com/lua/rspamd_http/


## Live scoring extension

See [AISSA live scoring](docs/aissa-scoring.md) for the current bridge/Lua
flow, configurable points, bounded scan wait, Redis collection and limitations.
This supersedes earlier observe-only integration instructions when enabled.


## Classifier evaluation

See [classifier evaluation](docs/aissa-evaluation.md) for the prompt rubric,
synthetic evaluation cases, expected labels, benchmark commands and limitations.

<!-- AISSA_FLOW_BEGIN -->
## Processing order (rough pseudocode)

This describes the current bridge/Lua integration. Configuration lives mainly in
rspamd/local.d. Selection, model classification, live scoring and later reputation
updates are separate steps. AISSA applies to both MX and Submission; it does not
require a direction. An authenticated account is used when available, otherwise
only the available IP identity is recorded.

```text
ON EACH MESSAGE (MX or Submission):
  rspamd:
    Run the normal enabled filters; compute existing symbols and score.
    Invoke the AISSA Lua postfilter if enabled for this scan.

  AISSA Lua + Redis:
    Read account, connecting IP, country metadata, queue ID and message digest.
    Record account/IP observations once per event; read reputation counters.
    If Redis is unavailable: add zero-point status; stop AISSA for this scan.
    Check configured conditions (country, URLs, score, symbols, reputation).
    Apply random sampling and the message-size limit.
    If not selected: add zero-point status; stop AISSA for this scan.

  Python bridge (authenticated local HTTP API):
    Reuse a fresh verdict or an already queued/running job for the same event.
    Otherwise check result capacity, admission rate and queue capacity.
    If full or rate-limited: refuse this job; Lua adds zero-point status.
    If accepted: queue the message for the single model worker.

  Python analyzer + local Ollama (background worker):
    Extract bounded subject, displayed sender, text and URLs from MIME.
    Exclude attachments; treat all mail content as untrusted evidence.
    Ask the configured model for ham/bulk/spam/phishing/uncertain + confidence.
    Validate JSON fields, class, confidence range and completion.
    Keep success or error until the Redis collector acknowledges it.
    Keep a separate short verdict cache for live scans and repeated scans.

  AISSA Lua + rspamd (the current scan):
    If scoring is disabled: finish immediately after submission.
    Otherwise poll for a verdict within the configured AISSA wait budget.
    Timely valid verdict: add its class symbol with the configured weight.
    Error, unavailable verdict or expired budget: add zero-point status.
    rspamd combines AISSA points with existing rules and chooses its action.
    AISSA does not directly force accept, reject, greylist or account disabling.

INDEPENDENTLY, EVERY COLLECTION INTERVAL:
  rspamd controller Lua + Python bridge + Redis:
    Fetch retained completed results, independently of incoming messages.
    For success: update account/IP ai_checked once per event.
    For spam/phishing: additionally update ai_suspect once per event.
    For inference error: add no ham or abuse reputation credit.
    For explicit operator confirmation only: update the separate confirmed lane.
    If Redis writing fails: retain the result and retry on the next poll.
    Acknowledge successfully applied or terminal-error rows to the bridge.
```

A late verdict can update reputation but cannot change an already finished mail
scan. AI suspicion is not operator-confirmed abuse. Live points are configured
in local.d/aissa-scores.conf; no additional reputation points are implemented.
Redis passwords/connections are handled by rspamd's lua_redis configuration;
Python does not read or copy the Redis password. Country uses rspamd's supplied
metadata, not a guarantee of exact physical location.

A 100% sample rate selects every message that passes the other gates; it does not
bypass rate/queue limits or guarantee a timely score. The single worker's queue
and model latency consume the live budget. The overall rspamd worker/client/MTA
timeouts must leave enough time for the complete scan. Confidence is a model
self-assessment, not a calibrated probability. Virus scanning is not part of
AISSA; attachments are excluded from model analysis. Bridge queues/results/cache
are in memory and are lost on restart. Acknowledgement does not delete the short
live verdict cache; expired finished verdicts can be analyzed again under the
normal admission limits, while Redis application remains deduplicated.

See [live scoring](docs/aissa-scoring.md) and
[classifier evaluation](docs/aissa-evaluation.md) for details and limitations.

<!-- AISSA_FLOW_END -->
