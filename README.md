# AISSA — AI Sample Spam Analyzer

Experimental local multilingual email analyzer for a future Postfix/rspamd
extension. MIT licensed. If it helps you and we meet, buy me a beer.

## Status: 0.2 asynchronous observation PoC

This release includes offline `.eml` analysis and an opt-in rspamd postfilter,
local bounded observation service and Redis account/IP state. It never rejects
messages, learns Bayes or locks users. There is no virus scanner. Campaign
similarity detection is not yet implemented. Live integration must be checked on
your rspamd version before enabling it. The initial Qwen 1.5B smoke test produced
a false positive on a French meeting request; do not use its verdicts to enforce
policy.

Target: Debian 12, Python 3.11+, rspamd 4.2.1 for the subsequent integration.
Python standard library only; no Python runtime dependencies.

## Setup on Debian 12

Install Ollama following https://docs.ollama.com/linux (review downloaded installers
before running them). Keep its API on 127.0.0.1:11434. Model download requires
internet access; inference does not require a cloud account or API key.

Set these variables in the Ollama service environment (systemd override):

```ini
[Service]
Environment="OLLAMA_HOST=127.0.0.1:11434"
Environment="OLLAMA_NUM_PARALLEL=1"
Environment="OLLAMA_MAX_LOADED_MODELS=1"
```

After reloading systemd and restarting Ollama:

```bash
ollama pull qwen2.5:1.5b
ollama show qwen2.5:1.5b
python3 -m aissa samples/ham-fr.eml
python3 -m aissa samples/*.eml > results.jsonl
python3 -m unittest discover -s tests -v
```

Run from the repository root. An optional installed command is available via
`python3 -m pip install .` inside a virtualenv. Windows can also run the CLI
with Python 3.11+ and local Ollama.

Qwen2.5-1.5B-Instruct is an Apache-2.0 test candidate, not a validated phishing
detector: https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct . Record the Ollama
version, model ID/digest and quantization with benchmark results. Tags can change.
Model weights are not bundled and have their own license.

## Output and limitations

Each input yields one JSON line, identified by zero-based sample_index. The
classification is ham, bulk, spam, phishing or uncertain. Confidence is an
uncalibrated model self-assessment; it must not trigger automatic account bans.
Errors produce uncertain/status=error and a nonzero process exit code. Model
explanations can quote mail content: treat output as sensitive.

Only text/plain and text/html bodies are processed. Attachments are skipped.
Displayed From is untrusted. No SPF/DKIM/DMARC verification, OCR, archive scanning,
link fetching or virus detection. Plain text is preferred over HTML when both
exist; HTML href targets are also retained, but anchor-to-target mappings are not
yet represented. The HTML parser is basic and does not simulate CSS rendering.

Input is limited to 2 MiB; body text to 4000 characters; URLs to 12 x 300 characters.
Truncation can hide attacks. Pathological MIME, token-heavy languages or large
prompts can exceed the context budget; investigate uncertain/errors rather than
assuming a successful scan. HTTP timeout defaults to 60 seconds: offline only,
not an acceptable SMTP latency target. Client timeout may not immediately cancel
server inference. Run only one analyzer process at a time during initial testing.

Requests use loopback only, bypass proxies and refuse redirects. Email instructions
are explicitly treated as untrusted, but prompt injection resistance is not
guaranteed. AISSA invokes no tools and executes no model output.

No raw mail is retained by AISSA. It prints the verdict and elapsed time; logging
and retention in Ollama remain the operator's responsibility. Never commit real
mail, keys, credentials or benchmark output containing private content.

## Benchmark before live integration

The five bundled messages are synthetic smoke tests, not evidence of detection
quality. Start with those, then use a private labeled corpus covering legitimate
FR/ES/DE/EN correspondence, newsletters and phishing. Record false positives,
missed attacks, errors, p50/p95 latency and RAM while normal mail services run.
Measure cold model load separately from warm requests. Compare with existing
rspamd decisions and keep training/evaluation campaigns separate.

## Earlier roadmap (superseded by integration below)

1. Validate this offline classifier and hardware budget.
2. Add a bounded local service and replay/benchmark tools.
3. Add zero-weight rspamd symbols for MX and Submission; observe only.
4. Add Redis campaign/account signals with trusted identity rules.
5. Evaluate enforcement only after measuring false positives and failure modes.

Contributions via https://github.com/frickl/aissa . Do not submit real mail in issues.


## Who checks what — data flow in 0.2

| Component | Input / job | Result / recipient |
|---|---|---|
| Postfix / MTA | Accept connection, supply actual client IP and authenticated account if available | Existing rspamd scan; AISSA does not authenticate users |
| Existing rspamd modules | Normal spam, URL, SPF/DKIM/DMARC checks as configured by the operator | Existing actions remain responsible for SMTP decisions |
| `rspamd/aissa.lua` | Observe metadata; apply conditions and sampling before transferring content | Zero-weight `AISSA_STATUS` symbol; selected raw message to local service |
| `aissa.service` | Validate requests, enforce rate/queue limits, admit to RAM queue | Immediate acknowledgement, no LLM wait on SMTP path |
| `aissa.state` / Redis | Account/IP scan counts and separate reputation lanes | Selection counters and expiring state; no bodies stored |
| Single Python worker | Extract bounded text and URLs from selected raw MIME | Local Ollama request, one worker |
| Ollama / Qwen | Classify untrusted text; no network tools or link execution | Advisory ham/bulk/spam/phishing/uncertain result |
| Python worker | Validate output strictly | Correlated JSON journal event; AI suspicion increment for spam/phishing |
| Operator | Independently confirm an abuse event | Explicit confirmed reputation lane; never written by the LLM |

Project maintainer: Gunther Nitzsche (`frickl`). Operator manages installation,
selection policy and independently confirmed events. Classifications are produced
by the named local model, not by the maintainer or ChatGPT. Copyright/license
covers AISSA code; rspamd, Ollama and model weights have separate licenses.

### Configurable selection

`/etc/rspamd/local.d/aissa.conf` is the operator-editable selection file. Conditions
are combined with `all` (AND) or `any` (OR); empty conditions mean eligible.
Sampling is always an additional gate after conditions. `sample_percent=100`
checks all eligible mail; `0.2` checks about one in 500; `0` disables content
submission but keeps metadata counters. There is no direction gate.

Available conditions: `country_not_in`, `require_url`, `min_rspamd_score`,
`symbols_any`, `account_min_10m`, `ip_min_10m`, and minimum suspicion/confirmed
counts for account and IP (see sample configuration). Suspicion is a count of
model spam/phishing verdicts, NOT a calibrated abuse score.

Country currently uses rspamd ASN module's `country` variable: this is the country
of the ASN owner, **not reliable client GeoIP location**. No GeoIP lookup is
implemented. If actual geographic filtering is required, replace this source
with a validated local GeoIP provider first. Unknown country is controlled by
`unknown_country=skip|match` when that condition is enabled. Source IP must be
correctly supplied by your MTA/HAProxy chain; a From/Received header is not trusted
as an identity. Account is only `task:get_user()` from trusted MTA metadata, never
an email From address. Preserve case; normalize account IDs upstream if necessary.

All enabled AISSA scans send small metadata to `/observe`; only selected mail
content goes to `/submit`. Each request timeout is 0.5 seconds, so a scan can wait
up to roughly one second for the two local acknowledgements (not for inference).
Failures add zero-weight status, never an action. If Redis is unavailable, AISSA
skips content submission and rspamd's original filtering continues.

### Redis layout and reputation

Dedicated namespace: `aissa:v1:*`, configurable local Redis DB (example: 6).
Identity keys use SHA-256 of the exact account/IP (pseudonymization, not anonymity).
Ensure DB 6 is appropriate before installation; no FLUSHDB command is used.
The minimal RESP client supports local unauthenticated TCP Redis only in this
release. Existing Redis requiring ACL/AUTH, TLS or Unix sockets needs an adapter;
do not weaken existing Redis security to install AISSA.

* Scan counters: aligned fixed buckets of 60/600/3600 seconds, TTL twice the bucket
  size. These are current-bucket counts, **not sliding windows**. Counts reset at
  boundaries and include attempted scans, not proof of delivery.
* `ai_suspect:<day>`: increment once per spam/phishing verdict, TTL 48h.
* `confirmed:<day>`: increment only by explicit operator command, TTL 48h.
* Selection reads current and previous day for each reputation lane. This is a
  coarse expiration policy, not exponential decay. No automatic sanctions.
* Observations and reputation writes use atomic Lua scripts and dedup keys with
  24h TTL. Same queue-ID+digest is counted once within that period. Different queue
  IDs/reinjections are distinct; rescans without queue ID collapse by digest.
* Submission dedup is local RAM for one hour, maximum 10,000 entries; it resets
  on restart. Redis verdict dedup limits repeated reputation increments.

Operator confirmation example (identity appears in shell history):

```bash
python3 -m aissa.reputation account USER_ID --event-id incident-unique-id --redis-db 6
```

This records one confirmed event; it does not disable the account. Avoid shared
IP sanctions: the initial IP lane is observation only.

### Installing the observation service on Debian 12

First merge these files into your checkout. Review existing Redis and rspamd
configuration. Commands below assume `/opt/aissa`, `_rspamd` as rspamd's group,
Python 3.11 and Redis on localhost:6379 without authentication, and local Ollama.
Run setup as root. Existing files must be preserved when merging configuration.

```bash
getent group _rspamd
redis-cli -n 6 PING
# Inspect existing use of DB 6 before choosing it.
redis-cli -n 6 DBSIZE
id aissa || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin aissa
usermod -a -G _rspamd aissa
install -d -m 0750 -o root -g _rspamd /etc/aissa
# Generate token once; preserve it on updates.
test -f /etc/aissa/token || python3 -c 'import secrets; print(secrets.token_hex(32))' > /etc/aissa/token
chown aissa:_rspamd /etc/aissa/token
chmod 0640 /etc/aissa/token
install -m 0640 -o root -g _rspamd deploy/service.json /etc/aissa/service.json
install -m 0644 deploy/aissa.service /etc/systemd/system/aissa.service
systemctl daemon-reload
systemctl enable --now aissa
systemctl status aissa --no-pager
```

The service MemoryMax applies only to the Python service, NOT Ollama. Ollama's
model memory and CPU must still be monitored/limited separately. Model inference
uses two threads but can share CPU resources with other services.

### Loading the rspamd module

```bash
install -m 0644 rspamd/aissa.lua /etc/rspamd/aissa.lua
install -m 0644 rspamd/aissa.conf /etc/rspamd/local.d/aissa.conf
```

Merge this block **once** into `/etc/rspamd/rspamd.conf.local` (create if absent).
Custom local.d files are not implicitly loaded just because they exist:

```ucl
aissa {
  .include "$LOCAL_CONFDIR/local.d/aissa.conf"
}
```

Merge this line **once** into `/etc/rspamd/rspamd.local.lua`, preserving existing
Lua customizations:

```lua
dofile('/etc/rspamd/aissa.lua')
```

Before reloading, verify the daemon is up and config/module loading succeeds:

```bash
rspamadm configtest
rspamadm configdump aissa
# Only reload after configtest succeeds.
systemctl reload rspamd
journalctl -u aissa -n 30 --no-pager
```

Start with 0.2% sampling. For a controlled `rspamc` smoke test temporarily set
`sample_percent=100`, leave conditions unset, configtest and reload. A real scan
should show AISSA_STATUS(queued), followed by a journal verdict later:

```bash
rspamc < samples/phish-fr.eml
journalctl -u aissa -n 20 --no-pager
```

Restore production sampling afterwards. No AI verdict is retroactively inserted
into the completed rspamd scan. Milter must already invoke rspamd for both MX and
Submission; existing rspamd bypass settings can prevent this postfilter from
running and must be tested on both paths.

### Metrics, retention and failure behavior

`GET /metrics` requires the same Bearer token; JSON counters include observations,
queued/completed jobs, duplicates, queue/rate rejection, inference/service errors
and pending queue size. Metrics reset on restart and cover this service instance.
Lua skip reasons are in zero-weight AISSA_STATUS symbols (`criteria`, `sample`,
`size`, `capacity`, etc.) in rspamd history/logs; they are not all aggregated by
service metrics yet. In a cluster each service has its own rate/queue limits;
Redis namespace and stable IDs require planned coordination before scaling.

Capacity: 20 waiting messages plus one running, at most 2 MiB each; 10 admissions
per fixed minute in the example. Excess checks are dropped, not retried. Raw MIME
(including attachments) traverses loopback and exists in process memory, but only
extracted text/URLs are sent to the model. Nothing is spooled to disk. Queued jobs
are lost on restart; a timeout may leave backend inference running temporarily.

Journal records event/queue ID, class, model confidence, latency and existing
rspamd score; model reason/body/account/IP are not printed by the service. CLI
output still includes model explanations and should be treated as sensitive.
OS swap/core dumps and Ollama/journal retention are operator-controlled.
The shared token prevents casual local submissions, but trusted privileged local
processes can still forge metadata; this is not a multi-tenant untrusted API.

Disable by setting `enabled=false`, configtest/reload rspamd, then stop aissa.
Existing mail filtering remains in place. No account-disable API is implemented.

### Verification status

Automated tests cover extraction, verdict validation, HTTP authentication and
submission, bounded queue/rate limits, RESP parsing and separation of reputation
lanes. Redis scripting and actual rspamd runtime behavior require integration
verification on the target server; passing Python tests is not an installation
certification. Model quality remains unvalidated and known false positives exist.

API references: https://docs.rspamd.com/lua/rspamd_http/ ,
https://docs.rspamd.com/lua/rspamd_task/ , https://docs.rspamd.com/modules/asn/ .
