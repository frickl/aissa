# AISSA live scoring

AISSA selects mail on MX and Submission without a direction requirement. This
extension preserves asynchronous Redis result collection and adds bounded live
scoring. Low volume permits `sample_percent = 100`; conditions still apply.

## What checks what

1. rspamd runs its existing rules and supplies authenticated account, connecting
   IP, queue ID, message digest, country metadata and current score.
2. Lua atomically records account/IP observations in rspamd's configured Redis
   and reads reputation. Redis connections/authentication remain in lua_redis;
   Python does not read or copy a Redis password.
3. Lua applies configured conditions, sampling and the message-size limit.
4. Selected MIME messages go to the authenticated loopback bridge. Its existing
   admission, rate, deduplication, queue and retained-result limits apply.
5. Python extracts bounded text/URLs and asks local Ollama for a classification.
   Attachments are excluded by the analyzer. This is not a virus scanner.
6. In scoring mode Lua polls `/verdict` every 0.25 seconds, using short HTTP
   requests. Poll timers belong to the current rspamd task. Its monotonic budget
   starts when the AISSA callback begins, including AISSA Redis/submission time.
7. A valid result arriving before the deadline inserts exactly one class symbol.
   rspamd combines its weight with existing rules and chooses its normal action.
   AISSA never directly forces accept/reject/greylist or modifies SMTP direction.
8. Controller workers independently collect `/results`, write reputation via
   Redis EVAL and `/ack` successfully applied rows. Error rows are acknowledged
   without ham or abuse credit. A scan never acknowledges collection rows.

## Configuration

Keep the existing loader and configuration includes. Add to
`/etc/rspamd/local.d/aissa.conf`:

```ucl
sample_percent = 100;
scoring_enabled = true;
score_wait_seconds = 10;
.include "$LOCAL_CONFDIR/local.d/aissa-scores.conf"
```

`score_wait_seconds` accepts 1..30 seconds. It is an AISSA budget, not a strict
wall-clock guarantee when an event loop or host is overloaded. Set
`scoring_enabled = false` to retain observation and Redis collection without
waiting for live verdicts. This also disables class symbols/points.

Weights live in `/etc/rspamd/local.d/aissa-scores.conf`, included inside the
AISSA section, not as a standalone rspamd section:

```ucl
scores {
  phishing = 3.0;
  spam = 1.0;
  bulk = 0.0;
  ham = 0.0;
  uncertain = 0.0;
}
```

Weights are registered as virtual symbols and remain subject to ordinary rspamd
metric/settings overrides. Change the weights and reload rspamd. Weight values
must be finite numbers in -100..100. Initial ham weight is zero: a small model's
ham verdict must not cancel other evidence. Confidence is displayed as an option,
not multiplied into the score or used as a calibrated probability threshold.

| Class | Symbol | Default weight |
|---|---|---:|
| phishing | AISSA_PHISHING | 3 |
| spam | AISSA_SPAM | 1 |
| bulk | AISSA_BULK | 0 |
| ham | AISSA_HAM | 0 |
| uncertain | AISSA_UNCERTAIN | 0 |

Errors, unavailable service, queue/rate/result capacity and expired live budgets
only insert zero-weight `AISSA_STATUS`. No fallback ham classification is added.
Late results still update asynchronous observation/reputation, but cannot modify
an already finished scan. Existing zero-weight status-symbol configuration should
remain zero. Model results can contribute to rejection together with other rules;
+3 by itself is not a guarantee against a false rejection.

## Timeouts and activation

A 10-second AISSA wait needs a larger *overall* rspamd task timeout to leave room
for preceding filters. Check actual scanner, proxy self-scan and controller
configuration; commonly used defaults are only 8 seconds. Set `task_timeout =
20s;` in the applicable worker's local configuration before enabling the 10-second
wait. Typical files are `local.d/worker-normal.inc`,
`local.d/worker-proxy.inc` (self-scan), and `local.d/worker-controller.inc` (rspamc).
Keep client/MTA deadlines above the overall scan timeout. Raising only the
rspamc client timeout does not raise the worker's task timeout.

The bridge's existing `llm_timeout` is independent: it limits a background Ollama
request, not the live SMTP wait. A slow 60-second inference may still yield
`AISSA_STATUS[score_timeout]` after 10 seconds and later appear in the journal.
A serial model worker means queue delay also consumes the live budget. Selection
of every mail does not imply every mail receives a model score.

After installation and timeout configuration:

```bash
cd /opt/aissa
python3 -m unittest discover -s tests -v
rspamadm configtest
# A restart loses pending in-memory jobs/results. Wait for outstanding=0 first.
systemctl restart aissa
systemctl reload rspamd
rspamc -t 30 -p < samples/phish-fr.eml
journalctl -u aissa --since '3 minutes ago' --no-pager
```

Expected when the verdict is timely: `AISSA_PHISHING (3.00)` and
`AISSA_STATUS (0.00)[scored]`. Exact effective weights can differ under rspamd
settings. A late verdict yields `AISSA_STATUS (0.00)[score_timeout]` instead.
Both are valid behaviors. Synthetic sample messages also trigger ordinary rules.

## Result retention and reputation

The new `/verdict` endpoint accepts an authenticated POST JSON object containing
`event_id`. It returns `pending`, `missing`, `error`, or `ok` with the class and
confidence. It does not return mail text, model explanation, account or IP.
Finished verdicts remain independently cached for 120 seconds after completion,
with a 10,000-entry cap; controller acknowledgement does not remove them. This
short cache is for scans/retries and does not replace the retained result queue.
When a cached verdict expires or is evicted, a new submission of the same event
may queue fresh inference under the normal rate/capacity limits. Only actual
queued/running work reports pending; cached verdicts report their finished state.
Reanalysis does not double-count reputation because Redis still deduplicates
application by event ID. Cache, queue, deduplication
and collection rows are RAM-only and lost on bridge restart.

`completed_at` now records actual completion rather than classification start.
Successful results increment `ai_checked`; spam/phishing also increment
`ai_suspect`; explicit operator confirmation alone increments `confirmed`.
Daily buckets expire after 48 hours and Lua reads today plus yesterday. Account
and IP lanes remain separate, Redis observation/result writes remain deduplicated,
and AI and operator-confirmed deduplication use separate keys. These counters are
not a calibrated risk score; this extension assigns no additional points for
reputation. Criteria may continue to use those counters.

The bridge journal and `/metrics` retain `mode: observe`: the bridge does not make
SMTP decisions and cannot know whether a particular rspamd scan scored its result.
Use rspamd class symbols and `AISSA_STATUS` to inspect live scoring.

## Limits and validation

The current small Qwen model has produced false positives and invented reasons.
Initial weights are deliberately modest. Backend tests mock inference: they do
not establish model accuracy or server throughput. Lua tests run a deterministic
mock event loop via an optional Lua 5.4 shared library and cover timely verdicts,
pending polling, late responses, budget expiry, disabled scoring, invalid JSON,
invalid confidence, HTTP failures, capacity and duplicate submissions. They do
not substitute for rspamadm configtest and a real scan on the installed rspamd.

Lua base64 conversion retains `tostring(util.encode_base64(value, 0))`, as required
by rspamd_text. The existing token path is `/etc/rspamd/local.d/aissa.token` in
both bridge service JSON and Lua configuration; preserve its permissions. Country
metadata remains rspamd's supplied mempool country, not a promise of exact GeoIP.
Mail text is treated as untrusted model input; this is not proof against prompt
injection. No external LLM service is used by this integration.
