#!/usr/bin/env python3
"""Add or update the AISSA flow section without replacing the existing README."""
import argparse
from pathlib import Path

START = '<!-- AISSA_FLOW_BEGIN -->'
END = '<!-- AISSA_FLOW_END -->'
FLOW = '''## Processing order (rough pseudocode)

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
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--readme', type=Path, default=Path('/opt/aissa/README.md'))
    args = parser.parse_args()
    path = args.readme
    source = path.read_text()
    section = START+'\n'+FLOW+'\n'+END
    if START in source or END in source:
        if source.count(START) != 1 or source.count(END) != 1:
            raise SystemExit('Ambiguous flow markers; README unchanged.')
        first = source.index(START)
        last = source.index(END)
        if last < first:
            raise SystemExit('Invalid flow markers; README unchanged.')
        updated = source[:first]+section+source[last+len(END):]
    else:
        updated = source.rstrip()+'\n\n'+section+'\n'
    if updated != source:
        path.write_text(updated)
    print('README flow section updated:',path)


if __name__ == '__main__':
    main()

