# Field notes: CPU-only Qwen and live Rspamd

Recorded during manual testing on 3 October 2026 (UTC). These are selected
observations, not a blind benchmark, measured error rate or capacity estimate.
No private raw messages or identifying transport headers are included here.

## Setup

- Rspamd 4.2.1, Postfix, local Ollama.
- Qwen 2.5 1.5B on CPU, two model threads, context 4,096.
- Prompt version 2026-10-03.1 for the final short-text tests.
- Serial bridge worker; live wait 20 seconds, global Rspamd task timeout 30 seconds,
  one-second scan completion reserve.
- Live selection: score at least 3 and below 15.
- Test server phishing weight +5, distinct from the repository example's +3.

## Selected observations

| Input | Model result | Model elapsed | Detail |
|---|---|---:|---|
| Explicit password/current-2FA demand, cold request | phishing | 15.128 s | Load 2.063 s; prompt 10.744 s; generation 2.310 s |
| Same demand, warm repeat | phishing | 2.523 s | Load 0.002 s; prompt 0.068 s; generation 2.442 s |
| Changed meeting arrangement, warm model | ham | 4.195 s | 456/536 input tokens cached; no truncation |
| Donation offer asking for a reply to unrelated Gmail | ham | 5.400 s | Incorrectly called a standard offer; confidence 1.0; no truncation |

The explicit phishing tests had approximately +11.9 points from ordinary rules
before AISSA; +5 additional points crossed the 15-point reject threshold.
The meeting counterpart received zero AISSA points and stayed below rejection.
These deliberately unauthenticated test submissions do not represent ordinary
legitimate sender authentication or all incoming mail.

The donation message passed SPF/DKIM/DMARC and had a total score of -5, so the
live selector skipped it (`AISSA_STATUS[criteria]`). A direct CLI call then
produced ham. This exposes independent selection and classification failures.
Even a hypothetical +5 phishing verdict would not have crossed rejection from
that negative baseline. Broader selection alone would not resolve this case.

Earlier long-text tests included an undeclared Base64 body whose manually
decoded bytes began with a ZIP local-file header. The MIME parser correctly did
not infer a transfer encoding absent headers. At 4,000 extracted characters,
classification timed out around 60 seconds; 1,000-character runs varied widely
with input tokenization and cache state. Some model explanations invented virus
or link evidence. Base64 itself is normal in MIME; it is not proof of an
attachment, ZIP archive or malware.

## Integration regression

An isolated Rspamd/Redis test with a fake always-pending bridge used a
4.324-second prefilter and an eight-second global scan limit. On Rspamd 4.2.1:

| Worker | Requested AISSA wait | Scan elapsed | Status |
|---|---:|---:|---|
| normal | 10 s | 7.006 s | score_timeout |
| normal | 2 s | 6.402 s | score_timeout |
| proxy self-scan | 10 s | 7.006 s | score_timeout |
| proxy self-scan | 2 s | 6.410 s | score_timeout |

These verify the remaining-budget cap in real Rspamd HTTP scans, not a strict
SMTP-chain deadline or model quality. The former uncapped wait could reach the
outer task timeout with an AISSA timer still pending.

## Implication

The wiring, deadline handling and prompt-prefix reuse can be tested separately
from classifier quality. The small model's self-reported confidence does not
resolve its incorrect judgments. Before enforcement, compare real abuse and
legitimate counterexamples, model/prompt versions, queue delay and latency. API
backends are proposed future work; no comparison with them has been measured.
