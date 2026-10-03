# Project announcement draft

Suggested subject: AISSA: experiments with selective LLM analysis in Rspamd

Hi all,

I've been working on AISSA (AI Sample Spam Analyzer), an experimental integration
between Rspamd and a local Ollama model. The idea is to select messages using
existing filter signals, analyze bounded message content, and optionally add
points while respecting the remaining Rspamd scan budget. Observation mode is
available without waiting for model inference.

The integration is working on Rspamd 4.2.1, but the small Qwen 2.5 1.5B model is
not yet something I'd trust for production decisions. It detected an explicit
password/2FA theft request, but called a real donation scam a normal offer with
confidence 1.0. That message also had a negative filter score and never reached
the live selector. Selection and classifier quality are separate problems.

On a CPU-only server, short cold requests took around 15 seconds; warm requests
were much quicker. A changed message reused 456 of 536 prompt tokens. The repo
includes the integration, synthetic evaluation cases, tests and field notes,
including the misses and timeout limitations.

I'd be interested in experiences with stronger models, privacy-reviewed test
cases (especially authenticated abuse and legitimate counterexamples), and
results from other Rspamd versions. Comparative API backends are planned but
not implemented. No attachments or URLs are fetched or inspected.

Repository: https://github.com/frickl/aissa
License: MIT

Gunther

---

Add https://frickl.de/aissa/ after the project page is deployed and verified.
This is a draft for manual posting; it has not been sent anywhere.
