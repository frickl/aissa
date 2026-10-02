# AISSA — AI Sample Spam Analyzer

Experimental local multilingual email analyzer for a future Postfix/rspamd
extension. MIT licensed. If it helps you and we meet, buy me a beer.

## Status: 0.1 offline sample PoC

This release analyzes `.eml` files via a local Ollama instance. It does not alter
Postfix or rspamd, reject messages, learn Bayes, lock users, or run a virus scanner.
It is suitable for inbound MX and outbound samples. Account behavior, Redis
campaign tracking and live rspamd integration are subsequent steps.

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

## Next milestones

1. Validate this offline classifier and hardware budget.
2. Add a bounded local service and replay/benchmark tools.
3. Add zero-weight rspamd symbols for MX and Submission; observe only.
4. Add Redis campaign/account signals with trusted identity rules.
5. Evaluate enforcement only after measuring false positives and failure modes.

Contributions via https://github.com/frickl/aissa . Do not submit real mail in issues.
