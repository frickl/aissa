# Offline model and thread comparison

The CLI can select a model, CPU thread count and explicit no-thinking mode.
These settings affect only that invocation; they do not change the running
bridge's model, two-thread default, prompt, scoring or deadlines.

```bash
python3 -m aissa --help
python3 -m aissa --model qwen3.5:4b --threads 2 --no-thinking --timeout 120 /path/to/sample.eml
```

Before pulling a model on the mail server, check the installed Ollama version,
available RAM and disk, and CPU allocation:

```bash
ollama --version
free -h
nproc
df -h / /opt
```

The Ollama library lists `qwen3.5:4b` at approximately 3.4 GB of model files;
loaded memory/context adds overhead. Check current tags and compatibility at
https://ollama.com/library/qwen3.5:4b before installation. If it is suitable for
the installed server and available resources:

```bash
ollama pull qwen3.5:4b
```

Start with the known missed donation offer, a phishing sample and a legitimate
counterexample, then add independently labeled real French mail. Do not change
the prompt for a case after seeing its result and call that an independent test.

```bash
python3 -m aissa --model qwen3.5:4b --threads 2 --no-thinking --timeout 120 /path/to/donation.eml /path/to/phishing.eml /path/to/legitimate.eml
```

`--no-thinking` explicitly sends `think: false`. Without it, no `think` field is
sent and the model's default applies. Use it only when the selected Ollama/model
supports that option; it is not a universal switch for all backends. The existing
192-output-token cap is intended for short JSON verdicts, not long reasoning.

Outputs record the requested thread count and thinking option alongside
classification, explanation, token/cache counts and timing. The settings are
requests, not measured CPU utilization. This still uses a network timeout,
not a reliable total deadline. Failures remain errors, not ham judgments.

For two versus four threads, alternate runs using the same input. Compare cached
counts and load times: a second warm run cannot fairly establish the benefit of
additional threads over a cold first run. More CPU threads may help input
processing but can contend with mail filtering and need not scale linearly.
Changing thread settings can also reload a runner or disturb its cache.

The local bridge and offline CLI share Ollama, so tests can consume CPU and
interfere with live inference. Run at low load and keep live scoring disabled
while evaluating. CLI timeout/interrupt alone is not proof that model work has
stopped. No service restart is needed for CLI tests; do not change the production
model tag until quality and latency have been measured.

Sources: https://docs.ollama.com/api/chat and the model tag page above.
