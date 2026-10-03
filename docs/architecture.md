# Architecture and state

AISSA runs as an Rspamd Lua postfilter plus an authenticated loopback Python
bridge. Existing Rspamd rules run first. Lua records observations in Redis,
applies selection and sampling, and submits selected MIME messages. A single
background worker calls local Ollama. With live scoring enabled, the scan polls
for a verdict within its remaining budget; with scoring disabled, it returns
after submission. Controller workers collect results independently of new mail.

Model input contains bounded subject, displayed From, body text and URLs.
Authenticated account and connection IP are used by Lua for selection and
counters; the model does not receive verified account history. Displayed From
is not an authenticated identity. URLs are not fetched and attachments are not
analyzed. Earlier emails are not appended to subsequent model requests.

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

## In-memory bridge state

Jobs, unacknowledged results and the short live verdict cache are held in RAM.
A restart loses them. Completed results remain until the controller successfully
writes Redis state and acknowledges them. Capacity exhaustion refuses new work
rather than silently deleting older unacknowledged results.

The live cache retains finished verdicts for 120 seconds, up to 10,000 entries.
Collection acknowledgement does not remove this cache. A late result may update
AI suspicion counters but cannot change a finished SMTP decision. Model errors
never count as ham or independently confirmed abuse.

See [live scoring](aissa-scoring.md) for deadlines and
[installation](installation.md) for effective paths and permissions.
