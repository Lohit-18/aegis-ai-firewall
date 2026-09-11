# Architecture

## Request path

```
                    ┌──────────────────────────────────────────────┐
   client ─────────▶│ POST /v1/chat/completions                    │
                    └──────────────────┬───────────────────────────┘
                                       ▼
                    ┌──────────────────────────────────────────────┐
                    │ scan_request()                               │
                    │   split messages by role → Channel           │
                    │   system  → skipped (it IS the instructions) │
                    │   user    → threshold 0.42                   │
                    │   tool    → threshold 0.42, boosted weights  │
                    │   document→ threshold 0.42, boosted weights  │
                    └──────────────────┬───────────────────────────┘
                                       ▼
                    ┌──────────────────────────────────────────────┐
                    │ per span:                                    │
                    │   structural(raw)    obfuscation as evidence │
                    │   signatures(NFKC)   35 rules                │
                    │   dedupe overlapping spans                   │
                    │   noisy-OR  P = 1 − Π(1 − wᵢ)                │
                    │   × (1 − damping)    use/mention             │
                    └──────────────────┬───────────────────────────┘
                          ┌────────────┴────────────┐
                    score ≥ threshold          score < threshold
                          │                          │
                          ▼                          ▼
                   403 + rule IDs          mint canary → system prompt
                                                      │
                                                      ▼
                                              upstream LLM
                                                      │
                          ┌───────────────────────────┴──────────┐
                     buffered                                streamed
                          │                                      │
                          ▼                                      ▼
                  scan_output_text()                    StreamScanner
                  whole response                    carry(512) + chunk
                          │                                      │
                          ▼                                      ▼
              block │ redact │ pass          release all but carry, per chunk
```

## Modules

| Module | Responsibility | Depends on |
|---|---|---|
| `config.py` | Settings, per-channel thresholds, fail-open/closed | — |
| `detect/types.py` | `Channel`, `Verdict`, `Signal`, `ScanResult` | — |
| `detect/signatures.py` | 35 pattern rules | types |
| `detect/structural.py` | Unicode smuggling, homoglyphs, encoded payloads | types, signatures |
| `detect/mitigations.py` | Use/mention damping | types |
| `detect/engine.py` | Combination, dedup, verdicts | all of the above |
| `detect/canary.py` | System-prompt honeytokens | config |
| `detect/egress.py` | Output scanning, streaming scanner | config, types |
| `providers/openai_compat.py` | Upstream adapter, SSE helpers | config |
| `proxy.py` | Routing, streaming orchestration | everything |
| `telemetry/` | Events (JSONL + SQLite), Prometheus metrics | config |

`detect/` has no FastAPI dependency, which is why the eval harness, the corpus
tooling and the tests can import the real scoring path rather than
reimplementing it. Any "offline" scorer would drift from production within a
month.

## Decisions and their trade-offs

### Reverse proxy rather than SDK middleware

**Chosen because** it is language-agnostic (any OpenAI-compatible client works
unchanged), it cannot be forgotten at a call site, and it puts policy in one
place an organisation can audit.

**Costs** a network hop, and it becomes a single point of failure. Mitigated by
`AEGIS_FAILURE_MODE` and by the fact that the process is stateless and trivially
horizontally scaled.

**Rejected alternative:** a Python decorator. Faster, but only covers Python, and
only the call sites someone remembered to decorate.

### Per-channel thresholds rather than one global threshold

**Chosen because** provenance genuinely changes the prior. A user attacking their
own session is an abuse problem; the same text inside a retrieved PDF is an
in-progress compromise.

**Costs** more configuration surface and a calibration step per channel.

### Noisy-OR rather than a weighted sum

See `detect/engine.py` for the full argument. Briefly: sums invert the
strong-signal/weak-signal ordering and destroy information by clipping.

**Costs** an independence assumption that is false. Mitigated by span
deduplication; the residual correlation is documented, not hidden.

### Redact on egress, block on ingress

**Chosen because** a blocked request costs the user one retry, while a blocked
response after 200 tokens have already rendered is both a bad experience and
usually too late. Redaction returns the answer with the payload removed.

The exception is a canary hit or a high-confidence credential, which block
outright — at that point the response is known-compromised.

### Telemetry off the request path

Events go to a bounded queue drained by a background task. Under backpressure
they are **dropped**, not queued.

**Chosen because** a security control that adds disk I/O to every request gets
disabled by the platform team, and a log queue that can block a request is a DoS
amplifier. The dropped count is exported so the loss is visible.

## Performance

Detection is CPU-bound regex over short strings; p50 is 0.107 ms and p99 is
0.302 ms against the corpus. Against a 300–3000 ms completion round trip that is
under 0.1%.

The streaming path adds one chunk of buffering — up to 512 characters — which is
a few tens of milliseconds of *content*, not of latency: the delay is bounded by
how fast the model produces 512 characters, and TTFT is unaffected because the
first chunks flow as soon as the buffer fills.

Memory is O(1) per stream by construction. `test_carry_buffer_is_bounded` asserts
it across 500 chunks.

## Scaling

The process is stateless apart from its telemetry sink, so `replicas: N` behind a
load balancer works with no coordination. SQLite is a single-node convenience for
the dashboard — a multi-node deployment should ship the JSONL to a log pipeline
and point the dashboard at that instead.

## What is deliberately not here

**No ML classifier.** It would raise recall on paraphrase, which is the biggest
gap. It is omitted so that every block can name a rule, and because the moment a
model is in the request path the latency argument above stops holding. The right
shape is tiered: cheap layers gate an expensive one that sees ~2% of traffic.

**No rate limiting or authentication.** Those belong at the edge gateway. Aegis
does one thing.

**No response caching.** Caching a security decision keyed on attacker-controlled
input is a cache-poisoning vector.
