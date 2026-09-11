# aegis

A reverse proxy that sits between your application and an LLM, scores every span of text by where it came from, and blocks prompt injection in both directions — before the model sees it, and before the response reaches the user.

```
client ──▶ ingress scan ──▶ canary ──▶ upstream LLM
              │                            │
              ├─ 403 + rule IDs            ▼
 client ◀── release ◀── streaming egress scan ◀── tokens
```

**92.3% detection at 1.05% false-positive rate, adding 0.11 ms to the median request.**

---

## Demo

![Aegis dashboard](docs/img/dashboard-dark.png)

Run it against a mock model — no API key, no cost:

```bash
make demo        # starts mock upstream + aegis, runs seven attack scenarios
```

<details>
<summary>What the seven scenarios show</summary>

| # | Scenario | Result |
|---|---|---|
| 1 | Ordinary question | forwarded, `x-aegis-verdict: allow` |
| 2 | Direct injection in the user turn | `403`, names `AEG-OVR-001` + `AEG-EXF-001` |
| 3 | Injection buried in a **tool result** | `403`, channel `tool`, score 0.964 |
| 4 | Model leaks its system prompt | `403` — canary token detected on the way out |
| 5 | Model emits an AWS key | `403` — clean request, dirty response |
| 6 | Exfiltration image, **streamed** | cut off mid-stream, `finish_reason: content_filter` |
| 7 | Long streamed response | passes through byte-for-byte intact |

</details>

---

## Why I built it

Most "prompt injection filters" scan the user's message. That is the one place
the attack usually isn't.

The user typing "ignore your instructions" into their own chat window is trying
to jailbreak a session they already control — a policy problem, not a security
breach. The actual breach is **indirect**: instructions hidden in a PDF your RAG
pipeline retrieves, in a web page your agent summarises, in a support ticket, in
a résumé being screened. The model receives one flat token stream and cannot
tell developer instructions from text that arrived inside a retrieved document.

A proxy *can* tell, because it sits at the boundary where the two are still
separate fields in a JSON body. That observation is the whole design.

---

## Install & usage

Requires Python 3.11+.

```bash
git clone https://github.com/<you>/aegis && cd aegis
pip install -e .

cp .env.example .env          # point AEGIS_UPSTREAM_BASE_URL at your provider
python -m aegis.main          # listens on :8080
```

Point any OpenAI-compatible client at it — the API is unchanged:

```python
from openai import OpenAI

client = OpenAI(base_url="http://localhost:8080/v1", api_key="sk-...")
client.chat.completions.create(model="gpt-4o-mini", messages=[...])
```

Works with OpenAI, Groq, Together, vLLM, LM Studio and Ollama. For zero-cost
local development:

```bash
ollama serve
AEGIS_UPSTREAM_BASE_URL=http://localhost:11434/v1 python -m aegis.main
```

A blocked request returns `403` with the rules that fired, so an application
developer can tell a false positive from a real detection without reading proxy
logs:

```json
{ "error": {
    "type": "aegis_prompt_injection_blocked",
    "aegis": {
      "score": 0.886, "threshold": 0.42, "channel": "user",
      "rules": [
        {"id": "AEG-EXF-001", "severity": "high", "message": "System-prompt extraction attempt"},
        {"id": "AEG-OVR-001", "severity": "high", "message": "Explicit instruction-override phrasing"}
      ]}}}
```

| Endpoint | Purpose |
|---|---|
| `POST /v1/chat/completions` | the proxy (streaming and buffered) |
| `GET /` | live telemetry dashboard |
| `POST /api/scan` | score text without forwarding it |
| `GET /metrics` | Prometheus exposition |
| `GET /healthz` | liveness + effective configuration |

---

## How it works

### 1. Provenance, not keywords

Every span is scored against the channel it arrived on:

| Channel | Trust | Why |
|---|---|---|
| `system` | trusted | It *is* the instruction set. Never scored — canary-instrumented instead. |
| `user` | semi-trusted | Users may jailbreak their own session. High threshold. |
| `tool` | untrusted | No legitimate tool result contains instructions for the assistant. |
| `document` | untrusted | Retrieved chunks, pasted pages. Where real attacks live. |

The same bytes score 0.62 in a user turn and 0.78 in a retrieved document. Prior
assistant turns are scanned as `document`, because in an agent loop a previous
turn may itself be the product of a successful injection.

### 2. Four detector families

**Signatures** — 35 rules over instruction override, role manipulation, system-prompt
extraction, chat-template delimiter smuggling, false authority, exfiltration,
agent abuse and decode-then-execute. Each carries an ID, a weight and a severity;
nothing is allowed to score 1.0.

**Structural** — obfuscation is itself evidence. Zero-width characters, Unicode
tag-block smuggling (`U+E0000`, invisible in every client, passed straight to the
tokeniser), bidi overrides, homoglyph script-mixing, and base64/hex payloads that
are decoded one level and re-scanned.

**Canary** — a 96-bit token spliced into the system prompt. If it ever appears in
output, the system prompt leaked, and that conclusion is certain: the token
exists nowhere else. The highest-precision detector here, at ~20 tokens per request.

**Egress** — scans responses for the canary, credential patterns, and markdown
images pointing at non-allowlisted hosts with a payload in the query string —
the zero-click exfiltration that fires the moment a client renders the response.

### 3. Noisy-OR, not a weighted sum

```
P(attack) = 1 − Π (1 − wᵢ)
```

Summing weights means five weak rules outrank one strong one, and clipping at 1.0
throws away information exactly where confidence matters. Noisy-OR is bounded,
monotonic, order-independent, and lets one strong signal carry a verdict alone.

Independence is false in practice — rules overlap — so signals covering
overlapping spans are collapsed to the strongest before combining. Five rules
firing on the same twenty characters is one observation, not five.

### 4. Use/mention damping

The hardest false positive is a person *discussing* prompt injection:

> "The paper demonstrates that models can be induced to **ignore previous
> instructions** when adversarial text is placed in retrieved documents."

Lexically identical to an attack. A separate layer detects quotation,
attribution verbs, security meta-discourse and interrogative framing, and damps
the score — 0.62 → 0.43 for the sentence above, while a real attack stays at 0.89.

Damping is **capped hard in untrusted channels**, because quoting is also an
evasion technique. A user gets the benefit of the doubt; a retrieved document
does not.

### 5. Bounded-window streaming egress

Buffering a stream to scan it destroys time-to-first-token, and the platform
team will simply turn the firewall off. Aegis keeps a 512-character carry buffer,
scans `carry + chunk`, and releases everything except the new carry — so a
pattern straddling a chunk boundary is still caught, memory is O(1) regardless of
response length, and added latency is one chunk rather than one response.

---

## Results

390 labelled samples, scored through the same `scan_text` the proxy calls.
Full report: [`bench/report.md`](bench/report.md).

| Metric | Value | 95% CI (Wilson) |
|---|---:|---|
| Recall | 92.3% | 85.6 – 96.1% |
| Precision | 97.0% | 91.5 – 99.0% |
| False-positive rate | 1.05% | 0.36 – 3.04% |
| F1 | 0.946 | — |

Confusion: TP 96 · FP 3 · TN 283 · FN 8. Detection latency p50 **0.107 ms**,
p99 0.302 ms — under 0.1% of a typical completion round trip.

### The number that actually matters

Precision above is measured at this corpus's 27% attack prevalence, which is
nothing like production:

| Real prevalence | PPV — an alert is genuine |
|---:|---:|
| 10% | 90.7% |
| 1% | 47.1% |
| 0.1% | **8.1%** |

At a realistic base rate, **eleven of every twelve alerts are false** — with the
detector working exactly as measured. That is the base-rate fallacy, not a bug,
and it drives three design decisions: the FLAG band records near-threshold
traffic instead of blocking it; thresholds are per channel because untrusted
channels carry far higher prevalence; and any vendor claiming "99% accurate"
should be asked *at what prevalence, and what is your PPV at mine?*

### Thresholds are calculated, not chosen

```bash
python bench/calibrate.py --target-fpr 0.01
```

Pick an acceptable false-positive rate — an operational question someone can
answer — and the threshold follows from the benign score distribution, subject to
a floor that forbids any single LOW-severity signal from blocking alone. Recall
is then *measured*, never tuned toward.

The first version of this project hand-picked 0.72 and scored 55.8% recall,
because the threshold sat above what any single rule could reach. The commit
history has that.

---

## Limitations

Stated in full, because a benchmark without them is marketing.

**The corpus and the rules share an author.** The dominant problem. These numbers
are an upper bound: they show the rules do what their author intended, not that
the system stops attackers. Cross-evaluation against an independently built set
is the highest-value next step.

**No adaptive attacker.** Every measurement is against a static corpus. A real
adversary reads `signatures.py` — it is open source — and paraphrases around it.
"Set aside your earlier guidance" defeats the regex families entirely. No amount
of rule tuning fixes that; it needs a model-based detector.

**Templated benign rows are correlated.** 200 of 286 benign samples come from a
small template grammar, so the effective sample size is well below the nominal
count and the FPR interval is optimistic.

**English only.** Every signature is English. A non-English injection passes the
signature layer untouched; only the structural detectors would fire.

**The canary detects leakage, not paraphrase.** A model that summarises its
instructions in its own words leaks the content without emitting the token.

**Prevalence is assumed.** The base-rate table uses plausible figures. Real
prevalence is deployment-specific and should be measured from the FLAG band
before thresholds are tuned.

## What I'd do next

1. **Cross-evaluate** against a public benchmark I did not write, and report the
   drop honestly. I expect recall to fall meaningfully.
2. **A distilled classifier** for semantic paraphrase, gated behind the cheap
   layers so it only sees the ~2% of traffic that is ambiguous.
3. **Adaptive-attacker evaluation** — a paraphrase loop that mutates a payload
   until it passes, reporting queries-to-evade rather than a static recall figure.
   That is the metric that would actually characterise this system.
4. **Per-tenant threshold learning** from the FLAG band, so thresholds track a
   deployment's own benign distribution instead of this corpus's.

---

## Development

```bash
make test        # 61 tests
make bench       # regenerate corpus, evaluate, write bench/report.md
make calibrate   # recompute thresholds from a target FPR
make lint
```

Tests assert design properties rather than regex behaviour — that noisy-OR is
bounded and order-independent, that overlapping evidence does not double-count,
that channel asymmetry changes the verdict, that the streaming scanner is
equivalent to the buffered one, and that a long stream is not truncated (a real
bug: the carry-buffer tail was being emitted *after* `[DONE]`, silently losing
the last 512 characters of every streamed response).

## Layout

```
aegis/
  config.py            settings, per-channel thresholds, fail-open/closed
  proxy.py             routes, streaming, block responses
  detect/
    types.py           Channel, Verdict, Signal — the provenance model
    engine.py          noisy-OR, span dedup, per-channel verdicts
    signatures.py      35 rules
    structural.py      Unicode smuggling, homoglyphs, encoded payloads
    mitigations.py     use/mention damping
    canary.py          system-prompt honeytokens
    egress.py          output scanning + bounded-window stream scanner
  telemetry/           JSONL + SQLite events, Prometheus metrics
  static/              dashboard
corpus/build_corpus.py reproducible labelled dataset
bench/evaluate.py      metrics, PR curve, base-rate analysis
bench/calibrate.py     threshold selection from a target FPR
```

## License

MIT
