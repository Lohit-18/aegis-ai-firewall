# Threat model

Written first, before the rules. A detector built without one is a pile of
regexes that happens to compile.

## What Aegis defends

An application that sends user input, retrieved documents, or tool results to an
LLM, where the model's output is rendered to a user or feeds an agent loop that
can take actions.

## Assets

| Asset | Why an attacker wants it |
|---|---|
| System prompt | Contains business logic, model configuration, and often the exact wording competitors would like. Leaking it also makes every subsequent attack easier. |
| Credentials in context | API keys and tokens that arrived via tool results or environment. |
| Retrieved data | Other tenants' documents, customer lists, anything the RAG index can reach. |
| Tool-call authority | The ability to make the agent send email, move money, or delete records. |
| User trust | A response that looks like it came from the operator but was written by an attacker. |

## Adversaries

**A1 — the end user.** Talks to the model directly, wants it to ignore its
instructions. This is the adversary everyone builds for and the *least*
dangerous: they are attacking a session they already control. Mostly a policy
and abuse problem.

**A2 — the content author.** Controls a document, web page, email, résumé,
support ticket, product review or code comment that the pipeline will ingest.
Never interacts with the application directly and may never know who their
victim is. **This is the adversary that matters**, and the one a user-input
filter cannot see.

**A3 — the tool/supply-chain adversary.** Controls an API the agent calls, an
MCP server it connects to, or the description text of a tool definition
templated from external data.

**A4 — the insider.** Has legitimate access and wants to exfiltrate through the
model rather than through monitored channels.

## Attack paths

| # | Path | Adversary | Aegis coverage |
|---|---|---|---|
| T1 | Direct instruction override in the user turn | A1 | Signatures, high threshold |
| T2 | Injection in retrieved document / RAG chunk | A2 | Document channel, aggressive threshold |
| T3 | Injection in tool result | A3 | Tool channel, aggressive threshold |
| T4 | Injection in a tool *description* | A3 | Tool definitions scanned as document |
| T5 | System-prompt extraction | A1, A2 | Signatures + canary on egress |
| T6 | Invisible payload (zero-width, tag block, bidi) | A2 | Structural detectors |
| T7 | Homoglyph substitution | A2 | Script-mixing detector |
| T8 | Encoded payload with decode-then-execute | A2 | One-level decode + rescan |
| T9 | Credential exfiltration in output text | A2, A4 | Egress secret patterns |
| T10 | Zero-click exfiltration via markdown image | A2, A4 | Egress URL analysis |
| T11 | Agent instructed to act without confirmation | A2, A3 | Agent-abuse signatures |
| T12 | Agent instructed to conceal its actions | A2, A3 | Concealment signatures |
| T13 | Replay of a poisoned prior assistant turn | A2 | Assistant turns scanned as document |
| T14 | Chat-template delimiter smuggling | A2 | Delimiter signatures |

## Explicitly out of scope

**Semantic paraphrase.** "Set aside the guidance you were given earlier" contains
no matched pattern. This is the largest gap and it is structural: signature
matching cannot close it. Mitigation requires a model-based detector.

**Non-English injection.** Every signature is English.

**Multimodal injection.** Instructions rendered into an image. Aegis reads text.

**Model-internal failures.** If the model misbehaves without any adversarial
input, that is an alignment problem, not a firewall problem.

**Timing and side channels.** Aegis's own responses differ in latency between
blocked and allowed requests, which leaks whether a probe tripped a rule. An
attacker can use this to map the ruleset. Not mitigated; the ruleset is open
source anyway, so the leak conveys little.

**Denial of service.** Rate limiting belongs at the gateway in front of this one.
The decoder is bounded to one level and six blobs specifically so a nested-
encoding payload cannot burn CPU, but that is a single hardening measure, not a
DoS defence.

## Assumptions

1. The system prompt is trusted. If an attacker controls it, nothing here helps.
2. Aegis is not bypassable — the application cannot reach the upstream directly.
   A proxy that can be routed around is decorative.
3. The operator can choose a tolerable false-positive rate. Every threshold in
   the system derives from that number.
4. Detection is probabilistic. Aegis raises the cost of an attack; it does not
   make one impossible, and any document claiming otherwise is selling something.

## Aegis as a target

This process sees every prompt and every response. That makes it worth attacking
in its own right.

- **Evidence is attacker-controlled text that ends up in logs.** It is truncated
  and stripped of control characters before writing, so a payload cannot forge
  log lines or break a downstream parser.
- **Secrets are never logged whole** — egress evidence is truncated to 12
  characters.
- **The container runs unprivileged** and writes only to a single data volume.
- **Telemetry drops under backpressure** rather than blocking a request, so the
  log queue cannot become a DoS amplifier.
- **The canary is minted per request** from `secrets.token_hex`, so observing one
  tells an attacker nothing about the next.
