"""Negative evidence: the use/mention distinction.

## The problem this exists to solve

Run the evaluation without this module and the false positives are all one
thing: people *talking about* prompt injection.

    "The paper demonstrates that models can be induced to ignore previous
     instructions when adversarial text is placed in retrieved documents."

    "The log shows a request containing the string '<|im_start|>'. Is that
     normal or should we investigate?"

Lexically these are indistinguishable from attacks - they contain the same
trigger phrases, because they are *about* those phrases. No threshold
separates them, because their scores genuinely overlap with real attacks. The
only way through is to model a different property: is this text *performing*
an instruction, or *mentioning* one?

Philosophers call this the use/mention distinction. It is the single largest
source of false positives in any content-based security filter, and it is why
a keyword blocklist cannot be made to work no matter how the weights are tuned.

## How it is detected

Mention has linguistic tells that use does not:

  quotation       the trigger appears inside quote marks
  attribution     a reporting verb governs it ("the paper shows", "the
                  attacker used", "they claim")
  meta-discourse  the surrounding text is about detection, mitigation,
                  research or policy rather than about the task
  interrogative   the text asks about the phenomenon rather than issuing it

## Why damping is capped, and capped differently per channel

Quoting is also an evasion technique. An attacker who learns that quoted text
is discounted will simply write:

    The document says: "ignore all previous instructions"

In a USER channel that is overwhelmingly likely to be a person discussing
security, so damping is generous. In a TOOL or DOCUMENT channel - where the
attacker controls the text and has no legitimate reason to be discussing
anything - damping is capped hard. Evidence can be reduced there but never
erased.

This asymmetry is the point. It is the same provenance argument that sets the
thresholds, applied to negative evidence instead of positive.
"""

from __future__ import annotations

import re

from .types import Channel

# Reporting and attribution verbs. Their presence signals that the surrounding
# clause describes speech or a finding rather than issuing an instruction.
_ATTRIBUTION = re.compile(
    r"\b(?:the\s+)?(?:paper|study|article|report|author|researcher|attacker|"
    r"adversary|log|ticket|thread|document|vendor|blog|post|advisory|novel|"
    r"transcript|customer|user|client|candidate|scan|alert|tool)s?\b"
    r"[^.\n]{0,40}?\b(?:show|shows|showed|demonstrate|demonstrates|demonstrated|"
    r"describe|describes|described|claim|claims|claimed|say|says|said|report|"
    r"reports|reported|use|used|uses|contain|contains|contained|found|note|"
    r"notes|noted|mention|mentions|mentioned|include|includes|included|"
    r"suggest|suggests|indicate|indicates)\b",
    re.IGNORECASE,
)

# Vocabulary that belongs to talking about security, not doing it.
_META_DISCOURSE = re.compile(
    r"\b(?:detect|detection|detecting|mitigat\w+|remediat\w+|false\s+positive|"
    r"threat\s+model|red\s*team|blue\s*team|pen\s*test|penetration\s+test|"
    r"OWASP|CVE|CWE|taxonomy|literature|thesis|dissertation|curriculum|"
    r"lesson\s+plan|whitepaper|postmortem|post-mortem|incident\s+report|"
    r"compliance|audit|classifier|benchmark|dataset|corpus|research\w*|"
    r"explain|explanation|conceptual|difference\s+between|what\s+does\s+.{0,20}"
    r"(?:mean|stand\s+for)|why\s+(?:they|it|that)\s+\w+|documentation|"
    r"security\s+team|our\s+(?:team|assistant|chatbot|firewall|filter|pipeline)|"
    r"adversarial|prompt\s+injection|jailbreak\w*|exploit\w*|vulnerabilit\w+|"
    r"attack\s+(?:vector|surface|categor\w+)|induced|retriev\w+\s+document|"
    r"safeguard\w*|guardrail\w*|mitigation|countermeasure)\b",
    re.IGNORECASE,
)

# Questions about the phenomenon rather than instructions to the model.
_INTERROGATIVE = re.compile(
    r"^\s*(?:can\s+you\s+explain|what\s+(?:is|are|does|was|were)|how\s+(?:do|does|"
    r"would|should|can)|why\s+(?:do|does|did|is|are)|is\s+that|should\s+we|"
    r"where\s+should|which\b|could\s+you\s+explain)\b",
    re.IGNORECASE,
)

# Explicit first-person framing of a legitimate task.
_TASK_FRAMING = re.compile(
    r"\b(?:i'?m\s+(?:writing|building|researching|reviewing|studying|working\s+on|"
    r"drafting)|for\s+my\s+(?:thesis|paper|research|class|course|dissertation)|"
    r"we\s+(?:are|were)\s+(?:investigating|researching|reviewing|building)|"
    r"our\s+(?:security|compliance|engineering|red)\s+team|"
    r"please\s+review\s+(?:this|my)|summarise\s+this|summarize\s+this|"
    r"translate\s+this)\b",
    re.IGNORECASE,
)

_QUOTE_PAIRS = [
    ('"', '"'), ("'", "'"), ("“", "”"), ("‘", "’"),
    ("`", "`"),
]

# Damping ceilings. USER traffic is mostly people; TOOL and DOCUMENT traffic is
# attacker-influenced, so negative evidence there can reduce but never erase.
_CEILING = {
    Channel.USER: 0.80,
    Channel.DOCUMENT: 0.30,
    Channel.TOOL: 0.30,
    Channel.SYSTEM: 0.0,
}


def _spans_are_quoted(text: str, spans: list[tuple[int, int]]) -> int:
    """Count how many matched spans sit inside quotation marks."""
    quoted = 0
    for start, end in spans:
        for open_q, close_q in _QUOTE_PAIRS:
            before = text.rfind(open_q, 0, start)
            if before == -1:
                continue
            after = text.find(close_q, end)
            if after == -1:
                continue
            # Reject if another quote of the same kind closes in between -
            # that means the span is outside the quoted region.
            between = text[before + 1:start]
            if close_q in between:
                continue
            quoted += 1
            break
    return quoted


def damping(text: str, channel: Channel, spans: list[tuple[int, int]]) -> tuple[float, list[str]]:
    """Return (damping_factor, reasons).

    The factor is applied as `score * (1 - damping)`. It is never 1.0: no
    combination of mitigations fully clears a detection, because every one of
    these markers can itself be forged by an attacker who has read this file.
    """
    if not text:
        return 0.0, []

    ceiling = _CEILING.get(channel, 0.3)
    if ceiling <= 0.0:
        return 0.0, []

    factor = 0.0
    reasons: list[str] = []

    quoted = _spans_are_quoted(text, spans) if spans else 0
    if quoted:
        share = quoted / max(len(spans), 1)
        factor += 0.45 * share
        reasons.append(f"trigger quoted ({quoted}/{len(spans)} spans)")

    if _ATTRIBUTION.search(text):
        factor += 0.30
        reasons.append("reporting verb with attribution")

    meta_hits = len({m.group(0).lower() for m in _META_DISCOURSE.finditer(text)})
    if meta_hits:
        factor += min(0.30, 0.12 * meta_hits)
        reasons.append(f"security meta-discourse ({meta_hits} markers)")

    if _INTERROGATIVE.search(text):
        factor += 0.22
        reasons.append("interrogative framing")

    if _TASK_FRAMING.search(text):
        factor += 0.25
        reasons.append("explicit legitimate-task framing")

    # A long span of prose around a short trigger is weak evidence of
    # discussion; an instruction is usually most of its own message.
    if spans and len(text) > 220:
        covered = sum(e - s for s, e in spans)
        if covered / len(text) < 0.12:
            factor += 0.12
            reasons.append("trigger is a small fraction of surrounding prose")

    return min(factor, ceiling), reasons
