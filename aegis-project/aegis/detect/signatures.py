"""Signature rules.

Design notes worth defending in an interview:

1. Weights are not severities. A rule's weight answers "if this is the only
   thing I saw, how sure am I?" - so a very specific pattern like a chat
   role-token appearing inside user text scores higher than the generic
   phrase "ignore the above", which occurs innocently in editing and
   proofreading contexts every day.

2. Nothing scores 1.0. Every pattern here has a benign counterexample. A
   documentation site explaining prompt injection will trip a dozen of these
   rules, and that is the correct behaviour for a *detector*; suppressing it
   is the policy layer's job, not the rule's.

3. Rules carry a `channels` set. Some patterns are only meaningful in
   untrusted channels. "Ignore previous instructions" typed by a user into
   their own chat is mildly interesting. The same bytes arriving inside a
   retrieved PDF is an attack in progress.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .types import Channel, Severity, Signal

UNTRUSTED = {Channel.USER, Channel.TOOL, Channel.DOCUMENT}
INJECTED_ONLY = {Channel.TOOL, Channel.DOCUMENT}


@dataclass(frozen=True)
class Rule:
    id: str
    pattern: re.Pattern[str]
    weight: float
    severity: Severity
    message: str
    channels: frozenset[Channel] = field(default_factory=lambda: frozenset(UNTRUSTED))
    # Multiplier applied when the rule fires in a channel that should never
    # contain instructions at all. Defaults to 1.0 (no adjustment).
    untrusted_boost: float = 1.0


def _r(
    rule_id: str,
    pattern: str,
    weight: float,
    severity: Severity,
    message: str,
    channels: set[Channel] | None = None,
    untrusted_boost: float = 1.0,
) -> Rule:
    return Rule(
        id=rule_id,
        pattern=re.compile(pattern, re.IGNORECASE | re.DOTALL),
        weight=weight,
        severity=severity,
        message=message,
        channels=frozenset(channels or UNTRUSTED),
        untrusted_boost=untrusted_boost,
    )


# Filler that attackers pad between the verb and the object to dodge naive
# substring matching: "ignore  all  of  the  previous   instructions".
_F = r"(?:\s+\w+){0,4}\s+"

RULES: list[Rule] = [
    # ---- instruction override -------------------------------------------
    _r(
        "AEG-OVR-001",
        rf"\b(?:ignore|disregard|forget|discard|override)\b{_F}"
        rf"\b(?:previous|prior|above|earlier|preceding|initial|original|foregoing)\b"
        rf"{_F}?\b(?:instruction|directive|prompt|rule|command|guideline|order)s?\b",
        0.62,
        Severity.HIGH,
        "Explicit instruction-override phrasing",
        untrusted_boost=1.25,
    ),
    _r(
        "AEG-OVR-002",
        r"\b(?:ignore|disregard|forget)\b\s+(?:every|all)\s*(?:thing)?\s*"
        r"(?:you\s+(?:were|have\s+been)\s+(?:told|instructed|trained))",
        0.68,
        Severity.HIGH,
        "Instruction-override targeting training or prior conditioning",
    ),
    _r(
        "AEG-OVR-003",
        r"(?:^|[\n\r])\s*(?:new|updated|revised|corrected)\s+"
        r"(?:instruction|directive|system\s+prompt|rule)s?\s*[:\-]",
        0.55,
        Severity.HIGH,
        "Text claims to supply replacement instructions",
        untrusted_boost=1.4,
    ),
    _r(
        "AEG-OVR-004",
        r"\bfrom\s+now\s+on\b[\s,]*\byou\s+(?:will|must|shall|are\s+to)\b",
        0.5,
        Severity.MEDIUM,
        "Deferred instruction override ('from now on you must...')",
    ),
    _r(
        "AEG-OVR-005",
        r"\b(?:end|close|terminate)\s+of\s+(?:the\s+)?(?:system\s+)?"
        r"(?:prompt|instruction|context|message)s?\b",
        0.58,
        Severity.HIGH,
        "Attempts to declare the trusted prompt finished",
        untrusted_boost=1.3,
    ),

    _r(
        "AEG-OVR-006",
        r"\b(?:instruction|directive|rule|guideline|restriction|constraint)s?\b"
        r"[^.\n]{0,30}\b(?:are|is|were|was|have\s+been|has\s+been)\b[^.\n]{0,20}"
        r"\b(?:obsolete|revoked|cancelled|canceled|void|expired|superseded|"
        r"rescinded|no\s+longer\s+(?:valid|apply|applicable|in\s+effect))\b",
        0.68,
        Severity.HIGH,
        "Asserts the governing instructions have been invalidated",
    ),
    _r(
        "AEG-OVR-007",
        r"\b(?:without|bypass\w*|circumvent\w*|disabl\w+|turn(?:ing)?\s+off)\b"
        r"[^.\n]{0,25}\b(?:any\s+|all\s+|your\s+|the\s+)?"
        r"(?:filter|restriction|limitation|guardrail|safeguard|safety\s+\w+|"
        r"content\s+polic\w+|moderation|censorship|guideline)s?\b",
        0.6,
        Severity.HIGH,
        "Requests operation with protections removed",
    ),

    # ---- role manipulation ----------------------------------------------
    _r(
        "AEG-ROL-001",
        r"\byou\s+are\s+(?:now|no\s+longer)\b",
        0.42,
        Severity.MEDIUM,
        "Role reassignment",
    ),
    _r(
        "AEG-ROL-002",
        r"\b(?:act|behave|respond|roleplay|role-play)\s+as\s+(?:if\s+you\s+"
        r"(?:are|were)\s+)?(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|"
        r"amoral|jailbroken|developer\s+mode|DAN\b)",
        0.72,
        Severity.HIGH,
        "Persona swap to an explicitly unrestricted character",
    ),
    _r(
        "AEG-ROL-003",
        r"\b(?:DAN|AIM|STAN|DUDE|Developer\s+Mode|Do\s+Anything\s+Now)\b"
        r"(?:\s+(?:mode|prompt|jailbreak))?",
        0.55,
        Severity.MEDIUM,
        "Named jailbreak persona",
    ),
    _r(
        "AEG-ROL-004",
        r"\byou\s+(?:have\s+)?no\s+(?:longer\s+)?(?:restrictions|limitations|"
        r"filters|guidelines|rules|constraints|ethics)\b",
        0.66,
        Severity.HIGH,
        "Asserts the model has no constraints",
    ),
    _r(
        "AEG-ROL-006",
        r"\byou\s+are\s+no\s+longer\b[^.\n]{0,30}\b(?:bound|constrained|limited|"
        r"restricted|governed|subject)\b",
        0.7,
        Severity.HIGH,
        "Asserts prior constraints no longer bind the model",
    ),
    _r(
        "AEG-ROL-005",
        r"\b(?:simulate|emulate|pretend)\b[^.\n]{0,40}\b(?:no\s+(?:filter|restriction|guardrail)|"
        r"without\s+(?:any\s+)?(?:filter|restriction|guardrail|censorship))",
        0.64,
        Severity.HIGH,
        "Requests simulation of an unguarded system",
    ),

    # ---- system prompt extraction ---------------------------------------
    _r(
        "AEG-EXF-001",
        r"\b(?:repeat|print|output|reveal|show|display|echo|recite|reproduce|"
        r"tell\s+me|state|list|give\s+me|disclose|expose|dump)\b"
        rf"{_F}?\b(?:your|the|initial|original|full|entire|exact|verbatim)\b"
        rf"{_F}?\b(?:system\s+(?:prompt|message|instruction)|instruction|"
        r"directive|prompt|configuration|config|rule\s*set|guideline|setup)s?\b",
        0.7,
        Severity.HIGH,
        "System-prompt extraction attempt",
    ),
    _r(
        "AEG-EXF-002",
        r"\bwhat\s+(?:were|was|are|is)\s+(?:you|your)\b[^.\n?]{0,40}"
        r"\b(?:told|instructed|system\s+prompt|initial\s+prompt|original\s+instruction)",
        0.6,
        Severity.MEDIUM,
        "Interrogates the model about its own instructions",
    ),
    _r(
        "AEG-EXF-003",
        r"\b(?:everything|all\s+(?:the\s+)?text)\s+(?:above|before|preceding)\b"
        r"[^.\n]{0,30}\b(?:verbatim|word\s+for\s+word|exactly|in\s+full)\b",
        0.66,
        Severity.HIGH,
        "Requests verbatim reproduction of prior context",
    ),
    _r(
        "AEG-EXF-004",
        r"\b(?:begin|start)(?:ning)?\s+(?:your\s+)?(?:reply|response|answer|output)\s+with\b"
        r"[^.\n]{0,40}\b(?:you\s+are|system|instruction)",
        0.58,
        Severity.MEDIUM,
        "Primes the response to begin leaking instructions",
    ),

    # ---- delimiter and role-token smuggling ------------------------------
    _r(
        "AEG-DLM-001",
        r"<\|(?:im_start|im_end|system|user|assistant|endoftext|eot_id|"
        r"start_header_id|end_header_id)\|>",
        0.84,
        Severity.CRITICAL,
        "Chat-template control token embedded in content",
        untrusted_boost=1.1,
    ),
    _r(
        "AEG-DLM-002",
        r"\[/?INST\]|<<\s*/?SYS\s*>>|\[/?s\]",
        0.76,
        Severity.HIGH,
        "Llama-family instruction delimiter embedded in content",
    ),
    _r(
        "AEG-DLM-003",
        # Requires a clause, not a value, after the colon. Without this,
        # ordinary config dumps ("system: linux/amd64") and API documentation
        # trip the rule - both were false positives in the benign corpus.
        # The lookahead is newline-free on purpose. An earlier version used
        # \s+, which matched across line breaks and fired on ordinary config
        # dumps ("system: linux/amd64\narchitecture: arm64 also supported").
        r"(?:^|[\n\r])[^\S\n]*(?:###[^\S\n]*)?(?:system|assistant)[^\S\n]*:[^\S\n]*"
        r"(?=[^\s\n]+[^\S\n]+[^\s\n]+[^\S\n]+[^\s\n]+)",
        0.48,
        Severity.MEDIUM,
        "Synthetic conversation turn injected into content",
        untrusted_boost=1.5,
    ),
    _r(
        "AEG-DLM-004",
        r"</?(?:system|instructions?|prompt|admin)>",
        0.52,
        Severity.MEDIUM,
        "Pseudo-XML instruction tag injected into content",
        untrusted_boost=1.4,
    ),

    # ---- authority and social engineering --------------------------------
    _r(
        "AEG-AUT-001",
        r"\b(?:i\s+am|this\s+is|speaking\s+as)\s+(?:your\s+)?"
        r"(?:developer|creator|administrator|admin|engineer|operator|owner|"
        r"anthropic|openai|the\s+system)\b",
        0.6,
        Severity.HIGH,
        "False authority claim",
    ),
    _r(
        "AEG-AUT-002",
        r"\b(?:authori[sz]ed|approved|sanctioned|official|legitimate)\b[^.\n]{0,30}"
        r"\b(?:test|audit|penetration\s+test|red\s*team|security\s+review)\b",
        0.46,
        Severity.MEDIUM,
        "Claims authorisation to bypass controls",
    ),
    _r(
        "AEG-AUT-003",
        r"\b(?:this\s+is\s+)?(?:an?\s+)?(?:emergency|urgent|critical)\b[^.\n]{0,40}"
        r"\b(?:override|bypass|ignore|disable)\b",
        0.54,
        Severity.MEDIUM,
        "Urgency pressure paired with a bypass request",
    ),

    # ---- exfiltration ----------------------------------------------------
    _r(
        "AEG-OUT-001",
        r"!\[[^\]]*\]\(\s*https?://[^)\s]{0,200}[?&][^)\s]{0,200}\)",
        0.5,
        Severity.HIGH,
        "Markdown image with query string - classic render-time exfiltration",
        untrusted_boost=1.5,
    ),
    _r(
        "AEG-OUT-002",
        r"\b(?:send|post|submit|transmit|upload|forward|exfiltrate|report)\b"
        r"(?:\s+[\w'-]+){0,9}\s+\b(?:to|at)\b\s*"
        r"(?:https?://|www\.|[a-z0-9.-]+\.(?:com|net|io|ru|cn|xyz|top))",
        0.6,
        Severity.HIGH,
        "Instruction to transmit data to an external endpoint",
        untrusted_boost=1.4,
    ),
    _r(
        "AEG-OUT-003",
        r"\b(?:append|include|add|embed|attach)\b[^.\n]{0,50}"
        r"\b(?:api[\s_-]?key|token|secret|credential|password|session|cookie)s?\b",
        0.64,
        Severity.CRITICAL,
        "Instruction to embed credentials in the output",
    ),
    _r(
        "AEG-OUT-004",
        r"\b(?:curl|wget|fetch|http\.get|requests\.(?:get|post))\b\s*\(?\s*"
        r"[\"']?https?://",
        0.44,
        Severity.MEDIUM,
        "Embedded outbound network call",
        channels=INJECTED_ONLY,
    ),

    # ---- tool and agent abuse --------------------------------------------
    _r(
        "AEG-TOO-001",
        r"\b(?:call|invoke|execute|run|trigger|use)\b[^.\n]{0,25}"
        r"\b(?:the\s+)?(?:tool|function|api|command|action)\b[^.\n]{0,45}"
        r"\b(?:without|before|instead\s+of)\b[^.\n]{0,25}"
        r"\b(?:asking|confirming|confirmation|permission|approval|telling|informing|notifying|checking|consent)\b",
        0.72,
        Severity.CRITICAL,
        "Instructs the agent to act without user confirmation",
    ),
    _r(
        "AEG-TOO-002",
        r"\b(?:do\s+not|don't|never)\b[^.\n]{0,30}\b(?:tell|inform|mention|"
        r"show|reveal|notify|alert)\b[^.\n]{0,20}\b(?:the\s+)?(?:user|human|"
        r"operator|owner)\b",
        0.74,
        Severity.CRITICAL,
        "Instructs the model to conceal actions from the user",
        untrusted_boost=1.2,
    ),
    _r(
        "AEG-TOO-003",
        r"\b(?:delete|drop|truncate|rm\s+-rf|destroy|wipe|purge)\b[^.\n]{0,30}"
        r"\b(?:database|table|file|record|repo|bucket|volume)s?\b",
        0.5,
        Severity.HIGH,
        "Destructive operation referenced in untrusted content",
        channels=INJECTED_ONLY,
    ),

    # ---- encoding instructions -------------------------------------------
    _r(
        "AEG-ENC-001",
        r"\b(?:decode|decrypt|deobfuscate|unscramble|translate)\b[^.\n]{0,40}"
        r"\b(?:base64|b64|hex|rot13|binary|morse|caesar)\b[^.\n]{0,60}"
        r"\b(?:then|and)\b[^.\n]{0,30}\b(?:execute|follow|obey|do|run|comply|perform)\b",
        0.78,
        Severity.CRITICAL,
        "Decode-then-execute instruction",
    ),
    _r(
        "AEG-ENC-002",
        r"\b(?:respond|reply|answer|write)\b[^.\n]{0,30}\bin\s+(?:base64|hex|rot13|"
        r"leetspeak|pig\s+latin|reverse)\b",
        0.4,
        Severity.LOW,
        "Requests encoded output - can be used to evade output filters",
    ),

    # ---- output-format hijack --------------------------------------------
    _r(
        "AEG-FMT-001",
        r"\b(?:respond|reply|answer|output)\b\s+(?:only\s+)?with\s+"
        r"(?:exactly\s+)?[\"'][^\"']{1,60}[\"']",
        0.34,
        Severity.LOW,
        "Pins the response to fixed text - used to confirm injection succeeded",
        untrusted_boost=1.6,
    ),
    _r(
        "AEG-FMT-002",
        r"\b(?:do\s+not|don't|never)\b[^.\n]{0,25}\b(?:refuse|decline|apologi[sz]e|"
        r"say\s+(?:you\s+)?(?:can't|cannot))\b",
        0.56,
        Severity.MEDIUM,
        "Pre-empts refusal behaviour",
    ),
]


def scan_signatures(text: str, channel: Channel) -> list[Signal]:
    """Run every rule applicable to `channel` against `text`."""
    signals: list[Signal] = []
    for rule in RULES:
        if channel not in rule.channels:
            continue
        match = rule.pattern.search(text)
        if match is None:
            continue
        weight = rule.weight
        if channel in INJECTED_ONLY:
            weight = min(0.97, weight * rule.untrusted_boost)
        signals.append(
            Signal(
                rule_id=rule.id,
                weight=weight,
                severity=rule.severity,
                message=rule.message,
                span=match.span(),
                evidence=match.group(0),
            )
        )
    return signals
