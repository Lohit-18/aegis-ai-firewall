"""Shared vocabulary for the detection pipeline.

Kept dependency-free on purpose: the corpus tooling, the eval harness and the
proxy all import these, and none of them should have to import FastAPI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Channel(StrEnum):
    """Provenance of a span of text.

    This is the single most important idea in Aegis. An LLM receives one flat
    token stream and has no way to tell developer instructions from text that
    arrived inside a retrieved document. The firewall does know, because it
    sits at the boundary where the two are still separate structures - so it
    can apply a different policy to each.

    SYSTEM    developer-authored. Trusted. Never scored for injection; it *is*
              the instruction set. Instrumented with a canary instead.
    USER      the human on the other end. Semi-trusted: they are allowed to
              try to jailbreak their own session. That is an abuse question,
              not a hijack, and it gets a high threshold.
    TOOL      output of a function/tool call. Untrusted. No legitimate tool
              result contains imperative instructions addressed to the
              assistant, so the threshold is aggressive.
    DOCUMENT  retrieved context, RAG chunks, pasted web pages. Untrusted, same
              reasoning as TOOL. This is where real-world attacks actually
              live, and where most "prompt firewalls" never look.
    """

    SYSTEM = "system"
    USER = "user"
    TOOL = "tool"
    DOCUMENT = "document"


class Verdict(StrEnum):
    ALLOW = "allow"
    FLAG = "flag"      # forward, but record and mark. Used below threshold but above noise.
    REDACT = "redact"  # forward with the offending span neutralised.
    BLOCK = "block"    # refuse upstream entirely.


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Signal:
    """One piece of evidence from one detector.

    `weight` is a likelihood-ish number in [0, 1): roughly "if I see only this,
    how confident am I". It is deliberately never 1.0 - no single regex should
    be able to reach certainty on its own, because every one of them has a
    benign counterexample somewhere.

    `span` lets the engine deduplicate overlapping evidence. Five rules firing
    on the same twenty characters is one observation, not five.
    """

    rule_id: str
    weight: float
    severity: Severity
    message: str
    span: tuple[int, int] | None = None
    evidence: str = ""
    meta: dict[str, Any] = field(default_factory=dict)

    def redacted_evidence(self, limit: int = 120) -> str:
        """Evidence is attacker-controlled text destined for a log. Truncate it
        and strip control characters so it cannot corrupt a terminal or a log
        aggregator's parser."""
        cleaned = "".join(ch if ch.isprintable() or ch == " " else "�" for ch in self.evidence)
        return cleaned[:limit] + ("..." if len(cleaned) > limit else "")


@dataclass
class ScanResult:
    """Outcome of scanning one span of text in one channel."""

    channel: Channel
    score: float
    verdict: Verdict
    signals: list[Signal] = field(default_factory=list)
    threshold: float = 1.0
    elapsed_ms: float = 0.0
    degraded: bool = False  # detection errored or blew the latency budget

    @property
    def top_rules(self) -> list[str]:
        return [s.rule_id for s in sorted(self.signals, key=lambda s: -s.weight)[:5]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "channel": self.channel.value,
            "score": round(self.score, 4),
            "verdict": self.verdict.value,
            "threshold": self.threshold,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "degraded": self.degraded,
            "signals": [
                {
                    "rule_id": s.rule_id,
                    "weight": s.weight,
                    "severity": s.severity.value,
                    "message": s.message,
                    "evidence": s.redacted_evidence(),
                }
                for s in sorted(self.signals, key=lambda s: -s.weight)
            ],
        }


@dataclass
class RequestScan:
    """Aggregate of every span scanned in one request."""

    results: list[ScanResult] = field(default_factory=list)
    canary: str | None = None

    @property
    def verdict(self) -> Verdict:
        order = [Verdict.ALLOW, Verdict.FLAG, Verdict.REDACT, Verdict.BLOCK]
        worst = Verdict.ALLOW
        for r in self.results:
            if order.index(r.verdict) > order.index(worst):
                worst = r.verdict
        return worst

    @property
    def score(self) -> float:
        return max((r.score for r in self.results), default=0.0)

    @property
    def elapsed_ms(self) -> float:
        return sum(r.elapsed_ms for r in self.results)

    @property
    def blocked(self) -> bool:
        return self.verdict is Verdict.BLOCK

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "score": round(self.score, 4),
            "elapsed_ms": round(self.elapsed_ms, 3),
            "results": [r.to_dict() for r in self.results],
        }
