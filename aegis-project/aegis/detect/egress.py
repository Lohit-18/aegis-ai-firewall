"""Output scanning, including the streaming case.

## The problem nobody solves

Ingress filtering is the easy half. The damaging half of a prompt-injection
incident is usually the *response*: the system prompt coming back out, an API
key the model found in a tool result, or - most elegantly - a markdown image
whose URL carries stolen data as a query parameter, exfiltrated the instant the
client renders it. No user click required.

Scanning that is trivial for a buffered response and genuinely hard for a
streamed one. You cannot wait for the stream to finish, because the entire
point of streaming is time-to-first-token; buffering it turns a 200 ms
perceived latency into 4 s and the product team will simply turn your firewall
off.

## The solution: bounded carry buffer

A pattern can straddle a chunk boundary - `sk-ab` arrives, then `cdef1234`.
So we keep a carry of the last `W-1` characters, where `W` is the longest
pattern we can match. Each chunk is scanned as `carry + chunk`, and we release
everything except the new carry.

`W` is bounded by construction (the longest regex here is capped with `{0,200}`
quantifiers), so memory is O(1) per stream regardless of response length, and
the added latency is one chunk of buffering rather than a whole response.

That bound is the load-bearing detail. An unbounded lookbehind is a memory
exhaustion bug waiting for a 2 MB response.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from ..config import settings
from .types import Severity, Signal

# Longest window any pattern below can span. Chosen to exceed the largest
# bounded quantifier in EGRESS_PATTERNS with headroom.
CARRY_WINDOW = 512


@dataclass(frozen=True)
class EgressRule:
    id: str
    pattern: re.Pattern[str]
    weight: float
    severity: Severity
    message: str
    redact: bool = True


EGRESS_PATTERNS: list[EgressRule] = [
    EgressRule(
        "AEG-EGR-010",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        0.95, Severity.CRITICAL, "AWS access key ID in model output",
    ),
    EgressRule(
        "AEG-EGR-011",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        0.95, Severity.CRITICAL, "GitHub token in model output",
    ),
    EgressRule(
        "AEG-EGR-012",
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
        0.9, Severity.CRITICAL, "OpenAI-style API key in model output",
    ),
    EgressRule(
        "AEG-EGR-013",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
        0.97, Severity.CRITICAL, "Private key material in model output",
    ),
    EgressRule(
        "AEG-EGR-014",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        0.7, Severity.HIGH, "JWT in model output",
    ),
    EgressRule(
        "AEG-EGR-015",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        0.93, Severity.CRITICAL, "Slack token in model output",
    ),
]

# Markdown images and links are handled separately because the decision depends
# on the host, not just the shape.
_MD_IMAGE = re.compile(r"!\[[^\]]{0,200}\]\(\s*(?P<url>[^)\s]{1,400})\s*\)")
_MD_LINK = re.compile(r"(?<!!)\[[^\]]{0,200}\]\(\s*(?P<url>https?://[^)\s]{1,400})\s*\)")
_BARE_URL = re.compile(r"https?://[^\s<>\"')]{4,400}")


def _host_allowed(url: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    if not host:
        return True  # relative or data: URL, not an exfiltration channel
    return any(host == a or host.endswith("." + a) for a in settings.egress_image_allowlist)


def _url_carries_payload(url: str) -> bool:
    """A URL is an exfiltration vector when it carries data the model chose."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    query = parsed.query or ""
    path = parsed.path or ""
    # Long query strings, or long opaque path segments, are how data leaves.
    return len(query) > 24 or any(len(seg) > 40 for seg in path.split("/"))


def scan_output_text(text: str, canary_token: str | None = None) -> list[Signal]:
    """Scan a complete (or windowed) span of model output."""
    signals: list[Signal] = []
    if not text:
        return signals

    if canary_token and canary_token in text:
        idx = text.find(canary_token)
        signals.append(
            Signal(
                rule_id="AEG-EGR-001",
                weight=0.99,
                severity=Severity.CRITICAL,
                message="System-prompt canary token present in output - the system "
                "prompt was exfiltrated",
                span=(idx, idx + len(canary_token)),
                evidence=canary_token[:24] + "...",
            )
        )

    for rule in EGRESS_PATTERNS:
        match = rule.pattern.search(text)
        if match:
            signals.append(
                Signal(
                    rule_id=rule.id,
                    weight=rule.weight,
                    severity=rule.severity,
                    message=rule.message,
                    span=match.span(),
                    evidence=match.group(0)[:12] + "...",  # never log a whole secret
                )
            )

    for match in _MD_IMAGE.finditer(text):
        url = match.group("url")
        if not _host_allowed(url) and _url_carries_payload(url):
            signals.append(
                Signal(
                    rule_id="AEG-EGR-020",
                    weight=0.86,
                    severity=Severity.CRITICAL,
                    message="Markdown image to a non-allowlisted host carrying a "
                    "payload - zero-click exfiltration on render",
                    span=match.span(),
                    evidence=url[:160],
                )
            )

    for match in _MD_LINK.finditer(text):
        url = match.group("url")
        if not _host_allowed(url) and _url_carries_payload(url):
            signals.append(
                Signal(
                    rule_id="AEG-EGR-021",
                    weight=0.44,
                    severity=Severity.MEDIUM,
                    message="Markdown link to a non-allowlisted host carrying a "
                    "payload - one-click exfiltration",
                    span=match.span(),
                    evidence=url[:160],
                )
            )

    return signals


@dataclass
class StreamScanner:
    """Incremental scanner over a streamed response.

    Usage:
        scanner = StreamScanner(canary_token=tok)
        for chunk in upstream:
            safe, signals = scanner.feed(chunk)
            if scanner.tripped: break
            yield safe
        tail, signals = scanner.finish()
        yield tail

    `feed` returns the portion of text that is safe to release now. The held
    back remainder is at most CARRY_WINDOW characters and is released by
    `finish`, or on the next `feed`.
    """

    canary_token: str | None = None
    carry: str = ""
    released: int = 0
    signals: list[Signal] = field(default_factory=list)
    tripped: bool = False

    def _record(self, new_signals: list[Signal]) -> None:
        seen = {s.rule_id for s in self.signals}
        for sig in new_signals:
            if sig.rule_id not in seen:
                self.signals.append(sig)
                seen.add(sig.rule_id)
            if sig.weight >= 0.8:
                self.tripped = True

    def feed(self, chunk: str) -> tuple[str, list[Signal]]:
        if not chunk:
            return "", []
        window = self.carry + chunk
        found = scan_output_text(window, self.canary_token)
        self._record(found)

        if len(window) <= CARRY_WINDOW:
            self.carry = window
            return "", found

        release = window[:-CARRY_WINDOW]
        self.carry = window[-CARRY_WINDOW:]
        self.released += len(release)
        return release, found

    def finish(self) -> tuple[str, list[Signal]]:
        tail = self.carry
        found = scan_output_text(tail, self.canary_token) if tail else []
        self._record(found)
        self.carry = ""
        self.released += len(tail)
        return tail, found

    def sanitize(self, text: str) -> str:
        """Neutralise known-bad content rather than dropping the whole response.

        Redaction beats blocking for egress: the user still gets their answer,
        and the attacker gets nothing. Blocking a streamed response after 200
        tokens have already rendered is both a bad experience and, often, too
        late.
        """
        out = text
        if self.canary_token:
            out = out.replace(self.canary_token, "[REDACTED-CANARY]")
        for rule in EGRESS_PATTERNS:
            if rule.redact:
                out = rule.pattern.sub("[REDACTED-SECRET]", out)
        out = _MD_IMAGE.sub(
            lambda m: "[image removed by Aegis: untrusted destination]"
            if not _host_allowed(m.group("url")) and _url_carries_payload(m.group("url"))
            else m.group(0),
            out,
        )
        return out


def should_block(signals: list[Signal]) -> bool:
    if not settings.egress_enabled:
        return False
    for sig in signals:
        if sig.rule_id == "AEG-EGR-001" and settings.egress_block_on_canary:
            return True
        if sig.severity is Severity.CRITICAL and sig.weight >= 0.9:
            return True
    return False
