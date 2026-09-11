"""Structural and obfuscation analysis.

Signature matching alone fails against an attacker who can spell. This module
looks at *how* the text is built rather than what it says, which catches the
two things regexes miss:

  1. Payloads hidden from the reader but visible to the tokeniser - zero-width
     characters, Unicode tag characters, bidirectional overrides, homoglyphs.
  2. Payloads hidden from the scanner but decodable by the model - base64 and
     hex blobs that the model is asked to decode and then obey.

The design principle: obfuscation is itself a signal. Nobody accidentally
writes a sentence containing seventeen zero-width joiners. Even when we cannot
decode the payload, the presence of the wrapper is evidence, and we score it.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata

from .types import Channel, Severity, Signal

# ---------------------------------------------------------------------------
# invisible character classes
# ---------------------------------------------------------------------------

ZERO_WIDTH = {
    0x200B,  # zero width space
    0x200C,  # zero width non-joiner
    0x200D,  # zero width joiner
    0x2060,  # word joiner
    0x2061, 0x2062, 0x2063, 0x2064,  # invisible maths operators
    0xFEFF,  # zero width no-break space / BOM
    0x180E,  # mongolian vowel separator
}

BIDI_CONTROLS = {
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,  # embedding / override
    0x2066, 0x2067, 0x2068, 0x2069,          # isolates
}

# U+E0000..U+E007F. These mirror ASCII and render as nothing in almost every
# client, but most tokenisers pass them straight through to the model. This is
# the cleanest "invisible instruction" channel that currently exists.
TAG_BLOCK = range(0xE0000, 0xE0080)


def _decode_tag_block(text: str) -> str:
    """Recover the ASCII hidden in Unicode tag characters."""
    out = []
    for ch in text:
        cp = ord(ch)
        if cp in TAG_BLOCK:
            ascii_cp = cp - 0xE0000
            if 0x20 <= ascii_cp <= 0x7E:
                out.append(chr(ascii_cp))
    return "".join(out)


# ---------------------------------------------------------------------------
# script confusion (homoglyphs)
# ---------------------------------------------------------------------------

_SCRIPT_RANGES: list[tuple[int, int, str]] = [
    (0x0041, 0x024F, "Latin"),
    (0x0370, 0x03FF, "Greek"),
    (0x0400, 0x04FF, "Cyrillic"),
    (0x0530, 0x058F, "Armenian"),
    (0x0590, 0x05FF, "Hebrew"),
    (0x0600, 0x06FF, "Arabic"),
]


def _script_of(ch: str) -> str | None:
    cp = ord(ch)
    for lo, hi, name in _SCRIPT_RANGES:
        if lo <= cp <= hi:
            return name
    return None


_WORD_RE = re.compile(r"[^\W\d_]{3,}", re.UNICODE)


def _mixed_script_words(text: str) -> list[str]:
    """Words that draw letters from more than one script.

    'аdmin' with a Cyrillic а looks identical to 'admin' but defeats every
    literal string match. Legitimate multi-script *words* are vanishingly rare;
    multi-script *sentences* are common, so this deliberately works per word.
    """
    hits = []
    for match in _WORD_RE.finditer(text):
        word = match.group(0)
        scripts = {s for s in (_script_of(c) for c in word) if s}
        if len(scripts) > 1:
            hits.append(word)
    return hits


# ---------------------------------------------------------------------------
# encoded payloads
# ---------------------------------------------------------------------------

_B64_RE = re.compile(r"(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}[\s:,-]?){16,}")


def _printable_ratio(data: str) -> float:
    if not data:
        return 0.0
    printable = sum(1 for c in data if c.isprintable() or c in "\n\r\t")
    return printable / len(data)


def decode_candidates(text: str, limit: int = 6) -> list[tuple[str, str]]:
    """Return (encoding, decoded_text) for blobs that decode to readable text.

    One level only. Recursing further is a denial-of-service invitation: an
    attacker can nest encodings cheaply and make the scanner do unbounded work.
    """
    found: list[tuple[str, str]] = []

    for match in _B64_RE.finditer(text):
        if len(found) >= limit:
            break
        blob = match.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            decoded = raw.decode("utf-8", errors="strict")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if len(decoded) >= 8 and _printable_ratio(decoded) > 0.9:
            found.append(("base64", decoded))

    for match in _HEX_RE.finditer(text):
        if len(found) >= limit:
            break
        blob = re.sub(r"[\s:,-]", "", match.group(0))
        if len(blob) % 2:
            blob = blob[:-1]
        try:
            decoded = bytes.fromhex(blob).decode("utf-8", errors="strict")
        except (ValueError, UnicodeDecodeError):
            continue
        if len(decoded) >= 8 and _printable_ratio(decoded) > 0.9:
            found.append(("hex", decoded))

    return found


# ---------------------------------------------------------------------------
# main entry point
# ---------------------------------------------------------------------------

def scan_structure(text: str, channel: Channel) -> list[Signal]:
    signals: list[Signal] = []
    if not text:
        return signals

    length = len(text)

    # -- invisible characters ------------------------------------------
    zw_count = sum(1 for ch in text if ord(ch) in ZERO_WIDTH)
    if zw_count >= 3:
        # Density matters more than raw count: three in a tweet is an attack,
        # three in a 40 KB document is probably a copy-paste artefact.
        density = zw_count / max(length, 1)
        weight = 0.45 if density > 0.005 else 0.28
        signals.append(
            Signal(
                rule_id="AEG-STR-001",
                weight=weight,
                severity=Severity.MEDIUM,
                message=f"{zw_count} zero-width characters embedded in text",
                evidence=f"density={density:.4f}",
                meta={"count": zw_count, "density": density},
            )
        )

    tag_payload = _decode_tag_block(text)
    if len(tag_payload) >= 4:
        signals.append(
            Signal(
                rule_id="AEG-STR-002",
                weight=0.88,
                severity=Severity.CRITICAL,
                message="Hidden instructions encoded in Unicode tag characters",
                evidence=tag_payload,
                meta={"decoded": tag_payload},
            )
        )

    bidi = sum(1 for ch in text if ord(ch) in BIDI_CONTROLS)
    if bidi:
        signals.append(
            Signal(
                rule_id="AEG-STR-003",
                weight=0.62,
                severity=Severity.HIGH,
                message=f"{bidi} bidirectional override characters - text renders "
                "differently than it tokenises",
                evidence=f"count={bidi}",
                meta={"count": bidi},
            )
        )

    # -- script confusion ------------------------------------------------
    mixed = _mixed_script_words(text)
    if mixed:
        signals.append(
            Signal(
                rule_id="AEG-STR-004",
                weight=min(0.6, 0.3 + 0.08 * len(mixed)),
                severity=Severity.MEDIUM,
                message=f"{len(mixed)} word(s) mix characters from multiple scripts",
                evidence=", ".join(mixed[:5]),
                meta={"words": mixed[:20]},
            )
        )

    # -- combining-character abuse ---------------------------------------
    combining = sum(1 for ch in text if unicodedata.combining(ch))
    if combining > 20 and combining / max(length, 1) > 0.08:
        signals.append(
            Signal(
                rule_id="AEG-STR-005",
                weight=0.34,
                severity=Severity.LOW,
                message="Excessive combining marks - obfuscation or rendering attack",
                evidence=f"count={combining}",
                meta={"count": combining},
            )
        )

    # -- context flooding -------------------------------------------------
    newlines = text.count("\n")
    if newlines > 60 and newlines / max(length, 1) > 0.25:
        signals.append(
            Signal(
                rule_id="AEG-STR-006",
                weight=0.3,
                severity=Severity.LOW,
                message="Heavy newline padding - used to push earlier context "
                "out of the model's attention",
                evidence=f"newlines={newlines}",
                meta={"newlines": newlines},
            )
        )

    # -- encoded payloads --------------------------------------------------
    # Imported here to keep the module import graph acyclic.
    from .signatures import scan_signatures

    for encoding, decoded in decode_candidates(text):
        nested = scan_signatures(decoded, channel)
        if nested:
            best = max(nested, key=lambda s: s.weight)
            signals.append(
                Signal(
                    rule_id="AEG-STR-010",
                    # Decoding to a live payload is close to conclusive: benign
                    # base64 does not decode into instruction-override English.
                    weight=min(0.94, best.weight + 0.2),
                    severity=Severity.CRITICAL,
                    message=f"{encoding} payload decodes to injection content "
                    f"({best.rule_id})",
                    evidence=decoded[:160],
                    meta={"encoding": encoding, "nested_rule": best.rule_id},
                )
            )
        elif len(decoded) > 40:
            signals.append(
                Signal(
                    rule_id="AEG-STR-011",
                    weight=0.2,
                    severity=Severity.LOW,
                    message=f"Large {encoding} blob decodes to readable text",
                    evidence=decoded[:120],
                    meta={"encoding": encoding},
                )
            )

    return signals


def normalise(text: str) -> str:
    """Strip the invisible layer so downstream matching sees what the model sees.

    Deliberately *not* used to replace the raw scan - we score the raw text for
    obfuscation signals first, then scan the normalised form for content. An
    attacker who strips their own obfuscation just gets caught by signatures.
    """
    hidden = _decode_tag_block(text)
    cleaned = "".join(
        ch for ch in text
        if ord(ch) not in ZERO_WIDTH
        and ord(ch) not in BIDI_CONTROLS
        and ord(ch) not in TAG_BLOCK
    )
    cleaned = unicodedata.normalize("NFKC", cleaned)
    return cleaned + ((" " + hidden) if hidden else "")
