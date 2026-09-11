"""The reverse proxy itself.

Request path:

    client ──▶ scan ingress ──▶ instrument canary ──▶ upstream
                   │                                      │
                   ├─ block ──▶ 403 + explanation         │
                                                          ▼
    client ◀── release ◀── streaming egress scan ◀── model tokens

Two properties the implementation protects:

  * Time to first token. Ingress detection is ~0.2 ms and the egress scanner
    holds back a bounded 512-character window, not the whole response. A
    firewall that doubles perceived latency will be switched off.

  * Transparency. A block returns a structured body naming the rules that
    fired, so an application developer can tell a false positive from a real
    detection without reading the proxy's logs.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

from .config import settings
from .detect import canary as canary_mod
from .detect.egress import StreamScanner, scan_output_text, should_block
from .detect.engine import scan_request
from .detect.types import RequestScan
from .providers.openai_compat import (
    OpenAICompatProvider,
    UpstreamError,
    make_sse_chunk,
    make_sse_stop,
    parse_sse_delta,
)
from .telemetry.events import Event, sink
from .telemetry.metrics import metrics

router = APIRouter()
provider = OpenAICompatProvider()

BLOCK_MESSAGE = (
    "This request was blocked by Aegis because its content matched patterns "
    "associated with prompt injection. If you believe this is a false positive, "
    "the rule identifiers below are the ones that fired."
)


def _client_id(request: Request) -> str:
    return (
        request.headers.get("x-aegis-client")
        or (request.client.host if request.client else "unknown")
    )


def _collect_rules(scan: RequestScan) -> list[str]:
    rules: list[str] = []
    for result in scan.results:
        for sig in result.signals:
            if sig.rule_id not in rules:
                rules.append(sig.rule_id)
    return rules


def _block_response(scan: RequestScan, request_id: str) -> JSONResponse:
    worst = max(scan.results, key=lambda r: r.score)
    return JSONResponse(
        status_code=403,
        content={
            "error": {
                "message": BLOCK_MESSAGE,
                "type": "aegis_prompt_injection_blocked",
                "code": "prompt_injection",
                "aegis": {
                    "request_id": request_id,
                    "score": round(scan.score, 4),
                    "threshold": worst.threshold,
                    "channel": worst.channel.value,
                    "rules": [
                        {
                            "id": s.rule_id,
                            "severity": s.severity.value,
                            "message": s.message,
                        }
                        for s in sorted(worst.signals, key=lambda s: -s.weight)[:6]
                    ],
                },
            }
        },
        headers={"x-aegis-verdict": "block", "x-aegis-request-id": request_id},
    )


# ---------------------------------------------------------------------------
# chat completions
# ---------------------------------------------------------------------------

@router.post("/v1/chat/completions")
async def chat_completions(request: Request) -> Any:
    started = time.perf_counter()
    request_id = uuid.uuid4().hex[:16]
    client = _client_id(request)

    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content={"error": {"message": "invalid JSON body", "type": "bad_request"}},
        )
    if not isinstance(payload, dict):
        return JSONResponse(
            status_code=400,
            content={"error": {"message": "body must be an object", "type": "bad_request"}},
        )

    model = str(payload.get("model", "unknown"))
    wants_stream = bool(payload.get("stream"))

    # ---- ingress ---------------------------------------------------------
    scan = scan_request(payload)
    metrics.observe("aegis_detect_duration_ms", scan.elapsed_ms, {"phase": "ingress"})
    metrics.inc("aegis_requests_total", {"verdict": scan.verdict.value, "model": model})

    sink.emit(Event(
        kind="ingress",
        verdict=scan.verdict.value,
        score=scan.score,
        channel=max(scan.results, key=lambda r: r.score).channel.value if scan.results else "",
        model=model,
        client=client,
        rules=_collect_rules(scan),
        detect_ms=scan.elapsed_ms,
        detail={"request_id": request_id, "results": scan.to_dict()["results"][:4]},
    ))

    if scan.blocked:
        metrics.inc("aegis_blocked_total", {"phase": "ingress", "model": model})
        return _block_response(scan, request_id)

    # ---- canary ----------------------------------------------------------
    token: str | None = None
    if settings.canary_enabled:
        instrumented, mint = canary_mod.instrument(provider.get_system_prompt(payload))
        payload = provider.set_system_prompt(payload, instrumented)
        token = mint.token

    inbound_headers = {"authorization": request.headers.get("authorization", "")}

    # ---- upstream --------------------------------------------------------
    if wants_stream:
        return StreamingResponse(
            _stream(payload, inbound_headers, token, request_id, model, client, started),
            media_type="text/event-stream",
            headers={
                "x-aegis-verdict": scan.verdict.value,
                "x-aegis-request-id": request_id,
                "cache-control": "no-cache",
                "x-accel-buffering": "no",
            },
        )

    try:
        upstream = await provider.chat(payload, inbound_headers)
    except UpstreamError as exc:
        metrics.inc("aegis_upstream_errors_total", {"status": str(exc.status)})
        return JSONResponse(
            status_code=exc.status,
            content={"error": {"message": "upstream error", "detail": exc.body[:500]}},
        )
    except Exception as exc:
        metrics.inc("aegis_upstream_errors_total", {"status": "transport"})
        return JSONResponse(
            status_code=502,
            content={"error": {"message": f"upstream unreachable: {type(exc).__name__}"}},
        )

    # ---- egress ----------------------------------------------------------
    text = _extract_completion_text(upstream)
    egress_signals = scan_output_text(text, token) if settings.egress_enabled else []
    blocked_out = should_block(egress_signals)

    if egress_signals:
        sink.emit(Event(
            kind="egress",
            verdict="block" if blocked_out else "flag",
            score=max(s.weight for s in egress_signals),
            model=model,
            client=client,
            rules=[s.rule_id for s in egress_signals],
            detail={
                "request_id": request_id,
                "signals": [
                    {"rule_id": s.rule_id, "message": s.message,
                     "evidence": s.redacted_evidence()}
                    for s in egress_signals
                ],
            },
        ))
        metrics.inc("aegis_egress_signals_total", {"blocked": str(blocked_out).lower()})

    if blocked_out:
        metrics.inc("aegis_blocked_total", {"phase": "egress", "model": model})
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "message": "The model's response was withheld: it contained "
                    "content Aegis classifies as data exfiltration.",
                    "type": "aegis_egress_blocked",
                    "aegis": {
                        "request_id": request_id,
                        "rules": [
                            {"id": s.rule_id, "message": s.message}
                            for s in egress_signals
                        ],
                    },
                }
            },
            headers={"x-aegis-verdict": "block", "x-aegis-request-id": request_id},
        )

    # Redact rather than block for lower-severity findings.
    if egress_signals and token:
        scanner = StreamScanner(canary_token=token)
        upstream = _replace_completion_text(upstream, scanner.sanitize(text))

    total_ms = (time.perf_counter() - started) * 1000
    metrics.observe("aegis_request_duration_ms", total_ms, {"stream": "false"})
    return JSONResponse(
        content=upstream,
        headers={
            "x-aegis-verdict": scan.verdict.value,
            "x-aegis-score": f"{scan.score:.4f}",
            "x-aegis-request-id": request_id,
        },
    )


async def _stream(
    payload: dict[str, Any],
    headers: dict[str, str],
    token: str | None,
    request_id: str,
    model: str,
    client: str,
    started: float,
) -> AsyncIterator[str]:
    """Proxy an SSE stream through the bounded-window egress scanner.

    Note the ordering: we scan, then release. A chunk is never forwarded before
    it has been through the window, which is what makes the guarantee real
    rather than best-effort.
    """
    scanner = StreamScanner(canary_token=token)
    first_token_ms: float | None = None
    finish_reason = "stop"

    try:
        async for line in provider.chat_stream(payload, headers):
            if not line:
                continue
            delta = parse_sse_delta(line)

            if delta is None:
                # Terminal frames must NOT be forwarded here. Up to
                # CARRY_WINDOW characters are still held in the scanner, and
                # forwarding [DONE] or a finish_reason before flushing them
                # makes well-behaved clients stop reading - silently truncating
                # the last ~512 characters of every streamed response.
                #
                # Caught by the end-to-end demo, not by a unit test: the
                # scanner released everything correctly, but in the wrong
                # order relative to the control frames. Terminal frames are
                # swallowed here and re-emitted after the tail below.
                if _is_terminal_frame(line):
                    finish_reason = _finish_reason_of(line) or finish_reason
                    continue
                if line.startswith("data:"):
                    yield line + "\n\n"
                continue

            if first_token_ms is None:
                first_token_ms = (time.perf_counter() - started) * 1000
                metrics.observe("aegis_time_to_first_token_ms", first_token_ms, {"model": model})

            released, _ = scanner.feed(delta)

            if scanner.tripped and settings.egress_enabled:
                metrics.inc("aegis_blocked_total", {"phase": "egress-stream", "model": model})
                sink.emit(Event(
                    kind="egress",
                    verdict="block",
                    score=max((s.weight for s in scanner.signals), default=1.0),
                    model=model,
                    client=client,
                    rules=[s.rule_id for s in scanner.signals],
                    detail={
                        "request_id": request_id,
                        "released_chars": scanner.released,
                        "signals": [
                            {"rule_id": s.rule_id, "message": s.message,
                             "evidence": s.redacted_evidence()}
                            for s in scanner.signals
                        ],
                    },
                ))
                yield make_sse_chunk(
                    "\n\n[Aegis withheld the remainder of this response: it "
                    "contained content classified as data exfiltration.]",
                    model=model,
                )
                yield make_sse_stop(model=model, reason="content_filter")
                return

            if released:
                yield make_sse_chunk(scanner.sanitize(released), model=model)

        tail, _ = scanner.finish()
        if tail and not scanner.tripped:
            yield make_sse_chunk(scanner.sanitize(tail), model=model)
        yield make_sse_stop(model=model, reason=finish_reason)

    except UpstreamError as exc:
        metrics.inc("aegis_upstream_errors_total", {"status": str(exc.status)})
        yield make_sse_chunk(f"[Aegis: upstream error {exc.status}]", model=model)
        yield make_sse_stop(model=model, reason="error")
    except Exception as exc:  # pragma: no cover - transport failures
        metrics.inc("aegis_upstream_errors_total", {"status": "transport"})
        yield make_sse_chunk(f"[Aegis: upstream failure {type(exc).__name__}]", model=model)
        yield make_sse_stop(model=model, reason="error")
    finally:
        total_ms = (time.perf_counter() - started) * 1000
        metrics.observe("aegis_request_duration_ms", total_ms, {"stream": "true"})
        if scanner.signals and not scanner.tripped:
            sink.emit(Event(
                kind="egress",
                verdict="flag",
                score=max(s.weight for s in scanner.signals),
                model=model,
                client=client,
                rules=[s.rule_id for s in scanner.signals],
                detail={"request_id": request_id},
            ))


# ---------------------------------------------------------------------------
# passthrough + helpers
# ---------------------------------------------------------------------------

@router.get("/v1/models")
async def models(request: Request) -> Any:
    try:
        return await provider.models({"authorization": request.headers.get("authorization", "")})
    except UpstreamError as exc:
        return JSONResponse(status_code=exc.status, content={"error": {"message": exc.body[:300]}})
    except Exception as exc:
        return JSONResponse(
            status_code=502,
            content={"error": {"message": f"upstream unreachable: {type(exc).__name__}"}},
        )


def _is_terminal_frame(line: str) -> bool:
    """True for `[DONE]` or any chunk carrying a finish_reason."""
    if not line.startswith("data:"):
        return False
    data = line[5:].strip()
    if data == "[DONE]":
        return True
    try:
        obj = json.loads(data)
    except json.JSONDecodeError:
        return False
    choices = obj.get("choices") or []
    return bool(choices) and choices[0].get("finish_reason") is not None


def _finish_reason_of(line: str) -> str | None:
    if not line.startswith("data:"):
        return None
    data = line[5:].strip()
    if data == "[DONE]":
        return None
    try:
        obj = json.loads(data)
    except json.JSONDecodeError:
        return None
    choices = obj.get("choices") or []
    return choices[0].get("finish_reason") if choices else None


def _extract_completion_text(response: dict[str, Any]) -> str:
    try:
        parts = []
        for choice in response.get("choices", []):
            content = (choice.get("message") or {}).get("content")
            if isinstance(content, str):
                parts.append(content)
        return "\n".join(parts)
    except (AttributeError, TypeError):
        return ""


def _replace_completion_text(response: dict[str, Any], text: str) -> dict[str, Any]:
    choices = response.get("choices") or []
    if choices and isinstance(choices[0], dict):
        message = dict(choices[0].get("message") or {})
        message["content"] = text
        choices[0] = {**choices[0], "message": message}
        response["choices"] = choices
    return response
