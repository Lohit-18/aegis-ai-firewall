"""Application entry point."""

from __future__ import annotations

import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from .config import settings
from .detect.signatures import RULES
from .proxy import provider, router
from .telemetry.events import sink
from .telemetry.metrics import metrics

STARTED_AT = time.time()
STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await provider.startup()
    await sink.startup()
    try:
        yield
    finally:
        await sink.shutdown()
        await provider.shutdown()


app = FastAPI(
    title="Aegis",
    description="Real-time prompt injection firewall and telemetry gateway for LLM traffic.",
    version="0.3.0",
    lifespan=lifespan,
)
app.include_router(router)


@app.get("/healthz")
async def healthz() -> dict:
    return {
        "status": "ok",
        "uptime_s": round(time.time() - STARTED_AT, 1),
        "detection_enabled": settings.detection_enabled,
        "egress_enabled": settings.egress_enabled,
        "canary_enabled": settings.canary_enabled,
        "failure_mode": settings.failure_mode.value,
        "upstream": settings.upstream_base_url,
        "rules_loaded": len(RULES),
    }


@app.get("/metrics")
async def prometheus_metrics() -> PlainTextResponse:
    if not settings.metrics_enabled:
        return PlainTextResponse("metrics disabled\n", status_code=404)
    return PlainTextResponse(metrics.render(), media_type="text/plain; version=0.0.4")


@app.get("/api/summary")
async def api_summary(window: float = 3600.0) -> JSONResponse:
    return JSONResponse(sink.summary(window_s=window))


@app.get("/api/events")
async def api_events(limit: int = 100, verdict: str | None = None) -> JSONResponse:
    return JSONResponse({"events": sink.recent(limit=min(limit, 500), verdict=verdict)})


@app.get("/api/rules")
async def api_rules() -> JSONResponse:
    return JSONResponse({
        "rules": [
            {
                "id": r.id,
                "weight": r.weight,
                "severity": r.severity.value,
                "message": r.message,
                "channels": sorted(c.value for c in r.channels),
            }
            for r in RULES
        ]
    })


@app.post("/api/scan")
async def api_scan(request: Request) -> JSONResponse:
    """Scan text without forwarding it upstream.

    Exists so the eval harness, the test suite and the dashboard's playground
    all exercise exactly the same code path the proxy does - no separate
    "offline" scoring implementation that can drift from production.
    """
    from .detect.engine import scan_text
    from .detect.types import Channel

    body = await request.json()
    text = str(body.get("text", ""))
    try:
        channel = Channel(str(body.get("channel", "user")))
    except ValueError:
        channel = Channel.USER
    return JSONResponse(scan_text(text, channel).to_dict())


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    if not settings.dashboard_enabled:
        return HTMLResponse("<h1>Aegis</h1><p>Dashboard disabled.</p>")
    return HTMLResponse((STATIC_DIR / "dashboard.html").read_text(encoding="utf-8"))


def run() -> None:
    import uvicorn

    uvicorn.run(
        "aegis.main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
    )


if __name__ == "__main__":
    run()
