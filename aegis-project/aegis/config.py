"""Runtime configuration.

Everything is overridable by environment variable so the same image runs in
dev (Ollama, fail-open, verbose) and in prod (hosted API, fail-closed, quiet).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class FailureMode(StrEnum):
    """What to do when the detection engine itself errors or times out.

    OPEN  - forward the request. Availability over security. Correct for a
            consumer chatbot where a false block is worse than a missed attack.
    CLOSED- reject the request. Security over availability. Correct when the
            model has access to tools that can spend money or move data.

    There is no universally right answer; the point of making it a config flag
    is that the deployer has to choose consciously.
    """

    OPEN = "open"
    CLOSED = "closed"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AEGIS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ---- upstream -------------------------------------------------------
    upstream_base_url: str = Field(
        default="http://localhost:11434/v1",
        description="OpenAI-compatible endpoint. Ollama, vLLM, Groq, OpenAI all work.",
    )
    upstream_api_key: str = Field(default="", description="Forwarded as Authorization: Bearer.")
    upstream_timeout_s: float = 120.0
    upstream_connect_timeout_s: float = 5.0

    # ---- detection ------------------------------------------------------
    detection_enabled: bool = True
    detection_budget_ms: float = Field(
        default=25.0,
        description="Soft latency budget for the whole ingress scan. Exceeding it is "
        "logged as a degradation, not an error - the scan still completes.",
    )
    failure_mode: FailureMode = FailureMode.OPEN

    # Thresholds are per trust channel. See detect/engine.py for the rationale:
    # the same string is far more alarming in a tool result than in a user turn.
    #
    # These values are NOT hand-picked. They come from `bench/calibrate.py`,
    # which sets each one at the (1 - target_FPR) quantile of the benign corpus
    # subject to a minimum-evidence floor. Re-run that script after changing
    # any rule weight; do not edit these by feel.
    threshold_user: float = Field(default=0.42, ge=0.0, le=1.0)
    threshold_tool: float = Field(default=0.42, ge=0.0, le=1.0)
    threshold_document: float = Field(default=0.42, ge=0.0, le=1.0)

    # ---- canary ---------------------------------------------------------
    canary_enabled: bool = True
    canary_prefix: str = "AEGIS-CANARY"

    # ---- egress ---------------------------------------------------------
    egress_enabled: bool = True
    egress_block_on_canary: bool = True
    egress_image_allowlist: tuple[str, ...] = ("localhost", "127.0.0.1")

    # ---- telemetry ------------------------------------------------------
    event_log_path: str = "./data/events.jsonl"
    sqlite_path: str = "./data/aegis.db"
    metrics_enabled: bool = True
    dashboard_enabled: bool = True

    # ---- server ---------------------------------------------------------
    host: str = "0.0.0.0"
    port: int = 8080
    log_level: Literal["debug", "info", "warning", "error"] = "info"

    def threshold_for(self, channel: str) -> float:
        return {
            "user": self.threshold_user,
            "tool": self.threshold_tool,
            "document": self.threshold_document,
        }.get(channel, self.threshold_user)


settings = Settings()
