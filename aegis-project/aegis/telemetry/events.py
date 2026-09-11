"""Structured event log.

Two sinks on purpose:

  JSONL  - append-only, greppable, trivially shipped to Loki/Splunk/S3. This is
           what a real deployment forwards.
  SQLite - queryable, powers the dashboard without standing up a database.

Both writes happen off the request path via a queue. A security control that
adds disk I/O latency to every request gets disabled by the platform team
within a week, and then you have no security control at all.

Attacker-controlled text reaches this module. Evidence strings are truncated
and stripped of control characters before they are written (see
`Signal.redacted_evidence`) so a payload cannot forge log lines or break a
downstream parser.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import sqlite3
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ..config import settings

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id           TEXT PRIMARY KEY,
    ts           REAL NOT NULL,
    kind         TEXT NOT NULL,
    verdict      TEXT,
    score        REAL,
    channel      TEXT,
    model        TEXT,
    client       TEXT,
    rules        TEXT,
    latency_ms   REAL,
    detect_ms    REAL,
    detail       TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_verdict ON events(verdict);
"""


@dataclass
class Event:
    kind: str                       # "ingress" | "egress" | "error"
    verdict: str = "allow"
    score: float = 0.0
    channel: str = ""
    model: str = ""
    client: str = ""
    rules: list[str] = field(default_factory=list)
    latency_ms: float = 0.0
    detect_ms: float = 0.0
    detail: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    ts: float = field(default_factory=time.time)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, default=str)


class EventSink:
    def __init__(self) -> None:
        self._queue: asyncio.Queue[Event] | None = None
        self._task: asyncio.Task[None] | None = None
        self._conn: sqlite3.Connection | None = None
        self._jsonl = None
        self.dropped = 0

    async def startup(self) -> None:
        Path(settings.event_log_path).parent.mkdir(parents=True, exist_ok=True)
        Path(settings.sqlite_path).parent.mkdir(parents=True, exist_ok=True)

        self._jsonl = open(settings.event_log_path, "a", encoding="utf-8")  # noqa: SIM115
        self._conn = sqlite3.connect(settings.sqlite_path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

        self._queue = asyncio.Queue(maxsize=4096)
        self._task = asyncio.create_task(self._drain())

    async def shutdown(self) -> None:
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        if self._jsonl:
            self._jsonl.close()
            self._jsonl = None
        if self._conn:
            self._conn.close()
            self._conn = None

    def emit(self, event: Event) -> None:
        """Non-blocking. Drops on backpressure rather than stalling a request.

        Dropping telemetry under load is the right trade: the alternative is
        letting the log queue become a denial-of-service amplifier.
        """
        if self._queue is None:
            return
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self.dropped += 1

    async def _drain(self) -> None:
        assert self._queue is not None
        while True:
            event = await self._queue.get()
            try:
                self._write(event)
            except Exception:  # pragma: no cover - never kill the drain loop
                self.dropped += 1
            finally:
                self._queue.task_done()

    def _write(self, event: Event) -> None:
        if self._jsonl:
            self._jsonl.write(event.to_json() + "\n")
            self._jsonl.flush()
        if self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO events "
                "(id, ts, kind, verdict, score, channel, model, client, rules, "
                " latency_ms, detect_ms, detail) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    event.id, event.ts, event.kind, event.verdict, event.score,
                    event.channel, event.model, event.client,
                    json.dumps(event.rules), event.latency_ms, event.detect_ms,
                    json.dumps(event.detail, default=str)[:8000],
                ),
            )
            self._conn.commit()

    # ---- queries used by the dashboard ---------------------------------

    def recent(self, limit: int = 100, verdict: str | None = None) -> list[dict[str, Any]]:
        if not self._conn:
            return []
        sql = "SELECT id, ts, kind, verdict, score, channel, model, client, rules, latency_ms, detect_ms, detail FROM events"
        params: tuple[Any, ...] = ()
        if verdict:
            sql += " WHERE verdict = ?"
            params = (verdict,)
        sql += " ORDER BY ts DESC LIMIT ?"
        params += (limit,)
        rows = self._conn.execute(sql, params).fetchall()
        out = []
        for r in rows:
            out.append({
                "id": r[0], "ts": r[1], "kind": r[2], "verdict": r[3],
                "score": r[4], "channel": r[5], "model": r[6], "client": r[7],
                "rules": json.loads(r[8] or "[]"),
                "latency_ms": r[9], "detect_ms": r[10],
                "detail": json.loads(r[11] or "{}"),
            })
        return out

    def summary(self, window_s: float = 3600.0) -> dict[str, Any]:
        if not self._conn:
            return {}
        since = time.time() - window_s
        rows = self._conn.execute(
            "SELECT verdict, COUNT(*), AVG(detect_ms) FROM events "
            "WHERE ts > ? AND kind = 'ingress' GROUP BY verdict",
            (since,),
        ).fetchall()
        counts = {r[0]: r[1] for r in rows}
        total = sum(counts.values()) or 0
        avg_detect = 0.0
        if rows:
            weighted = sum((r[1] or 0) * (r[2] or 0.0) for r in rows)
            avg_detect = weighted / max(total, 1)

        rule_rows = self._conn.execute(
            "SELECT rules FROM events WHERE ts > ? AND verdict IN ('block','flag')",
            (since,),
        ).fetchall()
        tally: dict[str, int] = {}
        for (raw,) in rule_rows:
            for rule in json.loads(raw or "[]"):
                tally[rule] = tally.get(rule, 0) + 1

        return {
            "window_s": window_s,
            "total": total,
            "counts": counts,
            "blocked": counts.get("block", 0),
            "flagged": counts.get("flag", 0),
            "allowed": counts.get("allow", 0),
            "block_rate": (counts.get("block", 0) / total) if total else 0.0,
            "avg_detect_ms": round(avg_detect, 3),
            "top_rules": sorted(tally.items(), key=lambda kv: -kv[1])[:10],
            "dropped_events": self.dropped,
        }


sink = EventSink()
