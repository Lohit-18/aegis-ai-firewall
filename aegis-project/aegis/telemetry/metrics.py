"""Prometheus metrics without the prometheus_client dependency.

A deliberate choice, not laziness: the exposition format is twelve lines of
text and the dependency pulls in a process collector we do not want in a
sidecar. Histograms use explicit buckets so the p95 that matters - detection
overhead - is readable straight off the scrape.
"""

from __future__ import annotations

import threading
from collections import defaultdict

_LATENCY_BUCKETS = (0.5, 1, 2, 5, 10, 25, 50, 100, 250, 500, 1000)


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.counters: dict[tuple[str, tuple[tuple[str, str], ...]], int] = defaultdict(int)
        self.hist_buckets: dict[tuple[str, tuple[tuple[str, str], ...]], list[int]] = {}
        self.hist_sum: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
        self.hist_count: dict[tuple[str, tuple[tuple[str, str], ...]], int] = defaultdict(int)

    @staticmethod
    def _key(name: str, labels: dict[str, str] | None):
        return name, tuple(sorted((labels or {}).items()))

    def inc(self, name: str, labels: dict[str, str] | None = None, by: int = 1) -> None:
        with self._lock:
            self.counters[self._key(name, labels)] += by

    def observe(self, name: str, value_ms: float, labels: dict[str, str] | None = None) -> None:
        key = self._key(name, labels)
        with self._lock:
            if key not in self.hist_buckets:
                self.hist_buckets[key] = [0] * (len(_LATENCY_BUCKETS) + 1)
            for i, bound in enumerate(_LATENCY_BUCKETS):
                if value_ms <= bound:
                    self.hist_buckets[key][i] += 1
            self.hist_buckets[key][-1] += 1  # +Inf
            self.hist_sum[key] += value_ms
            self.hist_count[key] += 1

    def render(self) -> str:
        lines: list[str] = []
        with self._lock:
            seen_help: set[str] = set()
            for (name, labels), value in sorted(self.counters.items()):
                if name not in seen_help:
                    lines.append(f"# TYPE {name} counter")
                    seen_help.add(name)
                lines.append(f"{name}{_fmt_labels(labels)} {value}")

            for (name, labels), buckets in sorted(self.hist_buckets.items()):
                if name not in seen_help:
                    lines.append(f"# TYPE {name} histogram")
                    seen_help.add(name)
                for i, bound in enumerate(_LATENCY_BUCKETS):
                    lines.append(
                        f"{name}_bucket{_fmt_labels(labels, le=str(bound))} {buckets[i]}"
                    )
                lines.append(f"{name}_bucket{_fmt_labels(labels, le='+Inf')} {buckets[-1]}")
                lines.append(f"{name}_sum{_fmt_labels(labels)} {self.hist_sum[(name, labels)]:.3f}")
                lines.append(f"{name}_count{_fmt_labels(labels)} {self.hist_count[(name, labels)]}")
        return "\n".join(lines) + "\n"


def _fmt_labels(labels: tuple[tuple[str, str], ...], le: str | None = None) -> str:
    items = list(labels)
    if le is not None:
        items.append(("le", le))
    if not items:
        return ""
    inner = ",".join(f'{k}="{str(v).replace(chr(34), "")}"' for k, v in items)
    return "{" + inner + "}"


metrics = Metrics()
