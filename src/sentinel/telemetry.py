"""Per-scan run metrics and events (technical specification section 15: publish observed scan
coverage and budget exhaustion to users).

The active collector is held in a context variable rather than on the shared runtime, so
concurrent API scans never mix their metrics.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from contextvars import ContextVar, copy_context
from typing import Any

from langchain_core.callbacks import BaseCallbackHandler

from sentinel.contracts import RunEvent, RunEventKind, StageMetric

_CURRENT: ContextVar[RunTelemetry | None] = ContextVar("sentinel_run_telemetry", default=None)


def current() -> RunTelemetry | None:
    return _CURRENT.get()


def emit(kind: RunEventKind, stage: str, detail: str = "") -> None:
    telemetry = current()
    if telemetry is not None:
        telemetry.event(kind, stage, detail)


class _StageCounter(BaseCallbackHandler):
    """Counts model calls, tokens, and tool calls for one stage, including nested subagents."""

    def __init__(self) -> None:
        self.model_calls = 0
        self.input_tokens = 0
        self.output_tokens = 0
        self.tool_calls = 0
        self._lock = threading.Lock()

    def on_llm_end(self, response: Any, **_: Any) -> None:
        with self._lock:
            self.model_calls += 1
            for generations in response.generations:
                for generation in generations:
                    message = getattr(generation, "message", None)
                    usage = getattr(message, "usage_metadata", None) or {}
                    self.input_tokens += int(usage.get("input_tokens", 0) or 0)
                    self.output_tokens += int(usage.get("output_tokens", 0) or 0)

    def on_tool_start(self, serialized: Any, input_str: str, **_: Any) -> None:
        with self._lock:
            self.tool_calls += 1


class RunTelemetry:
    def __init__(self, progress: Callable[[str], None] | None = None) -> None:
        self.progress = progress
        self.started = time.monotonic()
        self.metrics: list[StageMetric] = []
        self.events: list[RunEvent] = []
        self._budgets: dict[str, tuple[int, int]] = {}
        self._lock = threading.Lock()

    def _say(self, text: str) -> None:
        if self.progress is not None:
            self.progress(f"[{time.monotonic() - self.started:8.1f}s] {text}")

    def event(self, kind: RunEventKind, stage: str, detail: str = "") -> None:
        with self._lock:
            self.events.append(RunEvent(kind=kind, stage=stage, detail=detail[:2_000]))
        self._say(f"{kind:<24} {stage}  {detail[:300]}")

    def budget_refusal(self, label: str, limit: int) -> None:
        with self._lock:
            _, refused = self._budgets.get(label, (limit, 0))
            self._budgets[label] = (limit, refused + 1)
            first = refused == 0
        if first:
            self._say(f"{'budget_exhausted':<24} {label}  {limit}-call budget spent")

    @contextmanager
    def stage(self, name: str) -> Iterator[_StageCounter]:
        counter = _StageCounter()
        began = time.monotonic()
        self._say(f"{'stage_start':<24} {name}")
        outcome = "failed"
        try:
            yield counter
            outcome = "ok"
        finally:
            metric = StageMetric(
                stage=name,
                outcome=outcome,  # type: ignore[arg-type]
                duration_seconds=round(time.monotonic() - began, 2),
                model_calls=counter.model_calls,
                input_tokens=counter.input_tokens,
                output_tokens=counter.output_tokens,
                tool_calls=counter.tool_calls,
            )
            with self._lock:
                self.metrics.append(metric)
            self._say(
                f"{'stage_' + outcome:<24} {name}  {metric.duration_seconds}s "
                f"calls={metric.model_calls} tools={metric.tool_calls} "
                f"in={metric.input_tokens} out={metric.output_tokens}"
            )

    def snapshot(self) -> tuple[tuple[StageMetric, ...], tuple[RunEvent, ...]]:
        with self._lock:
            budget_events = [
                RunEvent(
                    kind="budget_exhausted",
                    stage=label,
                    detail=f"{limit}-call budget spent; {refused} further calls refused",
                )
                for label, (limit, refused) in sorted(self._budgets.items())
            ]
            return tuple(self.metrics), tuple([*self.events, *budget_events])


def parallel_map(function: Callable[[Any], Any], items: Any, workers: int) -> list[Any]:
    """Map over independent items, in order, on up to `workers` threads.

    Each call runs in a copy of the caller's context so run telemetry keeps collecting. The first
    exception propagates after the remaining calls finish.
    """
    items = list(items)
    if workers <= 1 or len(items) <= 1:
        return [function(item) for item in items]
    with ThreadPoolExecutor(max_workers=min(workers, len(items))) as pool:
        futures = [pool.submit(copy_context().run, function, item) for item in items]
        return [future.result() for future in futures]


@contextmanager
def collecting(telemetry: RunTelemetry) -> Iterator[RunTelemetry]:
    token = _CURRENT.set(telemetry)
    try:
        yield telemetry
    finally:
        _CURRENT.reset(token)
