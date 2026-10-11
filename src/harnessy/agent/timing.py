"""Observed stream intervals, deliberately separate from backend compute timings.

A phase starts when its first chunk is received and ends at the next phase or EOF.
Transport buffering and observer work are included. Buffered/mixed output cannot
be assigned reliable per-phase intervals and is explicitly marked unavailable.
"""
from __future__ import annotations

import time
from typing import Any, Callable


class StreamPhaseTimings:
    def __init__(self, clock: Callable[[], float] | None = None) -> None:
        self.clock = clock or time.perf_counter
        self.spans: list[dict[str, Any]] = []
        self.active: int | None = None

    def touch(self, kind: str, *, observable: bool = True) -> tuple[float, bool]:
        if kind not in {'reasoning', 'answer', 'tool_call'}:
            raise ValueError(f'Unknown output phase: {kind}')
        now = self.clock()
        previous = self.spans[self.active] if self.active is not None else None
        if previous is not None and previous['kind'] == kind:
            changed = previous['available'] and not observable
            previous['available'] = previous['available'] and observable
            return now, changed
        self.close(now)
        self.spans.append({'kind': kind, 'started_perf': now, 'duration_seconds': None,
                           'complete': False, 'available': observable})
        self.active = len(self.spans) - 1
        return now, True

    def close(self, now: float | None = None) -> None:
        if self.active is None:
            return
        now = self.clock() if now is None else now
        span = self.spans[self.active]
        span['duration_seconds'] = max(0.0, now - span['started_perf']) if span['available'] else None
        span['complete'] = True
        self.active = None

    def snapshot(self) -> list[dict[str, Any]]:
        return [dict(span) for span in self.spans]

    def totals(self) -> dict[str, float | None]:
        result: dict[str, float | None] = {}
        for kind in ('reasoning', 'answer', 'tool_call'):
            spans = [span for span in self.spans if span['kind'] == kind]
            result[kind] = (sum(float(span['duration_seconds']) for span in spans)
                            if spans and all(span['duration_seconds'] is not None for span in spans)
                            else None)
        return result


def timed_stream_segments(segments: list[dict[str, Any]], spans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add timing to segments; never mutate saved content or guess old durations."""
    result = []
    for segment in segments:
        row = dict(segment)
        index = row.get('timing_index')
        if isinstance(index, int) and 0 <= index < len(spans):
            span = spans[index]
            row.update(duration_seconds=span.get('duration_seconds'),
                       timing_source='stream_observed' if span.get('available') else 'unavailable',
                       timing_complete=bool(span.get('complete')))
        result.append(row)
    return result
