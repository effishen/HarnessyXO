"""Small process-owned activity ledger for user-initiated I/O.

Counts overlapping operations independently, so one completed upload cannot clear
another upload's spinner. No filesystem or task lifetime is owned by the page.
"""
from __future__ import annotations

from collections import defaultdict
from contextlib import contextmanager
from typing import Iterator


class TabActivityRegistry:
    def __init__(self) -> None:
        self._tokens: dict[str, set[object]] = defaultdict(set)

    def busy(self, key: str) -> bool:
        return bool(self._tokens.get(key))

    def acquire(self, key: str):
        token = object()
        self._tokens[key].add(token)
        def release() -> None:
            tokens = self._tokens.get(key)
            if tokens is not None:
                tokens.discard(token)
                if not tokens:
                    self._tokens.pop(key, None)
        return release

    @contextmanager
    def track(self, key: str) -> Iterator[None]:
        release = self.acquire(key)
        try:
            yield
        finally:
            release()


TAB_ACTIVITY = TabActivityRegistry()
