"""Short lived, delivered-alert routes for the interactive notification menu."""
from __future__ import annotations

from dataclasses import dataclass
import threading
import time


@dataclass(frozen=True, slots=True)
class NotificationRoute:
    code: str
    workspace_id: str
    chat_id: str
    run_id: str
    prompt_id: str
    config_fingerprint: str
    expires_at_monotonic: float
    notification_sequence: int
    workspace_name: str = ''
    chat_title: str = ''
    outcome: str = ''
    elapsed_seconds: float = 0.0
    workspace_generation: tuple = ()
    retry_code: str = ''


@dataclass(slots=True)
class NotificationCursor:
    browse_scope: str = 'prompt'
    answer_number: int | None = None
    answer_id: str = ''
    page: int = 1


class NotificationSessions:
    """Pin explicit selections; a later alert must never steal that target."""

    def __init__(self, limit: int = 256) -> None:
        self.limit = max(1, limit)
        self._lock = threading.RLock()
        self._routes: dict[str, NotificationRoute] = {}
        self._cursors: dict[str, NotificationCursor] = {}
        self._selected = ''
        self._fingerprint = ''

    def reset(self) -> None:
        with self._lock:
            self._routes.clear()
            self._cursors.clear()
            self._selected = ''
            self._fingerprint = ''

    def _prune(self) -> None:
        now = time.monotonic()
        for code, route in list(self._routes.items()):
            if route.expires_at_monotonic <= now:
                self._routes.pop(code, None)
                self._cursors.pop(code, None)
        while len(self._routes) > self.limit:
            oldest = min(self._routes, key=lambda code: self._routes[code].notification_sequence)
            self._routes.pop(oldest, None)
            self._cursors.pop(oldest, None)

    def arm(self, route: NotificationRoute) -> None:
        with self._lock:
            if self._fingerprint and self._fingerprint != route.config_fingerprint:
                self.reset()
            self._fingerprint = route.config_fingerprint
            self._routes[route.code.upper()] = route
            self._cursors.setdefault(route.code.upper(), NotificationCursor())
            self._prune()

    def recent(self, fingerprint: str) -> list[NotificationRoute]:
        with self._lock:
            self._prune()
            if self._fingerprint != fingerprint:
                return []
            return sorted(self._routes.values(), key=lambda route: route.notification_sequence, reverse=True)

    def resolve(self, fingerprint: str, code: str = '', *, select: bool = False) -> NotificationRoute | None:
        with self._lock:
            routes = self.recent(fingerprint)
            requested = code.strip().upper()
            if requested == 'LATEST':
                route = routes[0] if routes else None
            elif requested:
                route = self._routes.get(requested) if self._fingerprint == fingerprint else None
            elif self._selected:
                # An expired or evicted pinned route deliberately stays invalid.
                route = self._routes.get(self._selected) if self._fingerprint == fingerprint else None
            else:
                route = routes[0] if routes else None
            if route is not None and select:
                self._selected = route.code.upper()
            return route

    def cursor(self, route: NotificationRoute) -> NotificationCursor:
        with self._lock:
            return self._cursors.setdefault(route.code.upper(), NotificationCursor())

    def selected_code(self) -> str:
        with self._lock:
            return self._selected
