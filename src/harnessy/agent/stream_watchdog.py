"""Provider-neutral model-stream liveness tracking.

The watchdog deliberately separates transport liveness from inference
progress.  A TCP/SSE heartbeat proves that a connection still exists, but it
does not prove that a model request is advancing.  Conversely, a long initial
prefill may legitimately be quiet.  The shared policy therefore performs a
read-only health check after a short quiet period and only ends a request when
the backend confirms that the request disappeared or a conservative silence
ceiling is reached.
"""
from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

from harnessy.diagnostics import log_event


STREAM_STALL_SUSPECT_SECONDS = 30.0
STREAM_STALL_INITIAL_SECONDS = 600.0
STREAM_STALL_ACTIVE_SECONDS = 120.0
STREAM_STALL_GONE_CONFIRM_SECONDS = 5.0
STREAM_STALL_PROBE_SECONDS = 30.0
STREAM_STALL_PROBE_TIMEOUT_SECONDS = 5.0

HealthProbe = Callable[[str], Awaitable[dict[str, Any]]]


class StreamStallError(RuntimeError):
    """A model transport stopped making progress and was safely abandoned."""

    terminal_reason = 'backend_stream_stalled'

    def __init__(
        self,
        *,
        backend: str,
        silence_seconds: float,
        phase: str,
        reason: str,
        health: dict[str, Any] | None = None,
    ) -> None:
        self.backend = str(backend or 'model backend')
        self.silence_seconds = max(0.0, float(silence_seconds or 0.0))
        self.phase = str(phase or 'initializing')
        self.reason = str(reason or 'silence_timeout')
        health_map = health if isinstance(health, dict) else {}
        self.health = {
            key: value for key, value in health_map.items()
            if key in {'backend_reachable', 'request_state', 'request_scoped', 'evidence'}
        }
        if self.reason == 'request_disappeared':
            detail = 'the backend twice confirmed that the request was no longer active'
        else:
            detail = f'no inference progress was observed for {self.silence_seconds:.0f} seconds'
        super().__init__(
            f'{self.backend} stream stalled during {self.phase}: {detail}. '
            'HarnessyXO stopped waiting without automatically retrying the generation.'
        )


class StreamProgressWatchdog:
    """Track progress for one model request without assuming a provider API."""

    def __init__(
        self,
        backend: str,
        *,
        suspect_seconds: float = STREAM_STALL_SUSPECT_SECONDS,
        initial_seconds: float = STREAM_STALL_INITIAL_SECONDS,
        active_seconds: float = STREAM_STALL_ACTIVE_SECONDS,
        gone_confirm_seconds: float = STREAM_STALL_GONE_CONFIRM_SECONDS,
        probe_seconds: float = STREAM_STALL_PROBE_SECONDS,
        probe_timeout_seconds: float = STREAM_STALL_PROBE_TIMEOUT_SECONDS,
        clock: Callable[[], float] = time.perf_counter,
    ) -> None:
        self.backend = str(backend or 'model backend')
        self.suspect_seconds = max(0.01, float(suspect_seconds))
        self.initial_seconds = max(self.suspect_seconds, float(initial_seconds))
        self.active_seconds = max(self.suspect_seconds, float(active_seconds))
        self.gone_confirm_seconds = max(0.01, float(gone_confirm_seconds))
        self.probe_seconds = max(0.01, float(probe_seconds))
        self.probe_timeout_seconds = max(0.01, float(probe_timeout_seconds))
        self.clock = clock
        now = self.clock()
        self.started_at = now
        self.last_progress_at = now
        self.last_transport_at = now
        self.next_probe_at = now + self.suspect_seconds
        self.suspected_at: float | None = None
        self.missing_confirmed_at: float | None = None
        self.saw_output = False
        self.request_id = ''
        self.last_runtime_signature: tuple[Any, ...] | None = None
        self.last_health: dict[str, Any] = {}

    @property
    def phase(self) -> str:
        return 'generation' if self.saw_output else 'initial prefill / model startup'

    def silence_seconds(self, now: float | None = None) -> float:
        observed = self.clock() if now is None else float(now)
        return max(0.0, observed - self.last_progress_at)

    def hard_silence_seconds(self) -> float:
        return self.active_seconds if self.saw_output else self.initial_seconds

    def seconds_until_check(self) -> float:
        now = self.clock()
        hard_at = self.last_progress_at + self.hard_silence_seconds()
        due_at = min(hard_at, self.next_probe_at)
        return max(0.01, due_at - now)

    def observe_transport(self) -> None:
        self.last_transport_at = self.clock()

    @staticmethod
    def _payload_has_output(value: Any) -> bool:
        if not isinstance(value, dict):
            return False
        message = value.get('message') if isinstance(value.get('message'), dict) else {}
        if any(message.get(key) for key in ('content', 'thinking', 'reasoning', 'reasoning_content', 'tool_calls')):
            return True
        choices = value.get('choices') if isinstance(value.get('choices'), list) else []
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            delta = choice.get('delta') if isinstance(choice.get('delta'), dict) else {}
            snapshot = choice.get('message') if isinstance(choice.get('message'), dict) else {}
            if any(delta.get(key) for key in ('content', 'thinking', 'reasoning', 'reasoning_content', 'tool_calls')):
                return True
            if any(snapshot.get(key) for key in ('content', 'thinking', 'reasoning', 'reasoning_content', 'tool_calls')):
                return True
        return False

    @classmethod
    def _payload_is_progress(cls, value: Any) -> tuple[bool, bool]:
        """Return ``(progress, emitted_output)`` for a protocol object."""
        if not isinstance(value, dict):
            return False, False
        output = cls._payload_has_output(value)
        if output:
            return True, True
        usage = value.get('usage')
        if isinstance(usage, dict) and any(
            isinstance(item, (int, float)) and not isinstance(item, bool)
            for item in usage.values()
        ):
            return True, False
        if value.get('done') is True:
            return True, False
        if any(value.get(key) is not None for key in ('prompt_eval_count', 'eval_count')):
            return True, False
        choices = value.get('choices') if isinstance(value.get('choices'), list) else []
        if any(isinstance(choice, dict) and choice.get('finish_reason') for choice in choices):
            return True, False
        return False, False

    @staticmethod
    def _counter(value: Any) -> int:
        try:
            return max(0, int(float(value or 0)))
        except (TypeError, ValueError, OverflowError):
            return 0

    def _mark_progress(self, *, output: bool = False) -> dict[str, Any] | None:
        now = self.clock()
        quiet = max(0.0, now - self.last_progress_at)
        recovered = self.suspected_at is not None
        self.last_progress_at = now
        self.next_probe_at = now + self.suspect_seconds
        self.missing_confirmed_at = None
        if output:
            self.saw_output = True
        if not recovered:
            return None
        self.suspected_at = None
        return {
            'status': 'recovered',
            'backend': self.backend,
            'phase': self.phase,
            'quiet_seconds': quiet,
        }

    def observe(self, kind: str, value: Any) -> dict[str, Any] | None:
        """Observe one sanitized queue item and report a recovery if applicable."""
        event_kind = str(kind or '')
        if event_kind in {'accepted', 'transport', 'data', 'json', 'message', 'runtime_status', 'log_status'}:
            self.observe_transport()
        if event_kind in {'data', 'json', 'message'}:
            progress, output = self._payload_is_progress(value)
            # Empty JSON/SSE chunks remain transport activity only. They do not
            # extend an inference deadline unless they carry output, usage,
            # completion, or another monotonic request counter.
            return self._mark_progress(output=output) if progress else None
        if event_kind not in {'runtime_status', 'log_status'} or not isinstance(value, dict):
            return None

        request_id = str(value.get('request_id') or '')
        if request_id:
            self.request_id = request_id
        generated = self._counter(value.get('generated'))
        signature = (
            str(value.get('phase') or ''),
            self._counter(value.get('processed')),
            self._counter(value.get('total')),
            generated,
            self._counter(value.get('context_used')),
        )
        if signature == self.last_runtime_signature:
            return None
        self.last_runtime_signature = signature
        # A first status containing no request counters is reachability
        # telemetry, not proof that inference advanced.
        if not any(signature[1:]) and signature[0] not in {'prompt_processing', 'prefill', 'generating'}:
            return None
        return self._mark_progress(output=generated > 0)

    async def check(
        self,
        probe: HealthProbe,
        *,
        has_pending: Callable[[], bool] | None = None,
    ) -> dict[str, Any] | None:
        """Run a due read-only health probe or raise on a confirmed stall."""
        now = self.clock()
        quiet = self.silence_seconds(now)
        pending = bool(has_pending and has_pending())
        if quiet >= self.hard_silence_seconds() and not pending:
            raise StreamStallError(
                backend=self.backend,
                silence_seconds=quiet,
                phase=self.phase,
                reason='silence_timeout',
                health=self.last_health,
            )
        if quiet < self.suspect_seconds or now < self.next_probe_at:
            return None

        try:
            health = await asyncio.wait_for(
                probe(self.request_id), timeout=self.probe_timeout_seconds,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            health = {
                'backend_reachable': False,
                'request_state': 'unknown',
                'request_scoped': False,
                'evidence': 'health_probe_failed',
            }
        health_map = health if isinstance(health, dict) else {}
        self.last_health = {
            key: value for key, value in health_map.items()
            if key in {'backend_reachable', 'request_state', 'request_scoped', 'evidence'}
        }
        request_state = str(self.last_health.get('request_state') or 'unknown')
        request_scoped = self.last_health.get('request_scoped') is True
        now = self.clock()
        log_event(
            'backend', 'stream_health_checked', backend=self.backend, phase=self.phase,
            watchdog_request_state=request_state,
            watchdog_evidence=self.last_health.get('evidence'),
            request_scoped=request_scoped, request_id_seen=bool(self.request_id),
            backend_reachable=self.last_health.get('backend_reachable'),
            silence_seconds=self.silence_seconds(now),
            transport_silence_seconds=max(0.0, now - self.last_transport_at),
            generated_output_seen=self.saw_output,
        )
        if request_state == 'gone' and request_scoped:
            if self.missing_confirmed_at is None:
                self.missing_confirmed_at = now
            elif now - self.missing_confirmed_at >= self.gone_confirm_seconds and not (has_pending and has_pending()):
                raise StreamStallError(
                    backend=self.backend,
                    silence_seconds=self.silence_seconds(now),
                    phase=self.phase,
                    reason='request_disappeared',
                    health=self.last_health,
                )
            self.next_probe_at = now + self.gone_confirm_seconds
        else:
            self.missing_confirmed_at = None
            self.next_probe_at = now + self.probe_seconds

        if self.suspected_at is not None:
            return None
        self.suspected_at = now
        return {
            'status': 'suspected',
            'backend': self.backend,
            'phase': self.phase,
            'quiet_seconds': quiet,
            'health': dict(self.last_health),
        }


async def watched_queue(
    queue: asyncio.Queue[tuple[str, Any]],
    watchdog: StreamProgressWatchdog,
    probe: HealthProbe,
) -> AsyncIterator[tuple[str, Any]]:
    """Yield queue items plus transient watchdog notices until the caller ends."""
    while True:
        try:
            kind, value = await asyncio.wait_for(
                queue.get(), timeout=watchdog.seconds_until_check(),
            )
        except TimeoutError:
            notice = await watchdog.check(probe, has_pending=lambda: not queue.empty())
            if notice:
                yield 'watchdog', notice
            continue

        # Preserve the backend's real completion/error when it arrives exactly
        # on a watchdog boundary; terminal transport evidence outranks an
        # inferred silence timeout.
        if (kind in {'error', 'done'}
                or (kind in {'data', 'json', 'message'}
                    and isinstance(value, dict) and value.get('error'))):
            yield kind, value
            continue
        recovered = watchdog.observe(kind, value)
        if recovered:
            yield 'watchdog', recovered
        notice = await watchdog.check(probe, has_pending=lambda: not queue.empty())
        if notice:
            yield 'watchdog', notice
        yield kind, value
