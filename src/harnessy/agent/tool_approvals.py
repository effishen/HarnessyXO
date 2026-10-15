"""Run-owned, one-use tool approvals independent of transient browser views.

All methods are called on the application's asyncio event loop. The UI is
responsible for authenticating its user before calling ``decide``; this broker
then checks the exact request and run identity. Browser disconnection never
approves or denies a tool. Stopping the owning run cancels its pending request.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Mapping


@dataclass(frozen=True, slots=True)
class ToolApprovalSnapshot:
    request_id: str
    workspace_id: str
    chat_id: str
    run_id: str
    request: dict[str, Any]
    created_at: float


@dataclass(slots=True)
class _PendingApproval:
    snapshot: ToolApprovalSnapshot
    decision: asyncio.Future[bool]
    owner_task: asyncio.Task[Any]
    waiter_task: asyncio.Task[Any]


def _json_copy(value: Mapping[str, Any]) -> dict[str, Any]:
    """Keep neither caller-owned nested values nor non-JSON live objects."""
    copied = json.loads(json.dumps(dict(value), allow_nan=False))
    if not isinstance(copied, dict):  # Defensive: snapshots always have an object.
        raise ValueError('A tool approval request must be a JSON object.')
    return copied


def _task_stopping(task: asyncio.Task[Any]) -> bool:
    # Task.cancelling is unavailable on supported Python 3.10 installations.
    cancelling = getattr(task, 'cancelling', None)
    return task.done() or bool(cancelling and cancelling())


class ToolApprovalBroker:
    """Wait for a decision or an explicit change to the saved tool policy."""

    def __init__(self) -> None:
        self._pending: dict[str, _PendingApproval] = {}

    @staticmethod
    def _identity(workspace_id: str, chat_id: str, run_id: str) -> tuple[str, str, str]:
        values = (workspace_id, chat_id, run_id)
        if any(not isinstance(value, str) or not value.strip() for value in values):
            raise ValueError('Tool approval requires workspace, chat and run identities.')
        return values

    @staticmethod
    def _live(entry: _PendingApproval) -> bool:
        return (
            not entry.decision.done()
            and not _task_stopping(entry.owner_task)
            and not _task_stopping(entry.waiter_task)
        )

    def _discard_stale(self) -> None:
        for request_id, entry in tuple(self._pending.items()):
            if not self._live(entry):
                self._pending.pop(request_id, None)
                if not entry.decision.done():
                    entry.decision.cancel()

    async def request(
        self,
        *,
        workspace_id: str,
        chat_id: str,
        run_id: str,
        request: Mapping[str, Any],
        owner_task: asyncio.Task[Any] | None = None,
        live_policy_decision: Callable[[], bool | None] | None = None,
    ) -> bool:
        """Register one tool call and suspend it until allowed, denied or stopped."""
        self._identity(workspace_id, chat_id, run_id)
        loop = asyncio.get_running_loop()
        waiter = asyncio.current_task()
        if waiter is None:
            raise RuntimeError('Tool approval must be requested by an asyncio task.')
        owner = owner_task if owner_task is not None else waiter
        if owner.get_loop() is not loop:
            raise ValueError('Tool approval owner must use the application event loop.')
        if _task_stopping(owner) or _task_stopping(waiter):
            raise asyncio.CancelledError
        if not isinstance(request, Mapping):
            raise ValueError('A tool approval request must be a JSON object.')
        snapshot = ToolApprovalSnapshot(
            request_id=str(uuid.uuid4()),
            workspace_id=workspace_id,
            chat_id=chat_id,
            run_id=run_id,
            request=_json_copy(request),
            created_at=time.time(),
        )
        decision: asyncio.Future[bool] = loop.create_future()
        entry = _PendingApproval(snapshot, decision, owner, waiter)

        def owner_finished(_task: asyncio.Task[Any]) -> None:
            self._pending.pop(snapshot.request_id, None)
            if not decision.done():
                decision.cancel()

        self._discard_stale()
        self._pending[snapshot.request_id] = entry
        owner.add_done_callback(owner_finished)
        try:
            if live_policy_decision is None:
                return await decision
            while not decision.done():
                # A completed explicit decision always wins. The policy check
                # and decide are synchronous on the owning event loop.
                policy_decision = live_policy_decision()
                if policy_decision is not None:
                    self.decide(
                        snapshot.request_id, workspace_id=workspace_id,
                        chat_id=chat_id, run_id=run_id, allow=policy_decision,
                    )
                    break
                await asyncio.wait({decision}, timeout=0.25)
            return await decision
        finally:
            self._pending.pop(snapshot.request_id, None)
            owner.remove_done_callback(owner_finished)
            if not decision.done():
                decision.cancel()

    def pending(
        self,
        *,
        workspace_id: str | None = None,
        chat_id: str | None = None,
        run_id: str | None = None,
    ) -> tuple[ToolApprovalSnapshot, ...]:
        """Return fresh display snapshots, never the decision Future or tasks."""
        self._discard_stale()
        snapshots = []
        for entry in self._pending.values():
            snapshot = entry.snapshot
            if workspace_id is not None and snapshot.workspace_id != workspace_id:
                continue
            if chat_id is not None and snapshot.chat_id != chat_id:
                continue
            if run_id is not None and snapshot.run_id != run_id:
                continue
            snapshots.append(ToolApprovalSnapshot(
                request_id=snapshot.request_id,
                workspace_id=snapshot.workspace_id,
                chat_id=snapshot.chat_id,
                run_id=snapshot.run_id,
                request=_json_copy(snapshot.request),
                created_at=snapshot.created_at,
            ))
        return tuple(snapshots)

    def decide(
        self,
        request_id: str,
        *,
        workspace_id: str,
        chat_id: str,
        run_id: str,
        allow: bool,
    ) -> bool:
        """Apply an exact, still-pending decision once; return whether it applied.

        There is no await between matching, removal and setting the decision,
        so two clicks or browser sessions cannot both consume the same request.
        """
        if not isinstance(allow, bool):
            return False
        self._discard_stale()
        entry = self._pending.get(request_id)
        if entry is None:
            return False
        snapshot = entry.snapshot
        if (workspace_id, chat_id, run_id) != (
            snapshot.workspace_id, snapshot.chat_id, snapshot.run_id,
        ):
            return False
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return False
        if entry.decision.get_loop() is not loop:
            return False
        self._pending.pop(request_id)
        entry.decision.set_result(allow)
        return True

    def cancel_run(self, *, workspace_id: str, chat_id: str, run_id: str) -> int:
        """Synchronously invalidate a stopped run before cancelling its task.

        This also closes the Python 3.10 cancellation-forwarding gap when the
        approval waiter is a child task rather than the run's owning task.
        Cancelling a request raises CancelledError; it never means user denial.
        """
        self._identity(workspace_id, chat_id, run_id)
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return 0
        cancelled = 0
        for request_id, entry in tuple(self._pending.items()):
            snapshot = entry.snapshot
            if (snapshot.workspace_id, snapshot.chat_id, snapshot.run_id) != (
                workspace_id, chat_id, run_id,
            ) or entry.decision.get_loop() is not loop:
                continue
            self._pending.pop(request_id, None)
            if not entry.decision.done():
                entry.decision.cancel()
                cancelled += 1
        return cancelled


TOOL_APPROVALS = ToolApprovalBroker()
