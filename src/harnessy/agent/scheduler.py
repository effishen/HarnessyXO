from __future__ import annotations

import asyncio
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, AsyncIterator, Awaitable, Callable

WaitCallback = Callable[[dict[str, Any]], Awaitable[None]]


@dataclass(slots=True)
class GenerationLease:
    request_id: str
    label: str


class ModelGenerationScheduler:
    """Process-wide FIFO scheduler for expensive model inference.

    HarnessyXO agents remain independent and can overlap tool/VM work, but model
    generations are admitted through this small coordinator so several chats do
    not accidentally allocate several huge KV caches at once.  The limit is a
    runtime setting and defaults to one.
    """

    def __init__(self) -> None:
        self._condition = asyncio.Condition()
        self._queue: list[tuple[str, str]] = []
        self._active: dict[str, str] = {}
        self._limit = 1

    @staticmethod
    def _normalize_limit(value: Any) -> int:
        try:
            return max(1, min(int(value or 1), 32))
        except (TypeError, ValueError):
            return 1

    def snapshot(self) -> dict[str, Any]:
        return {
            'limit': self._limit,
            'active': list(self._active.values()),
            'queued': [label for _request_id, label in self._queue],
        }

    async def acquire(
        self,
        *,
        limit: int,
        label: str,
        on_wait: WaitCallback | None = None,
    ) -> GenerationLease:
        request_id = uuid.uuid4().hex
        label = str(label or 'another chat')
        normalized = self._normalize_limit(limit)
        async with self._condition:
            self._limit = normalized
            self._queue.append((request_id, label))
            self._condition.notify_all()

        last_wait_signature: tuple[str, ...] | None = None
        try:
            while True:
                wait_payload: dict[str, Any] | None = None
                async with self._condition:
                    self._limit = normalized
                    first = bool(self._queue and self._queue[0][0] == request_id)
                    if first and len(self._active) < self._limit:
                        self._queue.pop(0)
                        self._active[request_id] = label
                        self._condition.notify_all()
                        return GenerationLease(request_id=request_id, label=label)
                    active_labels = tuple(self._active.values())
                    signature = active_labels
                    if on_wait is not None and signature != last_wait_signature:
                        wait_payload = {
                            'limit': self._limit,
                            'active': list(active_labels),
                            'owner': active_labels[0] if active_labels else '',
                            'position': next((i + 1 for i, row in enumerate(self._queue) if row[0] == request_id), 0),
                        }
                        last_wait_signature = signature
                if wait_payload is not None:
                    await on_wait(wait_payload)
                async with self._condition:
                    try:
                        await asyncio.wait_for(self._condition.wait(), timeout=0.75)
                    except asyncio.TimeoutError:
                        pass
        except BaseException:
            async with self._condition:
                self._queue = [row for row in self._queue if row[0] != request_id]
                self._active.pop(request_id, None)
                self._condition.notify_all()
            raise

    async def release(self, lease: GenerationLease) -> None:
        async with self._condition:
            self._active.pop(lease.request_id, None)
            self._condition.notify_all()

    @asynccontextmanager
    async def slot(
        self,
        *,
        limit: int,
        label: str,
        on_wait: WaitCallback | None = None,
    ) -> AsyncIterator[GenerationLease]:
        lease = await self.acquire(limit=limit, label=label, on_wait=on_wait)
        try:
            yield lease
        finally:
            await self.release(lease)


MODEL_GENERATION_SCHEDULER = ModelGenerationScheduler()


@dataclass(slots=True)
class RunLaneLease:
    request_id: str
    lane: int
    label: str
    owner_key: str


class AgentRunLaneScheduler:
    """Hold one lane for an entire autonomous agent run.

    ``ModelGenerationScheduler`` deliberately releases capacity between model
    calls so agents may overlap Tool/VM work.  Overnight jobs need a stronger
    promise: within a lane, the next Project/Chat must not begin until the
    previous AgentRunner has completely unwound.  This process-wide scheduler
    supplies that full-run boundary while still allowing explicitly configured
    parallel lanes.
    """

    def __init__(self) -> None:
        self._condition = asyncio.Condition()
        self._queues: dict[int, list[tuple[str, str, str]]] = {}
        self._active: dict[int, RunLaneLease] = {}
        self._limit = 1

    @staticmethod
    def _normalize_limit(value: Any) -> int:
        try:
            return max(1, min(int(value or 1), 8))
        except (TypeError, ValueError):
            return 1

    def _lane_load(self, lane: int) -> int:
        return (1 if lane in self._active else 0) + len(self._queues.get(lane, []))

    def lane_for_owner(self, owner_key: str) -> int | None:
        owner_key = str(owner_key or '')
        if not owner_key:
            return None
        for lane, lease in self._active.items():
            if lease.owner_key == owner_key:
                return lane
        for lane, rows in self._queues.items():
            if any(row[2] == owner_key for row in rows):
                return lane
        return None

    def recommend_lane(self, *, limit: int, owner_key: str = '') -> dict[str, Any]:
        normalized = self._normalize_limit(limit)
        self._limit = normalized
        existing = self.lane_for_owner(owner_key)
        if existing is not None and existing <= normalized:
            lane = existing
            reason = 'same_chat'
        else:
            lane = min(range(1, normalized + 1), key=lambda value: (self._lane_load(value), value))
            reason = 'free_parallel' if self._lane_load(lane) == 0 and normalized > 1 else 'shortest'
        return {
            'lane': lane,
            'limit': normalized,
            'load': self._lane_load(lane),
            'reason': reason,
            'parallel_free': [value for value in range(1, normalized + 1) if self._lane_load(value) == 0],
        }

    def snapshot(self) -> dict[str, Any]:
        lanes = []
        for lane in range(1, self._limit + 1):
            active = self._active.get(lane)
            lanes.append({
                'lane': lane,
                'active': ({
                    'request_id': active.request_id,
                    'label': active.label,
                    'owner_key': active.owner_key,
                } if active else None),
                'queued': [
                    {'request_id': request_id, 'label': label, 'owner_key': owner_key}
                    for request_id, label, owner_key in self._queues.get(lane, [])
                ],
            })
        return {'limit': self._limit, 'lanes': lanes}

    async def acquire(
        self,
        *,
        limit: int,
        label: str,
        owner_key: str = '',
        preferred_lane: int | None = None,
        on_wait: WaitCallback | None = None,
    ) -> RunLaneLease:
        request_id = uuid.uuid4().hex
        normalized = self._normalize_limit(limit)
        clean_owner = str(owner_key or '')
        async with self._condition:
            self._limit = normalized
            existing = self.lane_for_owner(clean_owner)
            if existing is not None and existing <= normalized:
                lane = existing
            elif preferred_lane is not None:
                lane = max(1, min(int(preferred_lane), normalized))
            else:
                lane = min(range(1, normalized + 1), key=lambda value: (self._lane_load(value), value))
            queue = self._queues.setdefault(lane, [])
            queue.append((request_id, str(label or 'another Project / Chat'), clean_owner))
            self._condition.notify_all()

        last_signature: tuple[Any, ...] | None = None
        try:
            while True:
                wait_payload: dict[str, Any] | None = None
                async with self._condition:
                    queue = self._queues.setdefault(lane, [])
                    first = bool(queue and queue[0][0] == request_id)
                    active = self._active.get(lane)
                    if first and active is None:
                        queue.pop(0)
                        if not queue:
                            self._queues.pop(lane, None)
                        lease = RunLaneLease(request_id, lane, str(label or ''), clean_owner)
                        self._active[lane] = lease
                        self._condition.notify_all()
                        return lease
                    position = next((i + 1 for i, row in enumerate(queue) if row[0] == request_id), 0)
                    signature = (active.request_id if active else '', position)
                    if on_wait is not None and signature != last_signature:
                        wait_payload = {
                            'lane': lane,
                            'limit': normalized,
                            'owner': active.label if active else '',
                            'owner_key': active.owner_key if active else '',
                            'position': position,
                        }
                        last_signature = signature
                if wait_payload is not None:
                    await on_wait(wait_payload)
                async with self._condition:
                    try:
                        await asyncio.wait_for(self._condition.wait(), timeout=0.75)
                    except asyncio.TimeoutError:
                        pass
        except BaseException:
            async with self._condition:
                queue = self._queues.get(lane, [])
                self._queues[lane] = [row for row in queue if row[0] != request_id]
                if not self._queues[lane]:
                    self._queues.pop(lane, None)
                self._condition.notify_all()
            raise

    async def release(self, lease: RunLaneLease) -> None:
        async with self._condition:
            active = self._active.get(int(lease.lane))
            if active is not None and active.request_id == lease.request_id:
                self._active.pop(int(lease.lane), None)
                self._condition.notify_all()

    @asynccontextmanager
    async def slot(
        self,
        *,
        limit: int,
        label: str,
        owner_key: str = '',
        preferred_lane: int | None = None,
        on_wait: WaitCallback | None = None,
    ) -> AsyncIterator[RunLaneLease]:
        lease = await self.acquire(
            limit=limit,
            label=label,
            owner_key=owner_key,
            preferred_lane=preferred_lane,
            on_wait=on_wait,
        )
        try:
            yield lease
        finally:
            await self.release(lease)


AGENT_RUN_LANES = AgentRunLaneScheduler()


@dataclass(slots=True)
class WorkspaceMutationLease:
    workspace_id: str
    owner_id: str
    label: str


class WorkspaceMutationCoordinator:
    """One sticky workspace writer per agent run.

    Read-only tools never acquire this lease. The first mutating filesystem,
    shell/process, Git-write, or workspace-memory tool in an agent run acquires
    ownership and that runner keeps it until the run ends. This prevents two
    independent chats from unknowingly interleaving writes to one working tree.
    """

    def __init__(self) -> None:
        self._condition = asyncio.Condition()
        self._owners: dict[str, WorkspaceMutationLease] = {}
        self._queues: dict[str, list[tuple[str, str]]] = {}

    def owner(self, workspace_id: str) -> WorkspaceMutationLease | None:
        return self._owners.get(str(workspace_id))

    async def acquire(
        self,
        *,
        workspace_id: str,
        owner_id: str,
        label: str,
        on_wait: WaitCallback | None = None,
    ) -> WorkspaceMutationLease:
        workspace_id = str(workspace_id)
        owner_id = str(owner_id)
        label = str(label or owner_id)
        queued = False
        last_owner = None
        try:
            while True:
                wait_payload = None
                async with self._condition:
                    current = self._owners.get(workspace_id)
                    if current is not None and current.owner_id == owner_id:
                        return current
                    queue = self._queues.setdefault(workspace_id, [])
                    if not queued:
                        queue.append((owner_id, label))
                        queued = True
                    first = bool(queue and queue[0][0] == owner_id)
                    if current is None and first:
                        queue.pop(0)
                        if not queue:
                            self._queues.pop(workspace_id, None)
                        lease = WorkspaceMutationLease(workspace_id, owner_id, label)
                        self._owners[workspace_id] = lease
                        self._condition.notify_all()
                        return lease
                    current_label = current.label if current is not None else ''
                    if on_wait is not None and current_label != last_owner:
                        wait_payload = {
                            'workspace_id': workspace_id,
                            'owner': current_label,
                            'position': next((i + 1 for i, row in enumerate(queue) if row[0] == owner_id), 0),
                        }
                        last_owner = current_label
                if wait_payload is not None:
                    await on_wait(wait_payload)
                async with self._condition:
                    try:
                        await asyncio.wait_for(self._condition.wait(), timeout=0.75)
                    except asyncio.TimeoutError:
                        pass
        except BaseException:
            async with self._condition:
                queue = self._queues.get(workspace_id, [])
                self._queues[workspace_id] = [row for row in queue if row[0] != owner_id]
                if not self._queues[workspace_id]:
                    self._queues.pop(workspace_id, None)
                self._condition.notify_all()
            raise

    async def release(self, *, workspace_id: str, owner_id: str) -> None:
        async with self._condition:
            current = self._owners.get(str(workspace_id))
            if current is not None and current.owner_id == str(owner_id):
                self._owners.pop(str(workspace_id), None)
                self._condition.notify_all()


WORKSPACE_MUTATIONS = WorkspaceMutationCoordinator()


# ---------------------------------------------------------------------------
# v0.6 unified admission control
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class GlobalAgentLease:
    request_id: str
    slot: int
    label: str
    owner_key: str
    workspace_id: str
    project_chat_id: str
    conflict_keys: frozenset[str]
    kind: str = 'coordinator'
    parent_request_id: str = ''

    @property
    def lane(self) -> int:
        """Temporary compatibility alias for pre-v0.6 UI call sites."""
        return self.slot


@dataclass(slots=True)
class _GlobalAgentRequest:
    request_id: str
    label: str
    owner_key: str
    workspace_id: str
    project_chat_id: str
    conflict_keys: frozenset[str]
    kind: str
    parent_request_id: str
    preferred_slot: int = 0


class GlobalAgentSlotScheduler:
    """One process-wide pool for coordinators and temporary subagents.

    Requests which are blocked by an active ancestor/descendant do not occupy
    a slot and do not prevent an unrelated queued project from using capacity.
    """

    def __init__(self) -> None:
        self._condition = asyncio.Condition()
        self._queue: list[_GlobalAgentRequest] = []
        self._active: dict[str, GlobalAgentLease] = {}
        self._limit = 1

    @staticmethod
    def _normalize_limit(value: Any) -> int:
        try:
            return max(1, min(int(value or 1), 32))
        except (TypeError, ValueError):
            return 1

    @staticmethod
    def _keys(owner_key: str, project_chat_id: str, values: Any) -> frozenset[str]:
        clean = frozenset(str(value) for value in (values or ()) if str(value))
        if clean:
            return clean
        fallback = str(project_chat_id or owner_key or uuid.uuid4().hex)
        return frozenset((fallback,))

    def _conflicts_with_active(self, request: _GlobalAgentRequest) -> list[GlobalAgentLease]:
        blocked: list[GlobalAgentLease] = []
        for lease in self._active.values():
            # Delegated read-only workers belong to one top-level run. They may
            # overlap their own coordinator/siblings when capacity permits;
            # dependency exclusion is for other top-level project runs.
            if request.parent_request_id and (
                lease.request_id == request.parent_request_id
                or lease.parent_request_id == request.parent_request_id
            ):
                continue
            if request.workspace_id and lease.workspace_id and request.workspace_id != lease.workspace_id:
                continue
            if request.conflict_keys & lease.conflict_keys:
                blocked.append(lease)
        return blocked

    def _admissible(self, request: _GlobalAgentRequest) -> bool:
        return (len(self._active) < self._limit
                and bool(self._free_slot(request.preferred_slot))
                and not self._conflicts_with_active(request))

    def _first_admissible_id(self) -> str:
        if len(self._active) >= self._limit:
            return ''
        # Finish work belonging to an admitted run before starting another
        # queued coordinator. Already-running jobs are never pre-empted.
        ordered = [row for row in self._queue if row.kind == 'subagent'] + [
            row for row in self._queue if row.kind != 'subagent'
        ]
        for request in ordered:
            if self._admissible(request):
                return request.request_id
        return ''

    def _free_slot(self, preferred_slot: int = 0) -> int:
        occupied = {lease.slot for lease in self._active.values()}
        if 1 <= preferred_slot <= self._limit:
            return preferred_slot if preferred_slot not in occupied else 0
        return next((value for value in range(1, self._limit + 1) if value not in occupied), 0)

    async def set_limit(self, limit: int) -> None:
        """Apply a changed global ceiling to waiters as well as future runs."""
        normalized = self._normalize_limit(limit)
        async with self._condition:
            if self._limit != normalized:
                self._limit = normalized
                self._condition.notify_all()

    def lane_for_owner(self, owner_key: str) -> int | None:
        owner = str(owner_key or '')
        for lease in self._active.values():
            if lease.owner_key == owner:
                return lease.slot
        return None

    def recommend_lane(self, *, limit: int, owner_key: str = '') -> dict[str, Any]:
        self._limit = self._normalize_limit(limit)
        existing = self.lane_for_owner(owner_key)
        slot = existing or self._free_slot() or 1
        return {
            'lane': slot, 'slot': slot, 'limit': self._limit,
            'load': len(self._queue) + len(self._active),
            'reason': 'same_chat' if existing else ('free_parallel' if self._free_slot() else 'global_queue'),
            'parallel_free': [
                value for value in range(1, self._limit + 1)
                if value not in {lease.slot for lease in self._active.values()}
            ],
        }

    def snapshot(self) -> dict[str, Any]:
        active = [
            {
                'request_id': lease.request_id, 'slot': lease.slot, 'lane': lease.slot,
                'label': lease.label, 'owner_key': lease.owner_key,
                'workspace_id': lease.workspace_id, 'project_chat_id': lease.project_chat_id,
                'kind': lease.kind, 'parent_request_id': lease.parent_request_id,
            }
            for lease in sorted(self._active.values(), key=lambda value: value.slot)
        ]
        queued = [
            {
                'request_id': request.request_id, 'label': request.label,
                'owner_key': request.owner_key, 'workspace_id': request.workspace_id,
                'project_chat_id': request.project_chat_id, 'kind': request.kind,
                'position': index, 'preferred_slot': request.preferred_slot,
            }
            for index, request in enumerate(self._queue, start=1)
        ]
        # ``lanes`` keeps old read-only diagnostics functional while all queue
        # placement is now global rather than assigned to persistent lanes.
        lanes = []
        for slot in range(1, self._limit + 1):
            current = next((row for row in active if row['slot'] == slot), None)
            lanes.append({'lane': slot, 'active': current, 'queued': []})
        return {
            'limit': self._limit, 'active_count': len(active),
            'available': max(0, self._limit - len(active)),
            'active': active, 'queued': queued, 'lanes': lanes,
        }

    async def acquire(
        self, *, limit: int, label: str, owner_key: str = '',
        preferred_lane: int | None = None, on_wait: WaitCallback | None = None,
        workspace_id: str = '', project_chat_id: str = '', conflict_keys: Any = (),
        kind: str = 'coordinator', parent_request_id: str = '',
    ) -> GlobalAgentLease:
        preferred_slot = max(0, int(preferred_lane or 0))
        request = _GlobalAgentRequest(
            request_id=uuid.uuid4().hex, label=str(label or 'another Project / Chat'),
            owner_key=str(owner_key or ''), workspace_id=str(workspace_id or ''),
            project_chat_id=str(project_chat_id or ''),
            conflict_keys=self._keys(owner_key, project_chat_id, conflict_keys),
            kind=str(kind or 'coordinator'), parent_request_id=str(parent_request_id or ''),
            preferred_slot=preferred_slot,
        )
        normalized = self._normalize_limit(limit)
        async with self._condition:
            self._limit = normalized
            self._queue.append(request)
            self._condition.notify_all()
        last_signature: tuple[Any, ...] | None = None
        try:
            while True:
                wait_payload: dict[str, Any] | None = None
                async with self._condition:
                    if self._first_admissible_id() == request.request_id:
                        slot = self._free_slot(request.preferred_slot)
                        if slot:
                            self._queue = [row for row in self._queue if row.request_id != request.request_id]
                            lease = GlobalAgentLease(
                                request.request_id, slot, request.label, request.owner_key,
                                request.workspace_id, request.project_chat_id,
                                request.conflict_keys, request.kind, request.parent_request_id,
                            )
                            self._active[lease.request_id] = lease
                            self._condition.notify_all()
                            return lease
                    blockers = self._conflicts_with_active(request)
                    position = next(
                        (index for index, row in enumerate(self._queue, start=1)
                         if row.request_id == request.request_id), 0,
                    )
                    reason = ('related_project' if blockers else
                              'preferred_slot' if request.preferred_slot and not self._free_slot(request.preferred_slot)
                              else 'capacity')
                    signature = (reason, tuple(row.request_id for row in blockers), position,
                                 len(self._active), request.preferred_slot)
                    if on_wait is not None and signature != last_signature:
                        wait_payload = {
                            'limit': self._limit, 'position': position, 'reason': reason,
                            'owner': blockers[0].label if blockers else (
                                next((lease.label for lease in self._active.values()
                                      if lease.slot == request.preferred_slot), '')
                                if reason == 'preferred_slot' else
                                next(iter(self._active.values())).label if self._active else ''
                            ),
                            'active': [lease.label for lease in self._active.values()],
                            'lane': request.preferred_slot, 'slot': request.preferred_slot,
                        }
                        last_signature = signature
                if wait_payload is not None:
                    await on_wait(wait_payload)
                async with self._condition:
                    try:
                        await asyncio.wait_for(self._condition.wait(), timeout=0.75)
                    except asyncio.TimeoutError:
                        pass
        except BaseException:
            async with self._condition:
                self._queue = [row for row in self._queue if row.request_id != request.request_id]
                self._active.pop(request.request_id, None)
                self._condition.notify_all()
            raise

    async def release(self, lease: GlobalAgentLease) -> None:
        async with self._condition:
            self._active.pop(lease.request_id, None)
            self._condition.notify_all()

    @asynccontextmanager
    async def subagent_slot(
        self, *, parent: GlobalAgentLease, limit: int, label: str,
        on_wait: WaitCallback | None = None,
    ) -> AsyncIterator[GlobalAgentLease]:
        """Admit one ephemeral worker owned by an active coordinator.

        At a one-slot ceiling ownership is transferred atomically and restored
        before unrelated queued work can enter. With more capacity the
        coordinator retains its slot and delegated work gets queue priority.
        """
        normalized = self._normalize_limit(limit)
        if normalized == 1:
            async with self._condition:
                current = self._active.get(parent.request_id)
                if current is None:
                    raise RuntimeError('The coordinator no longer owns its Global Agent Slot')
                self._limit = 1
                self._active.pop(parent.request_id, None)
                worker = GlobalAgentLease(
                    uuid.uuid4().hex, current.slot, str(label or 'temporary subagent'),
                    current.owner_key, current.workspace_id, current.project_chat_id,
                    current.conflict_keys, 'subagent', current.request_id,
                )
                self._active[worker.request_id] = worker
                self._condition.notify_all()
            try:
                yield worker
            finally:
                async with self._condition:
                    self._active.pop(worker.request_id, None)
                    self._active[parent.request_id] = parent
                    self._condition.notify_all()
            return

        worker = await self.acquire(
            limit=normalized, label=label, owner_key=parent.owner_key,
            workspace_id=parent.workspace_id,
            project_chat_id=parent.project_chat_id,
            conflict_keys=parent.conflict_keys, kind='subagent',
            parent_request_id=parent.request_id, on_wait=on_wait,
        )
        try:
            yield worker
        finally:
            await self.release(worker)

    @asynccontextmanager
    async def slot(self, **kwargs: Any) -> AsyncIterator[GlobalAgentLease]:
        lease = await self.acquire(**kwargs)
        try:
            yield lease
        finally:
            await self.release(lease)


GLOBAL_AGENT_SLOTS = GlobalAgentSlotScheduler()
# Compatibility import name; semantics are the v0.6 global pool.
AGENT_RUN_LANES = GLOBAL_AGENT_SLOTS


@dataclass(slots=True)
class ProjectMutationLease:
    workspace_id: str
    owner_id: str
    label: str
    conflict_keys: frozenset[str]
    project_chat_id: str = ''
    phase: str = ''


class ProjectMutationCoordinator:
    """Allow unrelated project writers while serializing dependency families."""

    def __init__(self) -> None:
        self._condition = asyncio.Condition()
        self._owners: dict[str, dict[str, ProjectMutationLease]] = {}
        self._queues: dict[str, list[tuple[str, str, frozenset[str]]]] = {}
        self._borrowed: dict[str, ProjectMutationLease] = {}
        self._released_owners: set[int] = set()

    def owner(self, workspace_id: str) -> ProjectMutationLease | None:
        return next(iter(self._owners.get(str(workspace_id), {}).values()), None)

    @staticmethod
    def _conflicts(keys: frozenset[str], owners: dict[str, ProjectMutationLease]) -> list[ProjectMutationLease]:
        return [lease for lease in owners.values() if keys & lease.conflict_keys]

    async def acquire(
        self, *, workspace_id: str, owner_id: str, label: str,
        on_wait: WaitCallback | None = None, conflict_keys: Any = (), project_chat_id: str = '',
    ) -> ProjectMutationLease:
        workspace_id, owner_id = str(workspace_id), str(owner_id)
        label = str(label or owner_id)
        keys = frozenset(str(value) for value in (conflict_keys or ()) if str(value))
        if not keys:
            keys = frozenset((owner_id,))
        queued = False
        last_signature: tuple[Any, ...] | None = None
        try:
            while True:
                wait_payload = None
                async with self._condition:
                    owners = self._owners.setdefault(workspace_id, {})
                    if owner_id in owners and id(owners[owner_id]) not in self._released_owners:
                        return owners[owner_id]
                    queue = self._queues.setdefault(workspace_id, [])
                    if not queued:
                        queue.append((owner_id, label, keys))
                        queued = True
                    blockers = self._conflicts(keys, owners)
                    first_eligible = next(
                        (row[0] for row in queue if not self._conflicts(row[2], owners)), ''
                    )
                    if not blockers and first_eligible == owner_id:
                        queue[:] = [row for row in queue if row[0] != owner_id]
                        if not queue:
                            self._queues.pop(workspace_id, None)
                        lease = ProjectMutationLease(workspace_id, owner_id, label, keys, str(project_chat_id or ''))
                        owners[owner_id] = lease
                        self._condition.notify_all()
                        return lease
                    position = next(
                        (index for index, row in enumerate(queue, start=1) if row[0] == owner_id), 0,
                    )
                    signature = (tuple((row.owner_id, row.label, row.project_chat_id, row.phase) for row in blockers), position)
                    if on_wait is not None and signature != last_signature:
                        wait_payload = {
                            'workspace_id': workspace_id,
                            'owner': blockers[0].label if blockers else '',
                            'owner_id': blockers[0].owner_id if blockers else '',
                            'owner_project_chat_id': blockers[0].project_chat_id if blockers else '',
                            'owner_phase': blockers[0].phase if blockers else '',
                            'blockers': [
                                {'owner_id': row.owner_id, 'label': row.label,
                                 'project_chat_id': row.project_chat_id, 'phase': row.phase}
                                for row in blockers
                            ],
                            'position': position,
                            'reason': 'related_project' if blockers else 'fairness',
                        }
                        last_signature = signature
                if wait_payload is not None:
                    await on_wait(wait_payload)
                async with self._condition:
                    try:
                        await asyncio.wait_for(self._condition.wait(), timeout=0.75)
                    except asyncio.TimeoutError:
                        pass
        except BaseException:
            async with self._condition:
                queue = self._queues.get(workspace_id, [])
                self._queues[workspace_id] = [row for row in queue if row[0] != owner_id]
                if not self._queues[workspace_id]:
                    self._queues.pop(workspace_id, None)
                self._condition.notify_all()
            raise

    async def set_owner_label(self, *, workspace_id: str, owner_id: str, label: str, phase: str = '') -> bool:
        """Describe a held writer's current work without changing its ownership."""
        async with self._condition:
            lease = self._owners.get(str(workspace_id), {}).get(str(owner_id))
            if lease is None:
                return False
            lease.label = str(label or owner_id)
            lease.phase = str(phase or '')
            self._condition.notify_all()
            return True

    @asynccontextmanager
    async def borrow(
        self, *, workspace_id: str, owner_id: str = '', label: str = 'Guest project synchronization',
        conflict_keys: Any = (), project_chat_id: str = '',
    ):
        """Keep an existing writer alive through a bounded background sync.

        The borrower has its own opaque token. Releasing the original writer
        cannot admit conflicting work until the last borrower finishes, and a
        stale borrower cannot release a later lease reusing the same owner ID.
        If the original writer has already ended, acquire a new independent
        writer rather than recreating its owner identity.
        """
        workspace_id, owner_id = str(workspace_id), str(owner_id)
        token = uuid.uuid4().hex
        independent = ''
        async with self._condition:
            lease = self._owners.get(workspace_id, {}).get(owner_id)
            if lease is not None and id(lease) not in self._released_owners:
                self._borrowed[token] = lease
            else:
                lease = None
        if lease is None:
            independent = 'project-sync-' + token
            lease = await self.acquire(workspace_id=workspace_id, owner_id=independent, label=label,
                conflict_keys=conflict_keys, project_chat_id=project_chat_id)
            # Register without yielding after acquire: cancellation cannot leave
            # an acquired writer between acquisition and the cleanup region.
            self._borrowed[token] = lease
        try:
            yield lease
        finally:
            async with self._condition:
                borrowed = self._borrowed.pop(token, None)
                if borrowed is not None:
                    if independent:
                        self._released_owners.add(id(borrowed))
                    self._drop_released_owner(borrowed)
                self._condition.notify_all()

    @asynccontextmanager
    async def project_io(
        self, *, workspace_id: str, project_chat_id: str, conflict_keys: Any,
        label: str = 'Live project file write',
    ):
        """Coordinate a shared file channel by its trusted project origin.

        A FUSE connection serves several guest processes and carries no caller
        owner ID. Borrow only a current lease for this exact origin which covers
        every required conflict key. Keep it alive until the file operation has
        finished, including after its original run releases ownership.
        """
        workspace_id, project_chat_id = str(workspace_id), str(project_chat_id)
        keys = frozenset(str(value) for value in (conflict_keys or ()) if str(value))
        if not workspace_id or not project_chat_id or project_chat_id not in keys:
            raise ValueError('Live project writes require an exact project and its conflict keys.')
        token = uuid.uuid4().hex
        independent = False
        async with self._condition:
            lease = next((candidate for candidate in self._owners.get(workspace_id, {}).values()
                          if candidate.project_chat_id == project_chat_id
                          and id(candidate) not in self._released_owners
                          and keys <= candidate.conflict_keys), None)
            if lease is not None:
                self._borrowed[token] = lease
        if lease is None:
            lease = await self.acquire(workspace_id=workspace_id, owner_id='project-io-' + token,
                label=label, conflict_keys=keys, project_chat_id=project_chat_id)
            self._borrowed[token] = lease
            independent = True
        try:
            yield lease
        finally:
            async with self._condition:
                borrowed = self._borrowed.pop(token, None)
                if borrowed is not None:
                    if independent:
                        self._released_owners.add(id(borrowed))
                    self._drop_released_owner(borrowed)
                self._condition.notify_all()

    def _drop_released_owner(self, lease: ProjectMutationLease) -> None:
        if id(lease) not in self._released_owners or any(value is lease for value in self._borrowed.values()):
            return
        owners = self._owners.get(lease.workspace_id, {})
        if owners.get(lease.owner_id) is lease:
            owners.pop(lease.owner_id, None)
        if not owners:
            self._owners.pop(lease.workspace_id, None)
        self._released_owners.discard(id(lease))

    async def release(self, *, workspace_id: str, owner_id: str) -> None:
        async with self._condition:
            lease = self._owners.get(str(workspace_id), {}).get(str(owner_id))
            if lease is not None:
                self._released_owners.add(id(lease))
                self._drop_released_owner(lease)
            self._condition.notify_all()


WORKSPACE_MUTATIONS = ProjectMutationCoordinator()
