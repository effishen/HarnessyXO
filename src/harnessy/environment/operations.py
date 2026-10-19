from __future__ import annotations

import asyncio
import inspect
import json
import statistics
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from harnessy.diagnostics import log_event

from .manager import EnvironmentManager, environment_operation_context
from .base import environment_root, ENVIRONMENT_ID_RE, _validate_registry_path, EnvironmentModelAccessError
from .activity import reserve_policy_change, reserve_environment_change
from .base import environment_config_lock


class _OperationDeadlineExpired(Exception):
    """The registry's own timer expired, rather than a provider's timer."""


@dataclass(slots=True)
class EnvironmentOperationState:
    snapshot_tag: str = ''
    snapshot_attempted: bool = False
    snapshot_needs_reconciliation: bool = False
    verified_snapshots: list[str] = field(default_factory=list)
    operation_id: str = ''
    workspace_id: str = ''
    environment_id: str = ''
    kind: str = ''
    action: str = ''  # compatibility alias for older UI/state files
    status: str = 'idle'
    stage: str = 'idle'
    phase: str = 'idle'  # compatibility alias for older UI/state files
    busy: bool = False
    message: str = ''
    error: str = ''
    error_code: str = ''
    success: str = ''
    started_at: float = 0.0
    updated_at: float = 0.0
    deadline: float = 0.0
    stage_started_at: float = 0.0
    stage_deadline: float = 0.0
    detail: str = ''
    progress_percent: float | None = None
    stage_progress_percent: float | None = None
    progress_source: str = ''
    step_index: int = 0
    step_total: int = 0
    expected_total_seconds: float | None = None
    eta_seconds: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EnvironmentOperationRegistry:
    """Backend-owned, persistent and bounded environment lifecycle jobs."""

    DEADLINE_SECONDS = {
        # Create/Rebuild/Factory Reset may download an Ubuntu image and run the
        # one-time RE preset installer. Ordinary Stop -> Start does not run apt.
        # Limits remain intentionally generous but finite for those setup paths.
        'start': 2400.0,
        'stop': 240.0,
        'snapshot': 2100.0,
        'restore': 2400.0,
        'reset': 2400.0,
        'rebuild': 3000.0,
        'tools': 2400.0,
        'resources': 240.0,
        'remove': 300.0,
    }

    TERMINAL_STATUSES = {'succeeded', 'failed', 'timed_out', 'cancelled', 'interrupted'}

    WORKFLOW_STAGES = {
        'remove': ('removal_checking', 'removal_destroying', 'removal_complete'),
        'resources': ('resources_checking', 'resources_applying', 'resources_saving', 'resources_complete'),
        'network': ('checking_host_dependencies', 'network_stopping', 'network_applying', 'network_starting', 'ready'),
        'start': (
            'creating_vm', 'reconciling_environment', 'starting_vm', 'waiting_for_guest',
            'checking_provisioning', 'adopting_provisioning', 'provisioning_packages',
            'provisioning_package_index', 'provisioning_required_packages',
            'provisioning_optional_packages', 'provisioning_ghidra',
            'provisioning_ghidra_arm64', 'provisioning_python_re',
            'provisioning_skipped_offline', 'finalizing_provisioning',
            'installing_isolation', 'applying_isolation', 'verifying_isolation', 'ready',
        ),
        'stop': ('stopping_vm',),
        'tools': (
            'tools_saving', 'tools_removing', 'tools_pending', 'tools_installing',
            'provisioning_optional_packages', 'provisioning_ghidra',
            'provisioning_ghidra_arm64', 'provisioning_python_re', 'tools_complete',
        ),
        'snapshot': (
            'preparing_snapshot', 'stopping_snapshot_vm', 'cloning_snapshot',
            'saving_snapshot', 'restarting_snapshot_vm', 'verifying_snapshot_restart',
        ),
        'restore': (
            'preparing_restore', 'stopping_restore_vm', 'replacing_restore_vm',
            'reconciling_restore_files', 'restarting_restore_vm', 'verifying_restore_restart',
        ),
        'reset': (
            'factory_reset', 'restarting_reset_vm', 'starting_vm', 'waiting_for_guest',
            'checking_provisioning', 'adopting_provisioning', 'provisioning_packages', 'provisioning_package_index',
            'provisioning_required_packages', 'provisioning_optional_packages',
            'provisioning_ghidra', 'provisioning_ghidra_arm64', 'provisioning_python_re',
            'provisioning_skipped_offline',
            'finalizing_provisioning', 'installing_isolation', 'applying_isolation',
            'verifying_isolation', 'ready',
        ),
        'rebuild': (
            'rebuilding', 'creating_vm', 'starting_vm', 'waiting_for_guest',
            'checking_provisioning', 'adopting_provisioning', 'provisioning_packages', 'provisioning_package_index',
            'provisioning_required_packages', 'provisioning_optional_packages',
            'provisioning_ghidra', 'provisioning_ghidra_arm64', 'provisioning_python_re',
            'provisioning_skipped_offline',
            'finalizing_provisioning', 'installing_isolation', 'applying_isolation',
            'verifying_isolation', 'ready',
        ),
    }

    def __init__(self) -> None:
        self._states: dict[tuple[str, str], EnvironmentOperationState] = {}
        self._tasks: dict[tuple[str, str], asyncio.Task[None]] = {}

    @staticmethod
    def _environment_ids(workspace_root: str | Path) -> list[str]:
        return [cfg.id for cfg in EnvironmentManager(workspace_root).list()]

    @staticmethod
    def _selected_id(workspace_root: str | Path, environment_id: str | None = None) -> str:
        manager = EnvironmentManager(workspace_root, environment_id=environment_id)
        selected = manager.environment_id
        if selected or environment_id in {None, ''}:
            return selected
        # A completed removal remains observable without resolving an absent
        # definition to another VM. Only opaque validated IDs may outlive it.
        if isinstance(environment_id, str) and ENVIRONMENT_ID_RE.fullmatch(environment_id):
            return environment_id
        raise ValueError('This VM environment no longer exists.')

    @classmethod
    def _key(cls, workspace_root: str | Path, environment_id: str | None = None) -> tuple[str, str]:
        return (str(Path(workspace_root).expanduser().resolve()), cls._selected_id(workspace_root, environment_id))

    @classmethod
    def _state_path(cls, workspace_root: str | Path, environment_id: str | None = None) -> Path:
        root = Path(workspace_root).expanduser().resolve()
        path = environment_root(root, cls._selected_id(root, environment_id)) / 'state' / 'operation.json'
        _validate_registry_path(path, root)
        return path

    @classmethod
    def _timing_path(cls, workspace_root: str | Path, environment_id: str | None = None) -> Path:
        root = Path(workspace_root).expanduser().resolve()
        path = environment_root(root, cls._selected_id(root, environment_id)) / 'state' / 'timings.json'
        _validate_registry_path(path, root)
        return path

    def _read_timings(self, workspace_root: str | Path, *, environment_id: str | None = None) -> dict[str, list[float]]:
        path = self._timing_path(workspace_root, environment_id)
        try:
            raw = json.loads(path.read_text('utf-8'))
        except (OSError, json.JSONDecodeError):
            return {}
        actions = raw.get('actions') if isinstance(raw, dict) else None
        if not isinstance(actions, dict):
            return {}
        out: dict[str, list[float]] = {}
        for action, values in actions.items():
            if not isinstance(values, list):
                continue
            clean: list[float] = []
            for value in values[-8:]:
                try:
                    seconds = float(value)
                except (TypeError, ValueError):
                    continue
                if 0.05 <= seconds <= 24 * 60 * 60:
                    clean.append(seconds)
            if clean:
                out[str(action)] = clean
        return out

    def _timing_estimate(self, workspace_root: str | Path, action: str, *, environment_id: str | None = None) -> float | None:
        values = self._read_timings(workspace_root, environment_id=environment_id).get(str(action), [])
        return float(statistics.median(values)) if values else None

    def _record_timing(self, workspace_root: str | Path, action: str, duration_seconds: float, *, environment_id: str | None = None) -> None:
        if duration_seconds < 0.05 or duration_seconds > 24 * 60 * 60:
            return
        if EnvironmentManager(workspace_root, environment_id=environment_id).config is None:
            return
        path = self._timing_path(workspace_root, environment_id)
        try:
            actions = self._read_timings(workspace_root, environment_id=environment_id)
            values = list(actions.get(str(action), []))
            values.append(float(duration_seconds))
            actions[str(action)] = values[-8:]
            payload = {'version': 1, 'actions': actions, 'updated_at': time.time()}
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix('.tmp')
            tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n', encoding='utf-8')
            tmp.replace(path)
        except OSError:
            pass

    @classmethod
    def _workflow_progress(cls, action: str, stage: str, stage_percent: float | None = None) -> tuple[float | None, int, int]:
        stages = cls.WORKFLOW_STAGES.get(str(action), ())
        if not stages or stage not in stages:
            return None, 0, len(stages)
        index = stages.index(stage)
        total = len(stages)
        if stage == 'ready':
            return 100.0, total, total
        within = 0.0 if stage_percent is None else max(0.0, min(100.0, float(stage_percent))) / 100.0
        percent = max(0.0, min(99.0, ((index + within) / total) * 100.0))
        return percent, index + 1, total

    @staticmethod
    def _accepts_progress(method: Any) -> bool:
        try:
            signature = inspect.signature(method)
        except (TypeError, ValueError):
            return False
        return 'progress' in signature.parameters or any(
            p.kind == inspect.Parameter.VAR_KEYWORD for p in signature.parameters.values()
        )

    @staticmethod
    def _workspace_id(workspace_root: str | Path) -> str:
        path = Path(workspace_root).expanduser().resolve() / '.harnessy' / 'workspace.json'
        try:
            raw = json.loads(path.read_text('utf-8'))
        except (OSError, json.JSONDecodeError):
            return ''
        return str(raw.get('id') or '') if isinstance(raw, dict) else ''

    def _persist(self, workspace_root: str | Path, state: EnvironmentOperationState) -> None:
        if EnvironmentManager(workspace_root).get(state.environment_id) is None:
            return  # Never recreate an environment after its definition was removed.
        path = self._state_path(workspace_root, state.environment_id)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix('.tmp')
            tmp.write_text(json.dumps(state.to_dict(), indent=2, sort_keys=True) + '\n', encoding='utf-8')
            tmp.replace(path)
        except OSError:
            pass

    def _load(self, workspace_root: str | Path, *, environment_id: str | None = None) -> EnvironmentOperationState:
        path = self._state_path(workspace_root, environment_id)
        try:
            raw = json.loads(path.read_text('utf-8'))
        except (OSError, json.JSONDecodeError):
            return EnvironmentOperationState(environment_id=environment_id or '')
        if not isinstance(raw, dict):
            return EnvironmentOperationState(environment_id=environment_id or '')
        allowed = EnvironmentOperationState.__dataclass_fields__.keys()
        data = {k: raw[k] for k in allowed if k in raw}
        try:
            state = EnvironmentOperationState(**data)
        except (TypeError, ValueError):
            return EnvironmentOperationState(environment_id=environment_id or '')
        # Migrate the v0.2.13 persisted shape without discarding evidence.
        if not state.kind:
            state.kind = state.action
        if not state.action:
            state.action = state.kind
        if not state.stage or state.stage == 'idle':
            state.stage = state.phase or 'idle'
        if not state.phase or state.phase == 'idle':
            state.phase = state.stage
        if state.busy and state.status == 'idle':
            state.status = 'running'
        return state

    def state(self, workspace_root: str | Path, *, environment_id: str | None = None) -> EnvironmentOperationState:
        if environment_id is None:
            states = [self.state(workspace_root, environment_id=item) for item in self._environment_ids(workspace_root)]
            return max(states, key=lambda item: (item.busy, item.updated_at), default=EnvironmentOperationState())
        environment_id = self._selected_id(workspace_root, environment_id)
        key = self._key(workspace_root, environment_id)
        state = self._states.get(key)
        if state is None:
            state = self._load(workspace_root, environment_id=environment_id)
            state.environment_id = environment_id
            # A persisted running flag cannot represent a live asyncio task after
            # a process restart. Stop the spinner immediately and preserve the
            # interrupted operation for startup reconciliation/diagnostics.
            if (state.busy or state.status in {'queued', 'running'}) and key not in self._tasks:
                state.busy = False
                if state.kind == 'snapshot' and state.snapshot_attempted:
                    state.snapshot_needs_reconciliation = True
                state.status = 'interrupted'
                state.stage = state.phase = 'interrupted'
                state.error = state.error or 'The previous environment operation was interrupted when HarnessyXO stopped.'
                state.message = 'Operation interrupted'
                state.updated_at = time.time()
                self._persist(workspace_root, state)
                log_event(
                    'runtime', 'environment_operation_interrupted', workspace=str(Path(workspace_root).expanduser().resolve()), environment_id=environment_id,
                    workspace_id=state.workspace_id, operation_id=state.operation_id,
                    kind=state.kind or state.action, reason='process_restart',
                )
            self._states[key] = state
        return state

    def task(self, workspace_root: str | Path, *, environment_id: str | None = None) -> asyncio.Task[None] | None:
        if environment_id is None:
            return next((task for item in self._environment_ids(workspace_root)
                         if (task := self.task(workspace_root, environment_id=item)) is not None), None)
        key = self._key(workspace_root, environment_id)
        task = self._tasks.get(key)
        if task is not None and task.done():
            self._tasks.pop(key, None)
            return None
        return task

    def is_busy(self, workspace_root: str | Path, *, environment_id: str | None = None) -> bool:
        return self.task(workspace_root, environment_id=environment_id) is not None

    def _update(self, workspace_root: str | Path, *, environment_id: str, **changes: Any) -> EnvironmentOperationState:
        state = self.state(workspace_root, environment_id=environment_id)
        if 'kind' in changes and 'action' not in changes:
            changes['action'] = changes['kind']
        if 'action' in changes and 'kind' not in changes:
            changes['kind'] = changes['action']
        if 'stage' in changes and 'phase' not in changes:
            changes['phase'] = changes['stage']
        if 'phase' in changes and 'stage' not in changes:
            changes['stage'] = changes['phase']
        for key, value in changes.items():
            if hasattr(state, key):
                setattr(state, key, value)
        state.updated_at = time.time()
        self._persist(workspace_root, state)
        return state

    @classmethod
    def _deadline_seconds(cls, action: str) -> float:
        return float(cls.DEADLINE_SECONDS.get(action, 1800.0 if action == 'network' else 900.0))

    def start(self, workspace_root: str | Path, action: str, *, environment_id: str | None = None, **payload: Any) -> bool:
        selected_id = EnvironmentManager(workspace_root, environment_id=environment_id).environment_id
        # Serialize only synchronous enqueue/config writes. No lock is held
        # while downloading packages or awaiting guest operations.
        with environment_config_lock(workspace_root, selected_id):
            return self._start_locked(workspace_root, action, environment_id=environment_id, **payload)

    def _start_locked(self, workspace_root: str | Path, action: str, *, environment_id: str | None = None, **payload: Any) -> bool:
        if action == 'remove' and not environment_id:
            raise ValueError('Choose a specific VM environment to remove.')
        manager = EnvironmentManager(workspace_root, environment_id=environment_id)
        if manager.config is None:
            raise RuntimeError('Create a VM environment before starting an environment operation.')
        if action == 'tools' and payload.get('expected_preset') is not None:
            if payload['expected_preset'] != manager.config.preset:
                raise RuntimeError('The VM tool preset changed since this editor opened. Reopen Manage Optional Tools before applying.')
        environment_id = manager.environment_id
        key = self._key(workspace_root, environment_id)
        if self.task(workspace_root, environment_id=environment_id) is not None:
            return False
        previous = self.state(workspace_root, environment_id=environment_id)
        if action == 'snapshot':
            from .lima import LimaVMEnvironment
            requested = str(payload.get('name') or '').strip()
            retry_pending = bool(previous.snapshot_needs_reconciliation and previous.snapshot_tag)
            # Blank retry reuses the uncertain operation's identity, not a new
            # timestamp which could create a second checkpoint inadvertently.
            name = previous.snapshot_tag if retry_pending and not requested else LimaVMEnvironment._clean_snapshot_tag(requested)
            payload['name'] = name
            payload['reconcile_only'] = bool(retry_pending and name == previous.snapshot_tag)
        if action == 'network':
            policy_release = reserve_policy_change(workspace_root, environment_id=environment_id)
        elif action == 'tools':
            policy_release = reserve_environment_change(workspace_root, 'optional tools', environment_id=environment_id)
        elif action == 'resources':
            policy_release = reserve_environment_change(workspace_root, 'VM resources', environment_id=environment_id)
        elif action == 'remove':
            policy_release = reserve_environment_change(workspace_root, 'VM removal', environment_id=environment_id)
        else:
            policy_release = None
        try:
            now = time.time()
            operation_id = uuid.uuid4().hex
            deadline_seconds = self._deadline_seconds(action)
            state = self._update(
                workspace_root, environment_id=environment_id,
                operation_id=operation_id,
                snapshot_tag=str(payload.get('name') or '') if action == 'snapshot' else previous.snapshot_tag,
                snapshot_attempted=False if action == 'snapshot' else previous.snapshot_attempted,
                snapshot_needs_reconciliation=bool(payload.get('reconcile_only')) if action == 'snapshot' else previous.snapshot_needs_reconciliation,
                verified_snapshots=list(previous.verified_snapshots),
                workspace_id=self._workspace_id(workspace_root),
                kind=action,
                status='queued',
                busy=True,
                stage='queued',
                message=self._initial_message(action),
                error='',
                error_code='',
                success='',
                started_at=now,
                deadline=now + deadline_seconds,
                stage_started_at=now,
                stage_deadline=0.0,
                detail='',
                progress_percent=0.0,
                stage_progress_percent=None,
                progress_source='workflow',
                step_index=0,
                step_total=len(self.WORKFLOW_STAGES.get(action, ())),
                expected_total_seconds=self._timing_estimate(workspace_root, action, environment_id=environment_id),
                eta_seconds=self._timing_estimate(workspace_root, action, environment_id=environment_id),
            )
            try:
                from .status import ENVIRONMENT_STATUS
                ENVIRONMENT_STATUS.invalidate(workspace_root, environment_id=environment_id)
            except Exception:
                pass
            log_event(
                'runtime', 'environment_operation_started', workspace=str(Path(workspace_root).expanduser().resolve()), environment_id=environment_id,
                workspace_id=state.workspace_id, operation_id=operation_id, kind=action,
                stage='queued', deadline=state.deadline, deadline_seconds=deadline_seconds,
            )
            task = asyncio.create_task(self._run(Path(workspace_root).expanduser().resolve(), action, payload, environment_id=environment_id), name=f'harnessy-env-{action}-{operation_id[:8]}')
            self._tasks[key] = task
            if policy_release is not None:
                task.add_done_callback(lambda _task: policy_release())
            return True
        except BaseException:
            if policy_release is not None:
                policy_release()
            raise

    @staticmethod
    def _initial_message(action: str) -> str:
        return {
            'network': 'Applying public outbound policy…',
            'start': 'Starting environment…',
            'stop': 'Stopping environment…',
            'snapshot': 'Creating snapshot…',
            'restore': 'Restoring snapshot…',
            'reset': 'Factory resetting environment…',
            'rebuild': 'Rebuilding environment…',
            'tools': 'Applying optional tool selection…',
            'resources': 'Applying VM resource settings…',
            'remove': 'Removing VM environment…',
        }.get(action, 'Working…')

    @staticmethod
    def _validate_result(action: str, result: Any, *, snapshot_tag: str = '') -> None:
        # Provider lifecycle methods normally raise on failure, but the operation
        # manager is the final authority shown to the UI. Never advertise success
        # if a provider returns a non-Ready start/rebuild result or a still-running
        # stop result without raising.
        if action == 'snapshot':
            if not isinstance(result, list) or not result or (snapshot_tag and snapshot_tag not in result):
                raise RuntimeError(
                    f'Snapshot creation could not be verified: {snapshot_tag or "requested snapshot"} '
                    'is not in the provider list. Refresh/reconcile before taking another snapshot.'
                )
            return
        if result is None:
            return
        if action in {'start', 'restore', 'reset', 'rebuild'} and hasattr(result, 'ready'):
            if (str(getattr(result, 'provider', '')) == 'managed'
                    and bool(getattr(result, 'running', False))
                    and str(getattr(result, 'phase', '')) == 'installer_pending'):
                return  # A booted Windows installer needs user setup, not SSH readiness.
            if not bool(getattr(result, 'running', False)) or not bool(getattr(result, 'ready', False)):
                detail = str(getattr(result, 'error', '') or getattr(result, 'detail', '') or getattr(result, 'state', 'not ready'))
                raise RuntimeError(f'Environment did not become Ready: {detail}')
        if action in {'stop', 'resources'} and hasattr(result, 'running') and bool(getattr(result, 'running', False)):
            detail = str(getattr(result, 'detail', '') or getattr(result, 'state', 'still running'))
            raise RuntimeError(f'Environment did not stop: {detail}')

    @staticmethod
    def _status_fields(result: Any) -> dict[str, Any]:
        if result is None:
            return {}
        try:
            data = result.to_dict()
        except Exception:
            return {}
        if not isinstance(data, dict):
            return {}
        return {
            'vm_state': data.get('state'),
            'vm_running': data.get('running'),
            'readiness_state': data.get('phase'),
            'environment_ready': data.get('ready'),
        }

    @staticmethod
    async def _wait_for_operation(awaitable, timeout: float):
        # wait_for raises TimeoutError for both its own timer and a provider's
        # timer. Wait for completion explicitly so the UI can distinguish them.
        task = asyncio.create_task(awaitable)
        try:
            done, _ = await asyncio.wait({task}, timeout=timeout)
        except asyncio.CancelledError:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            raise
        if done:
            return task.result()
        task.cancel()
        # A cancelled child becomes a result, while a cancellation of this
        # registry task still propagates, including during deadline cleanup.
        await asyncio.gather(task, return_exceptions=True)
        raise _OperationDeadlineExpired

    @classmethod
    def _failure_stage(cls, stage: str) -> str:
        known = {'queued', 'unknown', 'checking_host_dependencies',
                 'installing_host_dependencies', 'host_dependencies_ready'}
        known.update(item for stages in cls.WORKFLOW_STAGES.values() for item in stages)
        return stage if isinstance(stage, str) and stage in known else 'unknown'

    async def _run(self, workspace_root: Path, action: str, payload: dict[str, Any], *, environment_id: str) -> None:
        key = self._key(workspace_root, environment_id)
        initial = self.state(workspace_root, environment_id=environment_id)
        operation_id = initial.operation_id

        def set_phase(
            stage: str, message: str, *, detail: str = '',
            stage_progress_percent: float | None = None, progress_source: str = '',
            stage_timeout_seconds: float | None = None,
        ) -> None:
            previous = self.state(workspace_root, environment_id=environment_id)
            now = time.time()
            stage_changed = previous.stage != stage
            workflow_percent, step_index, step_total = self._workflow_progress(
                action, stage, stage_progress_percent,
            )
            expected_total = previous.expected_total_seconds
            elapsed = max(0.0, now - previous.started_at) if previous.started_at else 0.0
            eta = max(0.0, expected_total - elapsed) if expected_total else None
            stage_started_at = now if stage_changed or not previous.stage_started_at else previous.stage_started_at
            if stage_timeout_seconds is not None:
                stage_deadline = stage_started_at + max(0.1, float(stage_timeout_seconds))
            elif stage_changed:
                stage_deadline = 0.0
            else:
                stage_deadline = previous.stage_deadline
            state = self._update(
                workspace_root, environment_id=environment_id, busy=True, status='running', stage=stage,
                message=message, detail=str(detail or ''), error='', success='',
                stage_started_at=stage_started_at, stage_deadline=stage_deadline,
                progress_percent=workflow_percent,
                stage_progress_percent=(None if stage_progress_percent is None else max(0.0, min(100.0, float(stage_progress_percent)))),
                progress_source=str(progress_source or ('lima' if stage_progress_percent is not None else 'workflow')),
                step_index=step_index, step_total=step_total, eta_seconds=eta,
            )
            fields = {
                'workspace': str(workspace_root), 'workspace_id': state.workspace_id, 'environment_id': environment_id,
                'operation_id': state.operation_id, 'kind': action,
                'stage': stage, 'message': message, 'detail': state.detail,
                'deadline': state.deadline, 'progress_percent': state.progress_percent,
                'stage_progress_percent': state.stage_progress_percent,
                'progress_source': state.progress_source, 'step_index': state.step_index,
                'step_total': state.step_total, 'eta_seconds': state.eta_seconds,
                'stage_deadline': state.stage_deadline,
            }
            # Retain the older event name for diagnostics compatibility while the
            # new event exposes the explicit operation/stage schema.
            log_event('runtime', 'environment_operation_phase', action=action, phase=stage, **fields)
            log_event('runtime', 'environment_operation_stage_changed', **fields)

        async def progress(stage: str, message: str, **meta: Any) -> None:
            set_phase(
                stage, message, detail=str(meta.get('detail') or ''),
                stage_progress_percent=meta.get('stage_progress_percent'),
                progress_source=str(meta.get('progress_source') or ''),
                stage_timeout_seconds=meta.get('stage_timeout_seconds'),
            )

        def check_model_access() -> None:
            # The marker comes only from the model-tool broker, never model
            # arguments. Browser lifecycle controls deliberately have no marker.
            if '_model_project_id' not in payload:
                return
            origin = payload['_model_project_id']
            current = EnvironmentManager(workspace_root).get(environment_id)
            if (not isinstance(origin, str) or not origin or current is None
                    or not current.enabled or not current.allows_project(origin)):
                raise EnvironmentModelAccessError(
                    'This VM is disabled or its model access does not include this project. '
                    'The queued VM action was not dispatched.'
                )

        async def execute(provider):
            # asyncio scheduling can yield between accepting a job and entering
            # this child task. Re-read the grant at the actual dispatch boundary.
            check_model_access()
            if action == 'remove':
                if not environment_id or not ENVIRONMENT_ID_RE.fullmatch(environment_id):
                    raise ValueError('Only an explicitly selected named VM environment can be removed.')
                set_phase('removal_checking', 'Checking VM before removal…')
                owned = environment_root(workspace_root, environment_id)
                _validate_registry_path(owned, workspace_root)
                if Path(provider.environment_root) != owned:
                    raise RuntimeError('VM storage ownership could not be verified. No files were removed.')
                vm_child = 'vm/lima' if provider.config.provider in {'lima', 'managed'} else 'qemu'
                snapshot_child = 'vm/snapshots' if provider.config.provider == 'managed' else 'snapshots'
                for attribute, name in (('vm_root', vm_child), ('snapshots_root', snapshot_child)):
                    child = Path(getattr(provider, attribute, owned / name))
                    if child != owned / name:
                        raise RuntimeError('VM storage ownership could not be verified. No files were removed.')
                    _validate_registry_path(child, workspace_root)
                current = await provider.status()
                if current.running or str(current.state).lower() not in {'stopped', 'not_created'}:
                    raise RuntimeError('Stop this VM and verify that it is stopped before removing it.')
                check_model_access()
                set_phase('removal_destroying', 'Removing this VM’s disk, snapshots and configuration…')
                await provider.destroy()
                EnvironmentManager(workspace_root).remove(environment_id)
                return None
            if action == 'resources':
                return await provider.apply_resources(
                    cpu=payload.get('cpu'), memory_mb=payload.get('memory_mb'), disk_gb=payload.get('disk_gb'),
                    expected=payload.get('expected'), progress=progress, reservation_held=True,
                )
            if action == 'start':
                return await provider.start(progress=progress)
            if action == 'network':
                return await provider.apply_network_policy(
                    payload.get('enabled'), expected=payload.get('expected'),
                    progress=progress, reservation_held=True,
                )
            if action == 'tools':
                if payload.get('expected_preset') is not None:
                    current = EnvironmentManager(workspace_root, environment_id=environment_id).config
                    if current is None or current.preset != payload['expected_preset']:
                        raise RuntimeError('The VM tool preset changed since this editor opened. Reopen Manage Optional Tools before applying.')
                raw_expected = payload.get('expected')
                return await provider.apply_optional_tools(
                    tuple(payload.get('optional_tools') or ()),
                    expected=None if raw_expected is None else tuple(raw_expected),
                    remove_deselected_bundles=bool(payload.get('remove_deselected_bundles')),
                    progress=progress, reservation_held=True,
                )
            if action == 'stop':
                set_phase('stopping_vm', 'Stopping workspace VM…')
                return await provider.stop()
            if action == 'snapshot':
                tag = str(payload['name'])
                if payload.get('reconcile_only'):
                    set_phase('preparing_snapshot', f'Reconciling snapshot {tag}…')
                    found = await provider.list_snapshots()
                    if tag in found:
                        return found  # Never replay a possibly completed create.
                    raise RuntimeError(
                        f'Snapshot {tag} is still not discoverable. No additional snapshot was created. '
                        'Check the controller/list error and refresh; use a different explicit name only '
                        'after confirming the previous checkpoint is absent.'
                    )
                set_phase('preparing_snapshot', 'Preparing VM snapshot…')
                self._update(workspace_root, environment_id=environment_id, snapshot_attempted=True, snapshot_needs_reconciliation=True)
                method = provider.snapshot
                if 'progress' in inspect.signature(method).parameters:
                    return await method(tag, progress=set_phase)
                return await method(tag)
            if action == 'restore':
                tag = str(payload.get('tag') or '').strip()
                if not tag:
                    raise ValueError('Choose a snapshot to restore.')
                set_phase('preparing_restore', f'Preparing snapshot {tag} for restore…')
                method = provider.restore_snapshot
                if self._accepts_progress(method):
                    return await method(tag, progress=progress)
                return await method(tag)
            if action == 'reset':
                set_phase('factory_reset', 'Factory resetting VM while preserving working roots…')
                method = provider.reset
                if self._accepts_progress(method):
                    return await method(progress=progress)
                return await method()
            if action == 'rebuild':
                set_phase('rebuilding', 'Rebuilding VM while preserving working roots…')
                method = provider.rebuild
                if self._accepts_progress(method):
                    return await method(progress=progress)
                return await method()
            raise ValueError(f'Unknown environment action: {action}')

        try:
            check_model_access()
            provider = EnvironmentManager(workspace_root, environment_id=environment_id).provider()
            state = self.state(workspace_root, environment_id=environment_id)
            remaining = max(0.1, state.deadline - time.time()) if state.deadline else self._deadline_seconds(action)
            with environment_operation_context(operation_id, action):
                result = await self._wait_for_operation(execute(provider), remaining)
            self._validate_result(action, result, snapshot_tag=str(payload.get('name') or ''))
            if action == 'snapshot':
                from .status import ENVIRONMENT_STATUS
                ENVIRONMENT_STATUS.publish_snapshots(workspace_root, result, environment_id=environment_id)
                self._update(workspace_root, environment_id=environment_id, verified_snapshots=list(result), snapshot_needs_reconciliation=False)
            success = {
                'network': 'Public outbound policy applied. VM disk and working roots were preserved.',
                'start': 'Environment is Ready.',
                'stop': 'Environment stopped.',
                'snapshot': 'Snapshot created.',
                'restore': 'Snapshot restored.',
                'reset': 'Factory reset complete. Files/ and private chat worktrees were preserved.',
                'rebuild': 'VM rebuild complete. Files/ and private chat worktrees were preserved.',
                'tools': 'Optional tool selection applied.',
                'resources': 'VM resources saved. Start the VM to use them.',
                'remove': 'VM environment removed. Workspace project files were preserved.',
            }.get(action, 'Environment operation complete.')
            if (str(getattr(result, 'provider', '')) == 'managed'
                    and str(getattr(result, 'phase', '')) == 'installer_pending'):
                success = 'Windows VM is running. Finish setup in its graphical tab before using model tools.'
            completed_at = time.time()
            duration_seconds = max(0.0, completed_at - initial.started_at) if initial.started_at else 0.0
            if action != 'remove':
                self._record_timing(workspace_root, action, duration_seconds, environment_id=environment_id)
            state = self._update(
                workspace_root, environment_id=environment_id,
                busy=False,
                status='succeeded',
                stage='complete',
                message=success,
                detail='',
                success=success,
                error='',
                progress_percent=100.0,
                stage_progress_percent=100.0,
                progress_source='complete',
                eta_seconds=0.0,
            )
            fields = self._status_fields(result)
            log_event(
                'runtime', 'environment_operation_succeeded', workspace=str(workspace_root), environment_id=environment_id,
                workspace_id=state.workspace_id, operation_id=state.operation_id,
                kind=action, stage=state.stage, deadline=state.deadline,
                duration_seconds=duration_seconds, **fields,
            )
            log_event('harnessy', 'environment_action_complete', workspace=str(workspace_root), environment_id=environment_id, action=action)
        except EnvironmentModelAccessError as exc:
            state = self._update(
                workspace_root, environment_id=environment_id, busy=False,
                status='failed', stage='access_denied', message='VM action blocked by model access settings.',
                error=str(exc), error_code='VM_PROJECT_ACCESS_DENIED', success='',
            )
            log_event(
                'runtime', 'environment_operation_access_denied', workspace=str(workspace_root),
                environment_id=environment_id, workspace_id=state.workspace_id,
                operation_id=state.operation_id, kind=action, stage=state.stage,
                error_code=state.error_code,
            )
        except _OperationDeadlineExpired:
            failed_stage = self._failure_stage(self.state(workspace_root, environment_id=environment_id).stage)
            state = self._update(
                workspace_root, environment_id=environment_id, busy=False, status='timed_out', stage='timed_out',
                message='Environment operation timed out.',
                error='The environment operation exceeded its total deadline and was stopped.', success='',
            )
            log_event(
                'runtime', 'environment_operation_timed_out', workspace=str(workspace_root), environment_id=environment_id,
                workspace_id=state.workspace_id, operation_id=state.operation_id,
                kind=action, stage=state.stage, deadline=state.deadline,
                failed_stage=failed_stage, timeout_scope='operation',
            )
        except asyncio.CancelledError:
            state = self._update(
                workspace_root, environment_id=environment_id, busy=False, status='cancelled', stage='cancelled',
                message='Environment operation cancelled.', error='Environment operation cancelled.', success='',
            )
            log_event(
                'runtime', 'environment_operation_cancelled', workspace=str(workspace_root), environment_id=environment_id,
                workspace_id=state.workspace_id, operation_id=state.operation_id,
                kind=action, stage=state.stage,
            )
            log_event('harnessy', 'environment_action_cancelled', workspace=str(workspace_root), environment_id=environment_id, action=action)
            raise
        except Exception as exc:
            failed_stage = self._failure_stage(self.state(workspace_root, environment_id=environment_id).stage)
            provider_timeout = isinstance(exc, asyncio.TimeoutError)
            stage_label = failed_stage.replace('_', ' ') if failed_stage != 'unknown' else 'environment provider'
            error = str(exc) or type(exc).__name__
            if provider_timeout:
                error += f'\nFailed stage: {stage_label}.'
            state = self._update(
                workspace_root, environment_id=environment_id,
                busy=False,
                status='failed',
                stage='failed',
                message='Environment operation failed.',
                error=error,
                success='',
                **({'detail': f'Timed out during {stage_label}.'} if provider_timeout else {}),
            )
            log_event(
                'runtime', 'environment_operation_failed', workspace=str(workspace_root), environment_id=environment_id,
                workspace_id=state.workspace_id, operation_id=state.operation_id,
                kind=action, stage=state.stage, error=error, deadline=state.deadline,
                failed_stage=failed_stage, error_type=type(exc).__name__,
                **({'timeout_scope': 'provider'} if provider_timeout else {}),
            )
            log_event('harnessy', 'environment_action_failed', workspace=str(workspace_root), environment_id=environment_id, action=action, error=error)
        finally:
            try:
                from .status import ENVIRONMENT_STATUS
                ENVIRONMENT_STATUS.invalidate(workspace_root, environment_id=environment_id)
            except Exception:
                pass
            current = self._tasks.get(key)
            if current is asyncio.current_task():
                self._tasks.pop(key, None)

    async def reconcile(self, workspace_root: str | Path, *, environment_id: str | None = None) -> EnvironmentOperationState:
        """Reconcile an interrupted persisted operation with current VM state.

        We deliberately do not resume destructive work automatically. The stale
        spinner is terminated immediately, then this bounded check records what
        VM/readiness state HarnessyXO actually found after restart.
        """
        if environment_id is None:
            for item in self._environment_ids(workspace_root):
                await self.reconcile(workspace_root, environment_id=item)
            return self.state(workspace_root)
        state = self.state(workspace_root, environment_id=environment_id)
        if state.status != 'interrupted':
            return state
        vm_fields: dict[str, Any] = {}
        try:
            provider = EnvironmentManager(workspace_root, environment_id=environment_id).provider()
            status = await asyncio.wait_for(provider.status(), timeout=20.0)
            vm_fields = self._status_fields(status)
            state = self._update(
                workspace_root, environment_id=environment_id,
                message='Previous operation interrupted; current environment state was reconciled.',
            )
        except Exception as exc:
            state = self._update(
                workspace_root, environment_id=environment_id,
                message='Previous operation interrupted; current environment state could not be reconciled.',
                error=(state.error + f'\nReconcile check: {type(exc).__name__}: {exc}').strip(),
            )
        log_event(
            'runtime', 'environment_operation_reconciled', workspace=str(Path(workspace_root).expanduser().resolve()), environment_id=environment_id,
            workspace_id=state.workspace_id, operation_id=state.operation_id,
            kind=state.kind or state.action, status=state.status, **vm_fields,
        )
        return state

    async def reconcile_many(self, workspace_roots: list[str | Path]) -> None:
        for root in workspace_roots:
            try:
                await self.reconcile(root)
            except Exception as exc:
                log_event('runtime', 'environment_operation_reconcile_failed', workspace=str(Path(root).expanduser().resolve()), error=str(exc))

    async def cancel_all(self) -> None:
        tasks = [task for task in self._tasks.values() if not task.done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._tasks.clear()


ENVIRONMENT_OPERATIONS = EnvironmentOperationRegistry()
