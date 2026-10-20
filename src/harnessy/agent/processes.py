from __future__ import annotations

import asyncio
import atexit
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, TYPE_CHECKING, Callable
from harnessy.environment.activity import acquire_activity

if TYPE_CHECKING:
    from harnessy.environment.base import WorkspaceEnvironment


_MAX_PENDING_BYTES = 2 * 1024 * 1024


@dataclass(slots=True)
class ProcessJob:
    id: str
    workspace_key: str
    command: str
    cwd: Path
    cwd_label: str
    process: asyncio.subprocess.Process
    environment: 'WorkspaceEnvironment'
    started_at: str
    started_perf: float
    stdout_pending: bytearray = field(default_factory=bytearray)
    stderr_pending: bytearray = field(default_factory=bytearray)
    activity: asyncio.Event = field(default_factory=asyncio.Event)
    stdout_task: asyncio.Task[Any] | None = None
    stderr_task: asyncio.Task[Any] | None = None
    watcher_task: asyncio.Task[Any] | None = None
    ended_at: str | None = None
    ended_perf: float | None = None
    activity_release: Callable[[], None] | None = None
    stop_requested: bool = False
    output_truncated: bool = False
    origin_chat_id: str = ''
    environment_id: str = ''
    environment_name: str = ''
    runtime_identity_start: dict[str, Any] = field(default_factory=dict)

    @property
    def status(self) -> str:
        if self.process.returncode is None:
            return 'running'
        if self.stop_requested:
            return 'stopped'
        return 'completed' if self.process.returncode == 0 else 'failed'

    @property
    def duration_seconds(self) -> float:
        end = self.ended_perf if self.ended_perf is not None else time.perf_counter()
        return max(0.0, end - self.started_perf)


class ProcessJobManager:
    """In-memory lifecycle manager for model-owned long-running processes.

    Jobs intentionally outlive individual WorkspaceToolbox / AgentRunner instances
    so later turns of the owning project can poll or stop existing work.
    Model-facing callers supply origin_chat_id; workspace-wide inspection is
    reserved for controller lifecycle and busy-state checks.
    """

    def __init__(self) -> None:
        self._jobs: dict[str, ProcessJob] = {}

    def _job_for(self, workspace_key: str, job_id: str, origin_chat_id: str | None = None,
                 environment_id: str | None = None) -> ProcessJob:
        job = self._jobs.get(job_id)
        if (not job or job.workspace_key != workspace_key
                or (origin_chat_id is not None and job.origin_chat_id != origin_chat_id)
                or (environment_id is not None and job.environment_id != environment_id)):
            raise KeyError(f'Unknown process job: {job_id}')
        return job

    @staticmethod
    def _model_access_current(job: ProcessJob) -> bool:
        from harnessy.environment import EnvironmentManager
        try:
            current = EnvironmentManager(job.environment.workspace_root).get(job.environment_id)
            return bool(current and current.enabled and current.allows_project(job.origin_chat_id))
        except Exception:
            return False

    def _withheld_poll(self, job: ProcessJob) -> dict[str, Any]:
        self._drain(job)
        return {**self._summary(job), 'ok': False, 'error_code': 'VM_PROJECT_ACCESS_DENIED',
                'error': 'This Project/Chat no longer has model access to this VM. Process output was withheld; stopping the owned job is still allowed.',
                'stdout': '', 'stderr': '', 'output_withheld': True}

    @staticmethod
    def _append_pending(job: ProcessJob, attr: str, chunk: bytes) -> None:
        if not chunk:
            return
        buffer = getattr(job, attr)
        buffer.extend(chunk)
        if len(buffer) > _MAX_PENDING_BYTES:
            del buffer[: len(buffer) - _MAX_PENDING_BYTES]
            job.output_truncated = True
        job.activity.set()

    async def _read_stream(self, job: ProcessJob, stream: asyncio.StreamReader | None, attr: str) -> None:
        if stream is None:
            return
        while True:
            chunk = await stream.read(4096)
            if not chunk:
                return
            self._append_pending(job, attr, chunk)

    async def _watch(self, job: ProcessJob) -> None:
        try:
            await job.process.wait()
            readers = [task for task in (job.stdout_task, job.stderr_task) if task is not None]
            if readers:
                await asyncio.gather(*readers, return_exceptions=True)
            job.ended_perf = time.perf_counter()
            job.ended_at = datetime.now().astimezone().isoformat(timespec='seconds')
            job.activity.set()
        finally:
            if job.activity_release is not None:
                job.activity_release()
                job.activity_release = None

    async def start(
        self,
        *,
        workspace_key: str,
        command: str,
        cwd: Path,
        cwd_label: str,
        active_root: Path,
        environment: 'WorkspaceEnvironment',
        origin_chat_id: str = '',
        output_policy: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        command = str(command or '').strip()
        if not command:
            raise ValueError('command must not be empty')
        if environment is None:
            raise RuntimeError('Workspace process jobs require a sandboxed environment; host execution is disabled.')
        environment_id = str(getattr(environment.config, 'id', '') or '')
        environment_name = str(getattr(environment.config, 'name', '') or '')
        from harnessy.environment import EnvironmentManager
        from harnessy.environment.base import EnvironmentModelAccessError
        current = EnvironmentManager(environment.workspace_root).get(environment_id)
        if current is None or not current.enabled or not current.allows_project(origin_chat_id):
            raise EnvironmentModelAccessError('This Project/Chat does not have model access to this VM environment.')
        release_activity = acquire_activity(environment.workspace_root, 'Process · ' + command[:80],
                                            environment_id=environment_id, project_id=origin_chat_id,
                                            owner_id=str((output_policy or {}).get('_file_view_owner_id') or ''))
        process = None
        try:
            spawn_kwargs: dict[str, Any] = {
                'cwd': cwd_label,
                'active_root': active_root,
                'output_policy': output_policy,
            }
            process = await environment.spawn(command, **spawn_kwargs)
            # Preparation belongs to this tool call. The running job must keep
            # a distinct lease so another tool in the same run cannot exempt it.
            release_running = acquire_activity(environment.workspace_root, 'Process · ' + command[:80],
                environment_id=environment_id, project_id=origin_chat_id, owner_id=uuid.uuid4().hex)
            release_activity()
            release_activity = release_running
        except BaseException:
            release_activity()
            if process is not None and process.returncode is None:
                await environment.terminate(process)
            raise
        try:
            runtime_identity = dict(environment.runtime_identity() or {})
        except Exception:
            runtime_identity = {}
        job = ProcessJob(
            id=f'job_{uuid.uuid4().hex[:12]}',
            workspace_key=workspace_key,
            command=command,
            cwd=cwd,
            cwd_label=cwd_label,
            process=process,
            environment=environment,
            started_at=datetime.now().astimezone().isoformat(timespec='seconds'),
            started_perf=time.perf_counter(),
            activity_release=release_activity,
            origin_chat_id=origin_chat_id,
            environment_id=environment_id, environment_name=environment_name,
            runtime_identity_start={key: value for key, value in runtime_identity.items()
                                    if key in {'environment_id', 'vm_generation', 'vm_boot_id',
                                               'vm_lifecycle_event', 'vm_lifecycle_updated_at'}},
        )
        self._jobs[job.id] = job
        job.stdout_task = asyncio.create_task(self._read_stream(job, process.stdout, 'stdout_pending'))
        job.stderr_task = asyncio.create_task(self._read_stream(job, process.stderr, 'stderr_pending'))
        job.watcher_task = asyncio.create_task(self._watch(job))
        return self._summary(job)

    @staticmethod
    def _summary(job: ProcessJob) -> dict[str, Any]:
        return {
            'ok': True,
            'job_id': job.id,
            'pid': job.process.pid,
            'command': job.command,
            'working_directory': job.cwd_label,
            'status': job.status,
            'returncode': job.process.returncode,
            'started_at': job.started_at,
            'ended_at': job.ended_at,
            'duration_seconds': job.duration_seconds,
            'environment': 'workspace-vm',
            'environment_id': job.environment_id,
            'environment_name': job.environment_name,
            'project_files_mode': job.environment.config.files_mode,
            'runtime_identity_start': job.runtime_identity_start,
        }

    @staticmethod
    def _drain(job: ProcessJob) -> tuple[str, str, bool]:
        stdout = bytes(job.stdout_pending).decode('utf-8', errors='replace')
        stderr = bytes(job.stderr_pending).decode('utf-8', errors='replace')
        job.stdout_pending.clear()
        job.stderr_pending.clear()
        truncated = job.output_truncated
        job.output_truncated = False
        return stdout, stderr, truncated

    async def poll(self, *, workspace_key: str, job_id: str, wait_seconds: float = 0.0,
                   origin_chat_id: str | None = None, environment_id: str | None = None) -> dict[str, Any]:
        job = self._job_for(workspace_key, job_id, origin_chat_id, environment_id)
        if not self._model_access_current(job):
            return self._withheld_poll(job)
        wait_seconds = max(0.0, min(float(wait_seconds or 0.0), 30.0))
        if wait_seconds and not job.stdout_pending and not job.stderr_pending and job.process.returncode is None:
            job.activity.clear()
            if not job.stdout_pending and not job.stderr_pending and job.process.returncode is None:
                try:
                    await asyncio.wait_for(job.activity.wait(), timeout=wait_seconds)
                except asyncio.TimeoutError:
                    pass
        # Give stream-reader tasks one loop turn to drain final bytes after exit.
        if job.process.returncode is not None:
            await asyncio.sleep(0)
        if not self._model_access_current(job):
            return self._withheld_poll(job)
        stdout, stderr, truncated = self._drain(job)
        return {
            **self._summary(job),
            'stdout': stdout,
            'stderr': stderr,
            'output_truncated': truncated,
        }

    async def send_input(
        self,
        *,
        workspace_key: str,
        job_id: str,
        text: str,
        append_newline: bool = True,
        origin_chat_id: str | None = None,
        environment_id: str | None = None,
    ) -> dict[str, Any]:
        job = self._job_for(workspace_key, job_id, origin_chat_id, environment_id)
        # A job retains its original provider. Revoking model access must also
        # stop later stdin from turning an already-started shell into a bypass.
        from harnessy.environment import EnvironmentManager
        current = EnvironmentManager(job.environment.workspace_root).get(job.environment_id)
        if current is None or not current.enabled or not current.allows_project(job.origin_chat_id):
            return {**self._summary(job), 'ok': False, 'error_code': 'VM_PROJECT_ACCESS_DENIED',
                    'error': 'This Project/Chat no longer has model access to this job\'s VM. Input was not sent.'}
        if job.process.returncode is not None:
            return {**self._summary(job), 'ok': False, 'error': 'Process is no longer running.'}
        if job.process.stdin is None:
            return {**self._summary(job), 'ok': False, 'error': 'Process stdin is unavailable.'}
        text = str(text)
        if len(text) > 200_000:
            raise ValueError('input is limited to 200000 characters per call')
        payload = text + ('\n' if append_newline else '')
        encoded = payload.encode('utf-8')
        await job.environment.stdin(job.process, encoded)
        return {**self._summary(job), 'characters_sent': len(payload)}

    async def stop(
        self,
        *,
        workspace_key: str,
        job_id: str,
        grace_seconds: float = 3.0,
        origin_chat_id: str | None = None,
        environment_id: str | None = None,
    ) -> dict[str, Any]:
        job = self._job_for(workspace_key, job_id, origin_chat_id, environment_id)
        if job.process.returncode is not None:
            return self._summary(job)
        job.stop_requested = True
        grace_seconds = max(0.1, min(float(grace_seconds or 3.0), 15.0))
        await job.environment.terminate(job.process, grace_seconds=grace_seconds)
        if job.watcher_task is not None:
            try:
                await asyncio.wait_for(asyncio.shield(job.watcher_task), timeout=1.0)
            except asyncio.TimeoutError:
                pass
        return self._summary(job)

    def has_running(self, *, workspace_key: str, chat_id: str | None = None,
                    environment_id: str | None = None) -> bool:
        return any(job.workspace_key == workspace_key and job.process.returncode is None
                   and (chat_id is None or job.origin_chat_id == chat_id)
                   and (environment_id is None or job.environment_id == environment_id)
                   for job in self._jobs.values())

    def list(self, *, workspace_key: str, origin_chat_id: str | None = None,
             environment_id: str | None = None) -> dict[str, Any]:
        jobs = [job for job in self._jobs.values() if job.workspace_key == workspace_key
                and (origin_chat_id is None or job.origin_chat_id == origin_chat_id)
                and (environment_id is None or job.environment_id == environment_id)]
        jobs.sort(key=lambda job: job.started_perf, reverse=True)
        return {'ok': True, 'jobs': [self._summary(job) for job in jobs]}

    def terminate_all_sync(self) -> None:
        """Best-effort cleanup so model-owned jobs are not orphaned on exit."""
        for job in list(self._jobs.values()):
            if job.process.returncode is not None:
                continue
            job.stop_requested = True
            try:
                # Killing the fixed Lima controller triggers the guest wrapper's
                # HUP/TERM trap, which terminates the owned guest process group.
                job.process.kill()
            except (OSError, ProcessLookupError):
                pass


PROCESS_JOBS = ProcessJobManager()
atexit.register(PROCESS_JOBS.terminate_all_sync)
