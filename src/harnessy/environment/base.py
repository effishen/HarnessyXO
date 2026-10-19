from __future__ import annotations

import abc
import asyncio
import json
import re
import os
import uuid
import hashlib
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from harnessy.core.project_access import canonical_project_id, normalize_project_access, allows_project

from .presets import canonical_arch


ENVIRONMENT_SCHEMA_VERSION = 3
ENVIRONMENT_ID_RE = re.compile(r'^[0-9a-f]{32}$')
_CONFIG_WRITE_LOCKS: dict[tuple[str, str], threading.RLock] = {}
_USER_CONFIG_FIELDS = ('name', 'purpose', 'enabled', 'project_access', 'allowed_project_ids')


def environment_config_lock(workspace_root: str | Path, environment_id: str) -> threading.RLock:
    key = str(Path(workspace_root).expanduser().resolve()), str(environment_id)
    return _CONFIG_WRITE_LOCKS.setdefault(key, threading.RLock())


class EnvironmentModelAccessError(PermissionError):
    error_code = 'VM_PROJECT_ACCESS_DENIED'


@dataclass(slots=True)
class EnvironmentConfig:
    id: str = ''
    name: str = 'VM Environment'
    purpose: str = ''
    enabled: bool = True
    iso_path: str = ''
    desktop: bool = False
    emulation: dict[str, bool] = field(default_factory=lambda: {'wifi': False, 'bluetooth': False})
    project_access: str = 'all'
    allowed_project_ids: tuple[str, ...] = ()
    type: str = 'vm'
    provider: str = 'lima'
    preset: str = 'ubuntu-reverse'
    architecture: str = 'arm64'
    cpu: int = 4
    memory_mb: int = 8192
    disk_gb: int = 128
    network: bool = True
    # Optional tool identifiers selected for this workspace. ``'*'`` means all
    # optional tools exposed by the selected preset. An explicit empty tuple
    # means install none. IDs are package names plus supplemental bundle IDs
    # (for example ``ghidra`` and ``python-re``).
    optional_tools: tuple[str, ...] = ('*',)
    gpu: bool = False
    files_mode: str = 'live'
    schema_version: int = ENVIRONMENT_SCHEMA_VERSION

    @staticmethod
    def _bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            parsed = default
        return max(minimum, min(parsed, maximum))

    @staticmethod
    def _bool(value: Any, default: bool) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {'1', 'true', 'yes', 'on', 'enabled'}:
                return True
            if lowered in {'0', 'false', 'no', 'off', 'disabled'}:
                return False
        return default

    def normalized(self) -> 'EnvironmentConfig':
        mode = str(self.files_mode or 'live').strip().lower()
        if mode not in {'live', 'readonly', 'copy'}:
            mode = 'invalid'  # provider/manager reject rather than weakening isolation
        raw_optional = self.optional_tools
        if isinstance(raw_optional, str):
            optional_values = (raw_optional,)
        elif isinstance(raw_optional, (list, tuple, set)):
            optional_values = tuple(str(v or '').strip() for v in raw_optional)
        else:
            optional_values = ('*',)
        optional_clean: list[str] = []
        seen_optional: set[str] = set()
        for value in optional_values:
            value = value.strip()
            if not value or value in seen_optional:
                continue
            seen_optional.add(value)
            optional_clean.append(value)
        # Missing/invalid legacy values mean the old default: every optional
        # tool selected. An explicit empty tuple/list remains empty.
        if raw_optional is None:
            optional_clean = ['*']
        access_policy = normalize_project_access({'project_access': self.project_access,
                                                  'allowed_project_ids': self.allowed_project_ids})
        return EnvironmentConfig(
            id=str(self.id or '').strip().lower(),
            name=' '.join(str(self.name or 'VM Environment').split())[:120] or 'VM Environment',
            purpose=str(self.purpose or '').strip()[:2000],
            enabled=self._bool(self.enabled, True),
            iso_path=str(self.iso_path or '').strip(),
            desktop=self._bool(self.desktop, False),
            emulation={key: self._bool((self.emulation if isinstance(self.emulation, dict) else {}).get(key), False)
                       for key in ('wifi', 'bluetooth')},
            project_access=access_policy['project_access'],
            allowed_project_ids=tuple(access_policy['allowed_project_ids']),
            type='vm',
            provider=str(self.provider or 'lima').strip().lower(),
            preset=str(self.preset or 'ubuntu-reverse').strip().lower(),
            architecture=canonical_arch(self.architecture or 'arm64'),
            cpu=self._bounded_int(self.cpu, 4, 1, 64),
            memory_mb=self._bounded_int(self.memory_mb, 8192, 1024, 262144),
            disk_gb=self._bounded_int(self.disk_gb, 128, 16, 4096),
            network=self._bool(self.network, True),
            optional_tools=tuple(optional_clean),
            gpu=False,  # Workspace VMs are intentionally CPU-only.
            files_mode=mode,
            schema_version=ENVIRONMENT_SCHEMA_VERSION,
        )

    @staticmethod
    def _project_id(value: Any) -> str:
        return canonical_project_id(value)

    def allows_project(self, chat_id: str) -> bool:
        """Exact project/chat membership; parent/child relationships confer none."""
        return allows_project({'project_access': self.project_access,
                               'allowed_project_ids': self.allowed_project_ids}, chat_id)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self.normalized())

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> 'EnvironmentConfig':
        data = dict(data or {})
        # Schema 1 had no optional-tool selector and therefore behaved as if all
        # preset optional tools were selected.
        if 'optional_tools' not in data:
            data['optional_tools'] = ('*',)
        allowed = {field for field in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in allowed}).normalized()


@dataclass(slots=True)
class EnvironmentStatus:
    state: str
    provider: str
    available: bool
    created: bool
    running: bool
    detail: str = ''
    backend_version: str = ''
    guest_architecture: str = 'arm64'
    guest_os: str = 'Ubuntu 24.04 LTS'
    files_mount: str = '/workspace'
    cpu_only: bool = True
    disk_usage_bytes: int | None = None
    ready: bool = False
    phase: str = ''
    error: str = ''
    environment_id: str = ''
    environment_name: str = ''

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ExecResult:
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class WorkspaceEnvironment(abc.ABC):
    def __init__(self, workspace_root: Path, config: EnvironmentConfig) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.config = config.normalized()
        self.files_root = self.workspace_root / 'Files'
        self.meta_root = self.workspace_root / '.harnessy'
        self.private_worktrees_root = self.meta_root / 'worktrees'
        self.environment_root = environment_root(self.workspace_root, self.config.id)

    @abc.abstractmethod
    async def create(self, progress=None) -> EnvironmentStatus: ...

    @abc.abstractmethod
    async def start(self, progress=None) -> EnvironmentStatus: ...

    @abc.abstractmethod
    async def stop(self, *, force: bool = False) -> EnvironmentStatus: ...

    @abc.abstractmethod
    async def status(self) -> EnvironmentStatus: ...

    @abc.abstractmethod
    async def exec(
        self, command: str, *, cwd: str = '/workspace', timeout: float | None = None,
        active_root: Path | None = None, output_policy: dict[str, Any] | None = None,
    ) -> ExecResult: ...

    @abc.abstractmethod
    async def spawn(
        self, command: str, *, cwd: str = '/workspace', active_root: Path | None = None,
        output_policy: dict[str, Any] | None = None,
    ) -> asyncio.subprocess.Process: ...

    async def terminate(self, process: asyncio.subprocess.Process, *, grace_seconds: float = 3.0) -> None:
        """Terminate an environment-owned controller/process without host-shell fallback."""
        if process.returncode is not None:
            return
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=max(0.1, grace_seconds))
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()

    async def stdin(self, process: asyncio.subprocess.Process, data: bytes) -> None:
        if process.stdin is None or process.returncode is not None:
            raise RuntimeError('environment process stdin is unavailable')
        process.stdin.write(data)
        await process.stdin.drain()

    async def open_terminal(self, *, active_root: Path | None = None) -> tuple[list[str], dict[str, str], Path]:
        from .activity import activity
        with activity(self.workspace_root, 'Opening VM terminal', environment_id=self.config.id):
            await self.start()
            return await asyncio.to_thread(self.terminal_command, active_root=active_root)

    async def open_guest_terminal(self) -> tuple[list[str], dict[str, str], Path]:
        """Open an explicit human console without preparing project files.

        This is separate from model execution and project terminals: callers
        must not attach a project synchronization watcher to this console.
        Providers must implement the guest transport; there is no host fallback.
        """
        raise RuntimeError('This VM provider does not support a guest console.')

    def runtime_identity(self) -> dict[str, Any]:
        """Return cheap, non-blocking lifecycle identity for tool provenance.

        Providers may override this with persisted readiness/lifecycle state. It
        must not perform network/controller I/O because it is attached to normal
        model tool results.
        """
        return {
            'environment_id': self.config.id,
            'environment_name': self.config.name,
            'environment_enabled': self.config.enabled,
            'files_mode': self.config.files_mode,
            'provider': self.config.provider,
            'vm_created': None,
            'vm_running': None,
            'vm_ready': None,
            'vm_generation': None,
            'vm_lifecycle_event': 'unknown',
            'vm_lifecycle_updated_at': None,
            'vm_boot_id': '',
            'vm_readiness_updated_at': None,
        }

    def resize_tty(self, _cols: int, _rows: int) -> None:
        # PTY resize is applied to the fixed controller process by TerminalSession
        # and propagated to the guest terminal transport.
        return None

    def mount_files(self) -> tuple[Path, str]:
        return self.files_root.resolve(), '/workspace'

    def _guest_project_key(self, active_root: Path | None) -> str:
        root = Path(active_root or (self.workspace_root / 'Files')).resolve()
        try:
            relative = root.relative_to(self.workspace_root).as_posix()
        except ValueError as exc:
            raise ValueError('Guest work directories require a project inside this workspace.') from exc
        return hashlib.sha256(relative.encode('utf-8')).hexdigest()[:20]

    def guest_work_paths(self, active_root: Path | None = None) -> dict[str, str]:
        """Default paths, resolved from the guest account home at execution.

        Each VM owns its guest home. The project key further separates build,
        Python-environment and cache data between projects in that VM. Programs
        explicitly writing ./build or .venv still write into project source.
        """
        key = self._guest_project_key(active_root)
        return {
            'HARNESSY_BUILD_ROOT': f'$HOME/.local/share/harnessy/build/{key}',
            'HARNESSY_VENV_ROOT': f'$HOME/.local/share/harnessy/venvs/{key}',
            'XDG_CACHE_HOME': f'$HOME/.cache/harnessy/{key}',
            'PYTHONPYCACHEPREFIX': f'$HOME/.cache/harnessy/{key}/pycache',
        }

    def _guest_work_path_exports(self, active_root: Path | None = None) -> str:
        """POSIX/ash-compatible setup executed after dropping guest privileges."""
        key = self._guest_project_key(active_root)
        return f'''_harnessy_home=$(awk -F: -v uid="$(id -u)" '$3 == uid {{ print $6; exit }}' /etc/passwd)
case "$_harnessy_home" in
  /workspace|/workspace/*|'') printf '%s\\n' 'HarnessyXO could not locate a VM-owned guest home for build and cache directories.' >&2; exit 72 ;;
  /*) ;;
  *) printf '%s\\n' 'HarnessyXO rejected an invalid guest home directory.' >&2; exit 72 ;;
esac
export HARNESSY_BUILD_ROOT="$_harnessy_home/.local/share/harnessy/build/{key}"
export HARNESSY_VENV_ROOT="$_harnessy_home/.local/share/harnessy/venvs/{key}"
export XDG_CACHE_HOME="$_harnessy_home/.cache/harnessy/{key}"
export PYTHONPYCACHEPREFIX="$XDG_CACHE_HOME/pycache"
mkdir -p "$HARNESSY_BUILD_ROOT" "$HARNESSY_VENV_ROOT" "$XDG_CACHE_HOME" "$PYTHONPYCACHEPREFIX" || exit 72
unset _harnessy_home
'''

    def _authorize_model_project(self, output_policy: dict[str, Any] | None) -> None:
        """Recheck a trusted model caller after startup or project preparation.

        Human terminals omit this controller-internal key. Model tool payloads
        never choose their own project ID; the toolbox supplies its chat ID.
        """
        if not isinstance(output_policy, dict) or '_model_project_id' not in output_policy:
            return
        current = load_environment_config(self.workspace_root, self.config.id)
        if current is None or not current.enabled or not current.allows_project(output_policy['_model_project_id']):
            raise EnvironmentModelAccessError('This VM is no longer enabled for model use by this project/chat.')

    @abc.abstractmethod
    async def snapshot(self, tag: str, progress=None) -> list[str]: ...

    @abc.abstractmethod
    async def list_snapshots(self) -> list[str]: ...

    @abc.abstractmethod
    async def restore_snapshot(self, tag: str, progress=None) -> EnvironmentStatus: ...

    @abc.abstractmethod
    async def reset(self) -> EnvironmentStatus: ...

    @abc.abstractmethod
    async def rebuild(self) -> EnvironmentStatus: ...

    @abc.abstractmethod
    async def destroy(self) -> None: ...

    @abc.abstractmethod
    def terminal_command(self, *, active_root: Path | None = None) -> tuple[list[str], dict[str, str], Path]: ...

    @abc.abstractmethod
    async def inspect(self) -> dict[str, Any]: ...


def environment_root(workspace_root: Path, environment_id: str = '') -> Path:
    root = Path(workspace_root).expanduser().resolve()
    if not environment_id:
        return root / '.harnessy' / 'environment'  # existing singleton, never used for new VMs
    if not ENVIRONMENT_ID_RE.fullmatch(str(environment_id)):
        raise ValueError('VM environment ID must contain 32 lowercase hexadecimal characters.')
    return root / '.harnessy' / 'environments' / str(environment_id)


def _validate_registry_path(path: Path, workspace_root: Path) -> None:
    """Never follow a redirected controller directory or metadata file."""
    root = Path(workspace_root).expanduser().resolve()
    try:
        parts = path.relative_to(root).parts
    except ValueError as exc:
        raise ValueError('VM environment metadata is outside its workspace.') from exc
    current = root
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise ValueError('VM environment metadata cannot use symlink redirects.')


def config_path(workspace_root: Path, environment_id: str | None = None) -> Path:
    root = Path(workspace_root).expanduser().resolve()
    if environment_id is not None:
        return environment_root(root, environment_id) / 'environment.json'
    registry = root / '.harnessy' / 'environments'
    _validate_registry_path(registry, root)
    if registry.is_dir():
        for entry in sorted(registry.iterdir(), key=lambda item: item.name):
            if ENVIRONMENT_ID_RE.fullmatch(entry.name) and (entry / 'environment.json').is_file():
                return entry / 'environment.json'
    return environment_root(root) / 'environment.json'


def save_environment_config(workspace_root: Path, config: EnvironmentConfig, *,
                            preserve_user_metadata: bool = False) -> Path:
    cfg = config.normalized()
    with environment_config_lock(workspace_root, cfg.id):
        if preserve_user_metadata:
            current = load_environment_config(workspace_root, cfg.id)
            if current is None:
                raise RuntimeError('The VM environment was removed; its old definition was not restored.')
            latest = current.to_dict()
            cfg = EnvironmentConfig.from_dict({**cfg.to_dict(),
                                               **{key: latest[key] for key in _USER_CONFIG_FIELDS}})
        return _save_environment_config_locked(workspace_root, cfg)


def _save_environment_config_locked(workspace_root: Path, cfg: EnvironmentConfig) -> Path:
    path = config_path(workspace_root, cfg.id)
    _validate_registry_path(path, workspace_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f'.{path.name}.{uuid.uuid4().hex}.tmp')
    try:
        with tmp.open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(cfg.to_dict(), indent=2) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        tmp.replace(path)
    finally:
        tmp.unlink(missing_ok=True)
    return path


def load_environment_config(workspace_root: Path, environment_id: str | None = None) -> EnvironmentConfig | None:
    path = config_path(workspace_root, environment_id)
    _validate_registry_path(path, workspace_root)
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text('utf-8'))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(raw, dict):
        raise ValueError('VM environment definition must be a JSON object.')
    cfg = EnvironmentConfig.from_dict(raw)
    if ENVIRONMENT_ID_RE.fullmatch(path.parent.name) and cfg.id != path.parent.name:
        raise ValueError('VM environment definition does not match its registry ID.')
    return cfg
