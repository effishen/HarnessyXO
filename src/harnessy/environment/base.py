from __future__ import annotations

import abc
import asyncio
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .presets import canonical_arch


ENVIRONMENT_SCHEMA_VERSION = 2


@dataclass(slots=True)
class EnvironmentConfig:
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
        if mode not in {'live', 'copy'}:
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
        return EnvironmentConfig(
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
        self.environment_root = self.meta_root / 'environment'

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
        await self.start()
        return self.terminal_command(active_root=active_root)

    def runtime_identity(self) -> dict[str, Any]:
        """Return cheap, non-blocking lifecycle identity for tool provenance.

        Providers may override this with persisted readiness/lifecycle state. It
        must not perform network/controller I/O because it is attached to normal
        model tool results.
        """
        return {
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


def config_path(workspace_root: Path) -> Path:
    return Path(workspace_root).resolve() / '.harnessy' / 'environment' / 'environment.json'


def save_environment_config(workspace_root: Path, config: EnvironmentConfig) -> Path:
    path = config_path(workspace_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(config.normalized().to_dict(), indent=2) + '\n', encoding='utf-8')
    tmp.replace(path)
    return path


def load_environment_config(workspace_root: Path) -> EnvironmentConfig | None:
    path = config_path(workspace_root)
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text('utf-8'))
    except (OSError, json.JSONDecodeError):
        return None
    return EnvironmentConfig.from_dict(raw if isinstance(raw, dict) else {})
