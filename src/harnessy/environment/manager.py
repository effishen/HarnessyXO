from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
import re
import uuid

from .base import EnvironmentConfig, WorkspaceEnvironment, load_environment_config, save_environment_config
from .lima import LimaVMEnvironment
from .presets import PRESETS


_PROVIDER_CACHE: dict[str, tuple[dict, WorkspaceEnvironment]] = {}
_OPERATION_CONTEXT: ContextVar[tuple[str, str]] = ContextVar('environment_operation', default=('', ''))
_OPERATION_ACTIONS = frozenset({'create', 'start', 'stop', 'reset', 'rebuild', 'destroy',
                              'restore', 'snapshot', 'tools', 'network', 'resources'})


def current_environment_operation() -> dict[str, str]:
    """Return task-local correlation, never another task's cached provider state."""
    operation_id, action = _OPERATION_CONTEXT.get()
    return {'operation_id': operation_id, 'environment_action': action} if operation_id else {}


@contextmanager
def environment_operation_context(operation_id: str = '', action: str = ''):
    """Correlate nested controller calls, including asyncio.wait_for children.

    A UI operation supplies its existing ID. Standalone lifecycle requests get
    one ID that is retained by nested reset/stop/start calls. Context restoration
    also prevents status polls on the shared provider inheriting stale IDs.
    """
    previous_id, previous_action = _OPERATION_CONTEXT.get()
    supplied_id = operation_id if isinstance(operation_id, str) and re.fullmatch(r'[0-9a-f]{32}', operation_id) else ''
    context = (supplied_id or previous_id or uuid.uuid4().hex,
               action if action in _OPERATION_ACTIONS and (supplied_id or not previous_id) else previous_action)
    token = _OPERATION_CONTEXT.set(context)
    try:
        yield current_environment_operation()
    finally:
        _OPERATION_CONTEXT.reset(token)


class EnvironmentManager:
    def __init__(self, workspace_root: str | Path) -> None:
        self.workspace_root = Path(workspace_root).expanduser().resolve()

    @property
    def config(self) -> EnvironmentConfig | None:
        return load_environment_config(self.workspace_root)

    @property
    def is_vm_workspace(self) -> bool:
        cfg = self.config
        return bool(cfg and cfg.type == 'vm')

    @staticmethod
    def _validate_config(cfg: EnvironmentConfig) -> None:
        if cfg.type != 'vm':
            raise RuntimeError(f'Unsupported environment type: {cfg.type}')
        if cfg.provider != 'lima':
            raise RuntimeError(f'Unsupported VM provider: {cfg.provider}')
        if cfg.preset not in PRESETS:
            raise RuntimeError(f'Unsupported environment preset: {cfg.preset}')
        image = PRESETS[cfg.preset].image
        if cfg.architecture not in image.architectures:
            raise RuntimeError(f'Unsupported architecture for {image.name}: {cfg.architecture}')
        if image.integration != 'linux-systemd':
            raise RuntimeError('This guest needs a separate, implemented isolation/command/file integration.')
        if cfg.files_mode == 'copy':
            raise NotImplementedError('Lima copy/snapshot Files mode is not implemented yet; use files_mode=live.')
        if cfg.files_mode != 'live':
            raise RuntimeError(f'Unsupported Files bridge mode: {cfg.files_mode}')

    def initialize(self, config: EnvironmentConfig | None = None) -> EnvironmentConfig:
        cfg = (config or EnvironmentConfig()).normalized()
        self._validate_config(cfg)
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        (self.workspace_root / 'Files').mkdir(parents=True, exist_ok=True)
        env_root = self.workspace_root / '.harnessy' / 'environment'
        for path in (env_root / 'vm', env_root / 'snapshots', env_root / 'templates', env_root / 'state'):
            path.mkdir(parents=True, exist_ok=True)
        save_environment_config(self.workspace_root, cfg)
        self.provider(cfg)  # creates provider-owned directory skeleton
        return cfg

    def provider(self, config: EnvironmentConfig | None = None) -> WorkspaceEnvironment:
        cfg = (config or self.config)
        if cfg is None:
            raise RuntimeError('Workspace has no environment.json. Create or rebuild the workspace environment first.')
        self._validate_config(cfg)
        cache_key = str(self.workspace_root)
        signature = cfg.to_dict()
        cached = _PROVIDER_CACHE.get(cache_key)
        if cached is not None and cached[0] == signature:
            return cached[1]
        provider = LimaVMEnvironment(self.workspace_root, cfg)
        _PROVIDER_CACHE[cache_key] = (signature, provider)
        return provider


def clear_environment_provider_cache(workspace_root: str | Path | None = None) -> None:
    if workspace_root is None:
        _PROVIDER_CACHE.clear()
        return
    _PROVIDER_CACHE.pop(str(Path(workspace_root).expanduser().resolve()), None)


def initialize_workspace_environment(workspace_root: str | Path, config: EnvironmentConfig | None = None) -> EnvironmentConfig:
    return EnvironmentManager(workspace_root).initialize(config)
