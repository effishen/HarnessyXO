from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
import re
import uuid
import shutil
import json
import time

from .base import (EnvironmentConfig, WorkspaceEnvironment, load_environment_config, save_environment_config,
                   environment_root, config_path, ENVIRONMENT_ID_RE, _validate_registry_path, environment_config_lock)
from .lima import LimaVMEnvironment
from .presets import PRESETS


_PROVIDER_CACHE: dict[tuple[str, str], tuple[dict, WorkspaceEnvironment]] = {}
_OPERATION_CONTEXT: ContextVar[tuple[str, str]] = ContextVar('environment_operation', default=('', ''))
_OPERATION_ACTIONS = frozenset({'create', 'start', 'stop', 'reset', 'rebuild', 'destroy',
                              'restore', 'snapshot', 'tools', 'network', 'resources', 'remove'})


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
    """Workspace-owned registry of independent named VM environments.

    The optional selection is local to this manager. It never changes a global
    "current VM", so a run and its processes cannot be redirected by another
    chat or browser tab selecting a different environment.
    """

    def __init__(self, workspace_root: str | Path, environment_id: str | None = None) -> None:
        self.workspace_root = Path(workspace_root).expanduser().resolve()
        self._selection = str(environment_id) if environment_id is not None else None
        from .file_views import FILE_VIEWS
        FILE_VIEWS.observe(self.workspace_root)

    def list(self) -> list[EnvironmentConfig]:
        registry = self.workspace_root / '.harnessy' / 'environments'
        _validate_registry_path(registry, self.workspace_root)
        configs: list[EnvironmentConfig] = []
        if registry.is_dir():
            for entry in sorted(registry.iterdir(), key=lambda item: item.name):
                if not ENVIRONMENT_ID_RE.fullmatch(entry.name):
                    continue
                _validate_registry_path(entry, self.workspace_root)
                if not entry.is_dir():
                    continue
                path = entry / 'environment.json'
                if not path.exists():
                    continue
                cfg = load_environment_config(self.workspace_root, entry.name)
                if cfg is None:
                    if not path.exists():
                        continue  # A completed Remove may delete it during this scan.
                    raise RuntimeError(f'Cannot read VM environment definition: {entry.name}.')
                self._validate_config(cfg)
                configs.append(cfg)
        # Retain a previously installed singleton without relocating its disks.
        # New workspaces and every newly created environment use the registry.
        legacy = load_environment_config(self.workspace_root, '')
        if legacy is not None:
            self._validate_config(legacy)
            configs.append(legacy)
        return sorted(configs, key=lambda cfg: (cfg.name.casefold(), cfg.id))

    def get(self, environment_id: str) -> EnvironmentConfig | None:
        key = str(environment_id or '')
        configs = self.list()
        exact = next((cfg for cfg in configs if cfg.id == key), None)
        if exact is not None:
            return exact
        matches = [cfg for cfg in configs if cfg.name.casefold() == key.casefold()]
        if len(matches) > 1:
            raise ValueError('More than one VM has this name. Select it by environment ID.')
        return matches[0] if matches else None

    @property
    def config(self) -> EnvironmentConfig | None:
        if self._selection is not None:
            return self.get(self._selection)
        # Match the compatibility helper's deterministic default. Explicit
        # run/chat selections always supply an ID and never use this fallback.
        self.list()  # validate every visible registry entry before choosing
        return load_environment_config(self.workspace_root)

    @property
    def environment_id(self) -> str:
        cfg = self.config
        return cfg.id if cfg else ''

    @property
    def environment_root(self) -> Path:
        cfg = self.config
        if cfg is None:
            raise RuntimeError('This workspace has no VM environment selected.')
        return environment_root(self.workspace_root, cfg.id)

    @property
    def is_vm_workspace(self) -> bool:
        return bool(self.list())

    @staticmethod
    def _validate_config(cfg: EnvironmentConfig) -> None:
        if cfg.type != 'vm':
            raise RuntimeError(f'Unsupported environment type: {cfg.type}')
        if cfg.id and not ENVIRONMENT_ID_RE.fullmatch(cfg.id):
            raise ValueError('Invalid VM environment ID.')
        if cfg.provider not in {'lima', 'openwrt', 'managed'}:
            raise RuntimeError(f'Unsupported VM provider: {cfg.provider}')
        if cfg.preset not in PRESETS:
            raise RuntimeError(f'Unsupported environment preset: {cfg.preset}')
        image = PRESETS[cfg.preset].image
        if cfg.architecture not in image.architectures:
            raise RuntimeError(f'Unsupported architecture for {image.name}: {cfg.architecture}')
        expected = {'openwrt': 'openwrt', 'managed': 'managed', 'lima': 'linux-systemd'}[cfg.provider]
        if image.integration != expected:
            raise RuntimeError('This image needs its own isolation, command and file integration.')
        if cfg.files_mode not in {'live', 'readonly', 'copy'}:
            raise RuntimeError(f'Unsupported project-files mode: {cfg.files_mode}')
        if cfg.provider == 'openwrt' and cfg.preset == 'openwrt-25.12.5' and cfg.files_mode != 'copy':
            raise ValueError('This OpenWrt release currently supports separate deployed project copies only.')
        if cfg.provider == 'managed':
            if cfg.files_mode != 'copy':
                raise ValueError('This guest supports separate deployed project copies only.')
            if cfg.preset != 'windows-11':
                raise ValueError('Unsupported managed guest image.')
            if not cfg.iso_path or any(value in cfg.iso_path for value in ('\x00', '\n', '\r')):
                raise ValueError('Select the Windows installer ISO on the HarnessyXO host.')
            if cfg.cpu < 2 or cfg.memory_mb < 4096 or cfg.disk_gb < 64:
                raise ValueError('Windows needs at least 2 CPUs, 4096 MiB RAM and 64 GiB storage.')

    def create(self, config: EnvironmentConfig | None = None) -> EnvironmentConfig:
        cfg = EnvironmentConfig.from_dict({**(config or EnvironmentConfig()).to_dict(),
                                           'id': uuid.uuid4().hex})
        self._validate_config(cfg)
        if any(old.name.casefold() == cfg.name.casefold() for old in self.list()):
            raise ValueError('A VM environment with this name already exists. Choose a different name.')
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        (self.workspace_root / 'Files').mkdir(parents=True, exist_ok=True)
        env_root = environment_root(self.workspace_root, cfg.id)
        _validate_registry_path(env_root, self.workspace_root)
        env_root.mkdir(parents=True, exist_ok=False)
        try:
            for name in ('vm', 'snapshots', 'templates', 'state'):
                (env_root / name).mkdir()
            save_environment_config(self.workspace_root, cfg)
        except BaseException:
            # Do not recursively remove a partially created directory. It may
            # contain useful failure evidence; an unregistered directory is inert.
            (env_root / 'environment.json').unlink(missing_ok=True)
            raise
        self._selection = cfg.id
        return cfg

    def initialize(self, config: EnvironmentConfig | None = None) -> EnvironmentConfig:
        return self.create(config)

    def save(self, config: EnvironmentConfig) -> EnvironmentConfig:
        cfg = config.normalized()
        self._validate_config(cfg)
        with environment_config_lock(self.workspace_root, cfg.id):
            original = self.get(cfg.id)
            if original is None:
                raise ValueError('This VM environment no longer exists.')
            if any(old.id != cfg.id and old.name.casefold() == cfg.name.casefold() for old in self.list()):
                raise ValueError('A VM environment with this name already exists.')
            old_image = PRESETS[original.preset].image_id
            new_image = PRESETS[cfg.preset].image_id
            if (original.provider, old_image, original.architecture, original.files_mode, original.desktop) != (
                    cfg.provider, new_image, cfg.architecture, cfg.files_mode, cfg.desktop):
                raise ValueError('Create a separate VM to change its OS, architecture, provider, project-files mode or graphical configuration.')
            preset_changed = cfg.preset != original.preset
            release = lambda: None
            if preset_changed:
                from .activity import reserve_environment_change
                from .operations import ENVIRONMENT_OPERATIONS
                release = reserve_environment_change(self.workspace_root, 'tool preset', environment_id=cfg.id)
                if ENVIRONMENT_OPERATIONS.state(self.workspace_root, environment_id=cfg.id).busy:
                    release()
                    raise RuntimeError('Wait for this VM operation to finish before changing its tool preset.')
            try:
                if preset_changed:
                    old_available = PRESETS[original.preset].optional_tool_ids
                    old_selected = set(old_available if '*' in original.optional_tools else original.optional_tools)
                    requested = old_selected if '*' in cfg.optional_tools else set(cfg.optional_tools)
                    retained = tuple(tool for tool in PRESETS[cfg.preset].optional_tool_ids
                                     if tool in old_selected and tool in requested)
                    cfg = EnvironmentConfig.from_dict({**cfg.to_dict(), 'optional_tools': retained})
                    # This changes desired tooling only. Do not touch VM disks,
                    # snapshots, source files, or already installed packages.
                    self._mark_tools_pending(cfg)
                save_environment_config(self.workspace_root, cfg)
                clear_environment_provider_cache(self.workspace_root, cfg.id)
                if (cfg.enabled, cfg.project_access, cfg.allowed_project_ids) != (original.enabled, original.project_access, original.allowed_project_ids):
                    from .file_views import FILE_VIEWS
                    FILE_VIEWS.request(self.workspace_root, reason='vm_project_access_changed', environment_id=cfg.id)
                if preset_changed:
                    from .status import ENVIRONMENT_STATUS
                    ENVIRONMENT_STATUS.invalidate(self.workspace_root, environment_id=cfg.id)
                return cfg
            finally:
                release()

    def _mark_tools_pending(self, config: EnvironmentConfig) -> None:
        path = environment_root(self.workspace_root, config.id) / 'state' / 'readiness.json'
        _validate_registry_path(path, self.workspace_root)
        if not path.exists():
            return  # a VM which has never started remains Not created
        if not path.is_file() or path.stat().st_size > 65536:
            raise RuntimeError('Cannot safely update this VM readiness metadata; no tool preset was changed.')
        try:
            state = json.loads(path.read_text('utf-8'))
        except json.JSONDecodeError:
            state = {}
        state = state if isinstance(state, dict) else {}
        state.update({'ready': False, 'phase': 'tools_pending', 'error': '', 'updated_at': time.time()})
        temporary = path.with_name('.readiness-' + uuid.uuid4().hex + '.tmp')
        try:
            with temporary.open('x', encoding='utf-8') as stream:
                stream.write(json.dumps(state, indent=2, sort_keys=True) + '\n')
                stream.flush()
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)

    def remove(self, environment_id: str, *, verified_stopped: bool = False) -> None:
        """Delete only an explicitly selected environment's owned metadata.

        The caller must first stop/destroy the VM. A remaining Lima instance is
        an additional stop against accidentally deleting a live virtual disk.
        This never traverses Files/, worktrees, history, or the workspace root.
        """
        cfg = self.get(environment_id)
        if cfg is None:
            raise ValueError('This VM environment no longer exists.')
        if not cfg.id:
            raise ValueError('Legacy workspace VMs must be removed through their existing VM controls.')
        root = environment_root(self.workspace_root, cfg.id)
        _validate_registry_path(root, self.workspace_root)
        from .activity import active_work
        if active_work(self.workspace_root, environment_id=cfg.id):
            raise RuntimeError("Stop this VM's active commands and terminals before removing it.")
        from .lima_runtime import bound_lima_home
        lima_home = bound_lima_home(root) if cfg.provider in {'lima', 'managed'} else root / 'vm' / 'lima'
        if not verified_stopped and ((lima_home / 'harnessy').exists()
                                     or (root / 'vm' / 'qemu.pid').exists()):
            raise RuntimeError('Stop and destroy the selected VM before removing its environment.')
        if lima_home != root / 'vm' / 'lima':
            # Only a destroyed, verified empty controller home can be removed
            # while deleting its workspace binding. Never orphan virtual disks.
            if any(lima_home.iterdir()):
                raise RuntimeError('Destroy this VM before removing its environment; its relocated storage still contains data.')
        from .file_views import FILE_VIEWS
        FILE_VIEWS.forget_environment(self.workspace_root, environment_id=cfg.id)
        if lima_home != root / 'vm' / 'lima':
            lima_home.rmdir()
        shutil.rmtree(root)
        clear_environment_provider_cache(self.workspace_root, cfg.id)

    def provider(self, config: EnvironmentConfig | None = None, *, environment_id: str | None = None) -> WorkspaceEnvironment:
        cfg = (config or (self.get(environment_id) if environment_id is not None else self.config))
        if cfg is None:
            raise RuntimeError('No VM environment is selected. Create or select a VM in Environments first.')
        self._validate_config(cfg)
        # Refuse a stale, removed configuration rather than creating a new VM
        # from a model/tool object retained by a previous run.
        current = self.get(cfg.id)
        if current is None:
            raise RuntimeError('The selected VM environment no longer exists.')
        cfg = current
        cache_key = (str(self.workspace_root), cfg.id)
        signature = cfg.to_dict()
        cached = _PROVIDER_CACHE.get(cache_key)
        if cached is not None and cached[0] == signature:
            return cached[1]
        if cfg.provider == 'openwrt':
            from .openwrt_environment import OpenWrtEnvironment
            provider = OpenWrtEnvironment(self.workspace_root, cfg)
        elif cfg.provider == 'managed':
            from .managed_environment import ManagedEnvironment
            provider = ManagedEnvironment(self.workspace_root, cfg)
        else:
            provider = LimaVMEnvironment(self.workspace_root, cfg)
        _PROVIDER_CACHE[cache_key] = (signature, provider)
        return provider


def clear_environment_provider_cache(workspace_root: str | Path | None = None,
                                     environment_id: str | None = None) -> None:
    if workspace_root is None:
        _PROVIDER_CACHE.clear()
        return
    root = str(Path(workspace_root).expanduser().resolve())
    for key in list(_PROVIDER_CACHE):
        if key[0] == root and (environment_id is None or key[1] == environment_id):
            _PROVIDER_CACHE.pop(key, None)


def initialize_workspace_environment(workspace_root: str | Path, config: EnvironmentConfig | None = None) -> EnvironmentConfig:
    return EnvironmentManager(workspace_root).initialize(config)
