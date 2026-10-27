"""Registry-bound graphical VM tabs, using the existing isolated display proxy."""
from __future__ import annotations

import re
from types import SimpleNamespace
from typing import Any

from nicegui import ui

from harnessy.environment import EnvironmentManager, ENVIRONMENT_OPERATIONS
from harnessy.environment.activity import acquire_activity

_ID = re.compile(r'^[a-f0-9]{32}$')


def vm_view_key(workspace_id: str, environment_id: str) -> str:
    if not _ID.fullmatch(str(environment_id)):
        raise ValueError('Invalid VM environment identity.')
    return f'vm_desktop:{workspace_id}:{environment_id}'


def _identity(config) -> dict[str, Any]:
    # Display access belongs to the signed-in human. Renaming a VM or disabling
    # model use must not revoke that human's view. Runtime changes do revoke it.
    return {key: value for key, value in config.to_dict().items()
            if key not in {'name', 'purpose', 'enabled', 'project_access', 'allowed_project_ids'}}


class RegistryViewManager:
    def __init__(self, workspace, config, provider, controller) -> None:
        self.workspace = workspace
        self.environment_id = config.id
        self.provider = provider
        self.controller = controller
        self._identity = _identity(config)
        self.target = SimpleNamespace(id=config.id, name=config.name)
        self.guest = controller.guest
        self.windows = bool(getattr(controller, 'windows', False))
        self.backend = str(getattr(controller, 'backend', config.provider))
        self.key = str(controller.key)
        self._desktop_checked = False

    @property
    def busy(self) -> bool:
        return (ENVIRONMENT_OPERATIONS.is_busy(self.workspace.root, environment_id=self.environment_id)
                or bool(self.controller.busy))

    def registry_valid(self) -> bool:
        config = EnvironmentManager(self.workspace.root).get(self.environment_id)
        return config is not None and _identity(config) == self._identity

    async def status(self) -> dict[str, Any]:
        if not self.registry_valid():
            raise RuntimeError('This VM environment is no longer available.')
        status = await self.provider.status()
        check = getattr(self.provider, 'verify_desktop_ready', None)
        if not self._desktop_checked and callable(check) and status.running:
            await check()
            self._desktop_checked = True
            status = await self.provider.status()
        return status.to_dict() if hasattr(status, 'to_dict') else dict(status)

    def desktop_info(self) -> dict[str, Any]:
        if not self.registry_valid():
            raise RuntimeError('This VM environment is no longer available.')
        return self.controller.desktop_info()

    def acquire(self):
        release = acquire_activity(self.workspace.root, 'VM graphical interface', environment_id=self.environment_id,
                                   project_id='__guest_console__')
        try:
            release_controller = self.controller.acquire()
        except BaseException:
            release()
            raise
        def done():
            try:
                release_controller()
            finally:
                release()
        return done

    async def set_windows_password(self, value: str) -> dict[str, Any]:
        if not self.registry_valid() or not self.windows:
            raise RuntimeError('This Windows VM is no longer available.')
        return await self.controller.set_windows_password(value)


def render_vm_tab(workbench, tab, workspace) -> None:
    from harnessy.ui.test_targets import _render_target_desktop
    environment_id = str(tab.environment_id or '')
    try:
        if tab.key != vm_view_key(workspace.id, environment_id):
            raise ValueError('This VM view has an invalid identity.')
        manager = EnvironmentManager(workspace.root, environment_id=environment_id)
        config = manager.config
        if config is None:
            raise ValueError('This VM environment no longer exists.')
        provider = manager.provider()
        controller = provider.desktop_manager(workspace)
        view_manager = RegistryViewManager(workspace, config, provider, controller)
    except (AttributeError, OSError, ValueError, RuntimeError) as exc:
        with ui.column().classes('w-full p-6 gap-2'):
            ui.label('VM interface unavailable').classes('font-semibold text-negative')
            ui.label(str(exc)).classes('text-sm hy-muted').style('overflow-wrap:anywhere')
        return
    _render_target_desktop(workbench, tab, view_manager)
