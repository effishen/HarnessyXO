"""Visible project VM-access warnings based only on current saved grants."""
from __future__ import annotations

import asyncio
from typing import Any

from harnessy.environment import EnvironmentManager


def project_vm_access_state(workspace: Any, chat_id: str) -> dict[str, Any]:
    """Check configuration, without selecting, starting or probing a guest.

    A stopped VM with an enabled exact-project grant is available to the
    project: the model can start it later.  Parent/child project membership
    never substitutes for the current project's own VM grant.
    """
    try:
        chat = workspace.get_chat(str(chat_id))
        if chat is None:
            return {'code': 'project_unavailable', 'warning': False,
                    'title': '', 'detail': '', 'environment_id': None}
        if chat.archived_at is not None or chat.locked:
            return {'code': 'project_readonly', 'warning': False,
                    'title': '', 'detail': '', 'environment_id': None}
        configs = EnvironmentManager(workspace.root).list()
        enabled = [config for config in configs if config.enabled]
        allowed = [config for config in enabled if config.allows_project(chat.id)]
        if allowed:
            return {'code': 'available', 'warning': False, 'title': '', 'detail': '',
                    'environment_id': allowed[0].id,
                    'vm_count': len(configs), 'enabled_count': len(enabled),
                    'allowed_count': len(allowed)}
        if not configs:
            return {'code': 'no_vms', 'warning': True,
                    'title': 'This project has no VM to use.',
                    'detail': 'Create a VM in this workspace and allow this project before asking it to run commands.',
                    'environment_id': None, 'vm_count': 0,
                    'enabled_count': 0, 'allowed_count': 0}
        if not enabled:
            return {'code': 'all_disabled', 'warning': True,
                    'title': 'All VMs are disabled for model use.',
                    'detail': 'Open VM Settings, enable a VM for model use, and allow this project.',
                    'environment_id': configs[0].id, 'vm_count': len(configs),
                    'enabled_count': 0, 'allowed_count': 0}
        # An allowed but disabled VM is the simplest settings target; otherwise
        # show an enabled VM whose exact project access can be updated.
        disabled_allowed = next((config for config in configs
                                 if not config.enabled and config.allows_project(chat.id)), None)
        selected = disabled_allowed or enabled[0]
        return {'code': 'project_denied', 'warning': True,
                'title': 'This project cannot use any enabled VM.',
                'detail': 'Open VM Settings to allow this project, or enable a VM that already allows it.',
                'environment_id': selected.id, 'vm_count': len(configs),
                'enabled_count': len(enabled), 'allowed_count': 0}
    except Exception:
        # Registry errors must not masquerade as an empty workspace, and raw
        # exception text can contain host paths or other unrelated information.
        return {'code': 'check_unavailable', 'warning': True,
                'title': 'VM access could not be checked.',
                'detail': 'Open VM Environments to review this workspace\'s saved VMs and project access.',
                'environment_id': None}


def render_project_vm_warning(page: Any, workspace: Any, chat_id: str) -> Any:
    """Render immediately above a composer; refresh grants without guest I/O."""
    from nicegui import ui

    state = project_vm_access_state(workspace, chat_id)
    with ui.row().classes('w-full items-start no-wrap gap-2 p-3 rounded-lg') \
            .style('border:1px solid rgba(217,119,6,.38); background:rgba(217,119,6,.08)') \
            .props('role=status aria-live=polite data-hy-project-vm-access-warning=true') as panel:
        ui.icon('warning_amber', size='20px').classes('text-warning shrink-0')
        with ui.column().classes('grow min-w-0 gap-1'):
            title = ui.label('').classes('text-sm font-semibold').style('overflow-wrap:anywhere')
            detail = ui.label('').classes('text-xs hy-muted').style('overflow-wrap:anywhere')

        def open_settings(_event: Any = None) -> None:
            from harnessy.ui.vm_environments import open_vm_settings
            fresh = project_vm_access_state(workspace, chat_id)
            open_vm_settings(page, workspace, fresh.get('environment_id'))

        ui.button('VM Environments', icon='settings', on_click=open_settings) \
            .props('flat dense no-caps').classes('shrink-0')

    def alive() -> bool:
        return not bool(getattr(panel, 'is_deleted', False)) and not bool(
            getattr(getattr(panel, 'client', None), 'is_deleted', False))

    def apply(current: dict[str, Any]) -> None:
        title.set_text(str(current.get('title') or ''))
        detail.set_text(str(current.get('detail') or ''))
        panel.props('data-hy-project-vm-access-state=' + str(current['code']))
        panel.set_visibility(bool(current.get('warning')))

    busy = False

    async def refresh() -> None:
        nonlocal busy
        if not alive():
            timer.cancel()
            return
        if busy:
            return
        busy = True
        try:
            fresh = await asyncio.to_thread(project_vm_access_state, workspace, chat_id)
            if not alive():
                timer.cancel()
                return
            apply(fresh)
        finally:
            busy = False

    apply(state)
    with panel:
        timer = ui.timer(5.0, refresh)
    return panel
