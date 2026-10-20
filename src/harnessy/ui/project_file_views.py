"""Requested project access and verified, provider-reported runtime file views."""
from __future__ import annotations

from typing import Any

from nicegui import ui

from harnessy.environment import EnvironmentManager
from harnessy.environment.file_views import FILE_VIEWS


def file_view_label(state: str, *, copy_mode: bool = False) -> str:
    return {
        'ready': 'Copy view ready' if copy_mode else 'Mounted',
        'mounted': 'Copy view ready' if copy_mode else 'Mounted',
        'pending': 'Access update pending' if copy_mode else 'Unmount pending',
        'preparing': 'Preparing…',
        'reconciling': 'Preparing…',
        'stopped': 'VM stopped',
        'unsupported': 'Unsupported',
        'error': 'Failed',
        'failed': 'Failed',
        'unmounted': 'Unmounted',
        'retired': 'Unmounted',
        'removed': 'Unmounted',
    }.get(state, 'Checking…')


def render_file_view_status(workspace, environment_id: str, *, project_id: str | None = None,
                            compact: bool = False) -> Any:
    with ui.column().classes('w-full gap-1 min-w-0').props(f'data-hy-file-views={environment_id}') as panel:
        with ui.row().classes('w-full items-center gap-2 flex-wrap'):
            ui.label('Project files').classes('text-sm font-semibold')
            badge = ui.badge('Checking…').props('color=grey')
            spinner = ui.spinner(size='16px')
            ui.space()
            retry = ui.button('Retry file views', icon='refresh').props('flat dense no-caps')
        detail = ui.label('').classes('text-xs hy-muted').style('white-space:pre-wrap;overflow-wrap:anywhere')
        error = ui.label('').classes('text-xs text-negative').style('white-space:pre-wrap;overflow-wrap:anywhere')
        pending = ui.label('').classes('text-xs text-warning').style('overflow-wrap:anywhere')
        pending.set_visibility(False)
        with ui.expansion('Runtime file views', icon='folder_open', value=False).classes('w-full min-w-0') as expansion:
            ui.label('Saved access is the requested policy. These states show what has actually been verified in this VM.').classes('text-xs hy-muted')
            rows = ui.column().classes('w-full gap-2 min-w-0')
        expansion.set_visibility(not compact)

    previous = {'rows': None}

    def refresh() -> None:
        if panel.is_deleted:
            timer.cancel()
            return
        try:
            config = EnvironmentManager(workspace.root).get(environment_id)
            if config is None:
                raise ValueError('This VM environment is no longer registered.')
            status = FILE_VIEWS.status(workspace.root, environment_id=environment_id)
            state = str(status.get('state') or 'preparing')
            projects = [dict(row) for row in status.get('projects') or () if isinstance(row, dict)]
            if project_id is not None:
                projects = [row for row in projects if row.get('project_id') == project_id]
                selected_row = projects[0] if projects else {}
                state = str(selected_row.get('state') or state)
            copy_mode = config.files_mode == 'copy'
            stage = str(status.get('stage') or '')
            requested = status.get('requested_revision')
            applied = status.get('applied_revision')
            waiting = state in {'preparing', 'reconciling'} or project_id is None and (bool(status.get('busy')) or state == 'ready' and requested != applied)
            effective_state = 'preparing' if waiting else state
            pending_ids = set(status.get('pending_project_ids') or ())
            in_use = stage == 'in_use' or not stage and bool(pending_ids)
            badge.set_text('Update pending' if effective_state == 'pending' and not in_use else file_view_label(effective_state, copy_mode=copy_mode))
            badge.props('color=negative' if state in {'error', 'failed', 'unsupported'} else 'color=warning' if state == 'pending' else 'color=positive' if effective_state in {'ready', 'mounted'} else 'color=grey')
            spinner.set_visibility(waiting)
            if project_id is not None and projects and state in {'ready', 'mounted'}:
                detail.set_text(str(projects[0].get('detail') or ''))
                error.set_text(str(projects[0].get('error') or ''))
            else:
                detail.set_text(str((projects[0].get('detail') if project_id is not None and projects else '') or status.get('detail') or ''))
                error.set_text(str(status.get('error') or ''))
            pending.set_text(
                'Finish this project’s tasks and close its project-files terminals, then retry. Unrelated projects can continue.'
                if project_id is not None else
                'Finish the affected projects’ tasks and close their project-files terminals, then retry. Unrelated projects can continue.'
            )
            pending.set_visibility(in_use and (state == 'pending' or (project_id in pending_ids if project_id is not None else bool(pending_ids))))
            retry.set_enabled(not waiting)
            labels = {}
            for row in projects:
                ident = str(row.get('project_id') or '')
                chat = workspace.get_chat(ident) if ident else None
                labels[ident] = f'{chat.title} · {chat.public_id}' if chat is not None else str(row.get('folder') or 'Unavailable project')
            signature = tuple((str(row.get('project_id') or ''), str(row.get('folder') or ''),
                               str(row.get('state') or ''), str(row.get('detail') or ''), labels[str(row.get('project_id') or '')]) for row in projects)
            if signature != previous['rows']:
                previous['rows'] = signature
                rows.clear()
                with rows:
                    if not projects:
                        ui.label('No project views are currently recorded.').classes('text-xs hy-muted')
                    for row in projects:
                        ident = str(row.get('project_id') or '')
                        title = labels[ident]
                        with ui.column().classes('w-full gap-0 min-w-0').props(f'data-hy-file-view-project={ident}'):
                            with ui.row().classes('w-full items-start gap-2 no-wrap'):
                                ui.label(title).classes('text-xs grow min-w-0').style('overflow-wrap:anywhere')
                                ui.label(file_view_label(str(row.get('state') or ''), copy_mode=copy_mode)).classes('text-xs font-semibold shrink-0')
                            if row.get('detail'):
                                ui.label(str(row['detail'])).classes('text-xs hy-muted').style('white-space:pre-wrap;overflow-wrap:anywhere')
        except Exception as exc:
            badge.set_text('Status unavailable')
            badge.props('color=negative')
            spinner.set_visibility(False)
            error.set_text(str(exc))
            retry.set_enabled(True)

    def retry_views() -> None:
        try:
            FILE_VIEWS.request(workspace.root, reason='manual_retry', environment_id=environment_id,
                               project_ids=[project_id] if project_id is not None else None)
            refresh()
        except Exception as exc:
            error.set_text(str(exc))

    retry.on('click', retry_views)
    timer = ui.timer(1.0, refresh)
    refresh()
    return panel
