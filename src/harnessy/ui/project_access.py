"""Explicit project/chat grants for one VM; roles and tool actions stay separate."""
from __future__ import annotations

from typing import Any
from nicegui import ui
from harnessy.core.project_access import normalize_project_access


class ProjectAccessEditor:
    def __init__(self, workspace, config=None, *, subject: str = 'VM') -> None:
        self.subject = subject
        stored = config if isinstance(config, dict) else {
            key: getattr(config, key, default) for key, default in (('project_access', 'all'), ('allowed_project_ids', ()))
        }
        stored = normalize_project_access(stored)
        self.chosen = set(stored['allowed_project_ids'])
        initial = stored['project_access']
        self.rows: dict[str, Any] = {}
        with ui.column().classes('w-full gap-1'):
            ui.label('Allowed projects / chats').classes('font-semibold text-sm')
            self.mode = ui.radio(
                {'all': 'All projects / chats', 'selected': 'Only selected projects / chats'},
                value=initial if initial in {'all', 'selected'} else 'selected',
            ).props('aria-label="Project access"').classes('w-full')
            self.description = ui.label('').classes('text-xs hy-muted').style('overflow-wrap:anywhere')
            with ui.expansion('Selected projects / chats', icon='account_tree', value=True).classes('w-full') as self.selection:
                self.count = ui.label('').classes('text-xs font-semibold')
                ui.label('Each checkbox grants that project or chat only. Parents, children and future chats are not included automatically.').classes('text-xs hy-muted')
                with ui.row().classes('w-full gap-2 flex-wrap'):
                    ui.button('Select listed', on_click=lambda: self._set_all(True)).props('flat dense no-caps')
                    ui.button('Clear selection', on_click=lambda: self._set_all(False)).props('flat dense no-caps')
                with ui.column().classes('w-full gap-0 overflow-y-auto').style('max-height:300px;min-width:0'):
                    count = 0
                    for archived in (False, True):
                        tree = workspace.list_chat_tree(archived=archived)
                        if tree and archived:
                            ui.label('Archived projects / chats').classes('text-xs font-semibold mt-3')
                        for chat, depth, _lineage in tree:
                            count += 1
                            chat_id = str(chat.id)
                            label = str(chat.title or 'Untitled') + (f' · {chat.public_id}' if chat.public_id else '')
                            checkbox = ui.checkbox(label, value=chat_id in self.chosen).classes('w-full text-sm').style(
                                f'padding-left:{min(8, max(0, int(depth))) * 14}px;min-width:0;overflow-wrap:anywhere')
                            checkbox.props(f'data-hy-project-id={chat_id}')
                            checkbox.on_value_change(lambda event, key=chat_id: self._select(key, bool(event.value)))
                            self.rows[chat_id] = checkbox
                    if not count:
                        ui.label('No projects / chats yet. Create them in the workspace, then choose their access here.').classes('text-xs hy-muted')
            self.mode.on_value_change(lambda _event: self._sync())
        self._sync()

    @property
    def project_access(self) -> str:
        return 'all' if self.mode.value == 'all' else 'selected'

    @property
    def allowed_project_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self.chosen))

    def _select(self, chat_id: str, value: bool) -> None:
        self.chosen.add(chat_id) if value else self.chosen.discard(chat_id)
        self._sync()

    def _set_all(self, value: bool) -> None:
        if not value:
            self.chosen.clear()
        for key, checkbox in self.rows.items():
            self.chosen.add(key) if value else self.chosen.discard(key)
            checkbox.set_value(value)
        self._sync()

    def _sync(self) -> None:
        selected = self.project_access == 'selected'
        self.selection.set_visibility(selected)
        if self.subject == 'VM':
            self.description.set_text(
                'Project-files terminals and model tools can use this VM from every project / chat, including future ones. Guest console controls remain available.'
                if not selected else
                'Project-files terminals and model tools can use this VM only from individually checked projects / chats. Guest console controls remain available.'
            )
        else:
            self.description.set_text(
                f'The model can use this {self.subject} from every project / chat in this workspace, including future ones. Manual controls remain available.'
                if not selected else
                f'The model can use this {self.subject} only from individually checked projects / chats. Manual controls remain available.'
            )
        selected_count = len(self.chosen.intersection(self.rows))
        missing = len(self.chosen.difference(self.rows))
        text = f'{selected_count} / {len(self.rows)} available projects / chats selected'
        if missing:
            text += f' · {missing} saved selection(s) unavailable'
        if not selected_count:
            text += f' · No available project access: the model cannot use this {self.subject} from any listed project / chat'
        self.count.set_text(text)
        self.count.classes(add='text-negative' if not selected_count else '',
                           remove='' if not selected_count else 'text-negative')
