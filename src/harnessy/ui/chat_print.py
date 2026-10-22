"""Printable chat controls; previews use the exact generated PDF."""
from __future__ import annotations

import asyncio
import json
import math
from pathlib import Path
from typing import Any

from nicegui import ui

from harnessy.agent.print_exports import PRINT_EXPORT_JOBS, PrintExportJob
from harnessy.core.print_export import (
    CONTENT_LABELS, DETAIL_MODES, METADATA_LABELS, PrintExportOptions, load_print_index,
)
from harnessy.ui.print_preview import create_print_preview_async


PRINT_CSS = '''
.hy-print-dialog { width:min(1400px,97vw) !important; max-width:97vw !important;
  height:94dvh; max-height:94dvh; display:flex; flex-direction:column; padding:0; overflow:hidden; }
.hy-print-layout { display:grid; grid-template-columns:minmax(280px,370px) minmax(0,1fr);
  flex:1; min-height:0; min-width:0; width:100%; gap:0; }
.hy-print-options { overflow-y:auto; overflow-x:hidden; min-width:0; padding:16px; gap:12px;
  border-right:1px solid var(--q-separator-color,rgba(127,127,127,.25)); }
.hy-print-preview { min-width:0; min-height:0; padding:16px; gap:10px; }
.hy-print-mode-radio { display:flex; flex-wrap:wrap; gap:0; }
.hy-print-mode-radio .q-radio { margin-left:0 !important; margin-right:10px; }
.hy-print-mode-radio .q-radio__label { font-size:12px; }
.hy-print-metadata { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:2px 8px; }
.hy-print-options .q-field, .hy-print-options .q-field__control-container { min-width:0; max-width:100%; }
.hy-print-options .q-chip { max-width:100%; height:auto; min-height:24px; }
.hy-print-options .q-chip__content { white-space:normal; overflow-wrap:anywhere; }
@media(max-width:850px) {
  .hy-print-layout { display:flex; flex-direction:column; overflow-y:auto; }
  .hy-print-options { flex:none; overflow:visible; border-right:0; border-bottom:1px solid rgba(127,127,127,.25); }
  .hy-print-preview { flex:none; min-height:65vh; }
  .hy-print-preview .hy-print-page-view { min-height:45vh; }
}
'''


def open_chat_print(page: Any, workspace: Any, chat_id: str) -> None:
    accounts = getattr(page, '_accounts', None)
    username = str(getattr(page, '_username', '') or '')
    if accounts is None or not username:
        ui.notify('Sign in again to export this chat.', type='warning')
        return
    machine = page.machine
    key = (username, workspace.id, chat_id)
    prior = PRINT_EXPORT_JOBS.get(key)
    initial = prior.options.as_dict() if prior is not None else PrintExportOptions().as_dict()
    state: dict[str, Any] = {'closed': False, 'index_ready': False, 'lease': None,
                             'preview_job': None, 'signature': None, 'display': None,
                             'page': 1, 'pages': 0, 'page_loading': False, 'page_request': 0,
                             'preview_preparing': False, 'starting': False}
    controls: list[Any] = []
    ui.add_css(PRINT_CSS)

    async def authorize() -> None:
        await accounts._require_session()
        if str(accounts.username) != username:
            raise ValueError('Sign in again to export this chat.')
        registration = machine.get_workspace(workspace.id)
        if registration is None or Path(registration.path).resolve() != workspace.root.resolve():
            raise ValueError('This workspace is no longer available.')
        def chat_exists() -> bool:
            con = workspace._connect(readonly=True, timeout=.25)
            try:
                return con.execute('SELECT 1 FROM chats WHERE id=?', (chat_id,)).fetchone() is not None
            finally:
                con.close()
        if not await asyncio.to_thread(chat_exists):
            raise ValueError('This Project / Chat is no longer available.')
        await accounts._require_session()

    with ui.dialog().props('persistent') as dialog, ui.card().classes('hy-print-dialog'):
        with ui.row().classes('hy-editor-header w-full items-center no-wrap'):
            ui.label('Printable PDF').classes('text-lg font-semibold')
            ui.space()
            ui.button(icon='close', on_click=dialog.close).props('flat round dense aria-label="Close PDF export"')
        with ui.element('div').classes('hy-print-layout'):
            with ui.column().classes('hy-print-options'):
                project_title = ui.label('Project / Chat').classes('font-semibold w-full').style('overflow-wrap:anywhere')
                ui.label('Export saved messages, including history outside the visible page. A running model continues; unsaved streaming text is excluded.').classes('text-xs hy-muted')
                index_status = ui.label('Loading saved message and prompt choices…').classes('text-xs hy-muted')
                scope = ui.radio({
                    'all': 'Entire chat', 'prompts': 'Selected prompts and replies', 'range': 'Message range',
                }, value=initial.get('scope', 'all')).props('dense role=radiogroup aria-label="Export scope"').classes('w-full')
                controls.append(scope)
                with ui.column().classes('w-full gap-1') as prompts_area:
                    prompts = ui.select({}, value=list(initial.get('selected_prompt_ids') or []),
                        label='Select prompts', multiple=True, with_input=True).props('use-chips clearable').classes('w-full')
                    ui.label('Each selected prompt includes the saved messages after it, up to the next user prompt. Nonadjacent selections keep their original order.').classes('text-xs hy-muted')
                controls.append(prompts)
                with ui.column().classes('w-full gap-2') as range_area:
                    with ui.row().classes('w-full gap-2 no-wrap'):
                        first_value = initial.get('first_record') or 1
                        first = ui.select({first_value: f'#{first_value}'}, value=first_value,
                            label='First message', with_input=True).classes('w-full')
                        last_value = initial.get('last_record')
                        last = ui.select({last_value: f'#{last_value}'} if last_value is not None else {},
                            value=last_value, label='Last message', with_input=True).props('clearable').classes('w-full')
                    ui.label('Search by message number or text to choose both ends. Events count too. Leave the last choice blank for the latest saved message.').classes('text-xs hy-muted')
                controls.extend([first, last])
                ui.separator()
                ui.label('Content').classes('font-semibold text-sm')
                ui.label('One line keeps a compact entry and wraps when needed to fit the page. Nothing removes that section.').classes('text-xs hy-muted')
                modes: dict[str, Any] = {}
                for name, label in CONTENT_LABELS.items():
                    with ui.column().classes('w-full gap-0'):
                        ui.label(label).classes('text-xs font-semibold')
                        modes[name] = ui.radio(DETAIL_MODES, value=(initial.get('modes') or {}).get(name, 'line')).props(
                            f'inline dense role=radiogroup aria-label="{label}"').classes('hy-print-mode-radio w-full')
                        controls.append(modes[name])
                ui.label('Attachment references list names, types and sizes. File contents and remote images are not fetched or embedded.').classes('text-xs hy-muted')
                ui.separator()
                ui.label('Metadata').classes('font-semibold text-sm')
                metadata: dict[str, Any] = {}
                with ui.element('div').classes('hy-print-metadata w-full'):
                    for name, label in METADATA_LABELS.items():
                        metadata[name] = ui.checkbox(label, value=name in initial.get('metadata', [])).props('dense').classes('text-xs')
                        controls.append(metadata[name])
            with ui.column().classes('hy-print-preview'):
                with ui.row().classes('w-full items-center gap-2'):
                    spinner = ui.spinner(size='20px')
                    status = ui.label('Choose what to include, then preview the PDF.').classes('text-sm').style('flex:1;white-space:pre-wrap;overflow-wrap:anywhere')
                empty = ui.label('Your print preview will appear here.').classes('hy-muted w-full text-center p-6')
                with ui.column().classes('hy-print-page-view w-full gap-0').style('flex:1;min-height:0;overflow-y:auto;overflow-x:hidden;background:#e8ebed;padding:10px') as preview_view:
                    frame = ui.element('img').props('alt="PDF page preview" referrerpolicy=no-referrer').style('display:block;width:100%;height:auto;flex:none;box-shadow:0 1px 5px #0003')
                preview_view.props(f'id=hy-print-page-view-{frame.id}')
                preview_view.set_visibility(False)
                with ui.row().classes('w-full items-center justify-center gap-1 flex-wrap') as pager:
                    first_page = ui.button(icon='first_page', on_click=lambda: show_page(1)).props('flat round dense aria-label="First PDF page"')
                    previous_page = ui.button(icon='chevron_left', on_click=lambda: show_page(state['page'] - 1)).props('flat round dense aria-label="Previous PDF page"')
                    page_label = ui.label('').classes('text-xs')
                    next_page = ui.button(icon='chevron_right', on_click=lambda: show_page(state['page'] + 1)).props('flat round dense aria-label="Next PDF page"')
                    last_page = ui.button(icon='last_page', on_click=lambda: show_page(state['pages'])).props('flat round dense aria-label="Last PDF page"')
                    page_input = ui.input('Page', value='1').props('dense inputmode=numeric').style('width:72px')
                    go_page = ui.button('Go', on_click=lambda: jump_page()).props('flat dense no-caps aria-label="Go to PDF page"')
                pager.set_visibility(False)
                note = ui.label('').classes('text-xs hy-muted').style('white-space:pre-wrap;overflow-wrap:anywhere')
                with ui.row().classes('w-full gap-2 flex-wrap'):
                    download = ui.button('Download PDF', icon='download').props('unelevated no-caps')
                    open_pdf = ui.link('Open PDF / Print', target='#', new_tab=True).classes('self-center text-primary')
                download.set_visibility(False)
                open_pdf.set_visibility(False)
        with ui.row().classes('hy-editor-footer w-full items-center justify-end gap-2'):
            ui.label('Completed PDFs are kept in this chat’s Downloads. Closing this dialog keeps an export running.').classes('text-xs hy-muted').style('flex:1;min-width:0')
            ui.button('Close', on_click=dialog.close).props('flat no-caps')
            cancel = ui.button('Cancel export').props('flat no-caps color=negative')
            generate = ui.button('Preview PDF', icon='picture_as_pdf').props('unelevated no-caps')

    def options() -> PrintExportOptions:
        def number(value: Any, default: int | None) -> int | None:
            if value is None or str(value).strip() == '':
                return default
            try:
                numeric = float(str(value))
            except (ValueError, TypeError, OverflowError):
                raise ValueError('Message numbers must be positive whole numbers.') from None
            if not math.isfinite(numeric) or not numeric.is_integer():
                raise ValueError('Message numbers must be positive whole numbers.')
            return int(numeric)
        value = PrintExportOptions(
            scope=str(scope.value), selected_prompt_ids=tuple(prompts.value or []) if scope.value == 'prompts' else (),
            first_record=number(first.value, 1) if scope.value == 'range' else 1,
            last_record=number(last.value, None) if scope.value == 'range' else None,
            modes={name: str(control.value) for name, control in modes.items()},
            metadata=frozenset(name for name, control in metadata.items() if control.value),
        )
        value.validate()
        return value

    def signature(value: PrintExportOptions) -> str:
        return json.dumps(value.as_dict(), sort_keys=True, ensure_ascii=True)

    def clear_preview() -> None:
        if state['lease'] is not None:
            state['lease'].close()
        state['lease'] = None
        state['preview_job'] = None
        state['page_loading'] = False
        state['page'] = 1
        state['pages'] = 0
        frame.props(remove='src')
        preview_view.set_visibility(False)
        pager.set_visibility(False)
        download.set_visibility(False)
        open_pdf.set_visibility(False)
        empty.set_visibility(True)
        note.set_text('')

    def changed(_event: Any = None) -> None:
        prompts_area.set_visibility(scope.value == 'prompts')
        range_area.set_visibility(scope.value == 'range')
        if state['preview_job'] is not None:
            clear_preview()
            empty.set_text('Options changed. Preview again to update the PDF.')
            status.set_text('Options changed. Preview again to update the PDF.')
        state['signature'] = None
        state['display'] = None

    def update_page_controls() -> None:
        ready = not state['page_loading'] and state['lease'] is not None
        first_page.set_enabled(ready and state['page'] > 1)
        previous_page.set_enabled(ready and state['page'] > 1)
        next_page.set_enabled(ready and state['page'] < state['pages'])
        last_page.set_enabled(ready and state['page'] < state['pages'])
        page_input.set_enabled(ready)
        go_page.set_enabled(ready)

    def show_page(number: int) -> None:
        lease = state['lease']
        if lease is None or state['closed'] or not 1 <= number <= state['pages']:
            return
        state['page'] = number
        state['page_loading'] = True
        state['page_request'] += 1
        frame.props(f"src={lease.page_url(number)}?view={state['page_request']}")
        page_label.set_text(f"Page {number:,} of {state['pages']:,}")
        page_input.set_value(str(number))
        update_page_controls()
        ui.run_javascript(f'document.getElementById("hy-print-page-view-{frame.id}")?.scrollTo(0,0);')
        spinner.set_visibility(True)

    def jump_page() -> None:
        try:
            raw = str(page_input.value or '').strip()
            if not raw.isdecimal() or not 1 <= int(raw) <= state['pages']:
                raise ValueError(f"Choose a page from 1 to {state['pages']:,}.")
            show_page(int(raw))
        except ValueError as exc:
            ui.notify(str(exc), type='warning')

    def preview_loaded() -> None:
        if not state['closed']:
            state['page_loading'] = False
            spinner.set_visibility(False)
            update_page_controls()

    def preview_failed() -> None:
        if not state['closed'] and state['lease'] is not None:
            state['page_loading'] = False
            spinner.set_visibility(False)
            update_page_controls()
            status.set_text('This preview page could not be loaded. Preview again, or download the completed PDF.')

    async def refresh() -> None:
        if state['closed'] or getattr(dialog, 'is_deleted', False):
            return
        job = PRINT_EXPORT_JOBS.get(key)
        job_running = bool(job and job.running)
        running = job_running or state['starting']
        spinner.set_visibility(running or not state['index_ready'] or state['page_loading'])
        cancel.set_visibility(job_running)
        generate.set_enabled(state['index_ready'] and not running)
        for control in controls:
            control.set_enabled(state['index_ready'] and not running)
        if job is None:
            return
        current_signature = None
        try:
            current_signature = signature(options())
        except ValueError:
            pass
        matches = current_signature == signature(job.options)
        display = (id(job), job.state, job.status, matches)
        if state['display'] != display:
            state['display'] = display
            if not state['starting'] and (matches or job_running):
                status.set_text(job.status)
        if (job.state == 'complete' and job.path is not None and matches
                and state['preview_job'] is not job and not state['preview_preparing'] and not state['starting']):
            state['preview_preparing'] = True
            try:
                lease = await create_print_preview_async(job, accounts, machine)
                try:
                    still_matches = signature(options()) == signature(job.options)
                except ValueError:
                    still_matches = False
                if state['closed'] or PRINT_EXPORT_JOBS.get(key) is not job or not still_matches:
                    lease.close()
                    return
                clear_preview()
                state['lease'] = lease
                state['preview_job'] = job
                state['pages'] = max(1, int((job.stats or {}).get('pages') or 1))
                preview_view.set_visibility(True)
                pager.set_visibility(True)
                show_page(1)
                empty.set_visibility(False)
                download.set_visibility(True)
                open_pdf.props(f'href={lease.preview_url}')
                open_pdf.set_visibility(True)
                warnings = list((job.stats or {}).get('warnings') or [])
                parts = ['The preview and download use the same PDF. Open PDF / Print to use your browser’s print controls.']
                parts.extend(str(warning) for warning in warnings)
                note.set_text('\n'.join(parts))
            except Exception as exc:
                if not state['closed']:
                    status.set_text('Preview unavailable: ' + str(exc))
            finally:
                state['preview_preparing'] = False

    async def begin() -> None:
        if state['starting']:
            return
        previous = PRINT_EXPORT_JOBS.get(key)
        if previous and previous.running:
            await refresh()
            return
        try:
            value = options()
            state['starting'] = True
            generate.set_enabled(False)
            for control in controls:
                control.set_enabled(False)
            spinner.set_visibility(True)
            status.set_text('Preparing PDF export…')
            await authorize()
            if state['closed']:
                return
            if signature(options()) != signature(value):
                raise ValueError('Export choices changed while preparing. Preview again with the current choices.')
            clear_preview()
            empty.set_text('Preparing your PDF…')
            job = PrintExportJob(workspace, chat_id, value, username,
                active_at_start=page._chat_is_busy(workspace.id, chat_id), authorize=authorize)
            job.start()
            state['display'] = None
            await refresh()
        except Exception as exc:
            if not state['closed']:
                status.set_text(str(exc))
                ui.notify(str(exc), type='negative')
        finally:
            state['starting'] = False
            await refresh()

    async def cancel_job() -> None:
        job = PRINT_EXPORT_JOBS.get(key)
        if job:
            job.cancel()
        await refresh()

    async def download_pdf() -> None:
        try:
            await authorize()
            lease = state['lease']
            if lease is None or state['preview_job'] is not PRINT_EXPORT_JOBS.get(key):
                raise ValueError('Preview the current options before downloading.')
            ui.download.from_url(lease.download_url)
        except Exception as exc:
            ui.notify(str(exc), type='warning')

    async def load_choices() -> None:
        try:
            await authorize()
            index = await asyncio.to_thread(load_print_index, workspace, chat_id)
            if state['closed']:
                return
            await authorize()
            if state['closed']:
                return
            prompts.options = {row['id']: f"#{row['record_number']} · {str(row.get('preview') or '[Attachments only]')[:140]}" for row in index['prompts']}
            prompts.update()
            range_options = {row['record_number']: f"#{row['record_number']} · {str(row.get('role') or 'Message').title()} · {str(row.get('preview') or '[No saved text]')[:120]}" for row in index.get('records', [])}
            first.options = dict(range_options) or {1: '#1 · No saved messages'}
            if first.value is not None and first.value not in first.options:
                first.options[first.value] = f'#{first.value} · No longer available'
            last.options = dict(range_options)
            if last.value is not None and last.value not in last.options:
                last.options[last.value] = f'#{last.value} · No longer available'
            first.update()
            last.update()
            index_status.set_text(f"{index['total_records']:,} saved messages · {len(index['prompts']):,} prompts")
            project_title.set_text(str(index.get('title') or 'Project / Chat'))
            state['index_ready'] = True
            await refresh()
        except Exception as exc:
            if not state['closed']:
                index_status.set_text('Could not load saved choices: ' + str(exc))
                spinner.set_visibility(False)
                status.set_text('Close and reopen Printable PDF to retry.')

    def close_dialog() -> None:
        state['closed'] = True
        timer.deactivate()
        clear_preview()

    for control in controls:
        control.on_value_change(changed)
    generate.on('click', begin)
    cancel.on('click', cancel_job)
    download.on('click', download_pdf)
    page_input.on('keydown.enter', jump_page)
    frame.on('load', preview_loaded)
    frame.on('error', preview_failed)
    changed()
    generate.set_enabled(False)
    cancel.set_visibility(False)
    for control in controls:
        control.set_enabled(False)
    with dialog:
        timer = ui.timer(.35, refresh)
        ui.timer(.01, load_choices, once=True)
    dialog.on('hide', close_dialog)
    dialog.open()
