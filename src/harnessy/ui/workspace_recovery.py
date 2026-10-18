"""Explicit, authenticated workspace checks and recovery previews."""
from __future__ import annotations

import inspect
import math
from pathlib import Path
from typing import Any, Callable

from nicegui import ui

from harnessy.core.paths import APP_ROOT


def _seconds(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        return ''
    seconds = int(value)
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    return f'{hours}h {minutes:02d}m {seconds:02d}s' if hours else f'{minutes}m {seconds:02d}s' if minutes else f'{seconds}s'


def _bytes(value: int) -> str:
    size = float(value)
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if size < 1024 or unit == 'TiB':
            return f'{int(size):,} B' if unit == 'B' else f'{size:.1f} {unit}'
        size /= 1024
    return ''


def _count_rows(counts: Any) -> list[dict[str, Any]]:
    if not isinstance(counts, dict):
        return []
    before, after = counts.get('before'), counts.get('after')
    if not isinstance(before, dict) or not isinstance(after, dict):
        return []
    rows = []
    for name in sorted(set(before) | set(after), key=str):
        if not isinstance(name, str) or len(name) > 128:
            continue
        values = []
        for source in (before, after):
            value = source.get(name)
            values.append(f'{value:,}' if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 'Unavailable')
        rows.append({'name': name, 'before': values[0], 'after': values[1]})
    return rows


def _eligible(snapshot: dict[str, Any]) -> bool:
    return (snapshot.get('status') == 'candidate_ready' and snapshot.get('candidate_verified') is True
            and snapshot.get('partial_salvage') is False
            and isinstance(snapshot.get('candidate_receipt_id'), str)
            and bool(snapshot.get('candidate_receipt_id')) and not snapshot.get('busy')
            and snapshot.get('activation_pending') is not True)


def _private_report(snapshot: dict[str, Any], state_root: Path) -> Path:
    value = snapshot.get('report_path')
    if not isinstance(value, str) or not value:
        raise ValueError('The recovery report is not available yet.')
    path = Path(value)
    parent = state_root / 'workspace-recovery'
    if (path.name != 'recovery-report.json' or not path.resolve().is_relative_to(parent.resolve())
            or not path.is_file() or path.is_symlink()):
        raise ValueError('The recovery report is unavailable. Run another check to create a new report.')
    return path


def render_workspace_recovery(
    page: Any, reg: Any, *, on_activate: Callable[[dict[str, Any]], Any] | None = None,
    on_open: Callable[[dict[str, Any]], Any] | None = None,
    on_start: Callable[[str], Any] | None = None, on_resume: Callable[[], Any] | None = None,
    is_queue_paused: Callable[[], bool] | None = None,
) -> None:
    """Observe one backend-owned job; rendering never starts a recovery task.

    Activation and opening are supplied by the authenticated application layer.
    The UI passes a fresh engine snapshot after revalidating the account session.
    """
    from harnessy.core.workspace_recovery import RECOVERY_OPERATIONS

    root, state_root = Path(reg.path), Path(page.machine.root)
    local: dict[str, Any] = {'pending': False, 'action': '', 'reviewed_receipt': '', 'counts': None, 'error': ''}

    with ui.card().classes('w-full gap-3 p-4').style('min-width:0').props('data-hy-workspace-recovery=1'):
        ui.label('Workspace recovery').classes('font-semibold')
        ui.label('An extended check gives a slow database more time to respond. Repair prepares a separate copy for review and preserves the original database.').classes('text-sm hy-muted')
        with ui.row().classes('w-full gap-2 flex-wrap'):
            check_button = ui.button('Extended check', icon='fact_check', on_click=lambda: start('check')).props('outline no-caps')
            repair_button = ui.button('Repair workspace', icon='build', on_click=lambda: start('repair')).props('outline no-caps')
        with ui.row().classes('w-full items-start gap-2').style('min-width:0'):
            spinner = ui.spinner(size='20px')
            with ui.column().classes('gap-1').style('flex:1;min-width:0'):
                message = ui.label('').classes('text-sm font-medium').style('overflow-wrap:anywhere')
                stage = ui.label('').classes('text-xs hy-muted').style('overflow-wrap:anywhere')
                timing = ui.label('').classes('text-xs hy-muted')
        progress = ui.linear_progress(value=0).classes('w-full').props('rounded size=6px')
        error = ui.label('').classes('text-sm text-negative').style('white-space:pre-wrap;overflow-wrap:anywhere')
        preview = ui.label('').classes('text-sm').style('white-space:pre-wrap;overflow-wrap:anywhere')
        counts = ui.table(columns=[
            {'name': 'name', 'label': 'Records', 'field': 'name', 'align': 'left', 'style': 'white-space:normal;overflow-wrap:anywhere'},
            {'name': 'before', 'label': 'Original', 'field': 'before', 'align': 'right'},
            {'name': 'after', 'label': 'Repaired copy', 'field': 'after', 'align': 'right'},
        ], rows=[], row_key='name', pagination={'rowsPerPage': 0}).classes('w-full hy-recovery-counts').props('dense flat wrap-cells hide-bottom').style('min-width:0;max-height:260px;overflow-y:auto')
        backup = ui.label('').classes('text-xs hy-muted').style('white-space:pre-wrap;overflow-wrap:anywhere')
        ui.label('Project files and VM disks are retained. Recovery reports contain operational details and record counts, without chat contents or SQL.').classes('text-xs hy-muted')
        queue_pause = ui.label('Queued work is paused for this workspace.').classes('text-sm hy-muted')
        with ui.row().classes('w-full gap-2 flex-wrap'):
            cancel_button = ui.button('Cancel recovery', icon='close', on_click=lambda: cancel()).props('flat no-caps')
            report_button = ui.button('Download recovery report', icon='download', on_click=lambda: download()).props('flat no-caps')
            open_button = ui.button('Open workspace', icon='folder_open', on_click=lambda: open_checked()).props('unelevated no-caps')
            activate_button = ui.button('Use repaired database', icon='check_circle', on_click=lambda: activate()).props('unelevated no-caps')
            rollback_button = ui.button('Restore original database', icon='restore', on_click=lambda: start('rollback')).props('outline no-caps')
            resume_button = ui.button('Resume queued work', icon='play_arrow', on_click=lambda: resume()).props('outline no-caps')

    ui.add_css('.hy-recovery-counts .q-table {table-layout:fixed;width:100%} '
               '.hy-recovery-counts th,.hy-recovery-counts td {white-space:normal!important;overflow-wrap:anywhere;padding:6px} '
               '.hy-recovery-counts .q-table__middle {overflow-x:visible}')

    def snapshot() -> dict[str, Any]:
        value = RECOVERY_OPERATIONS.snapshot(root, state_root=state_root)
        return dict(value) if isinstance(value, dict) else {}

    def refresh() -> None:
        try:
            data = snapshot()
        except Exception:
            local['error'] = 'Recovery status is unavailable. Check the settings folder and retry.'
            data = {}
        busy = bool(data.get('busy'))
        interrupted_switch = data.get('activation_pending') is True and not busy
        pending = bool(local['pending'])
        active = busy or pending
        for button in (check_button, repair_button):
            button.disable() if active or interrupted_switch else button.enable()
        spinner.set_visibility(active)
        activating = (str(data.get('kind') or data.get('action') or '') in {'activate', 'activation'}
                      or str(data.get('stage') or '').startswith(('activation', 'activating')))
        message.set_text('Finishing database switch…' if (pending and local['action'] == 'activate') or (busy and activating) else
                         'Repaired database is active. Open workspace to restore saved tabs.' if data.get('status') == 'activated' and not busy else
                         str(data.get('message') or ('Ready for an extended check or repair.' if not active else 'Working…')))
        phase = str(data.get('stage') or '').replace('_', ' ').strip()
        stage.set_text(phase.capitalize())
        stage.set_visibility(bool(phase and phase.lower() != 'idle'))
        duration = _seconds(data.get('elapsed_seconds'))
        parts = [f'Elapsed {duration}'] if duration and data.get('started_unix_seconds') else []
        transferred, total = data.get('progress_bytes'), data.get('total_bytes')
        real_bytes = (isinstance(transferred, int) and not isinstance(transferred, bool) and transferred >= 0)
        real_total = (isinstance(total, int) and not isinstance(total, bool) and total > 0)
        if real_bytes and (transferred > 0 or real_total):
            parts.append(_bytes(transferred) + (f' / {_bytes(total)}' if real_total else ' copied'))
        timing.set_text(' · '.join(parts))
        timing.set_visibility(bool(parts))
        progress.set_visibility(busy)
        if real_bytes and real_total:
            progress.props(remove='indeterminate')
            progress.set_value(min(1.0, transferred / total))
        else:
            progress.props(add='indeterminate')
        error.set_text(str(local['error'] or data.get('error') or ''))
        error.set_visibility(bool(local['error'] or data.get('error')))
        eligible = _eligible(data)
        partial = data.get('partial_salvage') is True or data.get('status') == 'partial_salvage'
        preview.set_text('An earlier database switch did not finish. Restore the preserved original before running another check or repair.'
            if interrupted_switch else
            'The repaired copy passed verification. Review its record counts, then choose Use repaired database. Your original database and journal files remain preserved.'
            if eligible else
            'Recovered data is incomplete or could not be verified. This result will not replace your workspace database. Keep the original files and review the recovery report.'
            if partial else ''
        )
        preview.set_visibility(interrupted_switch or eligible or partial)
        rows = _count_rows(data.get('candidate_counts')) if eligible or partial else []
        if rows != local['counts']:
            counts.rows = rows
            counts.update()
            local['counts'] = rows
        counts.set_visibility(bool(rows))
        local['reviewed_receipt'] = str(data.get('candidate_receipt_id') or '') if eligible else ''
        preserved = str(data.get('backup_path') or '')
        backup.set_text(f'Preserved original: {preserved}')
        backup.set_visibility(bool(preserved))
        cancel_button.set_visibility(busy and not activating and data.get('action') != 'rollback'
                                     and data.get('can_cancel') is not False and data.get('activation_pending') is not True)
        cancel_button.disable() if pending or data.get('status') == 'cancelling' else cancel_button.enable()
        try:
            report_available = bool(_private_report(data, state_root))
        except (OSError, ValueError):
            report_available = False
        report_button.set_visibility(report_available)
        report_button.disable() if pending else report_button.enable()
        open_button.set_visibility((data.get('healthy') is True or data.get('status') == 'activated') and not busy and not interrupted_switch)
        open_button.enable() if not active and on_open is not None else open_button.disable()
        activate_button.set_visibility(eligible and not interrupted_switch)
        activate_button.enable() if not active and on_activate is not None else activate_button.disable()
        rollback_button.set_visibility(interrupted_switch)
        rollback_button.enable() if not active and on_start is not None else rollback_button.disable()
        paused = is_queue_paused() is True if is_queue_paused is not None else False
        queue_pause.set_visibility(paused)
        resume_button.set_visibility(paused and not interrupted_switch and (data.get('healthy') is True or data.get('status') == 'activated'))
        resume_button.enable() if not active and on_resume is not None else resume_button.disable()

    async def authorized() -> bool:
        accounts = getattr(page, '_accounts', None)
        if accounts is None:
            local['error'] = 'Sign in again before starting or changing workspace recovery.'
            return False
        try:
            await accounts._require_session()
            return True
        except Exception:
            local['error'] = 'Your session could not be verified. Sign in again before continuing workspace recovery.'
            return False

    async def perform(action: Callable[[], Any], *, kind: str = '') -> None:
        if local['pending']:
            return
        local['pending'], local['error'], local['action'] = True, '', kind
        refresh()
        try:
            if await authorized():
                result = action()
                if inspect.isawaitable(result):
                    await result
        except Exception as exc:
            local['error'] = str(exc) or 'The recovery action could not complete. Check its report before retrying.'
        finally:
            local['pending'] = False
            local['action'] = ''
            refresh()

    async def start(kind: str) -> None:
        async def launch() -> None:
            data = snapshot()
            if data.get('busy'):
                return
            if data.get('activation_pending') is True and kind != 'rollback':
                raise ValueError('Restore the preserved original database before starting another recovery job.')
            if on_start is not None:
                result = on_start(kind)
                if inspect.isawaitable(result):
                    await result
                return
            if kind not in {'check', 'repair'}:
                raise ValueError('Interrupted-switch recovery is unavailable. Sign in again and retry.')
            method = RECOVERY_OPERATIONS.start_check if kind == 'check' else RECOVERY_OPERATIONS.start_repair
            method(root, app_root=APP_ROOT, state_root=state_root)
        await perform(launch, kind=kind)

    async def cancel() -> None:
        await perform(lambda: RECOVERY_OPERATIONS.cancel(root))

    async def download() -> None:
        def send_report() -> None:
            report = _private_report(snapshot(), state_root)
            ui.download.file(report, filename='HarnessyXO-Workspace-Recovery-Report' + report.suffix.lower())
        await perform(send_report)

    async def open_checked() -> None:
        async def open_current() -> None:
            data = snapshot()
            if (not (data.get('healthy') is True or data.get('status') == 'activated') or data.get('busy')
                    or data.get('activation_pending') is True or on_open is None):
                raise ValueError('Run a successful extended check before opening this workspace.')
            result = on_open(data)
            if inspect.isawaitable(result):
                await result
        await perform(open_current)

    async def activate() -> None:
        reviewed = local['reviewed_receipt']
        async def use_current() -> None:
            data = snapshot()
            if not _eligible(data) or not reviewed or reviewed != data.get('candidate_receipt_id') or on_activate is None:
                raise ValueError('The recovery result changed. Review the latest result before using it.')
            result = on_activate(data)
            if inspect.isawaitable(result):
                await result
        await perform(use_current, kind='activate')

    async def resume() -> None:
        async def resume_current() -> None:
            data = snapshot()
            if (data.get('busy') or data.get('activation_pending') is True
                    or not (data.get('healthy') is True or data.get('status') == 'activated') or on_resume is None):
                raise ValueError('Finish recovery and verify this workspace before resuming queued work.')
            result = on_resume()
            if inspect.isawaitable(result):
                await result
        await perform(resume_current, kind='resume')

    refresh()
    ui.timer(0.5, refresh)
