"""Measured guest storage and host disk-image allocation, from the status cache."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from nicegui import ui


def _bytes(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def storage_size(value: Any) -> str:
    amount = _bytes(value)
    if amount is None:
        return 'Unavailable'
    if amount < 1024:
        return f'{amount:,} B'
    for unit in ('KiB', 'MiB', 'GiB', 'TiB', 'PiB'):
        amount /= 1024
        if amount < 1024 or unit == 'PiB':
            return f'{amount:,.1f} {unit}'
    return 'Unavailable'


def storage_timestamp(value: Any) -> str:
    try:
        if isinstance(value, bool) or float(value) <= 0:
            return ''
        return datetime.fromtimestamp(float(value)).astimezone().strftime('%d %b %Y, %H:%M:%S %Z')
    except (TypeError, ValueError, OverflowError, OSError):
        return ''


def storage_view_model(receipt: dict[str, Any] | None) -> dict[str, Any]:
    """Keep absent values unknown and select explicitly stale previous readings."""
    current = dict(receipt or {})
    previous = current.get('last_known')
    previous = dict(previous) if isinstance(previous, dict) else {}
    result: dict[str, Any] = {
        'state': str(current.get('state') or 'unavailable'),
        'pending': bool(current.get('refreshing') or current.get('observation_pending')),
        'measured': bool(receipt),
    }
    for part in ('guest', 'host'):
        component = current.get(part)
        component = dict(component) if isinstance(component, dict) else {}
        last_component = previous.get(part)
        last_component = dict(last_component) if isinstance(last_component, dict) else {}
        valid_states = {'ready'} if part == 'guest' else {'ready', 'partial'}
        use_previous = component.get('state') not in valid_states and last_component.get('state') in valid_states
        selected = last_component if use_previous else component
        timestamp = (previous.get('captured_at') or current.get('last_success_at')) if use_previous else current.get('captured_at')
        # A stopped/failed observation never presents a saved guest sample as
        # current, even if an older service persisted it in the main payload.
        stale = use_previous or current.get('fresh') is False
        result[part] = {
            **selected, 'current_state': str(component.get('state') or 'unavailable'),
            'stale': stale, 'timestamp': storage_timestamp(timestamp),
        }
    result['stale'] = bool(current.get('fresh') is False)
    return result


def filesystem_warning(filesystem: dict[str, Any]) -> tuple[str, str]:
    if (_bytes(filesystem.get('inodes_total')) or 0) > 0 and _bytes(filesystem.get('inodes_available')) == 0:
        return 'No free inodes', 'negative'
    total, available = _bytes(filesystem.get('total_bytes')), _bytes(filesystem.get('available_bytes'))
    if total and available is not None:
        if available / total <= .05:
            return 'Almost full', 'negative'
        if available / total <= .10:
            return 'Low free space', 'warning'
    return '', 'primary'


class VMStorageUsage:
    """Update from ENVIRONMENT_STATUS; the button only queues an observation."""

    def __init__(self, root: str | Path, environment_id: str) -> None:
        self.root, self.environment_id = Path(root), environment_id
        self._signature: str | None = None
        self._busy = False
        self._can_refresh = False
        with ui.card().classes('hy-env-card w-full min-w-0 p-4 gap-3').props(f'data-hy-vm-storage={environment_id}') as self.panel:
            with ui.row().classes('w-full min-w-0 items-center gap-2 flex-wrap'):
                ui.label('Storage usage').classes('font-semibold min-w-0')
                self.badge = ui.badge('Not measured').props('color=grey')
                self.spinner = ui.spinner(size='16px')
                self.spinner.set_visibility(False)
                ui.space()
                self.refresh_button = ui.button('Refresh storage usage', icon='refresh', on_click=self.request).props('flat dense no-caps').classes('max-w-full')
            self.notice = ui.label('').classes('text-xs hy-muted w-full min-w-0').style('white-space:normal;overflow-wrap:anywhere')
            self.content = ui.column().classes('w-full min-w-0 gap-4')
        self.sync(None)

    def request(self) -> None:
        if not self._can_refresh:
            return
        try:
            from harnessy.environment.storage import VM_STORAGE
            if not VM_STORAGE.request(self.root, environment_id=self.environment_id):
                self.notice.set_text('Storage refresh is unavailable until this VM is running.')
                self._can_refresh = False
                self.refresh_button.disable()
                return
            self.notice.set_text('Storage refresh queued. Readings update when the check completes.')
            self.refresh_button.disable()
        except (OSError, RuntimeError, ValueError):
            self.notice.set_text('Storage refresh could not be queued. Try again after this VM’s current operation finishes.')

    def sync(self, receipt: dict[str, Any] | None, *, busy: bool = False, running: bool | None = None) -> None:
        if self.panel.is_deleted:
            return
        self._busy = bool(busy)
        model = storage_view_model(receipt)
        pending = bool(model['pending'])
        self._can_refresh = running is True and model['state'] != 'stopped' and not busy and not pending
        self.refresh_button.set_enabled(self._can_refresh)
        self.spinner.set_visibility(pending)
        state = model['state']
        self.badge.set_text('Updating…' if pending else {
            'ready': 'Last known' if model['stale'] else 'Measured', 'partial': 'Partial', 'stopped': 'VM stopped',
            'unsupported': 'Unsupported', 'unavailable': 'Unavailable',
        }.get(state, 'Unavailable') if model['measured'] else 'Not measured')
        self.badge.props('color=grey' if pending or state not in {'ready', 'partial'} else 'color=warning' if model['stale'] or state == 'partial' else 'color=positive')
        self.notice.set_text(
            'Storage measurement is queued; VM operations finish first.' if pending and busy else
            'Measuring storage usage…' if pending else
            'VM operations pause storage checks.' if busy else
            'Start this VM to refresh storage usage.' if state == 'stopped' or running is False else
            'Waiting for this VM’s running status before storage checks.' if running is not True else ''
        )
        signature = json.dumps(model, sort_keys=True, default=str)
        if signature == self._signature:
            return
        self._signature = signature
        self.content.clear()
        with self.content:
            self._guest(model['guest'])
            self._host(model['host'])

    @staticmethod
    def _sample_note(component: dict[str, Any]) -> None:
        timestamp = component.get('timestamp')
        if timestamp:
            text = f'Last measured {timestamp} · Out of date' if component.get('stale') else f'Measured {timestamp}'
            ui.label(text).classes('text-xs hy-muted min-w-0').style('overflow-wrap:anywhere')
        elif component.get('stale'):
            ui.label('Last known reading · Time unavailable · Out of date').classes('text-xs hy-muted')

    def _guest(self, guest: dict[str, Any]) -> None:
        with ui.column().classes('w-full min-w-0 gap-2').props('data-hy-guest-storage'):
            ui.label('Guest filesystems').classes('text-sm font-semibold')
            state = guest.get('current_state')
            if state != 'ready':
                ui.label('VM stopped · Guest usage is not current.' if state == 'stopped' else
                         'Guest storage reporting is unsupported for this VM.' if state == 'unsupported' else
                         'Guest storage usage is unavailable.').classes('text-xs hy-muted').style('overflow-wrap:anywhere')
            self._sample_note(guest)
            filesystems = [row for row in guest.get('filesystems') or () if isinstance(row, dict)]
            if not filesystems:
                ui.label('No guest filesystem measurement available.').classes('text-sm hy-muted')
            root_index = 0
            for row in filesystems:
                temporary = row.get('role') == 'temporary'
                if not temporary:
                    root_index += 1
                title = ('/tmp · Memory-backed temporary storage' if row.get('memory_backed') is True else
                         '/tmp · Temporary storage on disk' if row.get('memory_backed') is False else
                         '/tmp · Temporary storage') if temporary else 'Guest disk' + (f' {root_index}' if root_index > 1 else '')
                total, used, available = (_bytes(row.get(key)) for key in ('total_bytes', 'used_bytes', 'available_bytes'))
                warning, color = filesystem_warning(row)
                with ui.column().classes('w-full min-w-0 gap-1').props('data-hy-storage-temporary' if temporary else 'data-hy-storage-root'):
                    with ui.row().classes('w-full min-w-0 items-center gap-2 flex-wrap'):
                        ui.label(title).classes('text-sm min-w-0').style('overflow-wrap:anywhere')
                        if row.get('read_only') is True:
                            ui.badge('Read-only').props('color=grey')
                        if warning:
                            ui.badge(warning).props(f'color={color}')
                    ui.label(f'{storage_size(used)} used / {storage_size(total)} total · {storage_size(available)} free').classes('text-sm w-full min-w-0').style('overflow-wrap:anywhere')
                    if total and used is not None:
                        ui.linear_progress(min(1.0, used / total), show_value=False).props(f'rounded size=8px color={color}').classes('w-full')
                    if temporary and row.get('memory_backed') is True:
                        ui.label('Uses guest memory; separate from the VM disk.').classes('text-xs hy-muted')
                    elif temporary and row.get('memory_backed') is False:
                        ui.label('Disk-backed temporary storage; it may share space with the guest disk.').classes('text-xs hy-muted')
                    if warning == 'No free inodes':
                        ui.label('New files may fail even when disk space is free.').classes('text-xs text-negative')

    def _host(self, host: dict[str, Any]) -> None:
        with ui.column().classes('w-full min-w-0 gap-1').props('data-hy-host-storage'):
            with ui.row().classes('w-full min-w-0 items-center gap-2 flex-wrap'):
                ui.label('Disk images on host').classes('text-sm font-semibold')
                if host.get('state') == 'partial':
                    ui.badge('Partial measurement').props('color=warning')
            if host.get('current_state') not in {'ready', 'partial'}:
                ui.label('Current host disk-image usage is unavailable.').classes('text-xs hy-muted')
            self._sample_note(host)
            ui.label(f'Allocated on host: {storage_size(host.get("allocated_bytes"))}').classes('text-sm min-w-0').style('overflow-wrap:anywhere')
            ui.label(f'Image file length: {storage_size(host.get("logical_bytes"))}').classes('text-xs hy-muted min-w-0').style('overflow-wrap:anywhere')
            ui.label('Image file length includes sparse holes; it is separate from the configured virtual disk capacity.').classes('text-xs hy-muted min-w-0').style('overflow-wrap:anywhere')
            if host.get('state') == 'partial':
                ui.label('Some disk images could not be measured; the shown amounts are incomplete.').classes('text-xs hy-muted').style('overflow-wrap:anywhere')
