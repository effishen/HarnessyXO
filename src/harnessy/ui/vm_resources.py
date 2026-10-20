"""Guest CPU and memory measurements from the shared background observer."""
from __future__ import annotations

import math
from pathlib import Path
from typing import Any

from nicegui import ui

from .vm_storage import storage_size, storage_timestamp


def _counter(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _number(value: Any, *, maximum: float | None = None) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return number if math.isfinite(number) and number >= 0 and (maximum is None or number <= maximum) else None


def resource_uptime(value: Any) -> str:
    seconds = _number(value)
    if seconds is None:
        return 'Unavailable'
    seconds = int(seconds)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    parts = [f'{amount}{unit}' for amount, unit in ((days, 'd'), (hours, 'h'), (minutes, 'm')) if amount]
    return ' '.join(parts) if parts else f'{seconds}s'


def resources_view_model(snapshot: dict[str, Any] | None) -> dict[str, Any]:
    wrapper = dict(snapshot or {})
    current = wrapper.get('resources')
    current = dict(current) if isinstance(current, dict) else {}
    previous = wrapper.get('resources_last_known')
    previous = dict(previous) if isinstance(previous, dict) else {}
    state = str(current.get('state') or 'unavailable')
    use_previous = state not in {'ready', 'partial'} and previous.get('state') in {'ready', 'partial'}
    sample = previous if use_previous else current if state in {'ready', 'partial'} else {}
    return {
        'state': state, 'sample': sample,
        'stale': use_previous or current.get('fresh') is False,
        'pending': bool(current.get('refreshing') or current.get('observation_pending')),
        'measured': bool(current.get('captured_at')),
        'attempted': bool(current.get('captured_at') or current.get('observed_at') or
                          current.get('error_code') not in {None, '', 'VM_RESOURCES_NOT_OBSERVED'}),
        'timestamp': storage_timestamp(sample.get('captured_at') or current.get('last_success_at')),
    }


def _memory_warning(memory: dict[str, Any]) -> tuple[str, str]:
    total, available = _counter(memory.get('total_bytes')), _counter(memory.get('available_bytes'))
    if total and available is not None:
        if available / total <= .05:
            return 'Very low available memory', 'negative'
        if available / total <= .10:
            return 'Low available memory', 'warning'
    return '', 'primary'


class VMResourceUsage:
    """A fixed set of elements; repeated observations update them in place."""

    def __init__(self, root: str | Path, environment_id: str) -> None:
        self.root, self.environment_id = Path(root), environment_id
        self._can_refresh = False
        with ui.card().classes('hy-env-card w-full min-w-0 p-4 gap-3').props(f'data-hy-vm-resources={environment_id}') as self.panel:
            with ui.row().classes('w-full min-w-0 items-center gap-2 flex-wrap'):
                ui.label('CPU and memory').classes('font-semibold min-w-0')
                self.badge = ui.badge('Not measured').props('color=grey')
                self.spinner = ui.spinner(size='16px')
                ui.space()
                self.refresh_button = ui.button('Refresh CPU and memory', icon='refresh', on_click=self.request).props('flat dense no-caps').classes('max-w-full')
            self.notice = ui.label('').classes('text-xs hy-muted w-full min-w-0').style('white-space:normal;overflow-wrap:anywhere')
            self.timestamp = ui.label('').classes('text-xs hy-muted w-full min-w-0').style('overflow-wrap:anywhere')
            with ui.row().classes('w-full min-w-0 gap-4 flex-wrap items-start'):
                with ui.column().classes('min-w-0 gap-1').style('flex:1 1 260px;max-width:100%').props('data-hy-resource-cpu'):
                    with ui.row().classes('w-full min-w-0 items-center gap-2 flex-wrap'):
                        ui.label('Guest CPU').classes('text-sm font-semibold')
                        ui.icon('info_outline', size='16px').classes('hy-muted').tooltip('Active time across all guest vCPUs, normalized to 100%. Idle time, I/O wait and CPU steal are excluded. These readings come from inside the VM.')
                        self.cpu_count = ui.label('').classes('text-xs hy-muted')
                    self.cpu = ui.label('Unavailable').classes('text-sm')
                    self.cpu_bar = ui.linear_progress(0, show_value=False).props('rounded size=8px color=primary').classes('w-full')
                    self.iowait = ui.label('').classes('text-xs hy-muted')
                with ui.column().classes('min-w-0 gap-1').style('flex:1 1 260px;max-width:100%').props('data-hy-resource-memory'):
                    with ui.row().classes('w-full min-w-0 items-center gap-2 flex-wrap'):
                        ui.label('Guest RAM').classes('text-sm font-semibold')
                        ui.icon('info_outline', size='16px').classes('hy-muted').tooltip('Used RAM is total minus available memory. Available memory includes reclaimable caches; raw free memory alone does not describe memory pressure.')
                        self.memory_estimate = ui.badge('Estimated availability').props('color=warning')
                        self.memory_warning = ui.badge('').props('color=warning')
                    self.memory = ui.label('Unavailable').classes('text-sm w-full min-w-0').style('overflow-wrap:anywhere')
                    self.memory_bar = ui.linear_progress(0, show_value=False).props('rounded size=8px color=primary').classes('w-full')
                    self.cache = ui.label('').classes('text-xs hy-muted')
            with ui.row().classes('w-full min-w-0 gap-4 flex-wrap items-start'):
                with ui.column().classes('min-w-0 gap-1').style('flex:1 1 260px;max-width:100%').props('data-hy-resource-load'):
                    with ui.row().classes('min-w-0 items-center gap-2 flex-wrap'):
                        ui.label('System load · 1 / 5 / 15 min').classes('text-sm font-semibold').style('overflow-wrap:anywhere')
                        ui.icon('info_outline', size='16px').classes('hy-muted').tooltip('Guest load averages count runnable tasks and tasks waiting on uninterruptible I/O. Load is not a CPU percentage and may exceed the guest vCPU count.')
                    self.load = ui.label('Unavailable').classes('text-sm w-full min-w-0').style('overflow-wrap:anywhere')
                with ui.column().classes('min-w-0 gap-1').style('flex:1 1 260px;max-width:100%').props('data-hy-resource-swap'):
                    ui.label('Guest swap').classes('text-sm font-semibold')
                    self.swap = ui.label('Unavailable').classes('text-sm w-full min-w-0').style('overflow-wrap:anywhere')
                with ui.column().classes('min-w-0 gap-1').style('flex:1 1 180px;max-width:100%').props('data-hy-resource-uptime'):
                    ui.label('Guest uptime').classes('text-sm font-semibold')
                    self.uptime = ui.label('Unavailable').classes('text-sm')
        self.sync(None)

    def request(self) -> None:
        if not self._can_refresh:
            return
        try:
            from harnessy.environment.storage import VM_STORAGE
            if not VM_STORAGE.request(self.root, environment_id=self.environment_id, resources_only=True):
                self.notice.set_text('Resource refresh is unavailable until this VM is running.')
                self._can_refresh = False
                self.refresh_button.disable()
                return
            self.notice.set_text('CPU and memory refresh queued.')
            self.refresh_button.disable()
        except (OSError, RuntimeError, ValueError):
            self.notice.set_text('Resource refresh could not be queued. Try again after this VM’s current operation finishes.')

    def sync(self, snapshot: dict[str, Any] | None, *, busy: bool = False, running: bool | None = None) -> None:
        if self.panel.is_deleted:
            return
        model = resources_view_model(snapshot)
        state, sample, pending, stale = model['state'], model['sample'], model['pending'], model['stale']
        self._can_refresh = running is True and state != 'stopped' and not busy and not pending
        self.refresh_button.set_enabled(self._can_refresh)
        self.spinner.set_visibility(pending)
        self.badge.set_text('Updating…' if pending else {
            'ready': 'Last known' if stale else 'Measured', 'partial': 'Last known' if stale else 'Partial',
            'stopped': 'VM stopped', 'unsupported': 'Unsupported', 'unavailable': 'Unavailable',
        }.get(state, 'Unavailable') if model['attempted'] or sample or state in {'stopped', 'unsupported'} else 'Not measured')
        self.badge.props('color=grey' if pending or state not in {'ready', 'partial'} else 'color=warning' if stale or state == 'partial' else 'color=positive')
        self.notice.set_text(
            'Resource measurement is queued; VM operations finish first.' if busy and pending else
            'Measuring guest CPU and memory…' if pending else
            'VM operations pause resource checks.' if busy else
            'Start this VM to refresh guest CPU and memory.' if state == 'stopped' or running is False else
            'Guest CPU and memory reporting is unsupported for this VM.' if state == 'unsupported' else
            'Current guest CPU and memory usage is unavailable.' if state == 'unavailable' and model['attempted'] else
            'Waiting for this VM’s running status before resource checks.' if running is not True else ''
        )
        timestamp = model['timestamp']
        self.timestamp.set_text(f'Last measured {timestamp} · Out of date' if stale and timestamp else
                                f'Measured {timestamp}' if timestamp else
                                'Last known reading · Time unavailable · Out of date' if stale and sample else '')
        cpu = dict(sample.get('cpu') or {})
        cpu_state = str(cpu.get('state') or 'unavailable')
        percent = _number(cpu.get('usage_percent'), maximum=100) if cpu_state == 'ready' else None
        count = _counter(cpu.get('logical_count'))
        self.cpu_count.set_text(f'{count:,} guest vCPU' + ('s' if count != 1 else '') if count else '')
        self.cpu.set_text('Collecting sample…' if cpu_state == 'pending' else f'{percent:.1f}%' if percent is not None else 'Unavailable')
        self.cpu_bar.set_visibility(percent is not None)
        if percent is not None:
            self.cpu_bar.set_value(percent / 100)
        cpu_details = []
        sample_seconds = _number(cpu.get('sample_seconds'))
        if sample_seconds is not None:
            cpu_details.append(f'{sample_seconds:.1f}s sample')
        for field, label in (('iowait_percent', 'I/O wait'), ('steal_percent', 'CPU steal')):
            value = _number(cpu.get(field), maximum=100)
            if value is not None:
                cpu_details.append(f'{label}: {value:.1f}%')
        self.iowait.set_text(' · '.join(cpu_details))
        self.iowait.style('overflow-wrap:anywhere')
        self.iowait.set_visibility(bool(cpu_details))
        memory = dict(sample.get('memory') or {})
        memory_valid = memory.get('state') == 'ready'
        total, used, available = (_counter(memory.get(key)) if memory_valid else None for key in ('total_bytes', 'used_bytes', 'available_bytes'))
        self.memory.set_text(f'{storage_size(used)} used / {storage_size(total)} total · {storage_size(available)} available' if memory_valid else 'Unavailable')
        self.memory_bar.set_visibility(bool(total) and used is not None)
        if total and used is not None:
            self.memory_bar.set_value(min(1.0, used / total))
        estimate = memory_valid and (memory.get('available_estimated') is True or memory.get('available_source') == 'estimated')
        self.memory_estimate.set_visibility(estimate)
        warning, color = _memory_warning(memory) if memory_valid else ('', 'primary')
        self.memory_warning.set_text(warning)
        self.memory_warning.props(f'color={color}')
        self.memory_warning.set_visibility(bool(warning))
        self.memory_bar.props(f'color={color}')
        cache = _counter(memory.get('cache_bytes')) if memory_valid else None
        buffers = _counter(memory.get('buffers_bytes')) if memory_valid else None
        memory_details = [f'{label}: {storage_size(value)}' for label, value in (('Cached', cache), ('Buffers', buffers)) if value is not None]
        self.cache.set_text(' · '.join(memory_details))
        self.cache.style('overflow-wrap:anywhere')
        self.cache.set_visibility(bool(memory_details))
        swap = dict(sample.get('swap') or {})
        swap_valid = swap.get('state') == 'ready'
        swap_total, swap_used = (_counter(swap.get(key)) if swap_valid else None for key in ('total_bytes', 'used_bytes'))
        self.swap.set_text('Disabled' if swap_valid and swap_total == 0 else
                           f'{storage_size(swap_used)} used / {storage_size(swap_total)} total' if swap_valid else 'Unavailable')
        load = dict(sample.get('load') or {})
        loads = [_number(load.get(key)) if load.get('state') == 'ready' else None for key in ('one', 'five', 'fifteen')]
        self.load.set_text(' / '.join(f'{value:,.2f}' if value is not None else 'Unavailable' for value in loads) if load.get('state') == 'ready' else 'Unavailable')
        self.uptime.set_text(resource_uptime(sample.get('uptime_seconds')))
