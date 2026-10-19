"""Per-VM resource summary and stopped-VM editor."""
from __future__ import annotations

from typing import Any, Callable
from pathlib import Path
from contextlib import nullcontext

from nicegui import ui

from harnessy.environment.base import EnvironmentConfig
from harnessy.environment.resources import resource_values


class WorkspaceResourceEditor:
    def __init__(self, config: EnvironmentConfig, on_apply: Callable[..., Any], *, dialog_parent: Any = None) -> None:
        self.config = config
        self.on_apply = on_apply
        self.dialog_parent = dialog_parent
        self.busy = False
        self.active = False
        self.status: dict[str, Any] = {}
        ui.label('Resources').classes('text-xs hy-muted')
        self.summary = ui.label('').classes('text-sm font-semibold')
        self.storage = ui.label('').classes('text-sm')
        self.button = ui.button('Edit VM Resources', icon='tune', on_click=self.open).props('flat dense no-caps')
        self.summary.set_text(self._summary(config))
        self.storage.set_text(f'{config.disk_gb:,} GiB sparse disk capacity')

    @staticmethod
    def _memory_gib(config: EnvironmentConfig) -> str:
        return f'{config.memory_mb / 1024:.10f}'.rstrip('0').rstrip('.')

    @staticmethod
    def _summary(config: EnvironmentConfig) -> str:
        return f'{config.cpu} vCPU · {WorkspaceResourceEditor._memory_gib(config)} GiB RAM'

    def sync(self, config: EnvironmentConfig | None, status: dict[str, Any], *, busy: bool, active: bool) -> None:
        if config is not None:
            self.config = config
            self.summary.set_text(self._summary(config))
            self.storage.set_text(f'{config.disk_gb:,} GiB sparse disk capacity')
        self.busy, self.active, self.status = bool(busy), bool(active), dict(status)
        self.button.disable() if busy else self.button.enable()
        self.button.props(add='loading') if busy and status.get('resource_operation') else self.button.props(remove='loading')

    def _block_reason(self) -> str:
        if self.busy:
            return 'Wait for the current environment operation to finish.'
        if self.active:
            return 'Finish or stop active agents, terminals, and workspace processes before applying resources.'
        if not self.status.get('known'):
            return 'Waiting for this VM’s status. Close this editor and try again after the check finishes.'
        if self.status.get('running'):
            return 'Stop this VM before applying resources.'
        if self.status.get('created') and self.status.get('state') != 'stopped':
            return 'This VM must be fully stopped before applying resources.'
        return ''

    def open(self) -> None:
        config = self.config
        expected = config.to_dict()
        # NiceGUI attaches a lifetime canary to the construction slot. Creating
        # the modal under its stable owner keeps both alive across card redraws.
        with self.dialog_parent if self.dialog_parent is not None else nullcontext():
            dialog = ui.dialog()
        with dialog, ui.card().classes('w-[560px] max-w-[94vw] gap-3'):
            ui.label(f'Edit Resources · {config.name}').classes('text-lg font-semibold')
            ui.label('Apply while the VM is stopped, then Start it to use the new settings.').classes('text-sm hy-muted')
            # Text-valued numeric inputs avoid NiceGUI Number.sanitize comparing
            # a browser-supplied string against a numeric bound on blur.
            openwrt = config.provider == 'openwrt'
            mips = openwrt and config.architecture.startswith('mips')
            with ui.row().classes('w-full gap-3 flex-wrap'):
                cpu = ui.input('vCPU count', value=str(config.cpu)).props(f'type=number min=1 max={1 if mips else 64} step=1').style('flex:1 1 130px;min-width:120px')
                ram = ui.input('RAM (GiB)', value=self._memory_gib(config)).props(f'type=number min=1 max={2 if mips else 128 if openwrt else 256} step=0.5').style('flex:1 1 130px;min-width:120px')
                disk = ui.input('Storage (GiB)', value=str(config.disk_gb)).props(f'type=number min={config.disk_gb} max={64 if openwrt else 4096} step=1').style('flex:1 1 130px;min-width:120px')
            ui.label('Storage is sparse: this sets its maximum capacity, not an immediate host-space allocation. Existing storage can only grow. Files, installed tools, and the VM disk are retained.').classes('text-xs hy-muted')
            ui.label('OpenWrt Malta: 1 vCPU · RAM: 1–2 GiB · Storage: 16–64 GiB.' if mips else 'OpenWrt: RAM up to 128 GiB · Storage: 16–64 GiB.' if openwrt else 'CPU: 1–64 · RAM: 1–256 GiB · Storage: 16–4,096 GiB. Leave enough host resources for your model and other apps.').classes('text-xs hy-muted')
            error = ui.label('').classes('text-sm text-negative').style('white-space:pre-wrap;overflow-wrap:anywhere')
            reason = self._block_reason()
            if reason:
                error.set_text(reason)
            for field in (cpu, ram, disk):
                field.on_value_change(lambda _event: error.set_text(self._block_reason()))
            with ui.row().classes('w-full justify-end gap-2'):
                ui.button('Cancel', on_click=dialog.close).props('flat no-caps')

                def submit() -> None:
                    blocked = self._block_reason()
                    if blocked:
                        error.set_text(blocked)
                        return
                    try:
                        values = resource_values(cpu.value, ram.value, disk.value)
                        if openwrt and (values['disk_gb'] > 64 or values['memory_mb'] > (2048 if mips else 131072) or (mips and values['cpu'] != 1)):
                            raise ValueError('OpenWrt MIPS supports 1 vCPU and up to 2 GiB RAM; other OpenWrt guests support up to 128 GiB RAM. Disk maximum is 64 GiB.')
                        if values['disk_gb'] < config.disk_gb:
                            raise ValueError('Storage can only grow. Choose at least the existing capacity.')
                        if self.on_apply(**values, expected=expected) is not False:
                            dialog.close()
                    except (ValueError, RuntimeError) as exc:
                        error.set_text(str(exc))

                apply = ui.button('Apply Resources', icon='save', on_click=submit).props('unelevated no-caps')
                if reason:
                    apply.disable()
        dialog.open()


def render_unavailable_workspace_vm(workspace_root: str | Path) -> None:
    """Keep VM controls independent of the workspace database admission path."""
    from harnessy.environment import EnvironmentManager, ENVIRONMENT_OPERATIONS, ENVIRONMENT_STATUS
    from harnessy.environment.activity import active_work

    root = Path(workspace_root)
    try:
        configs = EnvironmentManager(root).list()
    except (OSError, ValueError):
        return
    for config in configs:
        _render_unavailable_vm(root, config)


def _render_unavailable_vm(root: Path, config: EnvironmentConfig) -> None:
    from harnessy.environment import EnvironmentManager, ENVIRONMENT_OPERATIONS, ENVIRONMENT_STATUS
    from harnessy.environment.activity import active_work

    environment_id = config.id
    manager = EnvironmentManager(root, environment_id=environment_id)
    current: dict[str, Any] = {'known': False}
    with ui.card().classes('w-full gap-2 p-4') as panel:
        ui.label(config.name).classes('font-semibold')
        ui.label('VM controls').classes('text-xs hy-muted')
        editor = WorkspaceResourceEditor(config, lambda **values: queue('resources', **values))
        status_label = ui.label('Checking VM state…').classes('text-sm hy-muted')
        with ui.row().classes('w-full items-center gap-2'):
            spinner = ui.spinner(size='18px')
            stop = ui.button('Stop VM', icon='stop', on_click=lambda: queue('stop')).props('outline no-caps')
        detail = ui.label('').classes('text-xs hy-muted').style('white-space:pre-wrap;overflow-wrap:anywhere')

    def sync() -> None:
        operation = ENVIRONMENT_OPERATIONS.state(root, environment_id=environment_id)
        busy = bool(operation.busy)
        active = bool(active_work(root, environment_id=environment_id))
        editor.sync(manager.config, {**current, 'resource_operation': operation.action == 'resources'}, busy=busy, active=active)
        spinner.set_visibility(busy or not current.get('known'))
        if busy:
            status_label.set_text(operation.message or 'Updating VM…')
        elif current.get('known'):
            status_label.set_text('VM running' if current.get('running') else 'VM stopped' if current.get('created') else 'VM not created')
        stop.enable() if current.get('known') and current.get('running') and not busy and not active else stop.disable()
        stop.props(add='loading') if busy and operation.action == 'stop' else stop.props(remove='loading')
        detail.set_text(operation.error or (operation.message if busy else operation.success) or '')

    def queue(action: str, **payload: Any) -> bool:
        if active_work(root, environment_id=environment_id):
            detail.set_text('Finish or stop active agents, terminals, and processes using this VM before changing it.')
            return False
        try:
            queued = ENVIRONMENT_OPERATIONS.start(root, action, environment_id=environment_id, **payload)
            if not queued:
                detail.set_text('Wait for this VM’s current operation to finish.')
                return False
            sync()
            return True
        except (RuntimeError, ValueError, OSError) as exc:
            detail.set_text(str(exc))
            return False

    async def refresh() -> None:
        if panel.is_deleted:
            timer.cancel()
            return
        try:
            info = await ENVIRONMENT_STATUS.get(root, environment_id=environment_id)
            if panel.is_deleted:
                timer.cancel()
                return
            poll_error = ''
            if info is not None:
                current.clear()
                current.update(dict(info.get('status') or {}))
                poll_error = str(info.get('_status_poll_error') or '')
                current['known'] = not bool(poll_error)
            sync()
            if poll_error:
                spinner.set_visibility(False)
                status_label.set_text('VM status unavailable')
                detail.set_text(poll_error)
        except (RuntimeError, ValueError, OSError) as exc:
            current['known'] = False
            editor.sync(editor.config, current,
                        busy=ENVIRONMENT_OPERATIONS.is_busy(root, environment_id=environment_id),
                        active=bool(active_work(root, environment_id=environment_id)))
            spinner.set_visibility(False)
            status_label.set_text('VM status unavailable')
            detail.set_text(str(exc))
            stop.disable()

    sync()
    timer = ui.timer(0.75, refresh, immediate=True)
