"""UI for independently managed test VMs in External/Test Targets."""
from __future__ import annotations

import asyncio
import json
import platform
import re
import time
import uuid
from datetime import datetime

from nicegui import ui

from harnessy.agent.external_targets import ExternalTargetBroker
from harnessy.core.terminal import TerminalSession
from harnessy.environment.presets import canonical_arch
from harnessy.environment.test_targets import TestTargetManager, target_operation_error


def open_vm_creator(ws, refresh, os_name='ubuntu-24.04'):
    from harnessy.environment.test_catalog import GUESTS, guest_os, target_architectures
    initial = guest_os(os_name)
    with ui.dialog() as dialog, ui.card().classes('hy-form-dialog hy-vm-creator'):
        with ui.row().classes('hy-dialog-header w-full no-wrap items-center'):
            ui.label('Create test VM').classes('text-lg font-semibold grow min-w-0')
            ui.button(icon='close', on_click=dialog.close).props('flat round dense aria-label="Close VM creator"')
        with ui.column().classes('hy-dialog-body w-full gap-3'):
            ui.label('A separate machine for testing, with internet access for packages and updates.').classes('text-sm hy-muted')
            operating_system = ui.select({key: item.label for key, item in GUESTS.items()},
                value=initial.id, label='Operating system', with_input=True).props('outlined').classes('w-full')
            description = ui.label(initial.description).classes('text-sm hy-muted')
            name = ui.input('Target name', value=initial.label + ' test').props('outlined').classes('w-full')
            with ui.row().classes('hy-vm-resources w-full gap-3'):
                cpu = ui.number('CPU cores', value=initial.cpu, min=1, max=32, step=1).props('outlined').classes('grow')
                memory = ui.number('RAM (MiB)', value=initial.memory, min=initial.min_memory, max=131072, step=256).props('outlined').classes('grow')
                disk = ui.number('Disk (GiB)', value=initial.disk, min=initial.min_disk, max=2048, step=1).props('outlined').classes('grow')
            desktop = ui.switch('Enable graphical interface', value=True)
            interface_hint = ui.label('Xfce desktop over VNC; turn off for a smaller shell-only VM.').classes('text-xs hy-muted')
            with ui.column().classes('w-full gap-2') as windows_options:
                iso = ui.input('Windows 11 ISO path on the HarnessyXO host', placeholder='/Users/you/Downloads/Windows11.iso').props('outlined').classes('w-full')
                ui.label('Use an English (United States) installer matching the architecture below. Installation and activation use your own media and licence.').classes('text-xs hy-muted')
                with ui.row().classes('gap-3'):
                    ui.link('Download ARM64 ISO', 'https://www.microsoft.com/software-download/windows11arm64', new_tab=True)
                    ui.link('Download x64 ISO', 'https://www.microsoft.com/software-download/windows11', new_tab=True)
            with ui.expansion('Architecture and model access', icon='tune').classes('w-full hy-target-details'):
                arch = ui.select(target_architectures(initial.id),
                    value=canonical_arch(platform.machine()), label='Architecture').classes('w-full')
                architecture_hint = ui.label('Matching the host enables acceleration. Other architectures use slower CPU emulation.').classes('text-xs hy-muted')
                approval = ui.select({'ask': 'Ask before protected target actions', 'on': 'Allow autonomous target tools'},
                    value='on', label='Model access').classes('w-full')
                ui.label('The model can install software and make system changes in this test VM.').classes('text-xs hy-muted')
            with ui.column().classes('w-full gap-2') as radio_options:
                ui.label('Guest radio emulation').classes('font-semibold text-sm')
                wifi = ui.checkbox('Emulated Wi-Fi radios (mac80211_hwsim)', value=False)
                bluetooth = ui.checkbox('Emulated Bluetooth controllers', value=False)
                ui.label('On Start, HarnessyXO downloads matching guest packages and sets up two software Bluetooth controllers. First setup can take longer; progress appears on the target card.').classes('text-xs hy-muted')
                ui.label('Software radios only: no physical RF, USB dongle identity or access to nearby devices. Matching Wi-Fi and Bluetooth dependencies download on Start. The model sees the saved selection and verified active controllers separately.').classes('text-xs hy-muted')
            prerequisite_hint = ui.label('').classes('text-xs hy-muted')
            start_now = ui.switch('Start after creating', value=True)
            error = ui.label('').classes('text-sm text-negative whitespace-pre-wrap').props('role=alert')

            selection = {'id': initial.id}
            def select_architecture(_=None):
                guest = guest_os(operating_system.value)
                mips = str(arch.value).startswith('mips')
                cpu.props(f'min={2 if guest.family == "windows" else 1} max={1 if mips else 32}')
                memory.props(f'min={guest.min_memory} max={2048 if mips else 131072}')
                if mips:
                    cpu.value = 1
                    memory.value = min(int(memory.value or guest.memory), 2048)
                architecture_hint.set_text(
                    'MIPS uses a Malta development board with software CPU emulation, one CPU and up to 2048 MiB RAM. It does not emulate a particular router model. Only official images available for this release are listed.' if mips else
                    'Matching the host enables acceleration. Other architectures use slower CPU emulation.')
            arch.on_value_change(select_architecture)
            def select_os(_=None):
                guest = guest_os(operating_system.value)
                previous = guest_os(selection['id'])
                if name.value == previous.label + ' test':
                    name.value = guest.label + ' test'
                if guest.id != previous.id:
                    cpu.value, memory.value, disk.value = guest.cpu, guest.memory, guest.disk
                cpu.props(f'min={2 if guest.family == "windows" else 1}')
                memory.props(f'min={guest.min_memory}')
                disk.props(f'min={guest.min_disk} max={64 if guest.family == "openwrt" else 2048}')
                selection['id'] = guest.id
                options = target_architectures(guest.id)
                current_arch = arch.value if arch.value in options else canonical_arch(platform.machine())
                arch.set_options(options, value=current_arch if current_arch in options else next(iter(options)))
                select_architecture()
                description.set_text(guest.description)
                windows_options.set_visibility(guest.family == 'windows')
                radio_options.set_visibility(guest.family == 'openwrt')
                interface_hint.set_text('LuCI web interface; the shell uses ash.' if guest.interface == 'web' else
                    ('Windows desktop over VNC.' if guest.family == 'windows' else 'Xfce desktop over VNC; turn off for a smaller shell-only VM.'))
                prerequisite_hint.set_text('Host requirements: QEMU and e2fsprogs. Official images download on first Start.' if guest.family == 'openwrt' else
                    ('Host requirements: Lima 2.2+, QEMU and swtpm.' if guest.family == 'windows' else 'Host requirements: current Lima and QEMU. The selected image downloads on first Start.'))
                error.set_text('')
            operating_system.on_value_change(select_os)
            select_os()
        with ui.row().classes('hy-dialog-footer w-full justify-end gap-2'):
            ui.button('Cancel', on_click=dialog.close).props('flat no-caps')
            def create():
                try:
                    guest = guest_os(operating_system.value)
                    if not str(name.value or '').strip():
                        raise ValueError('Enter a name for this test VM.')
                    target = ws.upsert_external_target(
                        name=name.value, host='managed-local', username='root' if guest.family == 'openwrt' else 'harnessy',
                        remote_root='C:/HarnessyTest' if guest.family == 'windows' else ('/root/hx-test' if guest.family == 'openwrt' else '/home/harnessy/hx-test'),
                        approval_mode=approval.value,
                        managed_vm={'os': guest.id, 'architecture': arch.value, 'cpu': int(cpu.value),
                                    'memory_mb': int(memory.value), 'disk_gb': int(disk.value),
                                    'desktop': bool(desktop.value), 'iso_path': str(iso.value or ''),
                                    'emulation': {'wifi': bool(wifi.value) if guest.family == 'openwrt' else False,
                                                  'bluetooth': bool(bluetooth.value) if guest.family == 'openwrt' else False}})
                    if start_now.value:
                        TestTargetManager(ws, target).begin('start')
                    dialog.close()
                    refresh()
                except Exception as exc:
                    error.set_text(str(exc))
            ui.button('Create test VM', icon='add', on_click=create).props('unelevated no-caps color=primary')
    dialog.open()

def target_tab_key(workspace_id, target_id, kind):
    """Canonical, workspace-scoped identities; reject restored cross-target aliases."""
    if kind not in {'target_terminal', 'target_desktop'} or not re.fullmatch(r'[a-f0-9]{32}', str(target_id)):
        raise ValueError('Invalid managed target view.')
    return ('test-target:' if kind == 'target_terminal' else 'target-desktop:') + str(workspace_id) + ':' + target_id


class _LeasedTargetSession:
    """A backend-owned PTY whose target lease ends on explicit close/shutdown."""
    def __init__(self, session, release):
        self._session, self._release = session, release

    def __getattr__(self, name):
        return getattr(self._session, name)

    def close(self):
        release, self._release = self._release, None
        try:
            self._session.close()
        finally:
            if release is not None:
                release()


def _record_view_result(manager, action, operation_id, started, error=None):
    from harnessy.diagnostics import log_event
    from harnessy.diagnostics.test_target_logs import classify_target_failure
    log_event('runtime', 'test_target_operation_finished', target_id=manager.target.id,
        target_backend=manager.backend, target_action=action,
        target_stage='probe_shell' if action == 'shell' else 'connection_test',
        target_outcome='failed' if error is not None else 'completed',
        target_failure_code=classify_target_failure(error) if error is not None else 'none',
        operation_id=operation_id, elapsed_seconds=max(0, time.monotonic() - started))


async def _create_target_session(manager):
    if manager.busy or not (await manager.status())['running'] or manager.busy:
        raise RuntimeError('Start this test VM and wait until it is ready before opening its shell.')
    argv, env, cwd = manager.terminal_command()
    release = manager.acquire()
    task = asyncio.create_task(asyncio.to_thread(TerminalSession, cwd, command_argv=argv, env=env))
    try:
        session = await asyncio.shield(task)
    except asyncio.CancelledError:
        # Closing a tab during PTY construction must close the eventual child too.
        try:
            orphan = await task
            orphan.close()
        finally:
            release()
        raise
    except BaseException:
        release()
        raise
    return _LeasedTargetSession(session, release)


async def open_target_shell(page, manager):
    page.open_target_tab(manager.workspace, manager.target.id, 'target_terminal')


async def open_target_desktop(page, manager):
    page.open_target_tab(manager.workspace, manager.target.id, 'target_desktop')


def render_target_tab(page, tab, ws):
    target = ws.get_external_target(tab.target_id or '')
    if not target or not target.managed_vm or tab.key != target_tab_key(ws.id, target.id, tab.kind):
        ui.label('This managed test target no longer exists.').classes('text-negative p-4')
        return
    manager = TestTargetManager(ws, target)
    if tab.kind == 'target_terminal':
        _render_target_shell(page, tab, manager)
    else:
        _render_target_desktop(page, tab, manager)


def _render_target_shell(page, tab, manager):
    session = page.terminal_sessions.get(tab.key)
    with ui.column().classes('hy-tool-panel hy-terminal-panel w-full no-wrap gap-0') as panel:
        with ui.row().classes('hy-tool-toolbar w-full items-center py-2 no-wrap gap-2'):
            ui.label(manager.target.name + ' · Shell').classes('font-semibold')
            ui.label('Independent test VM · ' + manager.guest.shell).classes('text-xs hy-muted')
            ui.space()
            if session is not None:
                ui.button('Ctrl+C', on_click=session.interrupt).props('flat dense no-caps')
                clear = ui.button('Clear').props('flat dense no-caps')
        if session is None:
            error = page.terminal_errors.get(tab.key)
            with ui.column().classes('w-full grow items-center justify-center gap-3'):
                if error:
                    ui.icon('error_outline', size='34px').classes('text-negative')
                    ui.label('Test VM shell could not open').classes('font-semibold text-negative')
                    ui.label(error).classes('text-sm hy-muted whitespace-pre-wrap').style('max-width:760px')
                    def retry():
                        page.terminal_errors.pop(tab.key, None)
                        page.refresh_tabs()
                    ui.button('Retry', icon='refresh', on_click=retry).props('unelevated no-caps')
                else:
                    ui.spinner(size='34px')
                    ui.label('Connecting to test VM…').classes('font-semibold')
            if not error and tab.key not in page.terminal_start_tasks:
                async def start():
                    operation_id, started = uuid.uuid4().hex, time.monotonic()
                    try:
                        page.terminal_sessions[tab.key] = await _create_target_session(manager)
                        page.terminal_errors.pop(tab.key, None)
                        _record_view_result(manager, 'shell', operation_id, started)
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        page.terminal_errors[tab.key] = str(exc)
                        _record_view_result(manager, 'shell', operation_id, started, exc)
                    finally:
                        if page.terminal_start_tasks.get(tab.key) is asyncio.current_task():
                            page.terminal_start_tasks.pop(tab.key, None)
                page.terminal_start_tasks[tab.key] = asyncio.create_task(start(), name='harnessy-target-shell-' + manager.target.id)
            if not error:
                async def watch():
                    if panel.is_deleted:
                        timer.deactivate()
                        return
                    task = page.terminal_start_tasks.get(tab.key)
                    if task is None or task.done():
                        timer.deactivate()
                        page.refresh_tabs()
                timer = ui.timer(0.25, watch)
            return
        dom = 'hy-target-' + re.sub(r'[^A-Za-z0-9_-]', '-', tab.key)
        element = ui.element('div').props(f'id={dom}').classes('hy-terminal-shell hy-xterm')
        clear.on('click', js_handler=f'() => window.harnessyTerminalClear && window.harnessyTerminalClear({json.dumps(tab.key)})')
        client = element.client
        client.run_javascript(f'window.harnessyCreateTerminal && window.harnessyCreateTerminal({json.dumps(dom)}, {json.dumps(tab.key)}, {json.dumps(manager.workspace.id)});', timeout=2)
        cursor, history = session.history_snapshot()
        cursor_state = {'value': cursor}
        if history:
            client.run_javascript(f'window.harnessyTerminalWrite && window.harnessyTerminalWrite({json.dumps(tab.key)}, {json.dumps(history)});', timeout=2)
        async def poll():
            if panel.is_deleted:
                timer.deactivate()
                return
            next_cursor, chunk = session.read_since(cursor_state['value'])
            if chunk:
                try:
                    await client.run_javascript(f'window.harnessyTerminalWrite && window.harnessyTerminalWrite({json.dumps(tab.key)}, {json.dumps(chunk)});', timeout=2)
                    cursor_state['value'] = next_cursor
                except Exception:
                    pass
        timer = ui.timer(0.08, poll)


# View handles remain server-side. Only workspace/target IDs enter UI-session settings.
_TARGET_DESKTOP_VIEWS = {}
_TARGET_DESKTOP_TASKS = {}
_TARGET_DESKTOP_ERRORS = {}


def _desktop_key(page, key):
    # Distinct logins for the same username must never share a captured session
    # capability. The server-only session token also survives a browser reload.
    accounts = getattr(page, '_accounts', None)
    session = str(getattr(accounts, '_token', '') or getattr(page, '_page_id', ''))
    return str(getattr(page, '_username', '') or ''), session, key


def close_target_desktop(page, key):
    identity = _desktop_key(page, key)
    task = _TARGET_DESKTOP_TASKS.pop(identity, None)
    if task is not None and not task.done():
        task.cancel()
    view = _TARGET_DESKTOP_VIEWS.pop(identity, None)
    if view is not None:
        view.close()
    _TARGET_DESKTOP_ERRORS.pop(identity, None)


async def close_target_tab_views():
    tasks = tuple(_TARGET_DESKTOP_TASKS.values())
    _TARGET_DESKTOP_TASKS.clear()
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    handles = tuple(_TARGET_DESKTOP_VIEWS.values())
    _TARGET_DESKTOP_VIEWS.clear()
    _TARGET_DESKTOP_ERRORS.clear()
    if handles:
        await asyncio.gather(*(view.aclose() for view in handles), return_exceptions=True)


def _render_target_desktop(page, tab, manager):
    identity = _desktop_key(page, tab.key)
    view = _TARGET_DESKTOP_VIEWS.get(identity)
    if view is not None and not view.active:
        close_target_desktop(page, tab.key)
        view = None
    with ui.column().classes('hy-tool-panel w-full no-wrap gap-0') as panel:
        with ui.row().classes('hy-tool-toolbar w-full items-center py-2 gap-2'):
            ui.label(manager.target.name + ' · ' + ('Web UI' if manager.guest.interface == 'web' else 'Desktop')).classes('font-semibold')
            ui.label('Independent test VM').classes('text-xs hy-muted')
            ui.space()
            if view is not None:
                def reconnect():
                    close_target_desktop(page, tab.key)
                    page.refresh_tabs()
                ui.button('Reconnect', icon='refresh', on_click=reconnect).props('flat dense no-caps')
        if manager.windows:
            with ui.expansion('Windows sign-in', icon='account_circle').classes('w-full px-3'):
                ui.label('Desktop sign-in user: harnessy. Set its Windows password after first Start has finished.').classes('text-sm hy-muted')
                password = ui.input('New Windows sign-in password', password=True, password_toggle_button=True).classes('w-full max-w-lg')
                async def set_password():
                    value = str(password.value or '')
                    if not value or any(c in value for c in ('\x00', '\r', '\n')):
                        ui.notify('Enter a non-empty password without line breaks.', type='warning')
                        return
                    try:
                        broker = ExternalTargetBroker(manager.workspace)
                        command = "Set-LocalUser -Name 'harnessy' -Password (ConvertTo-SecureString " + broker._ps_literal(value) + ' -AsPlainText -Force)'
                        result = await broker.exec(manager.target, command)
                        if not result['ok']:
                            raise RuntimeError(result.get('stderr') or 'Could not set the Windows password.')
                        password.value = ''
                        ui.notify('Windows sign-in password updated.', type='positive')
                    except Exception as exc:
                        ui.notify(str(exc), type='negative', timeout=6000)
                ui.button('Set Windows sign-in password', on_click=set_password).props('flat no-caps')
        if view is not None:
            ui.element('iframe').props(f'src={view.iframe_url} sandbox="{view.sandbox}" title="Test target graphical interface" referrerpolicy=no-referrer').classes('w-full grow border-0').style('min-height:0;flex:1')
            return
        error = _TARGET_DESKTOP_ERRORS.get(identity)
        with ui.column().classes('w-full grow items-center justify-center gap-3'):
            if error:
                ui.icon('error_outline', size='34px').classes('text-negative')
                ui.label('Test VM interface could not open').classes('font-semibold text-negative')
                ui.label(error).classes('text-sm hy-muted whitespace-pre-wrap').style('max-width:760px')
                def retry():
                    _TARGET_DESKTOP_ERRORS.pop(identity, None)
                    page.refresh_tabs()
                ui.button('Reconnect', icon='refresh', on_click=retry).props('unelevated no-caps')
            else:
                ui.spinner(size='34px')
                ui.label('Connecting to test VM interface…').classes('font-semibold')
        if not error and identity not in _TARGET_DESKTOP_TASKS:
            async def start():
                operation_id, started = uuid.uuid4().hex, time.monotonic()
                try:
                    if manager.busy or not (await manager.status())['running'] or manager.busy:
                        raise RuntimeError('Start this test VM and wait until it is ready before opening its interface.')
                    from harnessy.ui.target_views import create_target_view
                    _TARGET_DESKTOP_VIEWS[identity] = await create_target_view(manager, identity[0], getattr(page, '_accounts', None))
                    _record_view_result(manager, 'web', operation_id, started)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    _TARGET_DESKTOP_ERRORS[identity] = str(exc)
                    _record_view_result(manager, 'web', operation_id, started, exc)
                finally:
                    if _TARGET_DESKTOP_TASKS.get(identity) is asyncio.current_task():
                        _TARGET_DESKTOP_TASKS.pop(identity, None)
            _TARGET_DESKTOP_TASKS[identity] = asyncio.create_task(start(), name='harnessy-target-view-' + manager.target.id)
        if not error:
            async def watch():
                if panel.is_deleted:
                    timer.deactivate()
                    return
                task = _TARGET_DESKTOP_TASKS.get(identity)
                if task is None or task.done():
                    timer.deactivate()
                    page.refresh_tabs()
            timer = ui.timer(0.25, watch)


def render_managed_target(page, ws, target, refresh):
    manager = TestTargetManager(ws, target)
    with ui.card().classes('w-full hy-target-card') as panel:
        with ui.row().classes('w-full items-center gap-2'):
            ui.icon('router' if manager.guest.interface == 'web' else ('desktop_windows' if manager.windows else 'computer'))
            ui.label(target.name).classes('font-semibold hy-target-name')
            ui.badge(manager.guest.label).props('outline')
            ui.space()
            operation_spinner = ui.spinner(size='20px').classes('hy-vm-busy-spinner').props('aria-hidden=true data-hy-target-spinner=1')
            operation_spinner.set_visibility(False)
            state_label = ui.label('Checking status…').classes('text-xs hy-muted').props('role=status aria-live=polite')
        operation_progress = ui.linear_progress(value=0).classes('hy-vm-busy-progress w-full').props(
            'indeterminate rounded size=4px aria-label="Test VM operation in progress" data-hy-target-progress=1')
        operation_progress.set_visibility(False)
        operation_timing = ui.label('').classes('text-xs hy-muted').props('aria-live=off')
        operation_timing.set_visibility(False)
        c = manager.config
        radio_status = ui.label('').classes('text-xs hy-muted whitespace-pre-wrap') if manager.guest.family == 'openwrt' else None
        ui.label(f"{c['architecture']} · {c['cpu']} CPUs · {c['memory_mb']} MiB RAM · {c['disk_gb']} GiB disk · Internet enabled").classes('text-xs hy-muted')
        with ui.expansion('Model access and test files', icon='tune').classes('w-full hy-target-details'):
            ui.label(f'Test files: {target.remote_root}').classes('text-xs hy-muted break-all')
            enabled = ui.switch('Available to the model', value=target.enabled)
            approval = ui.select({'ask': 'Ask before protected actions', 'on': 'Allow autonomous target tools'}, value=target.approval_mode, label='Model access').classes('grow')
            def save_access(_=None):
                current = ws.get_external_target(target.id)
                if current is None:
                    return
                ws.upsert_external_target(target_id=target.id, name=target.name, host=target.host, username=target.username,
                    remote_root=target.remote_root, enabled=bool(enabled.value), approval_mode=approval.value, managed_vm=current.managed_vm)
            enabled.on_value_change(save_access)
            approval.on_value_change(save_access)
        if manager.guest.family == 'openwrt':
            with ui.expansion('Emulated radios', icon='wifi').classes('w-full hy-target-details'):
                requested = c.get('emulation') or {}
                wifi = ui.checkbox('Emulated Wi-Fi radios (mac80211_hwsim)', value=bool(requested.get('wifi')))
                bluetooth = ui.checkbox('Emulated Bluetooth controllers', value=bool(requested.get('bluetooth')))
                ui.label('Software radios only: no physical RF, USB dongle identity or access to nearby devices. Wi-Fi setup downloads matching signed simulator packages. Bluetooth downloads matching guest packages and sets up two software controllers on Start, then checks the live controllers. The model sees requested and verified active states separately.').classes('text-xs hy-muted')
                ui.label('Stop this VM before changing the saved selection. Retry its saved setup on a running VM with Set up / repair radios. Unticking Bluetooth stops its managed controllers on the next Start; packages stay installed. Unticking Wi-Fi skips future setup and keeps existing interfaces. Network and wireless configuration is kept.').classes('text-xs hy-muted')
                radio_error = ui.label('').classes('text-negative text-sm whitespace-pre-wrap').props('role=alert')
                async def save_radios():
                    try:
                        if manager.busy or (await manager.status())['state'] != 'stopped' or manager.busy:
                            raise RuntimeError('Stop this test VM and wait for its operation to finish before changing emulated radios.')
                        current = ws.get_external_target(target.id)
                        if current is None:
                            raise RuntimeError('This test VM no longer exists.')
                        config = dict(current.managed_vm)
                        config['emulation'] = {'wifi': bool(wifi.value), 'bluetooth': bool(bluetooth.value)}
                        ws.upsert_external_target(target_id=current.id, name=current.name, host=current.host,
                            username=current.username, remote_root=current.remote_root, enabled=current.enabled,
                            approval_mode=current.approval_mode, managed_vm=config)
                        manager.forget_radios()
                        refresh()
                    except Exception as exc:
                        radio_error.set_text(str(exc))
                ui.button('Apply for next Start', icon='save', on_click=save_radios).props('outline no-caps')
                radio_repair = ui.button('Set up / repair radios', icon='build',
                    on_click=lambda: start_action('radios')).props('outline no-caps')
                radio_guidance_label = ui.label('').classes('text-xs hy-muted whitespace-pre-wrap')

        async def start_action(action, tag=''):
            try:
                if action == 'stop':
                    await manager.request_stop()
                else:
                    manager.begin(action, tag=tag)
                observed_status['error'] = ''
                update_operation_state()
                await poll()
            except Exception as exc:
                ui.notify(str(exc), type='warning', timeout=6000)

        def snapshot_dialog():
            with ui.dialog() as dialog, ui.card().classes('w-[470px] max-w-[95vw]'):
                ui.label('Create test VM snapshot').classes('font-semibold')
                ui.label('Stop the VM and close its shell and graphical interface tabs first. The snapshot includes the VM disk and firmware/TPM state.').classes('text-sm hy-muted')
                name = ui.input('Snapshot name', value=datetime.now().strftime('test-%Y%m%d-%H%M%S')).classes('w-full')
                async def save():
                    await start_action('snapshot', str(name.value or ''))
                    dialog.close()
                ui.button('Create snapshot', on_click=save).props('unelevated no-caps')
                ui.button('Cancel', on_click=dialog.close).props('flat no-caps')
            dialog.open()

        def restore_dialog():
            tags = manager.snapshots()
            if not tags:
                ui.notify('No snapshots yet.', type='info')
                return
            with ui.dialog() as dialog, ui.card().classes('w-[470px] max-w-[95vw]'):
                ui.label('Restore test VM snapshot?').classes('font-semibold')
                ui.label('The stopped test VM returns to the selected snapshot. Changes made inside it since that snapshot are replaced.').classes('text-sm')
                tag = ui.select(tags, value=tags[-1], label='Snapshot').classes('w-full')
                async def restore():
                    await start_action('restore', tag.value)
                    dialog.close()
                ui.button('Restore snapshot', on_click=restore).props('unelevated no-caps color=negative')
                ui.button('Cancel', on_click=dialog.close).props('flat no-caps')
            dialog.open()

        def delete_dialog():
            with ui.dialog() as dialog, ui.card().classes('w-[470px] max-w-[95vw]'):
                ui.label('Delete test VM and its snapshots?').classes('font-semibold')
                ui.label(f'Deletes {target.name} and all data inside this test VM. Stop it and close its shell and graphical interface tabs first.').classes('text-sm')
                async def remove():
                    await start_action('delete')
                    dialog.close()
                ui.button('Delete test VM', on_click=remove).props('unelevated no-caps color=negative')
                ui.button('Cancel', on_click=dialog.close).props('flat no-caps')
            dialog.open()
        with ui.row().classes('w-full gap-1'):
            start_button = ui.button('Start', icon='play_arrow', on_click=lambda: start_action('start')).classes('hy-vm-busy-action').props('flat no-caps')
            stop_button = ui.button('Stop', icon='stop', on_click=lambda: start_action('stop')).classes('hy-vm-busy-action').props('flat no-caps')
            shell_button = ui.button('Shell', icon='terminal', on_click=lambda: open_target_shell(page, manager)).props('flat no-caps')
            desktop_button = ui.button('Web UI' if manager.guest.interface == 'web' else 'Desktop', icon='language' if manager.guest.interface == 'web' else 'desktop_windows', on_click=lambda: open_target_desktop(page, manager)).props('flat no-caps')
            desktop_button.set_visibility(bool(c['desktop']))
            snapshot_button = ui.button('Snapshot', icon='save', on_click=snapshot_dialog).props('flat no-caps')
            restore_button = ui.button('Restore', icon='restore', on_click=restore_dialog).props('flat no-caps')
            delete_button = ui.button(icon='delete_outline', on_click=delete_dialog).props('flat round color=negative aria-label="Delete test VM"').tooltip('Delete test VM')
        with ui.expansion('Activity and setup output', icon='receipt_long').classes('w-full'):
            output = ui.label('').classes('text-xs w-full font-mono').style('white-space:pre-wrap;max-height:260px;overflow:auto')
        error_label = ui.label('').classes('text-negative text-sm whitespace-pre-wrap').props('role=alert data-hy-target-error=1')
        radio_probe_busy = {'value': False}
        observed_status = {'state': 'checking_status', 'running': False, 'error': ''}

        def update_operation_state():
            if panel.is_deleted:
                operation_timer.deactivate()
                return
            op = manager.operation
            active = bool(manager.busy and op and op.state not in {'succeeded', 'failed', 'cancelled'})
            operation_spinner.set_visibility(active)
            operation_progress.set_visibility(active)
            operation_timing.set_visibility(active)
            panel.props(f'aria-busy={str(active).lower()}')
            actions = {'start': 'Starting VM', 'stop': 'Stopping VM', 'radios': 'Setting up emulated radios',
                       'snapshot': 'Creating snapshot', 'restore': 'Restoring snapshot', 'delete': 'Deleting VM'}
            stages = {'prerequisites': 'Checking requirements', 'download': 'Downloading guest image',
                      'prepare_disk': 'Preparing guest disk', 'launch': 'Booting guest',
                      'launch_reconcile': 'Checking VM after launcher timeout',
                      'wait_ssh': 'Waiting for guest SSH', 'probe_shell': 'Checking guest shell',
                      'radio_setup': 'Preparing and checking emulated radios',
                      'bluetooth_packages': 'Downloading matching Bluetooth packages',
                      'bluetooth_emulator': 'Preparing Bluetooth software emulator',
                      'bluetooth_attach': 'Attaching software Bluetooth controllers',
                      'bluetooth_verify': 'Verifying live Bluetooth controllers',
                      'ready': 'Finishing readiness checks'}
            if active:
                action = actions.get(op.action, 'Working on VM')
                stage = stages.get(op.stage, str(op.stage or '').replace('_', ' ').capitalize())
                state_label.set_text(action + (' · ' + stage if stage else '…'))
                elapsed = max(0, int(time.monotonic() - op.started))
                minutes, seconds = divmod(elapsed, 60)
                operation_timing.set_text(f'Elapsed {minutes}m {seconds:02d}s' if minutes else f'Elapsed {seconds}s')
            elif op and op.state in {'failed', 'cancelled'}:
                if (op.action == 'start' and op.state == 'failed' and observed_status['running']
                        and not observed_status['error']):
                    state_label.set_text('Guest running · Start setup incomplete')
                else:
                    state_label.set_text(('Radio setup' if op.action == 'radios' else op.action.capitalize())
                                         + (' failed' if op.state == 'failed' else ' cancelled'))
            elif op and op.state == 'succeeded' and op.action == 'start':
                state_label.set_text('Ready')
            else:
                state_label.set_text(str(observed_status['state']).replace('_', ' ').title())
            for action, button in (('start', start_button), ('stop', stop_button)):
                button.props(add='loading' if active and op.action == action else '',
                             remove='' if active and op.action == action else 'loading')
            retry_start = bool(op and op.action == 'start' and op.state in {'failed', 'cancelled'})
            start_button.set_text('Starting…' if active and op.action == 'start' else 'Retry Start' if retry_start else 'Start')
            stop_button.set_text('Stopping…' if active and op.action == 'stop' else 'Stop')
            operation_error = (str(op.error or '').strip() or target_operation_error(op)) if op and op.state == 'failed' else (
                str(op.error or '').strip() if op and op.state == 'cancelled' else '')
            status_error = str(observed_status['error'] or '')
            error_label.set_text('\n'.join(value for value in (operation_error, status_error) if value))

        async def poll():
            if panel.is_deleted:
                timer.deactivate()
                return
            op = manager.operation
            if op:
                output.set_text(op.output)
                error_label.set_text(op.error)
                if op.action == 'delete' and op.state == 'succeeded':
                    timer.deactivate()
                    refresh()
                    return
            busy = manager.busy
            update_operation_state()
            try:
                status = await manager.status()
                if panel.is_deleted:
                    return
                observed_status.update(state=status['state'], running=status['running'], error='')
                update_operation_state()
                running = status['running']
                if radio_status is not None:
                    from harnessy.environment.test_radios import radio_summary
                    snapshot = status.get('hardware_emulation')
                    if (snapshot and snapshot.get('observation') == 'not_probed' and running
                            and not busy and any((c.get('emulation') or {}).values())
                            and not radio_probe_busy['value']):
                        radio_probe_busy['value'] = True
                        radio_status.set_text('Checking emulated radios inside the running guest…')
                        try:
                            snapshot = await manager.inspect_radios()
                        finally:
                            radio_probe_busy['value'] = False
                    if snapshot and snapshot.get('observation') in {'last_guest_probe', 'live_guest_probe'}:
                        age = snapshot.get('probe_age_seconds')
                        when = f' ({int(age)} seconds ago)' if isinstance(age, (int, float)) and age >= 0 else ''
                        radio_status.set_text('Last guest probe' + when + ': ' + radio_summary(snapshot))
                        from harnessy.environment.test_radios import radio_guidance
                        radio_guidance_label.set_text(radio_guidance(snapshot))
                    else:
                        radio_status.set_text('Emulated radios: not yet probed inside this guest.')
                    radio_repair.set_enabled(running and not busy and any((c.get('emulation') or {}).values()))
                start_button.set_enabled(not busy and (not running or bool(op and op.state == 'failed')))
                stop_button.set_enabled(running and (not busy or bool(op and op.action == 'start')))
                shell_button.set_enabled(not busy and running)
                desktop_button.set_enabled(not busy and running)
                snapshot_button.set_enabled(not busy and status['state'] == 'stopped')
                restore_button.set_enabled(not busy and status['state'] == 'stopped' and bool(manager.snapshots()))
                delete_button.set_enabled(not busy and not running)
            except Exception as exc:
                if not panel.is_deleted:
                    observed_status['state'] = 'status_unavailable'
                    observed_status['error'] = str(exc).strip() or 'VM status could not be checked. Retry the status check before changing VM data.'
                    update_operation_state()
        for button in (start_button, stop_button, shell_button, desktop_button, snapshot_button, restore_button, delete_button):
            button.set_enabled(False)
        timer = ui.timer(5.0, poll)
        operation_timer = ui.timer(0.3, update_operation_state)
        initial_timer = ui.timer(0.1, poll, once=True)
        def dispose():
            timer.deactivate()
            operation_timer.deactivate()
            initial_timer.deactivate()
        panel.client.on_disconnect(dispose)
        return dispose
