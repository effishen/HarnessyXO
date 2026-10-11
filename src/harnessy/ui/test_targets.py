"""UI for independently managed test VMs in External/Test Targets."""
from __future__ import annotations

import asyncio
import json
import platform
import re
import shutil
from datetime import datetime

from nicegui import ui

from harnessy.agent.external_targets import ExternalTargetBroker
from harnessy.core.terminal import TerminalSession
from harnessy.environment.presets import canonical_arch
from harnessy.environment.test_targets import TestTargetManager


def open_vm_creator(ws, refresh, os_name='ubuntu-24.04'):
    from harnessy.environment.test_catalog import GUESTS, guest_os
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
                arch = ui.select({'arm64': 'ARM64 (Apple Silicon / ARM hosts)', 'x86_64': 'x86-64 (Intel / AMD)'},
                    value=canonical_arch(platform.machine()), label='Architecture').classes('w-full')
                ui.label('Matching the host enables acceleration. Other architectures use slower CPU emulation.').classes('text-xs hy-muted')
                approval = ui.select({'ask': 'Ask before protected target actions', 'on': 'Allow autonomous target tools'},
                    value='on', label='Model access').classes('w-full')
                ui.label('The model can install software and make system changes in this test VM.').classes('text-xs hy-muted')
            prerequisite_hint = ui.label('').classes('text-xs hy-muted')
            start_now = ui.switch('Start after creating', value=True)
            error = ui.label('').classes('text-sm text-negative whitespace-pre-wrap').props('role=alert')

            selection = {'id': initial.id}
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
                description.set_text(guest.description)
                windows_options.set_visibility(guest.family == 'windows')
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
                                    'desktop': bool(desktop.value), 'iso_path': str(iso.value or '')})
                    if start_now.value:
                        TestTargetManager(ws, target).begin('start')
                    dialog.close()
                    refresh()
                except Exception as exc:
                    error.set_text(str(exc))
            ui.button('Create test VM', icon='add', on_click=create).props('unelevated no-caps color=primary')
    dialog.open()

async def open_target_shell(page, manager):
    try:
        if manager.busy or not (await manager.status())['running']:
            raise RuntimeError('Start this test VM and wait until it is ready before opening its shell.')
        argv, env, cwd = manager.terminal_command()
        key = f'test-target:{manager.workspace.id}:{manager.target.id}'
        if key in page.terminal_sessions:
            raise RuntimeError('This test target already has an open shell.')
        release = manager.acquire()
        try:
            session = await asyncio.to_thread(TerminalSession, cwd, command_argv=argv, env=env)
        except BaseException:
            release()
            raise
        page.terminal_sessions[key] = session
    except Exception as exc:
        ui.notify(str(exc), type='negative', timeout=6000)
        return
    with ui.dialog().props('maximized') as dialog, ui.card().classes('w-full h-full no-wrap gap-1'):
        with ui.row().classes('w-full items-center'):
            ui.label(f'{manager.target.name} · ' + manager.guest.shell).classes('font-semibold')
            ui.label('Test VM shell · internet and system updates available').classes('text-xs hy-muted')
            ui.space()
            ui.button('Ctrl+C', on_click=session.interrupt).props('flat no-caps')
            ui.button('Close shell', on_click=dialog.close).props('flat no-caps')
        dom = 'hy-target-' + manager.target.id
        element = ui.element('div').props(f'id={dom}').classes('hy-terminal-shell hy-xterm w-full').style('flex:1;min-height:300px')
        client = element.client
        cursor = {'value': 0, 'mounted': False}
        async def mount():
            await client.run_javascript(f'window.harnessyCreateTerminal({json.dumps(dom)}, {json.dumps(key)}, {json.dumps(manager.workspace.id)});')
            cursor['mounted'] = True
        ui.timer(0.15, mount, once=True)
        async def poll():
            if not cursor['mounted']:
                return
            next_cursor, chunk = session.read_since(cursor['value'])
            if chunk:
                try:
                    await client.run_javascript(f'window.harnessyTerminalWrite({json.dumps(key)}, {json.dumps(chunk)});', timeout=2)
                    cursor['value'] = next_cursor
                except Exception:
                    pass
        timer = ui.timer(0.1, poll)
        def close():
            timer.deactivate()
            session.close()
            release()
            page.terminal_sessions.pop(key, None)
        dialog.on('hide', close)
        client.on_disconnect(close)
    dialog.open()


async def open_target_desktop(manager):
    try:
        if not (await manager.status())['running']:
            raise RuntimeError('Start this test VM before opening its graphical interface.')
        info = manager.desktop_info()
    except Exception as exc:
        ui.notify(str(exc), type='warning', timeout=6000)
        return
    web = info.get('kind') == 'web'
    with ui.dialog() as dialog, ui.card().classes('hy-simple-dialog w-[680px] max-w-[95vw]'):
        ui.label(f'{manager.target.name} · ' + ('Web interface' if web else 'Desktop')).classes('text-lg font-semibold')
        ui.label('Open this address on the computer running HarnessyXO.' if web else 'Open this VNC address on the computer running HarnessyXO.').classes('text-sm hy-muted')
        ui.input('Web address' if web else 'VNC address', value=info['url']).props('readonly').classes('w-full')
        ui.input('Root password' if web else 'VNC connection password', value=info['password'], password=True, password_toggle_button=True).props('readonly').classes('w-full')
        ui.label('On another computer, run this SSH tunnel, then open the address in your ' + ('browser. Sign in as root.' if web else 'VNC viewer.')).classes('text-xs hy-muted')
        ui.code(f"ssh -N -L {info['port']}:127.0.0.1:{info['port']} YOUR_USER@HARNESSY_HOST", language='bash').classes('w-full')
        async def launch():
            opener = shutil.which('open' if platform.system() == 'Darwin' else 'xdg-open')
            if not opener:
                ui.notify('Open the address in a browser on the HarnessyXO host.' if web else 'Open the address in a VNC viewer on the HarnessyXO host.', type='info')
                return
            proc = await asyncio.create_subprocess_exec(opener, info['url'], stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
            _, err = await proc.communicate()
            if proc.returncode:
                ui.notify('Could not open the graphical interface: ' + err.decode(errors='replace')[-300:], type='warning')
        ui.button('Open web interface on HarnessyXO host' if web else 'Open desktop on HarnessyXO host', icon='open_in_new', on_click=launch).props('unelevated no-caps')
        if manager.windows:
            ui.separator()
            ui.label('Windows desktop sign-in user: harnessy. After first Start finishes, you can set its sign-in password here.').classes('text-sm')
            password = ui.input('New Windows sign-in password', password=True, password_toggle_button=True).classes('w-full')
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
        ui.button('Close', on_click=dialog.close).props('flat no-caps')
    dialog.open()


def render_managed_target(page, ws, target, refresh):
    manager = TestTargetManager(ws, target)
    with ui.card().classes('w-full hy-target-card') as panel:
        with ui.row().classes('w-full items-center gap-2'):
            ui.icon('router' if manager.guest.interface == 'web' else ('desktop_windows' if manager.windows else 'computer'))
            ui.label(target.name).classes('font-semibold hy-target-name')
            ui.badge(manager.guest.label).props('outline')
            ui.space()
            state_label = ui.label('Checking status…').classes('text-xs hy-muted').props('role=status aria-live=polite')
        c = manager.config
        ui.label(f"{c['architecture']} · {c['cpu']} CPUs · {c['memory_mb']} MiB RAM · {c['disk_gb']} GiB disk · Internet enabled").classes('text-xs hy-muted')
        with ui.expansion('Model access and test files', icon='tune').classes('w-full hy-target-details'):
            ui.label(f'Test files: {target.remote_root}').classes('text-xs hy-muted break-all')
            enabled = ui.switch('Available to the model', value=target.enabled)
            approval = ui.select({'ask': 'Ask before protected actions', 'on': 'Allow autonomous target tools'}, value=target.approval_mode, label='Model access').classes('grow')
            def save_access(_=None):
                ws.upsert_external_target(target_id=target.id, name=target.name, host=target.host, username=target.username,
                    remote_root=target.remote_root, enabled=bool(enabled.value), approval_mode=approval.value, managed_vm=target.managed_vm)
            enabled.on_value_change(save_access)
            approval.on_value_change(save_access)

        async def start_action(action, tag=''):
            try:
                if action == 'stop':
                    await manager.request_stop()
                else:
                    manager.begin(action, tag=tag)
                state_label.set_text(action.capitalize() + ' in progress…')
                await poll()
            except Exception as exc:
                ui.notify(str(exc), type='warning', timeout=6000)

        def snapshot_dialog():
            with ui.dialog() as dialog, ui.card().classes('w-[470px] max-w-[95vw]'):
                ui.label('Create test VM snapshot').classes('font-semibold')
                ui.label('Stop the VM and close its shell first. The snapshot includes the VM disk and firmware/TPM state.').classes('text-sm hy-muted')
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
                ui.label(f'Deletes {target.name} and all data inside this test VM. Stop it and close its shell first.').classes('text-sm')
                async def remove():
                    await start_action('delete')
                    dialog.close()
                ui.button('Delete test VM', on_click=remove).props('unelevated no-caps color=negative')
                ui.button('Cancel', on_click=dialog.close).props('flat no-caps')
            dialog.open()
        with ui.row().classes('w-full gap-1'):
            start_button = ui.button('Start', icon='play_arrow', on_click=lambda: start_action('start')).props('flat no-caps')
            stop_button = ui.button('Stop', icon='stop', on_click=lambda: start_action('stop')).props('flat no-caps')
            shell_button = ui.button('Shell', icon='terminal', on_click=lambda: open_target_shell(page, manager)).props('flat no-caps')
            desktop_button = ui.button('Web UI' if manager.guest.interface == 'web' else 'Desktop', icon='language' if manager.guest.interface == 'web' else 'desktop_windows', on_click=lambda: open_target_desktop(manager)).props('flat no-caps')
            desktop_button.set_visibility(bool(c['desktop']))
            snapshot_button = ui.button('Snapshot', icon='save', on_click=snapshot_dialog).props('flat no-caps')
            restore_button = ui.button('Restore', icon='restore', on_click=restore_dialog).props('flat no-caps')
            delete_button = ui.button(icon='delete_outline', on_click=delete_dialog).props('flat round color=negative aria-label="Delete test VM"').tooltip('Delete test VM')
        with ui.expansion('Activity and setup output', icon='receipt_long').classes('w-full'):
            output = ui.label('').classes('text-xs w-full font-mono').style('white-space:pre-wrap;max-height:260px;overflow:auto')
        error_label = ui.label('').classes('text-negative text-sm whitespace-pre-wrap')
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
            try:
                status = await manager.status()
                if panel.is_deleted:
                    return
                state_label.set_text(f'{op.action} in progress' if busy else status['state'].replace('_', ' ').title())
                running = status['running']
                start_button.set_enabled(not busy and (not running or bool(op and op.state == 'failed')))
                stop_button.set_enabled(running and (not busy or bool(op and op.action == 'start')))
                shell_button.set_enabled(not busy and running)
                desktop_button.set_enabled(not busy and running)
                snapshot_button.set_enabled(not busy and status['state'] == 'stopped')
                restore_button.set_enabled(not busy and status['state'] == 'stopped' and bool(manager.snapshots()))
                delete_button.set_enabled(not busy and not running)
            except Exception as exc:
                if not panel.is_deleted:
                    state_label.set_text('Status unavailable')
                    error_label.set_text(str(exc))
        for button in (start_button, stop_button, shell_button, desktop_button, snapshot_button, restore_button, delete_button):
            button.set_enabled(False)
        timer = ui.timer(5.0, poll)
        initial_timer = ui.timer(0.1, poll, once=True)
        def dispose():
            timer.deactivate()
            initial_timer.deactivate()
        panel.client.on_disconnect(dispose)
        return dispose
