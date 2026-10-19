"""Named local VM environments, independent of workspace creation and SSH targets."""
from __future__ import annotations

import asyncio
import platform
import time
from dataclasses import replace
from typing import Any

from nicegui import ui

from harnessy.environment import EnvironmentConfig, EnvironmentManager, ENVIRONMENT_OPERATIONS, ENVIRONMENT_STATUS
from harnessy.environment.activity import active_work
from harnessy.environment.presets import IMAGES, PRESETS, TOOL_BUNDLES, canonical_arch, execution_mode, get_preset
from harnessy.environment.resources import resource_values
from harnessy.ui.project_access import ProjectAccessEditor


FILE_MODES = {
    'live': 'Shared project source (read/write)',
    'readonly': 'Shared project source (read-only)',
    'copy': 'Separate project copy',
}
TOOL_LABELS = {
    'rea': 'REA CLI (Reverse Engineer Anything)',
    'ghidra': 'Ghidra headless',
    'python-re': 'Python reverse engineering tools',
    'python-tooling': 'Python 3.11 development and testing tools',
    'bumble': 'Bumble Bluetooth tools',
}


def _copy_only(image) -> bool:
    return image.integration == 'managed' or image.id == 'openwrt-25.12.5'


def network_policy_text(provider: str) -> tuple[str, str]:
    if provider == 'openwrt':
        return 'Outbound network', 'QEMU NAT provides guest networking. When enabled, the guest can reach destinations permitted by the host network; this backend has no public-only destination filter. Verified setup downloads run through HarnessyXO even when guest outbound is off.'
    if provider == 'managed':
        return 'Outbound network', 'Windows Firewall applies the outbound policy inside the guest. Guest administrators can change that firewall.'
    return 'Public outbound network', 'The guest firewall filters host, LAN, private and reserved destinations. Disabling public outbound also skips downloadable optional tools.'


def _elapsed(started: float) -> str:
    value = max(0, int(time.time() - started)) if started else 0
    minutes, seconds = divmod(value, 60)
    hours, minutes = divmod(minutes, 60)
    return f'{hours}h {minutes:02d}m {seconds:02d}s' if hours else f'{minutes}m {seconds:02d}s'


def tool_label(preset, tool_id: str) -> str:
    if preset.image.integration == 'openwrt':
        from harnessy.environment.openwrt_tools import OPENWRT_TOOL_BY_ID
        tool = OPENWRT_TOOL_BY_ID.get(tool_id)
        if tool is not None:
            return tool.label
    return TOOL_LABELS.get(tool_id, tool_id)


def open_vm_creator(workbench, workspace, on_saved) -> None:
    """Save a definition first, then optionally start its independent operation."""
    state: dict[str, Any] = {'busy': False, 'optional': {}, 'syncing': False}
    with ui.dialog() as dialog, ui.card().classes('w-[880px] max-w-[96vw] gap-3').style('max-height:92vh'):
        with ui.row().classes('w-full items-center gap-2 no-wrap'):
            ui.icon('computer', size='24px')
            ui.label('Create VM Environment').classes('text-xl font-semibold grow min-w-0')
            close = ui.button(icon='close', on_click=dialog.close).props('flat round dense aria-label="Close dialog"')
        body = ui.column().classes('w-full gap-3 overflow-y-auto').style('min-height:0')
        with body:
            name = ui.input('VM name', placeholder='For example: OpenWrt MIPS or Ubuntu Build').props('autofocus outlined').classes('w-full')
            purpose = ui.textarea('Purpose / model instructions (optional)', placeholder='For example: run and test the project here; keep the base system clean.').props('outlined autogrow').classes('w-full')
            ui.label('The model can choose among enabled VMs. Names and purpose guide its choice; file and network settings control actual access.').classes('text-xs hy-muted')
            with ui.row().classes('w-full gap-3 flex-wrap'):
                image = ui.select({key: value.name for key, value in IMAGES.items()}, value='ubuntu-24.04', label='Operating system / release').props('outlined').style('flex:2 1 260px')
                architecture = ui.select({}, label='Architecture').props('outlined').style('flex:1 1 180px')
                bundle = ui.select({}, label='Tool preset').props('outlined').style('flex:1 1 180px')
            with ui.row().classes('w-full gap-3 flex-wrap'):
                cpu = ui.input('vCPU count', value='4').props('outlined type=number min=1 max=64 step=1').style('flex:1 1 140px')
                ram = ui.input('RAM (GiB)', value='8').props('outlined type=number min=1 max=256 step=0.5').style('flex:1 1 140px')
                disk = ui.input('Storage (GiB)', value='128').props('outlined type=number min=16 max=4096 step=1').style('flex:1 1 140px')
            mode = ui.label('').classes('text-xs hy-muted').style('overflow-wrap:anywhere')
            image_description = ui.label('').classes('text-xs hy-muted').style('overflow-wrap:anywhere')
            limits = ui.label('').classes('text-xs hy-muted')
            files = ui.select(FILE_MODES, value='live', label='Project files').props('outlined').classes('w-full')
            file_note = ui.label('').classes('text-xs hy-muted')
            installer_iso = ui.input('Windows installer ISO on the HarnessyXO host', placeholder='/path/to/windows.iso').props('outlined').classes('w-full')
            desktop = ui.switch('Enable graphical interface (desktop / Web UI)', value=False)
            with ui.expansion('Emulated radios', icon='wifi').classes('w-full') as radio_options:
                wifi = ui.checkbox('Emulated Wi-Fi radios (mac80211_hwsim)', value=False)
                bluetooth = ui.checkbox('Emulated Bluetooth controllers', value=False)
                ui.label('Software radios only: no real RF, USB dongle identity or nearby devices. Matching guest packages download on Start. The model sees requested and verified active controllers separately.').classes('text-xs hy-muted')
            with ui.row().classes('w-full gap-x-6 gap-y-1 flex-wrap'):
                network = ui.switch('Public outbound network', value=True)
                enabled = ui.switch('Enabled for model use', value=True)
            network_note = ui.label('').classes('text-xs hy-muted')
            project_access = ProjectAccessEditor(workspace)
            ui.label('Each VM has its own OS and installed packages. Keep builds and caches in VM-owned directories; anything written inside shared project source is shared. Resetting a VM preserves workspace source.').classes('text-xs hy-muted')
            optional_area = ui.column().classes('w-full gap-1')
            start = ui.checkbox('Start after creating', value=True)
        error = ui.label('').classes('text-sm text-negative').style('white-space:pre-wrap;overflow-wrap:anywhere')
        with ui.row().classes('w-full items-center justify-end gap-2'):
            save_spinner = ui.spinner(size='20px')
            save_spinner.set_visibility(False)
            cancel = ui.button('Cancel', on_click=dialog.close).props('flat no-caps')
            create = ui.button('Create VM', icon='add', on_click=lambda: submit()).props('unelevated no-caps')

        def selected_preset():
            options = [item for item in PRESETS.values() if item.image_id == image.value and item.tools_id == bundle.value]
            if not options:
                raise ValueError('Choose a compatible operating system and tool preset.')
            return options[0]

        def optional_for(preset) -> set[str]:
            return state['optional'].setdefault(preset.id, set())

        def choose_tool(preset_id: str, tool_id: str, selected: bool) -> None:
            values = state['optional'].setdefault(preset_id, set())
            values.add(tool_id) if selected else values.discard(tool_id)

        def update_file_note(_event=None) -> None:
            integration = IMAGES[str(image.value)].integration
            is_openwrt = integration == 'openwrt'
            if files.value == 'copy':
                text = 'The first use deploys an independent project copy. Changes remain separate from workspace source and are never written back automatically. Commands retain an isolated project view.'
                if integration == 'openwrt':
                    text = 'The first use deploys an independent project copy into this VM. Previously deployed guest files remain available there. Guest administration is allowed; canonical workspace source is never mounted or written back automatically.'
                if integration == 'managed':
                    text = 'Guest administration and previously deployed guest copies are available. Deploy selected project files explicitly; canonical workspace source is never mounted or written back automatically.'
            elif files.value == 'readonly':
                text = 'The VM can read the selected project source. Save builds and working data in its own writable directories.'
            else:
                text = 'Changes inside the selected project source are shared between VMs. Keep dependencies, builds and caches in this VM’s own directories.'
            if is_openwrt and files.value != 'copy':
                text += ' OpenWrt uses a synchronized guest projection for each command rather than a live host mount.'
                text += ' Guest system administration requires Separate project copy mode.'
            file_note.set_text(text)

        def preview(_event=None) -> None:
            if state['syncing']:
                return
            try:
                preset = selected_preset()
            except ValueError:
                return
            _driver, execution = execution_mode(str(architecture.value or ''))
            mode.set_text(execution)
            image_description.set_text(preset.image.description)
            provider = {'openwrt': 'openwrt', 'managed': 'managed'}.get(preset.image.integration, 'lima')
            network_label, network_description = network_policy_text(provider)
            network.set_text(network_label)
            network_note.set_text(network_description)
            if preset.image.integration == 'openwrt':
                mips = str(architecture.value or '').startswith('mips')
                cpu.props(f'max={1 if mips else 64}'); ram.props(f'max={2 if mips else 128}'); disk.props('max=64')
                limits.set_text('OpenWrt Malta MIPS: 1 vCPU · 1–2 GiB RAM · 16–64 GiB disk. Software CPU emulation; hardware-specific peripherals are not reproduced.' if mips else 'OpenWrt: up to 128 GiB RAM and 64 GiB sparse disk. The guest does not reproduce a particular router or its peripherals.')
            optional_area.clear()
            with optional_area:
                with ui.expansion('Optional tools to install', icon='construction').classes('w-full'):
                    ui.label('Only options compatible with this image are listed. Required runtime packages are always installed.').classes('text-xs hy-muted')
                    if not preset.optional_tool_ids:
                        ui.label('Install packages with the guest apk tool. The automated tool catalogue is not available for this release.' if preset.image_id == 'openwrt-25.12.5' else 'This image has no additional managed tool packages.').classes('text-xs hy-muted')
                    previous_group = ''
                    for tool_id in preset.optional_tool_ids:
                        tool = None
                        if preset.image.integration == 'openwrt':
                            from harnessy.environment.openwrt_tools import OPENWRT_TOOL_BY_ID
                            tool = OPENWRT_TOOL_BY_ID.get(tool_id)
                        if tool is not None and tool.group != previous_group:
                            ui.label(tool.group).classes('text-xs font-semibold mt-2')
                            previous_group = tool.group
                        checkbox = ui.checkbox(tool_label(preset, tool_id), value=tool_id in optional_for(preset))
                        checkbox.on_value_change(lambda event, pid=preset.id, tid=tool_id: choose_tool(pid, tid, bool(event.value)))
                        if tool is not None and tool.note:
                            ui.label(tool.note).classes('text-xs hy-muted pl-8')
                    if preset.image.integration == 'openwrt':
                        from harnessy.environment.openwrt_tools import OPENWRT_UNAVAILABLE_TOOLS
                        with ui.expansion('Unavailable for this image', icon='info_outline').classes('w-full'):
                            for tool_id, reason in OPENWRT_UNAVAILABLE_TOOLS.items():
                                box = ui.checkbox(TOOL_LABELS.get(tool_id, tool_id), value=False)
                                box.disable()
                                ui.label(reason).classes('text-xs hy-muted pl-8')
                    with ui.expansion('Required packages', icon='list').classes('w-full'):
                        ui.label(', '.join(preset.packages) or 'Image runtime only').classes('text-xs hy-muted').style('overflow-wrap:anywhere')
                    if not network.value:
                        ui.label('Verified setup packages download through HarnessyXO even when guest outbound is off.' if preset.image.integration == 'openwrt' else 'Downloads are skipped while public outbound is off. Selected tools remain pending.').classes('text-xs text-warning')
            update_file_note()

        def image_changed(_event=None) -> None:
            if state['syncing']:
                return
            state['syncing'] = True
            selected = IMAGES[str(image.value)]
            architectures = {item: {'mips': 'MIPS 24Kc · big-endian', 'arm64': 'ARM64', 'x86_64': 'x86-64'}.get(item, item) for item in selected.architectures}
            architecture.options = architectures
            preferred = canonical_arch(platform.machine())
            architecture.set_value(preferred if preferred in architectures else next(iter(architectures)))
            architecture.update()
            bundles = {item.tools_id: TOOL_BUNDLES.get(item.tools_id, item.tools_id) for item in PRESETS.values() if item.image_id == selected.id}
            bundle.options = bundles
            bundle.set_value('general' if 'general' in bundles else next(iter(bundles)))
            bundle.update()
            if selected.integration == 'openwrt':
                cpu.set_value('1'); ram.set_value('1'); disk.set_value('16')
                cpu.props('max=1'); ram.props('max=2'); disk.props('max=64')
                limits.set_text('OpenWrt Malta MIPS: 1 vCPU · 1–2 GiB RAM · 16–64 GiB disk. Software CPU emulation; hardware-specific peripherals are not reproduced.')
            elif selected.integration == 'managed':
                windows = selected.id.startswith('windows')
                cpu.set_value('4'); ram.set_value('8' if windows else '4'); disk.set_value('80' if windows else '40')
                cpu.props('max=64'); ram.props('max=256'); disk.props('max=4096')
                limits.set_text('Windows requires your own compatible installer ISO and guest setup.' if windows else 'Kali uses its own guest filesystem. Desktop access is optional.')
            else:
                cpu.set_value('4'); ram.set_value('8'); disk.set_value('128')
                cpu.props('max=64'); ram.props('max=256'); disk.props('max=4096')
                limits.set_text('Sparse storage sets maximum capacity. Multiple VMs can run together; leave resources for your model and host.')
            managed = selected.integration == 'managed'
            copy_only = _copy_only(selected)
            files.options = {'copy': FILE_MODES['copy']} if copy_only else FILE_MODES
            if copy_only or files.value not in files.options:
                files.set_value('copy' if copy_only else 'live')
            files.update()
            installer_iso.set_visibility(managed and selected.id.startswith('windows'))
            desktop.set_visibility(managed or selected.integration == 'openwrt' or selected.id.startswith('kali'))
            desktop.set_value((managed and selected.id.startswith('windows')) or selected.integration == 'openwrt')
            radio_options.set_visibility(selected.integration == 'openwrt')
            state['syncing'] = False
            preview()

        async def submit() -> None:
            if state['busy']:
                return
            try:
                vm_name = str(name.value or '').strip()
                if not vm_name:
                    raise ValueError('Enter a name for this VM.')
                preset = selected_preset()
                resources = resource_values(cpu.value, ram.value, disk.value)
                if preset.image.integration == 'openwrt':
                    mips = str(architecture.value or '').startswith('mips')
                    if resources['disk_gb'] > 64 or resources['memory_mb'] > (2048 if mips else 131072) or (mips and resources['cpu'] != 1):
                        raise ValueError('OpenWrt MIPS supports 1 vCPU and up to 2 GiB RAM; other OpenWrt guests support up to 128 GiB RAM. Disk maximum is 64 GiB.')
                config = EnvironmentConfig(
                    name=vm_name, purpose=str(purpose.value or '').strip(), enabled=bool(enabled.value),
                    preset=preset.id, provider={'openwrt': 'openwrt', 'managed': 'managed'}.get(preset.image.integration, 'lima'),
                    architecture=str(architecture.value or ''), **resources, network=bool(network.value),
                    files_mode=str(files.value), optional_tools=tuple(tool for tool in preset.optional_tool_ids if tool in optional_for(preset)),
                    iso_path=str(installer_iso.value or '').strip() if preset.image.integration == 'managed' else '',
                    desktop=bool(desktop.value) if (preset.image.integration in {'managed', 'openwrt'} or preset.image_id.startswith('kali')) else False,
                    emulation={'wifi': bool(wifi.value), 'bluetooth': bool(bluetooth.value)} if preset.image.integration == 'openwrt' else {},
                    project_access=project_access.project_access,
                    allowed_project_ids=project_access.allowed_project_ids,
                )
            except (ValueError, TypeError) as exc:
                error.set_text(str(exc)); return
            state['busy'] = True
            create.disable(); create.props('loading'); cancel.disable(); close.disable()
            dialog.props('persistent'); body.props('inert aria-busy=true'); save_spinner.set_visibility(True)
            error.set_text('')
            try:
                saved = await asyncio.to_thread(EnvironmentManager(workspace.root).create, config)
                # Creating a definition is successful even if a later boot fails.
                # Its operation banner retains the boot error and retry controls.
                if start.value:
                    try:
                        ENVIRONMENT_OPERATIONS.start(workspace.root, 'start', environment_id=saved.id)
                    except Exception as exc:
                        ui.notify(f'VM created, but Start could not begin: {exc}', type='warning')
                ui.notify(f'Created VM: {saved.name}', type='positive')
                dialog.close()
                on_saved(saved.id)
            except Exception as exc:
                if not error.is_deleted:
                    error.set_text(f'Could not create VM: {exc}')
            finally:
                state['busy'] = False
                if not create.is_deleted:
                    create.enable(); create.props(remove='loading'); cancel.enable(); close.enable()
                    dialog.props(remove='persistent'); body.props(remove='inert aria-busy'); save_spinner.set_visibility(False)

        image.on_value_change(image_changed)
        bundle.on_value_change(preview); architecture.on_value_change(preview); network.on_value_change(preview)
        files.on_value_change(update_file_note)
        image_changed()
    dialog.open()


def render_vm_environments(workbench, tab, workspace) -> None:
    manager = EnvironmentManager(workspace.root)
    if not hasattr(workbench, 'vm_environment_selection'):
        workbench.vm_environment_selection = {}
    selected_tab = workbench.environment_subtabs.get(workspace.id, 'VM Environments')
    if selected_tab not in {'VM Environments', 'External Targets'}:
        selected_tab = 'VM Environments'
    with ui.column().classes('hy-tool-panel w-full no-wrap gap-0'):
        with ui.row().classes('w-full items-center px-4 py-2 gap-2'):
            ui.icon('computer', size='22px')
            ui.label(f'{workspace.name} · Environments').classes('font-semibold')
        with ui.tabs(value=selected_tab).classes('w-full px-3').props('dense no-caps align=left') as tabs:
            local_tab = ui.tab('VM Environments')
            external_tab = ui.tab('External Targets')
        def remember(event) -> None:
            workbench.environment_subtabs[workspace.id] = str(event.value)
            workbench._save_ui_session()
        tabs.on_value_change(remember)
        with ui.tab_panels(tabs, value=selected_tab, animated=False).classes('w-full bg-transparent overflow-y-auto').style('flex:1;min-height:0;min-width:0'):
            with ui.tab_panel(local_tab).classes('p-4') as local_panel:
                with ui.row().classes('w-full items-center gap-2 flex-wrap'):
                    ui.label('VM Environments').classes('text-lg font-semibold grow')
                    ui.button('Create VM Environment', icon='add', on_click=lambda: open_vm_creator(workbench, workspace, selected)).props('unelevated no-caps')
                ui.label('Use named VMs for development, testing or both. The model can choose any enabled VM, and multiple VMs can run together.').classes('text-sm hy-muted')
                summary = ui.label('').classes('text-xs hy-muted')
                listing = ui.row().classes('w-full gap-3 flex-wrap items-stretch')
                details_area = ui.column().classes('w-full gap-3 mt-3')
            with ui.tab_panel(external_tab).classes('p-0'):
                workbench._render_test_targets(workspace)

    def selected(environment_id: str) -> None:
        workbench.vm_environment_selection[workspace.id] = environment_id
        workbench.environment_subtabs[workspace.id] = 'VM Environments'
        workbench._save_ui_session()
        if hasattr(workbench, 'refresh_sidebar'):
            workbench.refresh_sidebar()
        workbench.refresh_tabs()

    def edit(config) -> None:
        with ui.dialog() as editor, ui.card().classes('w-[620px] max-w-[94vw] gap-3').style('max-height:92vh;overflow-y:auto'):
            ui.label('VM Settings').classes('text-lg font-semibold')
            name = ui.input('VM name', value=config.name).classes('w-full')
            purpose = ui.textarea('Purpose / model instructions', value=config.purpose).props('autogrow').classes('w-full')
            project_access = ProjectAccessEditor(workspace, config)
            error = ui.label('').classes('text-sm text-negative')
            with ui.row().classes('w-full justify-end gap-2'):
                ui.button('Cancel', on_click=editor.close).props('flat no-caps')
                def save() -> None:
                    try:
                        latest = manager.get(config.id)
                        if latest is None:
                            raise ValueError('This VM is no longer registered.')
                        value = str(name.value or '').strip()
                        if not value:
                            raise ValueError('Enter a VM name.')
                        manager.save(replace(latest, name=value, purpose=str(purpose.value or '').strip(),
                                             project_access=project_access.project_access,
                                             allowed_project_ids=project_access.allowed_project_ids))
                        editor.close(); selected(config.id)
                    except Exception as exc:
                        error.set_text(str(exc))
                ui.button('Save', icon='save', on_click=save).props('unelevated no-caps')
        editor.open()

    def remove(config) -> None:
        with ui.dialog() as dialog, ui.card().classes('w-[560px] max-w-[94vw] gap-3'):
            ui.label('Remove VM Environment?').classes('text-lg font-semibold text-negative')
            ui.label(f'Remove “{config.name}” and its VM disk, snapshots, installed packages and private build files?').classes('text-sm')
            ui.label('Workspace project source and conversations are preserved. Stop this VM first.').classes('text-sm')
            confirmation = ui.input('Type the VM name to confirm', placeholder=config.name).classes('w-full')
            with ui.row().classes('w-full justify-end gap-2'):
                ui.button('Cancel', on_click=dialog.close).props('flat no-caps')
                def confirm() -> None:
                    if str(confirmation.value or '') != config.name:
                        return
                    try:
                        if not ENVIRONMENT_OPERATIONS.start(workspace.root, 'remove', environment_id=config.id):
                            ui.notify('Wait for this VM’s current operation to finish.', type='warning'); return
                        dialog.close(); render_cards()
                    except Exception as exc:
                        ui.notify(str(exc), type='negative')
                remove_button = ui.button('Remove VM', icon='delete_outline', on_click=confirm).props('unelevated no-caps color=negative')
                remove_button.disable()
                confirmation.on_value_change(lambda event: remove_button.set_enabled(str(event.value or '') == config.name))
        dialog.open()

    card_states: dict[str, dict[str, Any]] = {}
    signature = {'ids': None}

    def render_cards() -> None:
        configs = manager.list()
        signature['ids'] = tuple(item.id for item in configs)
        card_states.clear(); listing.clear(); details_area.clear()
        with listing:
            if not configs:
                with ui.card().classes('w-full p-8 items-center gap-2'):
                    ui.icon('add_to_queue', size='40px').classes('hy-muted')
                    ui.label('No VM environments yet').classes('text-lg font-semibold')
                    ui.label('Files, chats and web research are available. Create a VM to run commands or tests.').classes('text-sm hy-muted text-center')
            for config in configs:
                with ui.card().classes('hy-env-card p-4 gap-2').style('flex:1 1 340px;min-width:0;max-width:100%'):
                    with ui.row().classes('w-full items-start gap-2 no-wrap'):
                        with ui.column().classes('gap-1 grow min-w-0'):
                            ui.label(config.name).classes('text-lg font-semibold').style('overflow-wrap:anywhere')
                            preset = get_preset(config.preset)
                            ui.label(f'{preset.guest_os} · {config.architecture}').classes('text-xs hy-muted')
                        spinner = ui.spinner(size='24px')
                        status = ui.badge('Checking…').props('color=grey').classes('text-sm px-3 py-2')
                    if config.purpose:
                        ui.label(config.purpose).classes('text-sm hy-muted').style('white-space:pre-wrap;overflow-wrap:anywhere')
                    ui.label(f'{config.cpu} vCPU · {config.memory_mb / 1024:g} GiB RAM · {config.disk_gb} GiB disk').classes('text-xs hy-muted')
                    ui.label(FILE_MODES.get(config.files_mode, config.files_mode)).classes('text-xs hy-muted')
                    if config.project_access == 'all':
                        ui.label('Model project access: All projects / chats, including future ones').classes('text-xs hy-muted')
                    else:
                        count = len(config.allowed_project_ids)
                        ui.label(f'Model project access: {count} selected' if count else 'Model project access: None · model use is blocked for all projects / chats').classes('text-xs hy-muted' if count else 'text-xs text-negative')
                    availability = ui.switch('Enabled for model use', value=config.enabled).props('dense')
                    availability.tooltip('Off prevents the model from starting or using this VM. Manual controls remain available.')
                    def set_enabled(event, environment_id=config.id) -> None:
                        try:
                            latest = manager.get(environment_id)
                            if latest is None:
                                raise ValueError('This VM no longer exists.')
                            manager.save(replace(latest, enabled=bool(event.value)))
                        except Exception as exc:
                            ui.notify(str(exc), type='negative')
                    availability.on_value_change(set_enabled)
                    operation = ui.label('').classes('text-sm').style('white-space:pre-wrap;overflow-wrap:anywhere')
                    timing = ui.label('').classes('text-xs hy-muted')
                    with ui.row().classes('w-full gap-1 flex-wrap'):
                        def queue(action: str, environment_id=config.id) -> None:
                            try:
                                ENVIRONMENT_OPERATIONS.start(workspace.root, action, environment_id=environment_id)
                                sync_cards()
                            except Exception as exc:
                                ui.notify(str(exc), type='negative')
                        start_button = ui.button('Start', icon='play_arrow', on_click=lambda _=None, callback=queue: callback('start')).props('flat no-caps')
                        stop_button = ui.button('Stop', icon='stop', on_click=lambda _=None, callback=queue: callback('stop')).props('flat no-caps')
                        terminal = ui.button('Terminal', icon='terminal', on_click=lambda _=None, eid=config.id: workbench.open_tool_tab('terminal', workbench._find_reg(workspace.id), environment_id=eid)).props('flat no-caps')
                        graphical = None
                        if getattr(config, 'desktop', False):
                            graphical = ui.button('Web UI' if config.provider == 'openwrt' else 'Desktop', icon='desktop_windows',
                                      on_click=lambda _=None, eid=config.id: workbench.open_vm_tab(workspace, eid, 'desktop')).props('flat no-caps')
                        ui.button('Manage', icon='tune', on_click=lambda _=None, eid=config.id: selected(eid)).props('outline no-caps')
                        ui.button('Settings', icon='settings', on_click=lambda _=None, item=config: edit(item)).props('flat dense no-caps aria-label="VM settings"')
                        delete = ui.button(icon='delete_outline', on_click=lambda _=None, item=config: remove(item)).props('flat round dense color=negative aria-label="Remove VM environment"')
                    card_states[config.id] = dict(config=config, spinner=spinner, status=status, operation=operation, timing=timing, start=start_button, stop=stop_button, terminal=terminal, graphical=graphical, delete=delete, availability=availability, running=False)
        chosen = workbench.vm_environment_selection.get(workspace.id)
        chosen = chosen if any(item.id == chosen for item in configs) else (configs[0].id if configs else None)
        if chosen:
            workbench.vm_environment_selection[workspace.id] = chosen
            with details_area:
                workbench._render_vm_environment_details(tab, workspace, chosen)
        total_ram = sum(item.memory_mb for item in configs) / 1024
        summary.set_text(f'{len(configs)} configured · {sum(item.cpu for item in configs)} vCPU / {total_ram:g} GiB RAM allocated across all VMs')

    def sync_cards() -> None:
        for environment_id, controls in card_states.items():
            op = ENVIRONMENT_OPERATIONS.state(workspace.root, environment_id=environment_id)
            busy = bool(op.busy)
            controls['spinner'].set_visibility(busy or not controls.get('status_attempted'))
            if busy:
                controls['status'].set_text('Starting…' if op.action == 'start' else (op.message or 'Working…'))
                controls['status'].props('color=primary')
                controls['operation'].set_text(op.message or 'Working…')
                controls['timing'].set_text(f'Elapsed {_elapsed(float(op.started_at or 0))}')
            else:
                controls['operation'].set_text(op.error or controls.get('poll_error') or controls.get('status_detail') or '')
                controls['timing'].set_text('')
                ready = bool(controls.get('ready'))
                controls['status'].set_text('Ready' if ready else str(controls.get('state') or 'Checking…').replace('_', ' ').title())
                controls['status'].props('color=positive' if ready else 'color=negative' if op.error else 'color=grey')
            active = bool(active_work(workspace.root, environment_id=environment_id))
            known = bool(controls.get('known'))
            for key in ('start', 'stop', 'delete'):
                controls[key].set_enabled(known and not busy and not active)
            controls['start'].set_enabled(known and not busy and not (controls.get('running') and controls.get('ready')))
            controls['stop'].set_enabled(known and not busy and not active and bool(controls.get('running')))
            controls['terminal'].set_enabled(not busy and bool(controls.get('ready')))
            if controls['graphical'] is not None:
                controls['graphical'].set_enabled(not busy and bool(controls.get('running')))
            controls['delete'].set_enabled(known and not busy and not active and not controls.get('running'))
            controls['start'].props(add='loading') if busy and op.action == 'start' else controls['start'].props(remove='loading')
            controls['stop'].props(add='loading') if busy and op.action == 'stop' else controls['stop'].props(remove='loading')
        configs = [value['config'] for value in card_states.values()]
        running = [value['config'] for value in card_states.values() if value.get('running')]
        summary.set_text(
            f'{len(configs)} configured · {len(running)} running '
            f'({sum(item.cpu for item in running)} vCPU / {sum(item.memory_mb for item in running) / 1024:g} GiB RAM) '
            f'· total configured {sum(item.cpu for item in configs)} vCPU / {sum(item.memory_mb for item in configs) / 1024:g} GiB RAM'
        )

    async def refresh() -> None:
        if local_panel.is_deleted:
            poll.cancel(); return
        configs = manager.list()
        if signature['ids'] != tuple(item.id for item in configs):
            render_cards()
        for environment_id, controls in list(card_states.items()):
            try:
                info = await ENVIRONMENT_STATUS.get(workspace.root, environment_id=environment_id)
                if local_panel.is_deleted:
                    poll.cancel(); return
                if info is not None:
                    status = dict(info.get('status') or {})
                    poll_error = str(info.get('_status_poll_error') or '')
                    controls.update(status_attempted=True, known=not bool(poll_error), poll_error=poll_error,
                                    running=bool(status.get('running')), ready=bool(status.get('ready')),
                                    status_detail=str(status.get('error') or status.get('detail') or '') if not status.get('ready') else '',
                                    state='Unavailable' if poll_error else str(status.get('state') or 'stopped'))
            except Exception as exc:
                controls.update(status_attempted=True, known=False, ready=False, state='Unavailable', poll_error=str(exc))
        sync_cards()

    render_cards(); sync_cards()
    poll = ui.timer(0.75, refresh, immediate=True)
