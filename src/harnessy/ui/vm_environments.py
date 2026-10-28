"""Named local VM environments, independent of workspace creation and SSH targets."""
from __future__ import annotations

import asyncio
import platform
import time
from dataclasses import replace
from typing import Any

from nicegui import ui

from harnessy.environment import EnvironmentConfig, EnvironmentManager, ENVIRONMENT_OPERATIONS, ENVIRONMENT_STATUS
from harnessy.environment.activity import active_work, reserve_environment_change
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


def network_policy_text(provider: str) -> tuple[str, str]:
    if provider == 'openwrt':
        return 'Outbound network', 'QEMU NAT provides guest networking. When enabled, the guest can reach destinations permitted by the host network; this backend has no public-only destination filter. Verified setup downloads run through HarnessyXO even when guest outbound is off.'
    if provider == 'managed':
        return 'Outbound network after setup', 'Initial Windows setup uses internet access to install guest drivers and OpenSSH. This outbound policy is applied through Windows Firewall before Ready. Guest administrators can change that firewall.'
    return 'Public outbound network', 'The guest firewall filters host, LAN, private and reserved destinations. Disabling public outbound also skips downloadable optional tools.'


def _duration(seconds: float) -> str:
    minutes, seconds = divmod(max(0, int(seconds)), 60)
    hours, minutes = divmod(minutes, 60)
    return f'{hours}h {minutes:02d}m' if hours else f'{minutes}m {seconds:02d}s' if minutes else f'{seconds}s'


def _operation_timing(op) -> str:
    now = time.time()
    elapsed = max(0, now - float(op.started_at or now))
    stage_elapsed = max(0, now - float(op.stage_started_at or op.started_at or now))
    parts = [f'Elapsed {_duration(elapsed)}']
    if op.step_total and op.step_index:
        parts.append(f'Stage {op.step_index}/{op.step_total}')
    if op.progress_percent is not None:
        parts.append(f'Workflow {float(op.progress_percent):.0f}%')
    if op.stage_progress_percent is not None:
        parts.append(f'Current stage {float(op.stage_progress_percent):.0f}%')
    parts.append(f'This stage {_duration(stage_elapsed)}')
    expected = float(op.expected_total_seconds or 0)
    if expected > elapsed:
        parts.append(f'ETA ~{_duration(expected - elapsed)}')
    elif expected > 0:
        parts.append(f'Recent median {_duration(expected)}')
    else:
        parts.append('ETA learning from completed runs')
    if op.stage_deadline:
        parts.append(f'Stage timeout {_duration(float(op.stage_deadline) - now)}')
    if op.deadline:
        parts.append(f'Operation timeout {_duration(float(op.deadline) - now)}')
    return ' · '.join(parts)


def tool_label(preset, tool_id: str) -> str:
    if preset.image.integration == 'openwrt':
        from harnessy.environment.openwrt_tools import OPENWRT_TOOL_BY_ID
        tool = OPENWRT_TOOL_BY_ID.get(tool_id)
        if tool is not None:
            return tool.label
    return TOOL_LABELS.get(tool_id, tool_id)


def emulated_radio_lines(config, snapshot: Any = None, *, running: bool = False,
                         known: bool = True, busy: bool = False) -> tuple[str, str]:
    """Keep the saved selection separate from the last observed guest state."""
    if config.provider != 'openwrt':
        return ('Emulated radios are not managed for this VM image.', '')
    from harnessy.environment.test_radios import public_radio_snapshot
    observed = public_radio_snapshot(snapshot)
    requested = config.emulation or {}
    lines = []
    for kind, label, noun in (('wifi', 'Wi-Fi', 'radio'), ('bluetooth', 'Bluetooth', 'controller')):
        selected = bool(requested.get(kind))
        prefix = f'{label}: setup {"on" if selected else "off"}'
        item = observed[kind]
        if not known:
            detail = 'VM status unavailable'
        elif not running:
            detail = 'applies on next Start' if selected else 'VM stopped'
        elif busy:
            detail = 'VM operation in progress'
        elif item['verified']:
            count = item['radio_count']
            detail = f'{count} emulated {noun}{"s" if count != 1 else ""} verified at last probe'
        elif item['status'] in {'error', 'unavailable'}:
            detail = 'not ready · ' + item['reason'].replace('_', ' ')
        else:
            detail = 'not yet verified' if selected else 'none verified'
        lines.append(prefix + ' · ' + detail)
    return tuple(lines)


async def save_emulated_radio_selection(workspace_root, environment_id: str, *,
                                        wifi: bool, bluetooth: bool, expected: dict | None = None):
    """Save only a stopped VM's desired radios, preserving concurrent settings."""
    from harnessy.environment.base import environment_config_lock
    manager = EnvironmentManager(workspace_root, environment_id=environment_id)
    current = manager.config
    if current is None or current.provider != 'openwrt':
        raise ValueError('Radio emulation controls are available for OpenWrt VMs only.')
    release = reserve_environment_change(workspace_root, 'emulated radios', environment_id=environment_id)
    try:
        if ENVIRONMENT_OPERATIONS.state(workspace_root, environment_id=environment_id).busy:
            raise RuntimeError('Wait for this VM operation to finish before changing emulated radios.')
        provider = manager.provider()
        if (await provider.status()).running:
            raise RuntimeError('Stop this VM before changing emulated radios. The selection applies on its next Start.')
        with environment_config_lock(workspace_root, environment_id):
            latest = manager.get(environment_id)
            if latest is None or latest.provider != 'openwrt':
                raise ValueError('This OpenWrt VM no longer exists.')
            wanted = {'wifi': bool(wifi), 'bluetooth': bool(bluetooth)}
            if expected is not None and latest.emulation != expected and latest.emulation != wanted:
                raise ValueError('The radio selection changed while this dialog was open. Reopen Emulated radios to review it.')
            saved = manager.save(replace(latest, emulation=wanted))
        provider.controller.forget_radios()
        ENVIRONMENT_STATUS.invalidate(workspace_root, environment_id=environment_id)
        return saved
    finally:
        release()


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
            installer_source = ui.select(
                {'auto': 'Download automatically from Microsoft', 'local': 'Use an ISO on this host'},
                value='auto', label='Windows installation media').props('outlined').classes('w-full')
            installer_iso = ui.input('Windows installer ISO on the HarnessyXO host', placeholder='/path/to/windows.iso').props('outlined').classes('w-full')
            installer_note = ui.label('Windows 11 Pro installs automatically using English (United States) media for the selected architecture. Activation requires your own valid Windows licence.').classes('text-xs hy-muted')
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

        def update_installer(_event=None) -> None:
            windows = str(image.value or '') == 'windows-11'
            installer_source.set_visibility(windows)
            installer_iso.set_visibility(windows and installer_source.value == 'local')
            installer_note.set_visibility(windows)

        installer_source.on_value_change(update_installer)

        def optional_for(preset) -> set[str]:
            return state['optional'].setdefault(preset.id, set())

        def choose_tool(preset_id: str, tool_id: str, selected: bool) -> None:
            values = state['optional'].setdefault(preset_id, set())
            values.add(tool_id) if selected else values.discard(tool_id)

        def update_file_note(_event=None) -> None:
            if files.value == 'copy':
                text = 'Deploys independent project copies. Changes are not written back to workspace source automatically. Permission updates cannot recall files already copied or read; existing guest files remain intact. Refresh and artifact collection are explicit.'
            elif files.value == 'readonly':
                text = 'Reads canonical project files on demand. Own files, ancestors, direct Project Access sources and References are read-only. Save builds and working data in this VM’s own writable directories.'
            else:
                text = 'Reads and writes canonical project files on demand, without deploying the whole folder first. Ancestors, direct Project Access sources and References stay read-only. Keep dependencies, builds and caches in this VM’s own directories.'
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
                limits.set_text('Microsoft ISO download and unattended installation run on Start. Cross-architecture emulation can take substantially longer.' if windows else 'Kali uses its own guest filesystem. Desktop access is optional.')
            else:
                cpu.set_value('4'); ram.set_value('8'); disk.set_value('128')
                cpu.props('max=64'); ram.props('max=256'); disk.props('max=4096')
                limits.set_text('Sparse storage sets maximum capacity. Multiple VMs can run together; leave resources for your model and host.')
            managed = selected.integration == 'managed'
            files.options = {key: FILE_MODES[key] for key in selected.file_modes if key in FILE_MODES}
            if files.value not in files.options:
                files.set_value(next(iter(files.options), None))
            files.update()
            update_installer()
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
                if (preset.image.integration == 'managed' and installer_source.value == 'local'
                        and not str(installer_iso.value or '').strip()):
                    raise ValueError('Select an ISO on this host, or choose automatic download.')
                if preset.image.integration == 'openwrt':
                    mips = str(architecture.value or '').startswith('mips')
                    if resources['disk_gb'] > 64 or resources['memory_mb'] > (2048 if mips else 131072) or (mips and resources['cpu'] != 1):
                        raise ValueError('OpenWrt MIPS supports 1 vCPU and up to 2 GiB RAM; other OpenWrt guests support up to 128 GiB RAM. Disk maximum is 64 GiB.')
                config = EnvironmentConfig(
                    name=vm_name, purpose=str(purpose.value or '').strip(), enabled=bool(enabled.value),
                    preset=preset.id, provider={'openwrt': 'openwrt', 'managed': 'managed'}.get(preset.image.integration, 'lima'),
                    architecture=str(architecture.value or ''), **resources, network=bool(network.value),
                    files_mode=str(files.value), optional_tools=tuple(tool for tool in preset.optional_tool_ids if tool in optional_for(preset)),
                    iso_path=str(installer_iso.value or '').strip() if preset.image.integration == 'managed' and installer_source.value == 'local' else '',
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


def open_vm_settings(workbench, workspace, environment_id: str | None = None) -> None:
    """Open a VM's Manage → Settings panel, or the VM creator entry point."""
    configs = EnvironmentManager(workspace.root).list()
    selected = next((item for item in configs if item.id == environment_id), None)
    if selected is None and configs:
        selected = configs[0]
    if not hasattr(workbench, 'environment_subtabs'):
        workbench.environment_subtabs = {}
    if not hasattr(workbench, 'vm_environment_selection'):
        workbench.vm_environment_selection = {}
    workbench.environment_subtabs[workspace.id] = 'VM Environments'
    if selected is not None:
        workbench.vm_environment_selection[workspace.id] = selected.id
        workbench.environment_subtabs[f'{workspace.id}:active_vm'] = selected.id
        workbench.environment_subtabs[f'{workspace.id}:{selected.id}'] = 'Settings'
    workbench._save_ui_session()
    workbench.open_tool_tab('environment', workbench._find_reg(workspace.id))
    workbench.refresh_tabs()


def render_vm_settings(workbench, workspace, environment_id: str, *, on_saved=None) -> None:
    """Render the editable definition and model grants inside Manage Settings."""
    manager = EnvironmentManager(workspace.root, environment_id=environment_id)
    config = manager.config
    if config is None:
        ui.label('This VM environment is no longer registered.').classes('text-sm hy-muted')
        return
    with ui.column().classes('w-full gap-4').props(f'data-hy-vm-settings={environment_id}'):
        with ui.card().classes('hy-env-card w-full p-4 gap-3'):
            ui.label('Model access').classes('font-semibold')
            enabled = ui.switch('Enabled for model use', value=config.enabled).props('dense data-hy-vm-model-enabled=true')
            ui.label('Off prevents the model from starting or using this VM. Guest console and allowed Project files terminals remain available.').classes('text-xs hy-muted')
            project_access = ProjectAccessEditor(workspace, config)
            ui.label(
                'Saving rechecks project access. Independent copies already deployed or read cannot be recalled; guest files are preserved. A stopped VM stays stopped.'
                if config.files_mode == 'copy' else
                'Saving updates this VM’s project file views while it is running. In-use views show Unmount pending until their project tasks and terminals finish. A stopped VM stays stopped.'
            ).classes('text-xs hy-muted').style('overflow-wrap:anywhere')
        with ui.card().classes('hy-env-card w-full p-4 gap-3'):
            ui.label('VM configuration').classes('font-semibold')
            name = ui.input('VM name', value=config.name).classes('w-full')
            purpose = ui.textarea('Purpose / model instructions', value=config.purpose).props('autogrow').classes('w-full')
            image_id = get_preset(config.preset).image_id
            compatible_presets = {
                item.id: TOOL_BUNDLES.get(item.tools_id, item.tools_id)
                for item in PRESETS.values() if item.image_id == image_id
            }
            tool_preset = ui.select(compatible_presets, value=config.preset, label='Tool preset').props('outlined').classes('w-full')
            ui.label('Changes the available optional-tool list. Installed tools stay in this VM. Review and install your choices in Manage Optional Tools; required packages are checked on the next Start.').classes('text-xs hy-muted')
            if len(compatible_presets) == 1:
                tool_preset.disable()
                ui.label('This OS currently has one tool preset. You can still select its individual optional tools.').classes('text-xs hy-muted')
            elif ENVIRONMENT_OPERATIONS.is_busy(workspace.root, environment_id=config.id) or active_work(workspace.root, environment_id=config.id):
                tool_preset.disable()
                ui.label('Finish this VM’s current operation and active work before changing its tool preset.').classes('text-xs hy-muted')
        opened_scope = (config.project_access, frozenset(config.allowed_project_ids))
        error = ui.label('').classes('text-sm text-negative').props('role=alert')

        def save() -> None:
            try:
                from harnessy.environment.base import environment_config_lock
                with environment_config_lock(workspace.root, config.id):
                    latest = manager.get(config.id)
                    if latest is None:
                        raise ValueError('This VM is no longer registered.')
                    value = str(name.value or '').strip()
                    if not value:
                        raise ValueError('Enter a VM name.')
                    preset_id = latest.preset
                    optional_tools = latest.optional_tools
                    if tool_preset.value != config.preset:
                        if latest.preset != config.preset:
                            raise ValueError('This VM’s tool preset changed while Settings was open. Reopen Settings to use its current preset.')
                        preset_id = str(tool_preset.value or '')
                        if preset_id not in compatible_presets:
                            raise ValueError('Choose a tool preset for this VM’s current OS.')
                        previous_tools = get_preset(latest.preset).optional_tool_ids if '*' in latest.optional_tools else latest.optional_tools
                        optional_tools = tuple(tool for tool in get_preset(preset_id).optional_tool_ids if tool in previous_tools)
                    chosen_scope = (project_access.project_access, frozenset(project_access.allowed_project_ids))
                    latest_scope = (latest.project_access, frozenset(latest.allowed_project_ids))
                    if chosen_scope != opened_scope and latest_scope != opened_scope:
                        raise ValueError('Project access changed while Settings was open. Reopen Settings before changing it.')
                    if bool(enabled.value) != bool(config.enabled) and latest.enabled != config.enabled:
                        raise ValueError('Model access changed while Settings was open. Reopen Settings before changing it.')
                    manager.save(replace(latest, name=value, purpose=str(purpose.value or '').strip(),
                        enabled=bool(enabled.value) if bool(enabled.value) != bool(config.enabled) else latest.enabled,
                        preset=preset_id, optional_tools=optional_tools,
                        project_access=project_access.project_access if chosen_scope != opened_scope else latest.project_access,
                        allowed_project_ids=project_access.allowed_project_ids if chosen_scope != opened_scope else latest.allowed_project_ids))
                if preset_id != config.preset:
                    ui.notify(
                        'Tool preset saved. Review choices in Manage Optional Tools, or use Start / Retry Setup to check required tools.'
                        if get_preset(preset_id).optional_tool_ids else
                        'Tool preset saved. Use Start / Retry Setup to check its required tools.', type='positive')
                else:
                    ui.notify('VM settings saved.', type='positive')
                if on_saved is not None:
                    on_saved(config.id)
                else:
                    if hasattr(workbench, 'refresh_sidebar'):
                        workbench.refresh_sidebar()
                    workbench.refresh_tabs()
            except Exception as exc:
                if not error.is_deleted:
                    error.set_text(str(exc))

        with ui.row().classes('w-full justify-end gap-2'):
            ui.button('Save Settings', icon='save', on_click=save).props('unelevated no-caps data-hy-vm-settings-save=true')


def render_vm_environments(workbench, tab, workspace) -> None:
    manager = EnvironmentManager(workspace.root)
    if not hasattr(workbench, 'vm_environment_selection'):
        workbench.vm_environment_selection = {}
    active_vm_key = f'{workspace.id}:active_vm'
    ui.add_css('''
        .hy-vm-tabs, .hy-vm-tabs .q-tabs__content { overflow:visible; }
        .hy-vm-tabs .q-tabs__content { flex-wrap:wrap; gap:4px; }
        .hy-vm-tabs .q-tabs__arrow { display:none; }
        .hy-vm-tabs .q-tab { flex:0 1 auto; min-width:0; max-width:100%; }
        .hy-vm-tabs .q-tab__label { white-space:normal; overflow-wrap:anywhere; }
    ''')
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
                ui.label('Use named VMs for development, testing or both. The model can choose any enabled VM, and multiple VMs can run together.').classes('text-sm hy-muted')
                summary = ui.label('').classes('text-xs hy-muted')
                vm_tabs = ui.tabs().classes('hy-vm-tabs w-full').props('dense no-caps align=left')
                empty_area = ui.column().classes('w-full gap-3')
                listing = ui.tab_panels(vm_tabs, animated=False).classes('w-full bg-transparent')
            with ui.tab_panel(external_tab).classes('p-0'):
                workbench._render_test_targets(workspace)

    def selected(environment_id: str) -> None:
        workbench.vm_environment_selection[workspace.id] = environment_id
        workbench.environment_subtabs[active_vm_key] = environment_id
        workbench.environment_subtabs[workspace.id] = 'VM Environments'
        workbench._save_ui_session()
        if hasattr(workbench, 'refresh_sidebar'):
            workbench.refresh_sidebar()
        workbench.refresh_tabs()

    def create_vm() -> None:
        with local_panel:
            open_vm_creator(workbench, workspace, selected)

    def vm_dialog():
        # NiceGUI ties a dialog's lifetime to its construction context through
        # an invisible element; moving the dialog later does not move that tie.
        with local_panel:
            return ui.dialog()

    radio_editors: dict[str, dict[str, Any]] = {}

    def edit_radios(environment_id: str) -> None:
        config = manager.get(environment_id)
        if config is None or config.provider != 'openwrt':
            ui.notify('Radio emulation controls are available for OpenWrt VMs only.', type='warning')
            return
        expected = dict(config.emulation or {})
        with vm_dialog() as dialog, ui.card().classes('w-[620px] max-w-[94vw] gap-3').style('max-height:90vh;overflow-y:auto'):
            ui.label('Emulated radios · ' + config.name).classes('text-lg font-semibold').style('overflow-wrap:anywhere')
            ui.label('Software emulation only: no physical RF, USB dongle identity or nearby devices.').classes('text-xs hy-muted')
            state = ui.label('').classes('text-sm').style('white-space:pre-wrap;overflow-wrap:anywhere')
            wifi = ui.checkbox('Emulated Wi-Fi radios (mac80211_hwsim)', value=bool(expected.get('wifi'))).props('data-hy-vm-radio-wifi=true')
            bluetooth = ui.checkbox('Emulated Bluetooth controllers', value=bool(expected.get('bluetooth'))).props('data-hy-vm-radio-bluetooth=true')
            ui.label('Stop the VM to change this selection, then Start it to apply. Matching packages and controller setup are handled automatically.').classes('text-xs hy-muted')
            ui.label('Turning Bluetooth setup off stops HarnessyXO’s managed controllers on the next Start. Turning Wi-Fi setup off skips future setup; already installed interfaces and your network configuration stay in the guest.').classes('text-xs hy-muted')
            error = ui.label('').classes('text-sm text-negative').style('white-space:pre-wrap;overflow-wrap:anywhere').props('role=alert')
            with ui.row().classes('w-full justify-end gap-2 flex-wrap'):
                ui.button('Close', on_click=dialog.close).props('flat no-caps')

                def retry_setup() -> None:
                    try:
                        if ENVIRONMENT_OPERATIONS.start(workspace.root, 'start', environment_id=environment_id):
                            dialog.close(); sync_cards()
                        else:
                            error.set_text('Wait for this VM’s current operation to finish.')
                    except Exception as exc:
                        error.set_text(str(exc))

                repair = ui.button('Set up / repair radios', icon='build', on_click=retry_setup).props('outline no-caps')
                repair.tooltip('Check and repair the saved selection through Start / Retry Setup. VM storage is preserved.')

                async def apply() -> None:
                    if form['saving']:
                        return
                    form['saving'] = True
                    sync_cards()
                    try:
                        await save_emulated_radio_selection(workspace.root, environment_id,
                            wifi=bool(wifi.value), bluetooth=bool(bluetooth.value), expected=expected)
                        dialog.close(); render_cards(); sync_cards()
                        ui.notify('Radio selection saved for the next Start.', type='positive')
                    except Exception as exc:
                        if not error.is_deleted:
                            error.set_text(str(exc))
                    finally:
                        form['saving'] = False
                        sync_cards()

                save = ui.button('Apply for next Start', icon='save', on_click=apply).props('unelevated no-caps')
            form = dict(dialog=dialog, state=state, wifi=wifi, bluetooth=bluetooth, save=save, repair=repair, saving=False)
            radio_editors[environment_id] = form
            dialog.on_value_change(lambda event: radio_editors.pop(environment_id, None) if not event.value else None)
        sync_cards()
        dialog.open()

    def remove(config) -> None:
        with vm_dialog() as dialog, ui.card().classes('w-[560px] max-w-[94vw] gap-3'):
            ui.label('Remove VM Environment?').classes('text-lg font-semibold text-negative')
            ui.label(f'Remove “{config.name}” and its VM disk, snapshots, installed packages and private build files?').classes('text-sm')
            ui.label('HarnessyXO checks that this VM is stopped or was never created before removing anything. A running VM will not be removed. Workspace project source and conversations are preserved.').classes('text-sm')
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
    signature = {'configs': None}
    tab_syncing = {'value': False}

    def change_vm(event) -> None:
        if tab_syncing['value']:
            return
        environment_id = str(event.value or '')
        if environment_id in card_states:
            workbench.environment_subtabs[active_vm_key] = environment_id
            workbench._save_ui_session()
        else:
            tab_syncing['value'] = True
            previous = workbench.environment_subtabs.get(active_vm_key)
            vm_tabs.set_value(previous if previous in card_states else None)
            tab_syncing['value'] = False

    vm_tabs.on_value_change(change_vm)

    def toggle_manage(environment_id: str) -> None:
        opened = workbench.vm_environment_selection.get(workspace.id)
        if opened == environment_id:
            workbench.vm_environment_selection.pop(workspace.id, None)
        else:
            workbench.vm_environment_selection[workspace.id] = environment_id
        workbench._save_ui_session()
        sync_details()

    def sync_details() -> None:
        chosen = workbench.vm_environment_selection.get(workspace.id)
        for environment_id, controls in card_states.items():
            expanded = chosen == environment_id
            controls['details'].set_visibility(expanded)
            controls['manage'].set_text('Hide details' if expanded else 'Manage')
            controls['manage'].props(f'aria-expanded={str(expanded).lower()}')
            if expanded and not controls.get('details_loaded'):
                controls['details_loaded'] = True
                with controls['details']:
                    workbench._render_vm_environment_details(tab, workspace, environment_id, embedded=True, dialog_parent=local_panel)

    def render_cards() -> None:
        configs = manager.list()
        signature['configs'] = tuple(item.to_dict() for item in configs)
        if not any(item.id == workbench.vm_environment_selection.get(workspace.id) for item in configs):
            workbench.vm_environment_selection.pop(workspace.id, None)
        active_vm = workbench.environment_subtabs.get(active_vm_key)
        if not any(item.id == active_vm for item in configs):
            active_vm = configs[0].id if configs else None
        tab_syncing['value'] = True
        card_states.clear(); listing.clear(); vm_tabs.clear(); empty_area.clear()
        with vm_tabs:
            for config in configs:
                ui.tab(config.id, label=config.name).props(f'data-hy-vm-tab={config.id}')
            ui.tab('__create_vm__', label='+ Create VM').props('data-hy-vm-create=true').on('click', create_vm)
        vm_tabs.set_value(active_vm)
        if active_vm:
            workbench.environment_subtabs[active_vm_key] = active_vm
        listing.set_visibility(bool(configs))
        empty_area.set_visibility(not configs)
        if not configs:
            with empty_area:
                with ui.card().classes('w-full p-8 items-center gap-2'):
                    ui.icon('add_to_queue', size='40px').classes('hy-muted')
                    ui.label('No VM environments yet').classes('text-lg font-semibold')
                    ui.label('Files, chats and web research are available. Create a VM to run commands or tests.').classes('text-sm hy-muted text-center')
        with listing:
            for config in configs:
                panel = ui.tab_panel(config.id).classes('p-0')
                with panel, ui.card().classes('hy-env-card w-full p-4 gap-2').style('min-width:0;max-width:100%').props(f'data-hy-vm-card={config.id}') as vm_card:
                    with ui.row().classes('w-full items-start gap-2 no-wrap'):
                        with ui.column().classes('gap-1 grow min-w-0'):
                            ui.label(config.name).classes('text-lg font-semibold').style('overflow-wrap:anywhere')
                            preset = get_preset(config.preset)
                            ui.label(f'{preset.guest_os} · {config.architecture}').classes('text-xs hy-muted')
                        status = ui.badge('Checking…').props('color=grey').classes('text-sm px-3 py-2')
                    if config.purpose:
                        ui.label(config.purpose).classes('text-sm hy-muted').style('white-space:pre-wrap;overflow-wrap:anywhere')
                    ui.label(f'{config.cpu} vCPU · {config.memory_mb / 1024:g} GiB RAM · {config.disk_gb} GiB disk').classes('text-xs hy-muted')
                    ui.label(f'Tool preset: {TOOL_BUNDLES.get(preset.tools_id, preset.tools_id)}').classes('text-xs hy-muted')
                    ui.label(FILE_MODES.get(config.files_mode, config.files_mode)).classes('text-xs hy-muted')
                    desktop_status = None
                    if config.provider == 'lima' and config.desktop:
                        desktop_status = ui.label('Desktop: not checked').classes('text-xs hy-muted').style('overflow-wrap:anywhere').props(f'data-hy-vm-desktop-status={config.id}')
                    with ui.column().classes('w-full gap-1').props(f'data-hy-vm-radio-summary={config.id}'):
                        if config.provider == 'openwrt':
                            with ui.row().classes('w-full items-start no-wrap gap-2'):
                                ui.icon('wifi', size='16px').classes('shrink-0')
                                radio_wifi = ui.label('').classes('text-xs hy-muted').style('overflow-wrap:anywhere')
                            with ui.row().classes('w-full items-start no-wrap gap-2'):
                                ui.icon('bluetooth', size='16px').classes('shrink-0')
                                radio_bluetooth = ui.label('').classes('text-xs hy-muted').style('overflow-wrap:anywhere')
                            ui.label('Software emulation only · no physical RF or USB dongles').classes('text-xs hy-muted')
                        else:
                            radio_wifi = radio_bluetooth = None
                            ui.label('Emulated radios are not managed for this VM image.').classes('text-xs hy-muted')
                    if config.project_access == 'all':
                        ui.label('Project access: All projects / chats, including future ones').classes('text-xs hy-muted')
                    else:
                        count = len(config.allowed_project_ids)
                        ui.label(f'Project access: {count} selected' if count else 'Project access: None · project-files terminals and model use are blocked').classes('text-xs hy-muted' if count else 'text-xs text-negative')
                    from harnessy.ui.project_file_views import render_file_view_status
                    render_file_view_status(workspace, config.id)
                    ui.label('Model use: Enabled' if config.enabled else 'Model use: Disabled · change in Manage → Settings').classes('text-xs hy-muted' if config.enabled else 'text-xs text-negative')
                    with ui.row().classes('hy-env-status-banner w-full items-start gap-3 p-3 no-wrap').props(f'data-hy-vm-progress={config.id}') as progress_panel:
                        spinner = ui.spinner(size='20px').classes('hy-vm-busy-spinner shrink-0')
                        progress_icon = ui.icon('info', size='20px').classes('shrink-0')
                        with ui.column().classes('gap-1 grow min-w-0'):
                            operation = ui.label('').classes('text-sm font-semibold').style('white-space:pre-wrap;overflow-wrap:anywhere')
                            detail = ui.label('').classes('text-xs hy-muted').style('white-space:pre-wrap;overflow-wrap:anywhere')
                            progress = ui.linear_progress(value=0, show_value=False).classes('hy-vm-busy-progress w-full').props('rounded size=6px')
                            timing = ui.label('').classes('text-xs hy-muted').style('font-variant-numeric:tabular-nums;overflow-wrap:anywhere')
                    with ui.row().classes('w-full gap-1 flex-wrap').props(f'data-hy-vm-controls={config.id}'):
                        def queue(action: str, environment_id=config.id) -> None:
                            try:
                                if not ENVIRONMENT_OPERATIONS.start(workspace.root, action, environment_id=environment_id):
                                    ui.notify('Wait for this VM’s current operation to finish.', type='warning')
                                sync_cards()
                            except Exception as exc:
                                ui.notify(str(exc), type='negative')
                        start_button = ui.button('Start', icon='play_arrow', on_click=lambda _=None, callback=queue: callback('start')).props('flat no-caps')
                        stop_button = ui.button('Stop', icon='stop', on_click=lambda _=None, callback=queue: callback('stop')).props('flat no-caps')
                        cancel_setup_button = None
                        cancel_setup_state = {'pending': False}
                        if config.provider == 'managed' and config.preset == 'windows-11':
                            async def cancel_setup(_event=None, environment_id=config.id, state=cancel_setup_state) -> None:
                                if state['pending']:
                                    return
                                client = ui.context.client
                                state['pending'] = True
                                try:
                                    if not local_panel.is_deleted:
                                        sync_cards()
                                    cancelled = await ENVIRONMENT_OPERATIONS.cancel(
                                        workspace.root, environment_id=environment_id)
                                    if not client.is_deleted:
                                        with client:
                                            ui.notify(
                                                'Windows setup task cancelled. A running VM keeps running; use Start to check it again.'
                                                if cancelled else 'No Windows setup task is running.',
                                                type='info')
                                except Exception as exc:
                                    if not client.is_deleted:
                                        with client:
                                            ui.notify(str(exc), type='negative')
                                finally:
                                    state['pending'] = False
                                    if not client.is_deleted and not local_panel.is_deleted:
                                        with client:
                                            sync_cards()
                            cancel_setup_button = ui.button('Cancel setup', icon='cancel', on_click=cancel_setup).props('flat no-caps color=negative')
                            cancel_setup_button.tooltip('Cancel this setup task and keep the VM disk and completed download data. A running VM keeps running.')
                            cancel_setup_button.set_visibility(False)
                        terminal = ui.button('Terminal', icon='terminal', on_click=lambda _=None, eid=config.id: workbench.open_tool_tab('terminal', workbench._find_reg(workspace.id), environment_id=eid)).props('flat no-caps')
                        terminal_options = ui.button(icon='arrow_drop_down', on_click=lambda _=None, eid=config.id: workbench._choose_vm_terminal(workbench._find_reg(workspace.id), eid)).props('flat dense aria-label="Choose terminal mode and project"')
                        terminal_options.tooltip('Choose Project files or Guest console')
                        graphical = None
                        if getattr(config, 'desktop', False):
                            graphical = ui.button('Web UI' if config.provider == 'openwrt' else 'Desktop', icon='desktop_windows',
                                      on_click=lambda _=None, eid=config.id: workbench.open_vm_tab(workspace, eid, 'desktop')).props('flat no-caps')
                        if config.provider == 'openwrt':
                            ui.button('Emulated radios', icon='wifi', on_click=lambda _=None, eid=config.id: edit_radios(eid)).props('outline no-caps')
                        manage = ui.button('Manage', icon='tune', on_click=lambda _=None, eid=config.id: toggle_manage(eid)).props('outline no-caps')
                        delete = ui.button(icon='delete_outline', on_click=lambda _=None, item=config: remove(item)).props('flat round dense color=negative aria-label="Remove VM environment"')
                    details = ui.column().classes('w-full gap-0 mt-2 pt-2').style('min-width:0;border-top:1px solid var(--hy-border)').props(f'data-hy-vm-details={config.id}')
                    details.set_visibility(False)
                    card_states[config.id] = dict(config=config, card=vm_card, spinner=spinner, status=status, operation=operation, detail=detail, timing=timing, progress=progress, progress_panel=progress_panel, progress_icon=progress_icon, start=start_button, stop=stop_button, cancel_setup=cancel_setup_button, cancel_setup_state=cancel_setup_state, terminal=terminal, terminal_options=terminal_options, graphical=graphical, desktop_status=desktop_status, manage=manage, details=details, delete=delete, radio_wifi=radio_wifi, radio_bluetooth=radio_bluetooth, running=False)
        tab_syncing['value'] = False
        sync_details()

    def sync_cards() -> None:
        counts: dict[str, int] = {}
        for environment_id, controls in card_states.items():
            op = ENVIRONMENT_OPERATIONS.state(workspace.root, environment_id=environment_id)
            busy = bool(op.busy)
            checking = not controls.get('status_attempted')
            desktop_expected = controls['config'].provider == 'lima' and bool(controls['config'].desktop)
            desktop_pending = desktop_expected and bool(controls.get('running')) and not controls.get('desktop_ready')
            error = op.error or controls.get('poll_error') or ''
            status_detail = controls.get('status_detail') or ''
            show_panel = busy or checking or bool(error or status_detail)
            controls['progress_panel'].set_visibility(show_panel)
            controls['spinner'].set_visibility(busy or checking)
            controls['progress_icon'].set_visibility(show_panel and not (busy or checking))
            controls['progress_icon'].props('name=error_outline color=negative' if error else 'name=info color=primary')
            controls['progress'].set_visibility(busy)
            controls['timing'].set_visibility(busy)
            if busy:
                state_label = {'start': 'Starting…', 'stop': 'Stopping…', 'snapshot': 'Creating snapshot…',
                               'restore': 'Restoring…', 'reset': 'Resetting…', 'rebuild': 'Rebuilding…',
                               'tools': 'Updating tools…', 'resources': 'Applying resources…',
                               'network': 'Applying network…', 'remove': 'Removing…', 'desktop': 'Setting up desktop…'}.get(op.action, 'Working…')
                controls['status'].set_text(state_label)
                controls['status'].props('color=primary')
                controls['operation'].set_text(op.message or 'Working…')
                controls['detail'].set_text(op.detail or '')
                controls['timing'].set_text(_operation_timing(op))
                if op.progress_percent is None:
                    controls['progress'].props(add='indeterminate')
                else:
                    controls['progress'].props(remove='indeterminate')
                    controls['progress'].set_value(max(0, min(1, float(op.progress_percent) / 100)))
                summary_state = 'starting' if op.action in {'start', 'restore', 'reset', 'rebuild'} else 'stopping' if op.action == 'stop' else 'updating'
            else:
                controls['operation'].set_text(
                    'Desktop setup incomplete' if op.error and (op.action == 'desktop' or
                        (desktop_pending and controls.get('ready') and op.action in {'start', 'rebuild', 'reset'})) else
                    'VM setup incomplete' if op.error and op.action == 'start' and controls.get('running') else
                    'VM operation failed' if op.error else 'VM status unavailable' if controls.get('poll_error') else
                    'Checking VM status…' if checking else 'VM status'
                )
                controls['detail'].set_text(error or status_detail)
                controls['timing'].set_text('')
                ready = bool(controls.get('ready')) and not desktop_pending
                controls['status'].set_text('Ready' if ready else 'Desktop setup incomplete' if desktop_pending and controls.get('ready') else 'Setup incomplete' if controls.get('running') and error else str(controls.get('state') or 'Checking…').replace('_', ' ').title())
                controls['status'].props('color=positive' if ready else 'color=negative' if error else 'color=warning' if desktop_pending else 'color=grey')
                summary_state = 'ready' if ready else 'checking' if checking else 'unavailable' if not controls.get('known') else 'needs setup' if controls.get('running') else 'stopped'
            counts[summary_state] = counts.get(summary_state, 0) + 1
            active = bool(active_work(workspace.root, environment_id=environment_id))
            known = bool(controls.get('known'))
            if controls['radio_wifi'] is not None:
                lines = emulated_radio_lines(controls['config'], controls.get('radio_snapshot'),
                    running=bool(controls.get('running')), known=known, busy=busy)
                controls['radio_wifi'].set_text(lines[0])
                controls['radio_bluetooth'].set_text(lines[1])
            form = radio_editors.get(environment_id)
            if form is not None and not form['dialog'].is_deleted:
                can_edit = known and not busy and not active and not controls.get('running') and not form['saving']
                for key in ('wifi', 'bluetooth', 'save'):
                    form[key].set_enabled(can_edit)
                form['repair'].set_enabled(known and not busy and not active and bool(controls.get('running')) and not form['saving'])
                form['state'].set_text('Saving radio selection…' if form['saving'] else
                    'Checking VM status…' if not known else
                    'Wait for this VM’s current operation to finish.' if busy else
                    'Finish this VM’s commands and close its terminals first.' if active else
                    'VM is running. Stop it before changing the selection; saved setup can be repaired now.' if controls.get('running') else
                    'VM is stopped. Change the selection and apply it for the next Start.')
            # A failed observer is not proof that the VM is running, stopped,
            # or unsafe to inspect. Lifecycle operations perform their own
            # checks; keep those recovery entry points available after a poll
            # failure instead of making a broken controller impossible to fix.
            can_retry = (known or bool(controls.get('status_attempted'))) and not busy and not active
            controls['start'].set_enabled(can_retry and (not known or not (controls.get('running') and controls.get('ready')) or desktop_pending))
            controls['start'].set_text('Retry Setup' if controls.get('running') and (not controls.get('ready') or desktop_pending) else 'Start')
            controls['stop'].set_enabled(can_retry and (not known or bool(controls.get('running'))))
            cancel_setup = controls.get('cancel_setup')
            if cancel_setup is not None:
                show_cancel = busy and op.action in {'start', 'reset', 'rebuild', 'restore'}
                pending = bool(controls['cancel_setup_state']['pending'])
                cancel_setup.set_visibility(show_cancel)
                cancel_setup.set_enabled(show_cancel and not pending)
                cancel_setup.set_text('Cancelling…' if pending else 'Cancel setup')
            controls['terminal'].set_enabled(not busy and bool(controls.get('ready')))
            controls['terminal_options'].set_enabled(not busy and bool(controls.get('ready')))
            if controls['graphical'] is not None:
                controls['graphical'].set_enabled(not busy and bool(controls.get('running')) and
                    (not desktop_expected or bool(controls.get('desktop_ready'))))
            if controls.get('desktop_status') is not None:
                line = ('Desktop: VM stopped' if not controls.get('running') else
                        'Desktop: Ready' if controls.get('desktop_ready') else
                        'Desktop: ' + (str(controls.get('desktop_error') or '') or
                                       ('checking…' if controls.get('desktop_state') == 'checking' else
                                        'not verified. Use Retry Setup to complete desktop setup.')))
                controls['desktop_status'].set_text(line)
                if controls.get('running') and not controls.get('desktop_ready'):
                    controls['desktop_status'].classes(add='text-warning', remove='hy-muted text-positive')
                elif controls.get('running'):
                    controls['desktop_status'].classes(add='text-positive', remove='hy-muted text-warning')
                else:
                    controls['desktop_status'].classes(add='hy-muted', remove='text-positive text-warning')
            controls['delete'].set_enabled(can_retry and (not known or not controls.get('running')))
        configs = [value['config'] for value in card_states.values()]
        parts = [f'{len(configs)} VM' + ('' if len(configs) == 1 else 's')]
        parts.extend(f'{counts[state]} {state}' for state in ('starting', 'stopping', 'updating', 'ready', 'needs setup', 'stopped', 'checking', 'unavailable') if counts.get(state))
        if configs:
            parts.append(f'Allocated {sum(item.cpu for item in configs)} vCPU / {sum(item.memory_mb for item in configs) / 1024:g} GiB RAM')
        summary.set_text(' · '.join(parts))

    async def refresh() -> None:
        if local_panel.is_deleted:
            poll.cancel(); return
        configs = manager.list()
        if signature['configs'] != tuple(item.to_dict() for item in configs):
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
                                    desktop_ready=bool(status.get('desktop_ready')), desktop_state=str(status.get('desktop_state') or ''),
                                    desktop_error=str(status.get('desktop_error') or ''),
                                    status_detail=str(status.get('error') or status.get('detail') or '') if not status.get('ready') else '',
                                    state='Unavailable' if poll_error else str(status.get('state') or 'stopped'),
                                    radio_snapshot=info.get('hardware_emulation'))
            except Exception as exc:
                controls.update(status_attempted=True, known=False, ready=False, state='Unavailable', poll_error=str(exc))
        sync_cards()

    render_cards(); sync_cards()
    poll = ui.timer(0.75, refresh, immediate=True)
