"""Target action editor and the effective global/target permission breakdown."""
from __future__ import annotations

from html import escape
import inspect
from typing import Any, Callable

from nicegui import ui

from harnessy.core.target_policy import (
    TARGET_ACCESS_MODE_LABELS, TARGET_ACTION_GROUPS, TARGET_ACTION_LABELS,
    TARGET_PERMISSION_LABELS, merge_target_permissions, normalize_target_policy,
    target_action_permission,
)


def target_action_rows(global_permission: str, target_mode: str = 'selected', *, enabled: bool = True,
                       managed_vm: bool = False, policy: dict[str, Any] | None = None) -> list[tuple[str, str]]:
    """Project the same independent gates enforced by target tool execution."""
    canonical = normalize_target_policy(policy, approval_mode=target_mode, managed_vm=managed_vm)
    if target_mode in {'full', 'selected'}:
        canonical['access_mode'] = target_mode
    rows = []
    for action, label in TARGET_ACTION_LABELS.items():
        if action.startswith('vm_') and not managed_vm:
            continue
        gates = [global_permission, target_action_permission(canonical, action, managed_vm=managed_vm)]
        if action.startswith('exec_'):
            gates.append(target_action_permission(canonical, 'allow_exec', managed_vm=managed_vm))
        permission = merge_target_permissions(gates) if enabled else 'off'
        rows.append((label, {'off': 'Off — blocked', 'ask': 'Ask — approval required', 'on': 'On — allowed'}[permission]))
    return rows


class TargetAccessEditor:
    """Keep dormant selected rules intact when Full access is saved or toggled."""
    def __init__(self, machine: Any, policy: dict[str, Any] | None = None, *, approval_mode: str = 'ask',
                 managed_vm: bool = False, enabled: Any = None, on_change: Callable[[], Any] | None = None,
                 draft: bool = True) -> None:
        self.machine, self.managed_vm, self.enabled = machine, bool(managed_vm), enabled
        self.on_change, self.draft = on_change, bool(draft)
        canonical = normalize_target_policy(policy, approval_mode=approval_mode, managed_vm=self.managed_vm)
        self._selected = dict(canonical['actions'])
        self.controls: dict[str, Any] = {}
        with ui.column().classes('w-full min-w-0 gap-2').props('data-hy-target-access-editor=1'):
            self.mode = ui.select(TARGET_ACCESS_MODE_LABELS, value=canonical['access_mode'], label='Model access').classes('w-full').props('outlined dense data-hy-target-access-mode=1')
            self.description = ui.label('').classes('text-xs hy-muted').style('overflow-wrap:anywhere')
            self.summary = ui.label('').classes('text-xs hy-muted').props('role=status data-hy-target-global-access=1').style('overflow-wrap:anywhere')
            with ui.expansion('Selected action permissions', icon='tune', value=True).classes('w-full min-w-0').props('data-hy-target-selected-actions=1') as self.selected_card:
                with ui.column().classes('w-full min-w-0 gap-2'):
                    ui.label('Off blocks the action. Ask requests approval. On permits it, subject to global access and the target account.').classes('text-xs hy-muted')
                    for group, actions in TARGET_ACTION_GROUPS:
                        if group == 'Test VM controls' and not self.managed_vm:
                            continue
                        ui.label(group).classes('text-xs font-semibold mt-2')
                        for action in actions:
                            with ui.row().classes('w-full min-w-0').style('display:grid;grid-template-columns:minmax(0,1fr) 132px;column-gap:8px;align-items:center').props(f'data-hy-target-action={action}'):
                                ui.label(TARGET_ACTION_LABELS[action]).classes('text-xs').style('overflow-wrap:anywhere')
                                control = ui.toggle(TARGET_PERMISSION_LABELS, value=self._selected[action]).props('dense no-caps spread').classes('text-xs').style('width:132px;min-width:0;font-size:11px')
                                control.props(f'role=group aria-label="{TARGET_ACTION_LABELS[action]} permission"')
                                self.controls[action] = control
                                control.on_value_change(self._changed)
                    ui.label('Command categories also require Run commands. Path permissions apply in addition to the requested tool.').classes('text-xs hy-muted')
                    ui.label('Command categories use best-effort text checks. They do not isolate a shell or prevent code from using the account’s permissions.').classes('text-xs hy-muted')
            with ui.expansion('Effective model access', icon='policy').classes('w-full min-w-0') as effective:
                with ui.column().classes('w-full min-w-0 gap-2'):
                    ui.label('Global access: Settings → Agent / Tools → Tool Permissions → External/Test Targets. Global Off blocks all target calls; Ask requests approval; On permits access while preserving each selected action’s Off or Ask.').classes('text-xs hy-muted')
                    ui.label('Save this target to apply its draft.' if self.draft else 'Changes to this target are saved as you make them.').classes('text-xs hy-muted')
                    ui.button('Refresh global access', icon='refresh', on_click=self.refresh).props('flat dense no-caps')
                    self.table = ui.html('').classes('w-full min-w-0')
                    ui.label('A command matching several categories needs every applicable action. Any required Off blocks it; otherwise Ask requires approval.').classes('text-xs hy-muted')
                    if not self.managed_vm:
                        ui.label('VM start, stop and snapshot actions apply only to managed test VMs.').classes('text-xs hy-muted')
            self.error = ui.label('').classes('text-xs text-negative').style('white-space:pre-wrap;overflow-wrap:anywhere')
        self.mode.on_value_change(self._changed)
        effective.on_value_change(self.refresh)
        if self.enabled is not None:
            self.enabled.on_value_change(self.refresh)
        self.refresh()

    @property
    def approval_mode(self) -> str:
        return 'on' if self.mode.value == 'full' else 'ask'

    def policy(self) -> dict[str, Any]:
        values = dict(self._selected)
        values.update({action: control.value for action, control in self.controls.items()})
        return normalize_target_policy({'access_mode': self.mode.value, 'actions': values}, managed_vm=self.managed_vm)

    async def _changed(self, _event: Any = None) -> None:
        self.error.set_text('')
        self.refresh()
        if self.on_change is not None:
            try:
                result = self.on_change()
                if inspect.isawaitable(result):
                    await result
            except Exception as exc:
                self.error.set_text(str(exc) or 'Target access could not be saved. Try again.')

    def refresh(self, _event: Any = None) -> None:
        full = self.mode.value == 'full'
        self.selected_card.set_visibility(not full)
        self.description.set_text(
            'Every target action is On. The configured SSH or guest account’s permissions still limit what succeeds. Global access still applies. Your selected action settings are retained when you switch back.'
            if full else 'Choose Off, Ask, or On for each action below. Global access is a separate gate.'
        )
        try:
            permission = self.machine.load_tool_permission_settings()['agent']['tool_permissions']['external_targets']
        except (AttributeError, OSError, ValueError, KeyError, TypeError, RuntimeError):
            permission = 'unavailable'
        if not isinstance(permission, str) or permission not in {'off', 'ask', 'on'}:
            permission = 'unavailable'
        available = bool(self.enabled.value) if self.enabled is not None else True
        text = {
            'off': 'Global access: Off. All model target tools are blocked.',
            'ask': 'Global access: Ask. Target tool calls need approval; selected action Off still blocks.',
            'on': 'Global access: On. Selected action Off still blocks and Ask still requires approval.',
        }.get(permission, 'Global access is unavailable. Model target tools remain blocked.')
        if not available:
            text = 'This target is unavailable to the model. ' + text
        self.summary.set_text(text)
        rows = target_action_rows(permission, str(self.mode.value), enabled=available,
                                  managed_vm=self.managed_vm, policy=self.policy())
        cell = 'padding:6px 4px;border-bottom:1px solid var(--hy-border);vertical-align:top;overflow-wrap:anywhere'
        body = ''.join(f'<tr><td style="{cell}">{escape(label)}</td><td style="{cell}">{escape(access)}</td></tr>' for label, access in rows)
        self.table.set_content('<table style="width:100%;table-layout:fixed;border-collapse:collapse;font-size:12px">'
                               '<thead><tr><th scope="col" style="text-align:left;width:58%">Action</th>'
                               '<th scope="col" style="text-align:left">Effective access</th></tr></thead><tbody>' + body + '</tbody></table>')
