"""Visible explanation of the target broker's existing access rules."""
from __future__ import annotations

from html import escape
from typing import Any

from nicegui import ui

from harnessy.agent.external_targets import EXTERNAL_TARGET_COMMAND_RULES, EXTERNAL_TARGET_PROTECTED_PATHS
from harnessy.agent.tools import tool_permission_reason


def target_action_rows(global_permission: str, target_mode: str, *, enabled: bool = True,
                       managed_vm: bool = False, policy: dict[str, Any] | None = None) -> list[tuple[str, str]]:
    policy = policy or {}
    actions = [
        ('List enabled targets', False, '', False),
        ('Check status, identity and test-root access', False, '', True),
        ('List files under the test root', False, 'allow_list', True),
        ('Run any command, including ls, pwd, cat and uname', True, 'allow_exec', True),
        ('Copy a file to the target', True, 'allow_copy_to', True),
        ('Copy a file from the target', True, 'allow_copy_from', True),
    ]
    if managed_vm:
        actions.append(('Start, stop, snapshot or restore this test VM', True, '', True))
    rows = []
    for label, protected, policy_key, needs_target in actions:
        if (global_permission not in {'ask', 'on'} or (needs_target and not enabled)
                or (policy_key and not policy.get(policy_key, True))):
            access = 'Blocked'
        else:
            reason = tool_permission_reason(
                {'external_targets': global_permission}, approve_when_ask=protected,
                target_state='enabled' if needs_target else 'not_applicable', target_mode=target_mode,
            )
            access = 'Ask for approval' if reason == 'ask' else 'No approval dialog'
        rows.append((label, access))
    return rows


def render_target_access_help(machine: Any, approval: Any, *, enabled: Any = None,
                              managed_vm: bool = False, policy: dict[str, Any] | None = None,
                              draft: bool = False) -> None:
    with ui.column().classes('w-full min-w-0 gap-1').props('data-hy-target-access-help=1'):
        summary = ui.label('').classes('text-xs hy-muted hy-wrap-anywhere').props('role=status')
        with ui.expansion('Allowed actions and command limits', icon='policy').classes('w-full min-w-0') as details:
            with ui.column().classes('w-full min-w-0 gap-2'):
                ui.label('Global control: Settings → Agent / Tools → Tool Permissions → External/Test Targets.').classes('text-xs hy-muted hy-wrap-anywhere')
                ui.label('This breakdown uses the selected target mode. Save the target to apply changes.' if draft
                         else 'This breakdown uses the selected target mode.').classes('text-xs hy-muted')
                ui.button('Refresh access rules', icon='refresh', on_click=lambda: refresh()).props(
                    'flat dense no-caps aria-label="Refresh target access rules"')
                ui.label('Refresh after changing the global setting. Saved global permissions apply to tool calls immediately.').classes('text-xs hy-muted')
                table = ui.html('').classes('w-full min-w-0')
                ui.label('Command approval covers the whole Run command tool. There is no separate list of harmless commands that bypasses Ask.').classes('text-xs hy-muted')
                if managed_vm:
                    ui.label('This managed test VM allows package installation and privileged guest commands. The approval rules above and the guest account’s permissions still apply.').classes('text-xs hy-muted')
                else:
                    ui.label('Blocked command names on SSH devices').classes('text-sm font-semibold mt-1')
                    ui.label('These names are rejected by the command text filter, including after approval or with autonomous access enabled.').classes('text-xs hy-muted')
                    for label, _pattern, names in EXTERNAL_TARGET_COMMAND_RULES:
                        ui.label(f'{label}: {names}').classes('text-xs hy-muted hy-wrap-anywhere')
                    ui.label('Protected paths in command text: ' + ', '.join(EXTERNAL_TARGET_PROTECTED_PATHS) + '.').classes('text-xs hy-muted hy-wrap-anywhere')
                    ui.label('A configured /root/subdirectory is excepted from the /root rule. Direct references to other protected paths and parent-directory traversal are rejected. These command-text restrictions apply to Run command; fixed status checks and file-transfer tools have their own path rules.').classes('text-xs hy-muted')
                    ui.label('Commands that pass these checks run with the SSH account’s privileges after any required approval. The text filter is best effort: root code and symlinks can escape it.').classes('text-xs hy-muted')
                ui.label('Working directories and remote copy paths must be relative to the configured test root. Copies transfer one regular file, up to 256 MiB, between that root and the active workspace.').classes('text-xs hy-muted')

        def refresh(_event: Any = None) -> None:
            try:
                saved = machine.load_tool_permission_settings()
                permission = str(saved['agent']['tool_permissions']['external_targets'])
            except (AttributeError, OSError, ValueError, KeyError, TypeError):
                permission = 'unavailable'
            mode = 'on' if approval.value == 'on' else 'ask'
            available = bool(enabled.value) if enabled is not None else True
            if permission == 'unavailable':
                text = 'Global permissions unavailable: target tools are blocked until saved permissions can be read.'
            elif permission == 'off':
                text = 'Global Off: all model target tools are blocked, including status checks.'
            elif not available:
                text = f'Target disabled. Global {permission.title()} still applies to listing other enabled targets.'
            elif permission == 'on':
                text = 'Global On: target actions run without approval, including when this target is set to Ask.'
            elif mode == 'on':
                text = 'Global Ask + target autonomous: target actions run without approval.'
            else:
                text = ('Global Ask + target Ask: fixed read-only checks run directly; commands, file copies and VM controls ask.'
                        if managed_vm else 'Global Ask + target Ask: fixed read-only checks run directly; commands and file copies ask.')
            summary.set_text(text)
            rows = target_action_rows(permission, mode, enabled=available, managed_vm=managed_vm, policy=policy)
            cell = 'padding:6px 4px;border-bottom:1px solid var(--hy-border);vertical-align:top;overflow-wrap:anywhere'
            body = ''.join(f'<tr><td style="{cell}">{escape(label)}</td><td style="{cell}">{escape(access)}</td></tr>' for label, access in rows)
            table.set_content('<table style="width:100%;table-layout:fixed;border-collapse:collapse;font-size:12px">'
                              '<thead><tr><th scope="col" style="text-align:left;width:65%">Action</th>'
                              '<th scope="col" style="text-align:left">Approval</th></tr></thead><tbody>' + body + '</tbody></table>')

        approval.on_value_change(refresh)
        if enabled is not None:
            enabled.on_value_change(refresh)
        details.on_value_change(refresh)
        refresh()
