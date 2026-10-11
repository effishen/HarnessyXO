"""Small, credential-free snapshots of the settings attached to a message."""
from __future__ import annotations

from typing import Any

from harnessy.core.thinking import canonical, level_label, resolve_thinking


def model_settings_snapshot(
    profile: dict[str, Any], choice: Any, *, model: str | None = None,
) -> dict[str, Any]:
    selected = canonical(choice)
    resolved = resolve_thinking(profile, selected)
    return {
        'version': 1,
        'model': str(model if model is not None else profile.get('model') or ''),
        'profile_id': str(profile.get('id') or ''),
        'profile_name': str(profile.get('name') or ''),
        'thinking_choice': selected,
        'thinking': resolved,
        'thinking_label': (
            'Model default (no override requested)' if resolved == 'default'
            else level_label(profile, resolved)
        ),
    }


def message_settings_tooltip(
    snapshot: Any = None, *, model: str | None = None,
    thinking: str | None = None, role: str = 'assistant',
) -> str:
    """Use only recorded evidence; current chat/profile settings are irrelevant."""
    saved = snapshot if isinstance(snapshot, dict) and snapshot.get('version') == 1 else {}
    recorded_model = str(saved.get('model') or model or '').strip()
    profile_name = str(saved.get('profile_name') or '').strip()
    recorded_thinking = str(saved.get('thinking') or thinking or '').strip()
    thinking_label = str(saved.get('thinking_label') or '').strip()
    if not thinking_label:
        if recorded_thinking == 'default':
            thinking_label = 'Model default (no override requested)'
        elif recorded_thinking == 'profile':
            thinking_label = 'Profile preset (resolved level not recorded)'
        else:
            # Legacy messages lack the profile's historical label/wire mapping.
            thinking_label = recorded_thinking.capitalize() if recorded_thinking else 'Not recorded'
    heading = {
        'user': 'Model selected for this input',
        'tool': 'Model that requested this tool',
    }.get(role, 'Model for this response')
    lines = [f'{heading}: {recorded_model or "Not recorded"}']
    if profile_name and profile_name != recorded_model:
        lines.append(f'Profile: {profile_name}')
    lines.append(f'Thinking: {thinking_label}')
    if saved.get('thinking_choice') == 'profile':
        lines.append('Selected through the profile preset.')
    return '\n'.join(lines)
