"""Thinking controls: chat intent, model capabilities and wire values are distinct.

No model-name heuristic is allowed to invent a native Ollama level mapping.
Qwen3.8 native levels require a renderer verification record for this endpoint/model.
Model default is represented by omission, never by an implicit Medium or True.
"""
from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from typing import Any

CHOICES = ('default', 'profile', 'off', 'on', 'low', 'medium', 'high')
PRESETS = {
    'auto': 'Auto (metadata / model family)',
    'binary': 'On / Off only',
    'generic': 'Generic levels (low / medium / high)',
    'qwen3.8': 'Qwen3.8 levels (including custom models)',
    'custom': 'Custom wire values',
    'legacy': 'Existing compatibility configuration',
}
OFF_MODES = {
    'auto': 'Auto (model / API mode)',
    'reasoning_none': 'reasoning_effort / reasoning: none',
    'enable_thinking': 'enable_thinking: false',
    'chat_template_kwargs': 'chat_template_kwargs.enable_thinking: false',
    'unsupported': 'Off is not supported',
}
DETECTION_FIELDS = ('supports_vision', 'supports_usage_stream', 'supports_thinking',
                    'supports_reasoning_effort', 'supports_developer_role', 'supports_strict_mode',
                    'thinking_mode', 'thinking_detection', 'capability_detection',
                    'thinking_native_verification', 'thinking_default_verification')


class ThinkingConfigurationError(ValueError):
    """A requested explicit setting cannot be faithfully sent to this backend."""


def canonical(value: Any) -> str:
    if value is True:
        return 'on'
    if value is False:
        return 'off'
    text = str(value or 'default').strip().lower()
    return {'xhigh': 'high', 'max': 'high', 'none': 'off', 'model default': 'default'}.get(text, text)


def resolve_thinking(profile: dict[str, Any], choice: Any = None) -> str:
    """Default always means no override, including for legacy Medium profiles.

    New-chat/model-switch callers initialize choices from the profile setting.
    Here only an explicit 'profile' follows the current profile value; a saved
    'default' always remains omission and never masquerades as an explicit level.
    """
    selected = canonical(choice)
    if selected == 'profile':
        selected = canonical(profile.get('default_thinking', 'default'))
    if selected not in CHOICES or selected == 'profile':
        raise ThinkingConfigurationError(f'Unknown Thinking choice: {selected!r}. Select Model default or a supported level.')
    return selected


def profile_identity(profile: dict[str, Any]) -> str:
    value = [str(profile.get(k) or '').rstrip('/') for k in ('base_url', 'model', 'api_mode')]
    return hashlib.sha256(json.dumps(value, separators=(',', ':')).encode()).hexdigest()


def model_family(profile: dict[str, Any], metadata: dict[str, Any] | None = None) -> str:
    if profile.get('thinking_preset') == 'qwen3.8':
        return 'qwen3.8'
    detection = profile.get('thinking_detection') or {}
    if metadata is None and detection.get('profile_identity') == profile_identity(profile):
        if detection.get('family'):
            return str(detection['family'])
    data = metadata or {}
    details = data.get('details') if isinstance(data.get('details'), dict) else {}
    info = data.get('model_info') if isinstance(data.get('model_info'), dict) else {}
    signals = [profile.get('model', ''), data.get('model', ''), data.get('name', ''),
               data.get('renderer', ''), data.get('parser', ''), details.get('family', ''),
               *list(details.get('families') or []), info.get('general.name', ''),
               info.get('general.basename', ''), info.get('general.architecture', '')]
    text = ' '.join(str(s) for s in signals)
    # qwen3_5 architecture does not contradict a stronger Qwen3.8 name/renderer.
    if re.search(r'qwen[\s._-]*3[._-]8(?!\d)', text, re.I):
        return 'qwen3.8'
    if re.search(r'gpt[-_ ]?oss', text, re.I):
        return 'gpt-oss'
    return ''


def detected_profile(profile: dict[str, Any], metadata: dict[str, Any], *, version: str = '') -> dict[str, Any]:
    """Pure /api/show translation. No inference; explicit presets remain intact."""
    result = deepcopy(profile)
    if not isinstance(metadata.get('capabilities'), list):
        return result  # absent metadata is not evidence that thinking is absent
    caps = sorted({str(x).strip().lower() for x in metadata['capabilities'] if str(x).strip()})
    family = model_family(profile, metadata)
    details = metadata.get('details') if isinstance(metadata.get('details'), dict) else {}
    info = metadata.get('model_info') if isinstance(metadata.get('model_info'), dict) else {}
    evidence = {k: metadata.get(k) for k in ('capabilities', 'details', 'model_info', 'template', 'renderer', 'parser', 'parameters', 'modified_at', 'system', 'messages')}
    metadata_key = hashlib.sha256(json.dumps(evidence, sort_keys=True, default=str).encode()).hexdigest()
    result.update(supports_vision='vision' in caps, supports_thinking='thinking' in caps)
    result['thinking_detection'] = {
        'source': 'Ollama /api/show', 'backend': 'ollama', 'profile_identity': profile_identity(profile),
        'capabilities': caps, 'family': family, 'version': str(version), 'metadata_key': metadata_key,
        'architecture': str(info.get('general.architecture') or details.get('family') or ''),
        'renderer': str(metadata.get('renderer') or ''), 'parser': str(metadata.get('parser') or ''),
    }
    if 'thinking' in caps:
        if str(result.get('thinking_mode') or 'none') == 'none':
            result['thinking_mode'] = 'reasoning_effort' if family else 'enable_thinking'
        if family in {'qwen3.8', 'gpt-oss'}:
            result['supports_reasoning_effort'] = True
    record = result.get('thinking_native_verification') or {}
    if record and (record.get('profile_identity') != profile_identity(profile)
                   or record.get('metadata_key') != metadata_key or record.get('version') != str(version)):
        result['thinking_native_verification'] = None
    # A saved default observation belongs to a particular endpoint, credentials,
    # model metadata and server version. Never carry it to a changed model.
    if result.get('thinking_default_verification') and not default_record_valid(result):
        result['thinking_default_verification'] = None
    return result


def control_description(profile: dict[str, Any]) -> dict[str, Any]:
    preset = str(profile.get('thinking_preset') or 'auto')
    mode = str(profile.get('thinking_mode') or 'reasoning_effort')
    family = model_family(profile)
    supported = bool(profile.get('supports_thinking'))
    if not supported or mode == 'none':
        return {'kind': 'none', 'choices': [], 'family': family, 'label': 'Not enabled', 'preset': preset}
    detection = profile.get('thinking_detection') or {}
    native = str(profile.get('api_mode') or '') in {'ollama','ollama-native','native-ollama'} or (
        detection.get('profile_identity') == profile_identity(profile) and detection.get('backend') == 'ollama')
    if preset == 'binary' or (mode == 'enable_thinking' and not (native and family and preset in {'auto','qwen3.8'})):
        choices = ['off', 'on']
        label = 'On / Off'
    elif preset in {'generic', 'custom', 'legacy'} or family or bool(profile.get('supports_reasoning_effort')):
        choices = ['off', 'low', 'medium', 'high']
        label = 'Qwen3.8 levels' if family == 'qwen3.8' and preset not in {'generic', 'custom', 'legacy'} else 'Levels'
    else:
        # The thinking capability alone never proves an effort vocabulary.
        choices = ['off', 'on']
        label = 'On / Off (level vocabulary unknown)'
    if family == 'gpt-oss' or profile.get('thinking_off_mode') == 'unsupported':
        choices = [c for c in choices if c != 'off']
    return {'kind': 'binary' if 'on' in choices else 'levels', 'choices': choices,
            'family': family, 'label': label, 'preset': preset}


def thinking_choices(profile: dict[str, Any]) -> list[str]:
    return list(control_description(profile)['choices'])


def default_proof_identity(profile: dict[str, Any]) -> str:
    """Opaque identity also scopes observations to the configured credentials."""
    value = [profile_identity(profile), str(profile.get('api_key') or '').strip()]
    return hashlib.sha256(json.dumps(value, separators=(',', ':')).encode()).hexdigest()


def default_record_valid(profile: dict[str, Any], *, backend: str | None = None) -> bool:
    """Validate display evidence only. This NEVER changes the outgoing controls.

    A previous explicit-level verification, model name or public template default
    is insufficient: the recorded request must actually OMIT all Thinking fields.
    """
    record = profile.get('thinking_default_verification')
    detection = profile.get('thinking_detection')
    if not isinstance(record, dict) or not isinstance(detection, dict):
        return False
    mode = str(profile.get('api_mode') or 'auto').strip().lower()
    native = mode in {'ollama', 'ollama-native', 'native-ollama'} or (
        mode == 'auto' and detection.get('backend') == 'ollama')
    if backend is not None:
        native = backend == 'ollama'
    if (not native or not profile.get('supports_thinking') or profile.get('thinking_mode') == 'none'
            or record.get('schema') != 1 or record.get('status') != 'verified'
            or record.get('backend') != 'ollama' or record.get('request_fields') != {}
            or record.get('method') != 'Ollama /api/chat _debug_render_only'
            or record.get('profile_identity') != profile_identity(profile)
            or record.get('proof_identity') != default_proof_identity(profile)
            or detection.get('profile_identity') != profile_identity(profile)
            or not record.get('metadata_key') or not record.get('version')
            or record['metadata_key'] != detection.get('metadata_key')
            or record['version'] != detection.get('version')
            or not isinstance(record.get('checked_at'), str) or not record['checked_at']):
        return False
    sample = record.get('sample')
    if (not isinstance(sample, dict) or sample.get('think_omitted') is not True
            or 'think' in sample or sample.get('result') != 'rendered' or sample.get('effort_ambiguous')
            or sample.get('http_status') != 200
            or not re.fullmatch(r'[a-f0-9]{64}', str(sample.get('render_sha256') or ''))):
        return False
    level, effort = record.get('level'), record.get('effort')
    if not isinstance(level, str):
        return False
    if level == 'off':
        return (effort is None and sample.get('thinking_closed') is True
                and sample.get('thinking_open') is False and record.get('evidence') == 'closed_thinking_prefix')
    if (sample.get('thinking_open') is not True or sample.get('thinking_closed') is not False
            or level not in {'low', 'medium', 'high'}):
        return False
    expected = {'low': 'low', 'medium': 'medium', 'high': 'xhigh'}[level]
    if effort != expected:
        return False
    if sample.get('effort') == expected and record.get('evidence') == 'explicit_effort_marker':
        return True
    comparison = record.get('comparison')
    # Medium has no instruction in some Qwen renderers. Absence is not a level;
    # require an identical prompt to a separately proven Medium reference.
    return bool(level == 'medium' and sample.get('effort') is None
                and record.get('evidence') == 'verified_medium_comparison'
                and isinstance(comparison, dict) and comparison.get('status') == 'verified'
                and comparison.get('level') == 'medium'
                and comparison.get('render_sha256') == sample.get('render_sha256'))


def model_default_status(profile: dict[str, Any], *, backend: str | None = None) -> dict[str, Any]:
    """Small, credential-free presentation/diagnostics object for the real default."""
    if not default_record_valid(profile, backend=backend):
        return {'status': 'unverified', 'level': None, 'effort': None,
                'reason': "The backend's default level has not been verified for this configuration."}
    record = profile['thinking_default_verification']
    return {'status': 'verified', 'level': record['level'], 'effort': record['effort'],
            'source': record['method'], 'checked_at': record['checked_at'],
            'backend': 'ollama', 'request_fields': {}}


def level_label(profile: dict[str, Any], value: Any) -> str:
    """Model-facing names are presentation; persisted canonical IDs stay stable."""
    selected = canonical(value)
    if (selected == 'high' and model_family(profile) == 'qwen3.8'
            and str(profile.get('thinking_preset') or 'auto') in {'auto', 'qwen3.8'}):
        return 'xhigh'
    return selected.title()


def observed_default_label(status: dict[str, Any]) -> str:
    if status.get('status') != 'verified':
        return 'Unverified'
    return 'xhigh' if status.get('effort') == 'xhigh' else str(status.get('level') or '').title()


def model_default_label(profile: dict[str, Any]) -> str:
    status = model_default_status(profile)
    return f"Default · {observed_default_label(status)}" if status['status'] == 'verified' else 'Model default'


def default_label(profile: dict[str, Any]) -> str:
    return model_default_label(profile)


def profile_preset_label(profile: dict[str, Any]) -> str:
    value = canonical(profile.get('default_thinking', 'default'))
    return ('Use profile preset · no override' if value == 'default' else
            f'Use profile preset · {level_label(profile, value)}')


def profile_thinking_options(profile: dict[str, Any]) -> dict[str, str]:
    return {'default': model_default_label(profile) + ' (no override)',
            **{x: level_label(profile, x) for x in ('off', 'on', 'low', 'medium', 'high')}}


def model_default_note(profile: dict[str, Any]) -> str:
    status = model_default_status(profile)
    if status['status'] != 'verified':
        return ("No override sent. The backend's default level has not been verified. "
                'For supported native Ollama models, use Settings → Models → Capabilities → '
                'Verify Thinking levels & default, then Save. No level is guessed from the model name.')
    effort = status['effort'] or 'disabled'
    note = (f"Model default: {observed_default_label(status)}. Backend effort: {effort}. No override sent. "
            f"Last verified: {status['checked_at']} using the installed Ollama renderer. "
            'This describes the fixed probe rendering, not measured model-internal compute. '
            'Default continues to follow the backend; it is not an explicit level selection.')
    if model_family(profile) == 'qwen3.8' and status['effort'] != 'xhigh':
        note += (' Stock Qwen3.8 template default: xhigh. This observed result is the serving endpoint default, '
                 'which may differ. Select xhigh explicitly to request the highest effort.')
    return note


def thinking_tooltip(profile: dict[str, Any], selected: Any) -> str:
    choice = canonical(selected)
    if choice == 'profile':
        value = resolve_thinking(profile, choice)
        return (f'Profile preset explicitly selected for this chat: {level_label(profile, value)}. '
                'It follows the optional profile setting, not the model default. '
                'Choosing Default sends no override. See Stats for the request fields actually sent.')
    if choice != 'default':
        return (f'{level_label(profile, choice)} explicitly selected for this chat; retained after reloads and model changes. '
                'This is a chat override, not Model default. Choosing Default again removes it. '
                'See Stats for the request fields actually sent.')
    note = model_default_note(profile)
    value = canonical(profile.get('default_thinking', 'default'))
    if value != 'default':
        note += (f' The saved profile preset ({level_label(profile, value)}) is not applied. '
                 'Select Use profile preset explicitly to apply it.')
    return note


def composer_options(profile: dict[str, Any], selected: Any) -> dict[str, str]:
    choices = thinking_choices(profile)
    if not choices:
        return {}
    result = {'default': default_label(profile), **{x: level_label(profile, x) for x in choices}}
    saved = canonical(selected)
    if canonical(profile.get('default_thinking', 'default')) != 'default' or saved == 'profile':
        result['profile'] = profile_preset_label(profile)
    if saved not in result:
        result[saved] = f'{level_label(profile, saved)} (unavailable here)'
    return result


def validate_wire_overrides(profile: dict[str, Any]) -> None:
    for key in ('thinking_wire_values', 'thinking_ollama_values'):
        values = profile.get(key) or {}
        allowed = {'off', 'on', 'low', 'medium', 'high'} if key == 'thinking_ollama_values' else {'low', 'medium', 'high'}
        if not isinstance(values, dict) or any(k not in allowed for k in values):
            raise ThinkingConfigurationError(f'{key} must be a JSON object keyed by off/on/low/medium/high.')
        for value in values.values():
            if key == 'thinking_ollama_values':
                if not isinstance(value, (bool, str)) or (isinstance(value, str) and value not in {'low','medium','high','max'}):
                    raise ThinkingConfigurationError('Native Ollama wire values must be boolean or low/medium/high/max, not xhigh.')
            elif not isinstance(value, str) or not value.strip() or len(value) > 40:
                raise ThinkingConfigurationError('Compatible wire values must be non-empty short strings.')


def native_record_valid(profile: dict[str, Any]) -> bool:
    record = profile.get('thinking_native_verification') or {}
    detection = profile.get('thinking_detection') or {}
    values = record.get('wire_values') if isinstance(record, dict) else None
    if not isinstance(values, dict) or values.get('off') is not False:
        return False
    if any(not isinstance(values.get(k), str) or values[k] not in {'low', 'medium', 'high', 'max'} for k in ('low', 'medium', 'high')):
        return False
    return bool(record.get('status') == 'verified' and record.get('profile_identity') == profile_identity(profile)
                and detection.get('profile_identity') == profile_identity(profile)
                and record.get('metadata_key') == detection.get('metadata_key')
                and record.get('version') == detection.get('version'))


def thinking_payload(profile: dict[str, Any], choice: Any, backend: str) -> dict[str, Any]:
    selected = resolve_thinking(profile, choice)
    desc = control_description(profile)
    if desc['kind'] == 'none' or selected == 'default':
        return {}
    if selected not in desc['choices']:
        raise ThinkingConfigurationError(
            f'Thinking {selected.title()} is not supported by this profile. The chat choice was preserved; '
            'choose Model default or a supported option, or configure the model compatibility preset.')
    validate_wire_overrides(profile)
    family = desc['family']
    preset = desc['preset']
    qwen = family == 'qwen3.8' and preset not in {'binary', 'generic', 'custom', 'legacy'}
    if backend == 'ollama':
        if preset == 'custom':
            mapping = profile.get('thinking_ollama_values') or {}
            if selected not in mapping:
                raise ThinkingConfigurationError(f'Custom Ollama wire value for {selected} is missing.')
            return {'think': mapping[selected]}
        if selected in {'off', 'on'}:
            return {'think': selected == 'on'}
        if qwen:
            if not native_record_valid(profile):
                raise ThinkingConfigurationError('Qwen3.8 native Thinking levels need installed-endpoint verification. '
                    'Use Detect / Verify Thinking in Models settings, or Model default / Off until verified.')
            mapping = profile['thinking_native_verification'].get('wire_values') or {}
            if selected not in mapping:
                raise ThinkingConfigurationError(f'No verified native mapping for {selected}.')
            return {'think': mapping[selected]}
        return {'think': selected}
    mode = str(profile.get('thinking_mode') or 'reasoning_effort')
    if selected == 'off':
        off_mode = str(profile.get('thinking_off_mode') or 'auto')
        if off_mode == 'auto':
            off_mode = 'enable_thinking' if mode == 'enable_thinking' else ('chat_template_kwargs' if qwen or mode == 'chat_template_kwargs' else 'reasoning_none')
        if off_mode == 'enable_thinking':
            return {'enable_thinking': False}
        if off_mode == 'chat_template_kwargs':
            return {'chat_template_kwargs': {'enable_thinking': False}}
        if off_mode == 'unsupported':
            raise ThinkingConfigurationError('This profile has no verified Off mechanism.')
        return {'reasoning': {'effort': 'none'}} if mode == 'reasoning' else {'reasoning_effort': 'none'}
    if mode == 'enable_thinking':
        return {'enable_thinking': True}
    if selected == 'on':
        raise ThinkingConfigurationError('This compatible profile has no known On parameter. Choose Model default or set Thinking API mode to enable_thinking for a boolean endpoint.')
    mapping = {'low': 'low', 'medium': 'medium', 'high': 'xhigh' if qwen else 'high'}
    mapping.update(profile.get('thinking_wire_values') or {})
    value = mapping[selected]
    if mode == 'reasoning':
        return {'reasoning': {'effort': value}}
    if mode == 'chat_template_kwargs':
        return {'chat_template_kwargs': {'enable_thinking': True, 'reasoning_effort': value}}
    return {'reasoning_effort': value}


def control_note(profile: dict[str, Any]) -> str:
    desc = control_description(profile)
    detected = profile.get('thinking_detection') or {}
    text = desc['label']
    if detected.get('profile_identity') == profile_identity(profile):
        text += f" · {detected.get('source', 'metadata')}"
    if desc['family'] == 'qwen3.8' and desc['kind'] == 'levels':
        text += ' · Qwen highest: xhigh (canonical saved ID: high); compatible effort → xhigh.'
        if native_record_valid(profile):
            text += f" Native levels renderer-verified ({profile['thinking_native_verification']['wire_values']})."
        else:
            text += ' Native level mapping is checked against the installed endpoint before an explicit level is sent.'
    text += ' Backend default: ' + model_default_note(profile)
    value = canonical(profile.get('default_thinking', 'default'))
    if value != 'default':
        text += f' Optional profile preset: {level_label(profile, value)}. Not used by Default; requires an explicit Use profile preset selection.'
    text += ' Explicit chat choices survive reloads.'
    return text
