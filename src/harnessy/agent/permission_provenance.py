"""Content-free provenance for repeated permission acknowledgements.

This observes the actual request/response text without modifying it. Only fixed
labels and bounded counts leave this module; matched text, arguments, names,
identifiers and arbitrary dictionary keys are never included in a receipt.
"""
from __future__ import annotations

import json
import re
from typing import Any

SCHEMA_VERSION = 1
PERMISSION_ACKNOWLEDGEMENT_EVENTS = frozenset({
    'permission_acknowledgement_input', 'permission_acknowledgement_output',
    'permission_acknowledgement_trace_failed',
})
COMPONENTS = (
    'core', 'global_instructions', 'workspace_instructions',
    'project_chat_instructions', 'task_state', 'skill',
    'upstream_reconciliation', 'memory', 'archive_policy',
)
ROLES = frozenset({'system', 'developer', 'user', 'assistant', 'tool', 'other'})
REGIONS = frozenset({
    'system_snapshot', 'history_hot', 'active_tail', 'warm_archive',
    'historical_visual', 'automatic_continuation', 'completion_check',
    'adaptive_retention', 'adaptive_retention_capsule', 'retained_retrieval',
    'archive_marker', 'other',
})
KINDS = ('permission_confirmed_on', 'all_permissions_on')
METADATA_KEYS = ('approval_mode', 'policy', 'model_access')
MAX_COUNT = 10_000_000
MAX_ROWS = 20_000
MAX_ROW_RECEIPTS = 40
MAX_TEXT_CHARS = 4 * 1024 * 1024
_GAP = r'[\s*_`~:;,=()\[\]{}\"\x27!\.\-]{1,24}'
_PATTERNS = {
    'permission_confirmed_on': re.compile(
        rf'\b(?:all{_GAP})?permissions?{_GAP}(?:(?:are|is){_GAP})?'
        rf'confirmed{_GAP}(?:(?:as|to{_GAP}be){_GAP})?on\b', re.I,
    ),
    'all_permissions_on': re.compile(
        rf'\ball{_GAP}permissions?{_GAP}(?:(?:are|is){_GAP})?on\b', re.I,
    ),
}
# JSON-shaped key mentions are cues, not proof that a target has this policy.
# The optional backslash also observes a historical JSON payload nested inside
# a read_chat_message result. Values are deliberately neither parsed nor saved.
_METADATA_KEY = re.compile(r'(?:\\?\")(?P<key>approval_mode|policy|model_access)(?:\\?\")\s*:')


def _empty_counts() -> dict[str, Any]:
    return {
        'acknowledgements': 0,
        'acknowledgement_kinds': {key: 0 for key in KINDS},
        'metadata_key_mentions': {key: 0 for key in METADATA_KEYS},
    }


def _scan_text(text: Any) -> tuple[dict[str, Any], bool]:
    counts = _empty_counts()
    if not isinstance(text, str):
        return counts, False
    truncated = len(text) > MAX_TEXT_CHARS
    text = text[:MAX_TEXT_CHARS]
    for key, pattern in _PATTERNS.items():
        counts['acknowledgement_kinds'][key] = min(MAX_COUNT, sum(1 for _ in pattern.finditer(text)))
    counts['acknowledgements'] = sum(counts['acknowledgement_kinds'].values())
    for match in _METADATA_KEY.finditer(text):
        key = match.group('key')
        counts['metadata_key_mentions'][key] = min(MAX_COUNT, counts['metadata_key_mentions'][key] + 1)
    return counts, truncated


def _add_counts(target: dict[str, Any], incoming: dict[str, Any]) -> None:
    target['acknowledgements'] = min(MAX_COUNT, target['acknowledgements'] + incoming['acknowledgements'])
    for field, keys in (('acknowledgement_kinds', KINDS), ('metadata_key_mentions', METADATA_KEYS)):
        for key in keys:
            target[field][key] = min(MAX_COUNT, target[field][key] + incoming[field][key])


def _content_texts(content: Any) -> list[str]:
    if isinstance(content, str):
        return [content]
    if isinstance(content, list):
        # Public text parts only: no image URLs/base64 or private native copies.
        return [part['text'] for part in content[:MAX_ROWS]
                if isinstance(part, dict) and part.get('type') == 'text'
                and isinstance(part.get('text'), str)]
    return []


def permission_input_provenance(
    messages: Any, system_components: dict[str, str] | None = None, tools: Any = None,
) -> dict[str, Any]:
    """Observe the assembled request; attribute only an intact system snapshot.

    Row indices refer to the passed request, never to private transcript IDs.
    Components are an additional view of the same system text, so their counts
    must not be added to request totals. The caller should pass its frozen
    component snapshot, not fresh mutable instruction/memory reads.
    """
    rows = messages if isinstance(messages, (list, tuple)) else []
    result: dict[str, Any] = {
        'schema_version': SCHEMA_VERSION, 'rows_available': min(MAX_COUNT, len(rows)),
        'rows_scanned': min(MAX_ROWS, len(rows)), 'scan_truncated': len(rows) > MAX_ROWS,
        **_empty_counts(), 'rows_with_acknowledgements': 0,
        'by_role': {}, 'system_components_attribution': 'unavailable',
        'by_component': {}, 'matched_rows': [], 'matched_rows_available': 0,
        'tool_schemas_scanned': isinstance(tools, (list, tuple)), 'tool_schemas': _empty_counts(),
    }
    system_texts: list[str] = []
    for index, row in enumerate(rows[:MAX_ROWS]):
        if not isinstance(row, dict):
            continue
        role = row.get('role') if isinstance(row.get('role'), str) and row['role'] in ROLES else 'other'
        region = row.get('_harnessy_region')
        region = region if isinstance(region, str) and region in REGIONS else 'other'
        row_counts = _empty_counts()
        location_counts = {'content': 0, 'tool_arguments': 0}
        texts = _content_texts(row.get('content'))
        if role == 'system':
            system_texts.append(''.join(texts))
        # Native transports concatenate public text parts; count a phrase even
        # when it crosses two adjacent text parts. Image parts are not scanned.
        counts, truncated = _scan_text(''.join(texts))
        _add_counts(row_counts, counts)
        location_counts['content'] += counts['acknowledgements']
        result['scan_truncated'] = (result['scan_truncated'] or truncated
            or (isinstance(row.get('content'), list) and len(row['content']) > MAX_ROWS))
        calls = row.get('tool_calls')
        result['scan_truncated'] = result['scan_truncated'] or (isinstance(calls, list) and len(calls) > MAX_ROWS)
        for call in calls[:MAX_ROWS] if isinstance(calls, list) else []:
            function = call.get('function') if isinstance(call, dict) else None
            if not isinstance(function, dict):
                continue
            counts, truncated = _scan_text(function.get('arguments'))
            _add_counts(row_counts, counts)
            location_counts['tool_arguments'] += counts['acknowledgements']
            result['scan_truncated'] = result['scan_truncated'] or truncated
        role_counts = result['by_role'].setdefault(role, {'rows': 0, **_empty_counts()})
        role_counts['rows'] += 1
        _add_counts(role_counts, row_counts)
        _add_counts(result, row_counts)
        if row_counts['acknowledgements']:
            result['rows_with_acknowledgements'] += 1
        if row_counts['acknowledgements'] or any(row_counts['metadata_key_mentions'].values()):
            result['matched_rows_available'] += 1
            if len(result['matched_rows']) < MAX_ROW_RECEIPTS:
                result['matched_rows'].append({
                    'row_index': index, 'role': role, 'region': region,
                    **row_counts, 'locations': location_counts,
                })
    components = system_components if isinstance(system_components, dict) else {}
    # Reconstruct the same insertion-ordered snapshot used by AgentRunner.
    # No component is attributed merely because an unrelated live document
    # contains matching text; the complete frozen snapshot must be present.
    snapshot = '\n\n'.join(value for value in components.values() if isinstance(value, str) and value).strip()
    actual_system = '\n\n'.join(text.strip() for text in system_texts if text.strip())
    present = bool(snapshot and actual_system.startswith(snapshot)
                   and (len(actual_system) == len(snapshot) or actual_system[len(snapshot)].isspace()))
    if present:
        result['system_components_attribution'] = 'intact_snapshot_prefix'
        for key in COMPONENTS:
            if key in components and isinstance(components[key], str):
                counts, truncated = _scan_text(components[key])
                result['by_component'][key] = counts
                result['scan_truncated'] = result['scan_truncated'] or truncated
    # Schema contents are an independent input source. Keep these counts
    # separate from message-row totals and never emit names or schema text.
    schemas = tools if isinstance(tools, (list, tuple)) else []
    result['scan_truncated'] = result['scan_truncated'] or len(schemas) > MAX_ROWS
    for schema in schemas[:MAX_ROWS]:
        function = schema.get('function') if isinstance(schema, dict) else None
        if not isinstance(function, dict):
            continue
        counts, truncated = _scan_text(function.get('description'))
        _add_counts(result['tool_schemas'], counts)
        result['scan_truncated'] = result['scan_truncated'] or truncated
        try:
            parameters = json.dumps(function.get('parameters', {}), ensure_ascii=False, separators=(',', ':'))
        except (TypeError, ValueError, RecursionError):
            result['scan_truncated'] = True
            continue
        counts, truncated = _scan_text(parameters)
        _add_counts(result['tool_schemas'], counts)
        result['scan_truncated'] = result['scan_truncated'] or truncated
    result['matched_rows_truncated'] = result['matched_rows_available'] > len(result['matched_rows'])
    return result


def permission_output_provenance(answer_text: Any, reasoning_text: Any = '') -> dict[str, Any]:
    """Count final/current partial backend channels without retaining their text."""
    result: dict[str, Any] = {'schema_version': SCHEMA_VERSION, **_empty_counts(),
                              'scan_truncated': False, 'channels': {}}
    for channel, text in (('answer', answer_text), ('reasoning', reasoning_text)):
        counts, truncated = _scan_text(text)
        result['channels'][channel] = counts
        _add_counts(result, counts)
        result['scan_truncated'] = result['scan_truncated'] or truncated
    return result


def _integer(value: Any) -> int | None:
    return value if type(value) is int and 0 <= value <= MAX_COUNT else None


def _validated_counts(value: Any) -> dict[str, Any]:
    raw = value if isinstance(value, dict) else {}
    safe = _empty_counts()
    safe['acknowledgements'] = _integer(raw.get('acknowledgements')) or 0
    for field, keys in (('acknowledgement_kinds', KINDS), ('metadata_key_mentions', METADATA_KEYS)):
        source = raw.get(field) if isinstance(raw.get(field), dict) else {}
        for key in keys:
            safe[field][key] = _integer(source.get(key)) or 0
    return safe


def _valid_counts(value: Any) -> bool:
    if not isinstance(value, dict) or _integer(value.get('acknowledgements')) is None:
        return False
    for field, keys in (('acknowledgement_kinds', KINDS), ('metadata_key_mentions', METADATA_KEYS)):
        source = value.get(field)
        if not isinstance(source, dict) or any(_integer(source.get(key)) is None for key in keys):
            return False
    return value['acknowledgements'] == min(MAX_COUNT, sum(value['acknowledgement_kinds'][key] for key in KINDS))


def _valid_provenance(value: Any, *, output: bool) -> bool:
    if (not isinstance(value, dict) or type(value.get('schema_version')) is not int
            or value['schema_version'] != SCHEMA_VERSION or not _valid_counts(value)
            or not isinstance(value.get('scan_truncated'), bool)):
        return False
    if output:
        channels = value.get('channels')
        return isinstance(channels, dict) and all(_valid_counts(channels.get(key)) for key in ('answer', 'reasoning'))
    if any(_integer(value.get(key)) is None for key in (
            'rows_available', 'rows_scanned', 'rows_with_acknowledgements', 'matched_rows_available')):
        return False
    if not 0 <= value['rows_with_acknowledgements'] <= value['rows_scanned'] <= value['rows_available']:
        return False
    if (not isinstance(value.get('matched_rows'), list)
            or not isinstance(value.get('matched_rows_truncated'), bool)
            or not isinstance(value.get('by_role'), dict)
            or not isinstance(value.get('by_component'), dict)
            or not isinstance(value.get('tool_schemas_scanned'), bool)
            or not _valid_counts(value.get('tool_schemas'))
            or not isinstance(value.get('system_components_attribution'), str)
            or value['system_components_attribution'] not in {'intact_snapshot_prefix', 'unavailable'}):
        return False
    for role in ROLES:
        counts = value['by_role'].get(role)
        if counts is not None and (not _valid_counts(counts) or _integer(counts.get('rows')) is None):
            return False
    for component in COMPONENTS:
        counts = value['by_component'].get(component)
        if counts is not None and not _valid_counts(counts):
            return False
    return True


def validate_permission_provenance(value: Any, *, output: bool = False) -> dict[str, Any]:
    """Project receipts through a strict fixed-label allowlist, even on export."""
    raw = value if isinstance(value, dict) else {}
    safe: dict[str, Any] = {'schema_version': SCHEMA_VERSION, **_validated_counts(raw)}
    safe['scan_truncated'] = raw.get('scan_truncated') is True
    if output:
        channels = raw.get('channels') if isinstance(raw.get('channels'), dict) else {}
        safe['channels'] = {key: _validated_counts(channels.get(key)) for key in ('answer', 'reasoning')}
        return safe
    for key in ('rows_available', 'rows_scanned', 'rows_with_acknowledgements', 'matched_rows_available'):
        safe[key] = _integer(raw.get(key)) or 0
    safe['matched_rows_truncated'] = raw.get('matched_rows_truncated') is True
    safe['tool_schemas_scanned'] = raw.get('tool_schemas_scanned') is True
    safe['tool_schemas'] = _validated_counts(raw.get('tool_schemas'))
    safe['system_components_attribution'] = ('intact_snapshot_prefix'
        if raw.get('system_components_attribution') == 'intact_snapshot_prefix' else 'unavailable')
    source = raw.get('by_role') if isinstance(raw.get('by_role'), dict) else {}
    safe['by_role'] = {key: {'rows': _integer(source[key].get('rows')) or 0, **_validated_counts(source[key])}
                       for key in sorted(ROLES) if isinstance(source.get(key), dict)}
    source = raw.get('by_component') if isinstance(raw.get('by_component'), dict) else {}
    safe['by_component'] = ({key: _validated_counts(source[key]) for key in COMPONENTS
                             if isinstance(source.get(key), dict)}
                            if safe['system_components_attribution'] == 'intact_snapshot_prefix' else {})
    safe['matched_rows'] = []
    rows = raw.get('matched_rows') if isinstance(raw.get('matched_rows'), list) else []
    for row in rows[:MAX_ROW_RECEIPTS]:
        if not isinstance(row, dict) or _integer(row.get('row_index')) is None:
            continue
        role, region = row.get('role'), row.get('region')
        if not isinstance(role, str) or role not in ROLES or not isinstance(region, str) or region not in REGIONS:
            continue
        locations = row.get('locations') if isinstance(row.get('locations'), dict) else {}
        safe['matched_rows'].append({'row_index': row['row_index'], 'role': role, 'region': region,
            **_validated_counts(row), 'locations': {key: _integer(locations.get(key)) or 0
                                                   for key in ('content', 'tool_arguments')}})
    return safe


def validate_permission_acknowledgement_event(event: Any, fields: Any) -> dict[str, Any] | None:
    if not isinstance(event, str) or event not in PERMISSION_ACKNOWLEDGEMENT_EVENTS or not isinstance(fields, dict):
        return None
    safe: dict[str, Any] = {'event': event}
    if event != 'permission_acknowledgement_trace_failed':
        if not _valid_provenance(fields.get('provenance'), output=event == 'permission_acknowledgement_output'):
            return None
        safe['provenance'] = validate_permission_provenance(
            fields.get('provenance'), output=event == 'permission_acknowledgement_output')
    # These are caller-generated routing IDs, never identifiers extracted from
    # prompt/tool contents. Invalid caller strings are dropped, not echoed.
    for key in ('workspace_id', 'chat_id', 'run_id', 'client_request_id'):
        value = fields.get(key)
        if isinstance(value, str) and re.fullmatch(r'(?:[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})', value):
            safe[key] = value
    if _integer(fields.get('step')) is not None:
        safe['step'] = fields['step']
    for key, permitted in (
        ('transport_reason', frozenset({'model_call', 'runtime_budget', 'prefill_recovery', 'backend_gpu_retry'})),
        ('request_kind', frozenset({'response', 'completion_check'})),
        ('phase', frozenset({'request', 'response', 'stalled_partial', 'completion_check'})),
        ('failure_kind', frozenset({'invalid_receipt', 'collection_failed'})),
    ):
        value = fields.get(key)
        if isinstance(value, str) and value in permitted:
            if key == 'phase' and value == 'request' and event == 'permission_acknowledgement_output':
                continue
            if key == 'failure_kind' and event != 'permission_acknowledgement_trace_failed':
                continue
            safe[key] = value
    return safe


def build_permission_acknowledgement_audit(rows: list[dict[str, Any]]) -> tuple[dict[str, Any], list[str]]:
    """Summarize retained observations, with no transcript/database access."""
    receipts: list[dict[str, Any]] = []
    input_totals = _empty_counts()
    input_roles: dict[str, Any] = {}
    input_components: dict[str, Any] = {}
    input_tool_schemas = _empty_counts()
    output_totals = {phase: _empty_counts() for phase in ('response', 'stalled_partial', 'completion_check')}
    output_channels = {channel: _empty_counts() for channel in ('answer', 'reasoning')}
    input_records = output_records = attributed_records = truncated_records = failed_records = 0
    for row in rows:
        safe = validate_permission_acknowledgement_event(row.get('event'), row)
        if safe is None:
            continue
        # _rows supplies these parser-validated observation labels. Revalidate
        # here because this function can also be used independently.
        stamp = row.get('timestamp')
        if isinstance(stamp, str) and re.fullmatch(r'\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3,6}', stamp):
            safe['timestamp'] = stamp
        if isinstance(row.get('session_scope'), str) and row['session_scope'] in {'current', 'previous'}:
            safe['session_scope'] = row['session_scope']
        receipts.append(safe)
        if safe['event'] == 'permission_acknowledgement_trace_failed':
            failed_records += 1
            continue
        provenance = safe['provenance']
        truncated_records += bool(provenance.get('scan_truncated'))
        if safe['event'] == 'permission_acknowledgement_input':
            input_records += 1
            _add_counts(input_totals, provenance)
            for role, counts in provenance['by_role'].items():
                _add_counts(input_roles.setdefault(role, _empty_counts()), counts)
            attributed_records += provenance['system_components_attribution'] == 'intact_snapshot_prefix'
            for component, counts in provenance['by_component'].items():
                _add_counts(input_components.setdefault(component, _empty_counts()), counts)
            _add_counts(input_tool_schemas, provenance['tool_schemas'])
        else:
            output_records += 1
            phase = safe.get('phase', 'response')
            _add_counts(output_totals[phase], provenance)
            # Final ordinary responses have separate totals from partial/error
            # receipts and completion-check output; do not double count them.
            if phase == 'response':
                for channel, counts in provenance['channels'].items():
                    _add_counts(output_channels[channel], counts)
    retained = receipts[-120:]
    audit: dict[str, Any] = {
        'schema_version': SCHEMA_VERSION,
        'status': 'partial' if failed_records or truncated_records else 'recorded' if receipts else 'unrecorded',
        'scope': 'bounded_current_and_previous_session_log_tails',
        'output_scope': 'completed_responses_stalled_partials_and_completion_checks',
        'count_unit': 'occurrences_per_observed_request_or_response_not_unique_transcript_text',
        'input_records': input_records, 'output_records': output_records,
        'intact_system_snapshot_records': attributed_records, 'truncated_scan_records': truncated_records,
        'failed_trace_records': failed_records,
        'input_occurrences': input_totals, 'input_by_role': input_roles,
        'input_by_component': input_components, 'output_by_phase': output_totals,
        'input_tool_schemas': input_tool_schemas,
        'response_output_by_channel': output_channels,
        'receipts_available': len(receipts), 'receipts_retained': len(retained),
        'recent_receipts': retained,
        'metadata_key_semantics': 'json_shaped_key_mentions_not_proof_of_applied_target_policy',
        'component_count_semantics': 'subset_of_system_rows_do_not_add_to_request_totals',
    }
    lines = ['Permission acknowledgement provenance: PERMISSION_ACKNOWLEDGEMENTS.json contains counts and fixed source labels without chat text.']
    if not receipts:
        lines.append('  No provenance receipts were recorded; this export cannot identify which prompt source contains repeated acknowledgement text.')
    else:
        lines.append(f'  Examined input receipts: {input_records}; output receipts: {output_records}; intact system snapshots attributed: {attributed_records}.')
        lines.append(f'  Acknowledgement occurrences across observed inputs: {input_totals["acknowledgements"]}; ordinary response outputs: {output_totals["response"]["acknowledgements"]}.')
        role_counts = {key: value['acknowledgements'] for key, value in input_roles.items() if value['acknowledgements']}
        component_counts = {key: value['acknowledgements'] for key, value in input_components.items() if value['acknowledgements']}
        if role_counts:
            lines.append('  Input roles containing acknowledgement text: ' + '; '.join(f'{key} {value}' for key, value in sorted(role_counts.items())) + '.')
        if component_counts:
            lines.append('  Intact frozen system components containing acknowledgement text: ' + '; '.join(f'{key} {value}' for key, value in sorted(component_counts.items())) + '.')
        if input_tool_schemas['acknowledgements']:
            lines.append(f'  Separate tool-schema acknowledgement occurrences: {input_tool_schemas["acknowledgements"]}.')
        metadata_counts = input_totals['metadata_key_mentions']
        if any(metadata_counts.values()):
            lines.append('  Input JSON-shaped access metadata key mentions: ' + '; '.join(f'{key} {value}' for key, value in metadata_counts.items()) + '.')
        if truncated_records:
            lines.append(f'  Scan bounds limited {truncated_records} receipts; omitted text may contain additional occurrences.')
        if failed_records:
            lines.append(f'  Provenance collection failed for {failed_records} observations; missing evidence does not establish zero occurrences.')
    lines.extend([
        '  Reused history is counted again on each request. Counts identify visible cues, not the semantic cause of a model response; request and system-component totals overlap.',
        '  Metadata mentions do not establish applied target permissions. Partial response and completion-check output counts are separate from ordinary response totals.', '',
        '  Output receipts cover completed responses, recorded stalled partials and completion checks. Interrupted ordinary streams may have no output receipt; zero observed matches does not establish absence outside retained coverage.', '',
    ])
    return audit, lines
