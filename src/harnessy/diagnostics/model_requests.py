"""Content-free, bounded evidence for model transports and native counters.

Stream fragments are never tokens. Reachability is never inference progress.
Old logs without invocation IDs are retained as explicitly labelled candidates.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
import math
import re
from typing import Any

MAX_REQUESTS = 24
MAX_PROTOCOL_ROWS = 2500
MAX_STREAM_BYTES = 2 * 1024 * 1024
MAX_COUNTER = 2**53 - 1
SOURCE_ENUMS = {
    'timing_source': frozenset({'stream_observed', 'unavailable'}),
    'throughput_source': frozenset({'llama.cpp timings', 'oMLX usage metadata',
        'oMLX timing counters', 'Ollama timing counters', 'backend timing counters',
        'stream observed fallback', 'unavailable'}),
    'prefill_throughput_source': frozenset({'llama.cpp timings', 'oMLX usage metadata',
        'oMLX timing counters', 'Ollama timing counters', 'backend timing counters',
        'TTFT fallback', 'unavailable'}),
    'tps_source': frozenset({'', 'llama.cpp_stream', 'omlx_usage', 'omlx_activity',
        'ollama_log', 'ambiguous_concurrent_requests', 'unavailable'}),
}
_NUMERIC_FIELDS = {
    'usage': frozenset({'prompt_tokens', 'completion_tokens', 'total_tokens', 'cached_tokens',
        'generation_tokens_per_second', 'prompt_tokens_per_second', 'generation_duration',
        'prompt_eval_duration', 'time_to_first_token', 'total_time'}),
    'timings': frozenset({'cache_n', 'prompt_n', 'prompt_ms', 'prompt_per_token_ms',
        'prompt_per_second', 'predicted_n', 'predicted_ms', 'predicted_per_token_ms',
        'predicted_per_second', 'draft_n', 'draft_n_accepted'}),
    'prompt_progress': frozenset({'total', 'cache', 'processed', 'time_ms'}),
}
COUNTERS = frozenset({'protocol_chunks', 'timings_samples', 'usage_samples',
    'prompt_progress_samples', 'transport_lines', 'heartbeat_lines', 'malformed_json_chunks',
    'reasoning_chunks', 'content_chunks', 'tool_call_chunks', 'transport_events', 'malformed_json_events'})
OBSERVATION_TIMES = frozenset({'elapsed_seconds', 'accepted_seconds',
    'first_payload_seconds', 'first_output_seconds', 'last_payload_seconds', 'last_output_seconds'})
MODEL_EVENTS = frozenset({'request_start', 'request_complete', 'request_http_error',
    'request_error', 'stream_health_checked', 'stream_observation', 'model_request',
    'model_step_complete', 'model_stream_stalled'})


def finite_number(value: Any) -> int | float | None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    if not 0 <= value <= MAX_COUNTER or not math.isfinite(value):
        return None
    return value


def identifier(value: Any) -> str | None:
    if isinstance(value, str) and re.fullmatch(r'(?:[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})', value):
        return value
    return None


def timestamp(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value)
        return parsed.isoformat(timespec='milliseconds') if parsed.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


def source_label(value: Any, key: str) -> str | None:
    allowed = SOURCE_ENUMS[key]
    if isinstance(value, str) and value in allowed:
        return value
    # Earlier privacy exports hashed these fixed application labels. Recover
    # only an exact known enum digest; arbitrary redacted prose stays absent.
    if isinstance(value, str):
        match = re.fullmatch(r'<redacted ' + re.escape(key) + r'; chars=(\d{1,4}); sha256_12=([0-9a-f]{12})>', value)
        if match:
            for item in allowed:
                if len(item) == int(match[1]) and hashlib.sha256(item.encode()).hexdigest()[:12] == match[2]:
                    return item
    return None


def numeric_projection(value: Any, *, kind: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    allowed = _NUMERIC_FIELDS.get(kind, frozenset())
    safe = {key: number for key in allowed
            if (number := finite_number(value.get(key))) is not None}
    if kind == 'usage':
        for key, fields in {
            'prompt_tokens_details': ('cached_tokens', 'audio_tokens'),
            'completion_tokens_details': ('reasoning_tokens', 'audio_tokens',
                                          'accepted_prediction_tokens', 'rejected_prediction_tokens'),
        }.items():
            raw = value.get(key)
            if isinstance(raw, dict):
                detail = {field: number for field in fields
                          if (number := finite_number(raw.get(field))) is not None}
                if detail:
                    safe[key] = detail
    return safe


def validate_protocol_receipt(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict) or value.get('kind') != 'model_protocol_receipt':
        return None
    safe: dict[str, Any] = {'kind': 'model_protocol_receipt'}
    for key in ('client_request_id', 'workspace_id', 'chat_id', 'run_id'):
        if (item := identifier(value.get(key))) is not None:
            safe[key] = item
    if (stamp := timestamp(value.get('timestamp'))) is not None:
        safe['timestamp'] = stamp
    for key in COUNTERS | {'step', 'elapsed_seconds', 'first_output_seconds',
                           'last_transport_seconds', 'last_output_seconds'}:
        if (number := finite_number(value.get(key))) is not None:
            safe[key] = number
    for key in ('timings_present', 'usage_present', 'prompt_progress_present', 'prompt_progress_valid'):
        if type(value.get(key)) is bool:
            safe[key] = value[key]
    for key in ('usage', 'timings', 'prompt_progress'):
        if isinstance(value.get(key), dict):
            safe[key] = numeric_projection(value[key], kind=key)
    for key in SOURCE_ENUMS:
        if (label := source_label(value.get(key), key)) is not None:
            safe[key] = label
    return safe


def provenance_projection(value: Any) -> dict[str, Any]:
    """Preserve reviewed output-routing counts, never generated text."""
    if not isinstance(value, dict):
        return {}
    safe: dict[str, Any] = {'records_generated_text': False}
    for key in ('version', 'transition_count', 'mixed_text_events', 'multiple_reasoning_field_events'):
        if (number := finite_number(value.get(key))) is not None:
            safe[key] = number
    for key in ('answer_was_reclassified', 'reasoning_after_answer', 'answer_replays_reasoning'):
        if type(value.get(key)) is bool:
            safe[key] = value[key]
    for key, allowed in {
        'classification': {'answer_replays_reasoning', 'answer_contains_reasoning_markers',
            'interleaved_channels', 'separate_backend_channels', 'answer_channel_only',
            'reasoning_channel_only', 'no_text'},
        'confidence': {'direct', 'limited', 'warning'},
    }.items():
        if isinstance(value.get(key), str) and value[key] in allowed:
            safe[key] = value[key]
    sequence = value.get('channel_sequence')
    if isinstance(sequence, list):
        safe['channel_sequence'] = [item for item in sequence[:64]
                                    if isinstance(item, str) and item in {'reasoning', 'answer'}]
    fields = {f'{container}.{field}' for container in ('delta', 'message')
              for field in ('content', 'thinking', 'reasoning', 'reasoning_content')}
    for channel in ('reasoning', 'answer'):
        raw = value.get(channel)
        if not isinstance(raw, dict):
            continue
        result = {key: number for key in ('chars', 'chunks')
                  if (number := finite_number(raw.get(key))) is not None}
        for key, allowed in (('source_fields', fields), ('source_events', {'delta', 'message'})):
            counts = raw.get(key)
            if isinstance(counts, dict):
                result[key] = {field: number for field in allowed
                    if (number := finite_number(counts.get(field))) is not None}
        safe[channel] = result
    return safe


def _stamp(value: Any) -> datetime | None:
    try:
        if isinstance(value, str) and re.fullmatch(r'\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3,6}', value):
            return datetime.strptime(value, '%Y-%m-%d %H:%M:%S,%f')
        stamp = timestamp(value)
        return datetime.fromisoformat(stamp).replace(tzinfo=None) if stamp else None
    except (ValueError, TypeError, OverflowError):
        return None


def _delta(left: Any, right: Any) -> float | None:
    a, b = _stamp(left), _stamp(right)
    return round((a - b).total_seconds(), 3) if a is not None and b is not None and a >= b else None


def _backend(row: dict[str, Any]) -> str:
    request = row.get('request') if isinstance(row.get('request'), dict) else {}
    raw = str(request.get('backend') or row.get('backend') or row.get('provider') or '').lower()
    return {'llamacpp': 'llama.cpp', 'llama.cpp': 'llama.cpp', 'omlx': 'oMLX',
            'ollama': 'Ollama', 'openai': 'OpenAI-compatible'}.get(raw, 'unrecorded')


def _request_id(row: dict[str, Any]) -> str | None:
    request = row.get('request') if isinstance(row.get('request'), dict) else {}
    performance = row.get('performance') if isinstance(row.get('performance'), dict) else {}
    value = (identifier(row.get('client_request_id')) or identifier(request.get('client_request_id'))
             or identifier(performance.get('client_request_id')))
    return value.replace('-', '') if value else None


def _metric(row: dict[str, Any]) -> dict[str, Any]:
    raw = row.get('performance') if isinstance(row.get('performance'), dict) else {}
    safe = {key: value for key in ('prompt_tokens', 'completion_tokens', 'total_tokens', 'cached_tokens',
        'duration_seconds', 'ttft_seconds', 'tps', 'prefill_tps', 'reasoning_duration_seconds',
        'answer_duration_seconds', 'tool_call_generation_seconds')
        if (value := finite_number(raw.get(key))) is not None}
    for key in SOURCE_ENUMS:
        if (label := source_label(raw.get(key), key)) is not None:
            safe[key] = label
    safe['usage_estimated'] = raw.get('usage_estimated') if type(raw.get('usage_estimated')) is bool else None
    safe['timestamp'] = row['timestamp']
    safe['session_scope'] = row.get('session_scope', 'current')
    for key in ('workspace_id', 'chat_id', 'run_id'):
        if (item := identifier(row.get(key))) is not None:
            safe[key] = item
    if type(row.get('step')) is int and 0 <= row['step'] <= 1000000:
        safe['step'] = row['step']
    if (identity := _request_id(row)) is not None:
        safe['client_request_id'] = identity
    return safe


def build_model_audit(rows: list[dict[str, Any]], coverage: list[dict[str, Any]],
                      latest, captured_at: str | None) -> tuple[dict[str, Any], list[str]]:
    """Build observations only; an unmatched start is not proof of a hang."""
    from .logging import _read_snapshot_bytes

    candidates = [row for row in rows if row.get('event') in MODEL_EVENTS]
    starts = [row for row in candidates if row.get('event') == 'request_start']
    metrics = [row for row in candidates if row.get('event') == 'model_step_complete'
               and isinstance(row.get('performance'), dict)]
    stream = latest / 'backend-stream-tail.log'
    payload = _read_snapshot_bytes(stream, tail_bytes=MAX_STREAM_BYTES)
    try:
        stream_limited = stream.stat().st_size > MAX_STREAM_BYTES
    except OSError:
        stream_limited = False
    lines = payload.decode('utf-8', errors='replace').splitlines() if payload else []
    protocol: list[dict[str, Any]] = []
    malformed = 0
    for line in lines[-MAX_PROTOCOL_ROWS:]:
        try:
            value = json.loads(line)
        except (ValueError, RecursionError):
            malformed += 1
            continue
        if isinstance(value, dict):
            protocol.append(value)
    stream_limited |= len(lines) > MAX_PROTOCOL_ROWS
    # Once unlabelled starts overlap, their completions cannot identify which
    # call ended. Never give the nearest later start another call's counters.
    ambiguous_legacy: set[int] = set()
    active_legacy: dict[str, list[dict[str, Any]]] = {}
    for row in candidates:
        if _request_id(row):
            continue
        scope = row.get('session_scope', 'current')
        active = active_legacy.setdefault(scope, [])
        if row.get('event') == 'request_start':
            active.append(row)
            if len(active) > 1:
                ambiguous_legacy.update(id(item) for item in active)
        elif row.get('event') in {'request_complete', 'request_error', 'request_http_error'} and active:
            active.pop(0)
    requests: list[dict[str, Any]] = []
    for start in starts[-MAX_REQUESTS:]:
        scope, identity = start.get('session_scope', 'current'), _request_id(start)
        scope_rows = [row for row in candidates if row.get('session_scope', 'current') == scope]
        if identity:
            related = [row for row in scope_rows if _request_id(row) == identity]
            confidence = 'request_uuid'
        else:
            # A unique, non-overlapping legacy interval can be a candidate,
            # never an exact identity join. Keep metrics separately as well.
            next_start = next((row for row in starts if row.get('session_scope', 'current') == scope
                               and row['timestamp'] > start['timestamp']), None)
            stop_at = next_start['timestamp'] if next_start else None
            overlapping = id(start) in ambiguous_legacy
            related = [] if overlapping else [row for row in scope_rows
                if row['timestamp'] >= start['timestamp']
                and (stop_at is None or row['timestamp'] < stop_at)
                and not _request_id(row)]
            confidence = 'unassociated' if overlapping else 'timestamp_candidate'
        ends = [row for row in related if row.get('event') == 'request_complete']
        errors = [row for row in related if row.get('event') in
                  {'request_http_error', 'request_error', 'model_stream_stalled'}]
        status = 'completion_observed' if ends else 'error_observed' if errors else 'no_completion_observed'
        end_stamp = ends[-1]['timestamp'] if ends else errors[-1]['timestamp'] if errors else None
        item: dict[str, Any] = {
            'started_at': start['timestamp'], 'session_scope': scope,
            'client_request_id': identity, 'association': confidence,
            'backend': _backend(start), 'status': status,
            'finished_at': end_stamp,
            'observed_duration_seconds': _delta(end_stamp, start['timestamp']) if end_stamp else None,
            'wait_at_capture_seconds': _delta(captured_at, start['timestamp'])
                if scope == 'current' and not end_stamp else None,
        }
        request = start.get('request') if isinstance(start.get('request'), dict) else {}
        for key in ('workspace_id', 'chat_id', 'run_id'):
            if (ident := identifier(start.get(key)) or identifier(request.get(key))) is not None:
                item[key] = ident
        for key in ('step', 'request_sequence'):
            if (value := finite_number(start.get(key, request.get(key)))) is not None:
                item[key] = value
        observations = [row for row in related if row.get('event') == 'stream_observation']
        complete = observations[-1] if observations else ends[-1] if ends else {}
        item['transport_counters'] = {key: value for key in COUNTERS
            if (value := finite_number(complete.get(key))) is not None}
        item['transport_counter_source'] = ('stream_observation' if observations else
                                            'request_complete' if ends else 'unrecorded')
        item['stream_observation_times'] = {key: value for key in OBSERVATION_TIMES
            if (value := finite_number(complete.get(key))) is not None}
        if 'first_output_seconds' in complete:
            item['semantic_output_observed'] = finite_number(complete['first_output_seconds']) is not None
        if observations and observations[-1].get('observation') == 'transport_closed' and not end_stamp:
            item['status'] = 'transport_closed_without_completion'
        health = [row for row in related if row.get('event') == 'stream_health_checked']
        if health:
            last = health[-1]
            item['last_health'] = {'timestamp': last['timestamp'],
                'request_state': last.get('watchdog_request_state') if last.get('watchdog_request_state') in {'active', 'gone', 'unknown'} else 'unknown',
                'request_scoped': last.get('request_scoped') is True,
                'backend_reachable': last.get('backend_reachable') if type(last.get('backend_reachable')) is bool else None,
                'generated_output_seen': last.get('generated_output_seen') if type(last.get('generated_output_seen')) is bool else None,
            }
            for key in ('silence_seconds', 'transport_silence_seconds'):
                if (value := finite_number(last.get(key))) is not None:
                    item['last_health'][key] = value
        associated_metrics = [row for row in related if row in metrics]
        if associated_metrics:
            item['completed_metric'] = _metric(associated_metrics[-1])
        if identity and scope == 'current':
            samples = [row for row in protocol if _request_id(row) == identity]
            item['retained_protocol_records'] = len(samples)
            item['retained_timing_samples'] = sum(row.get('timings_present') is True or bool(numeric_projection(row.get('timings'), kind='timings')) for row in samples)
            item['retained_usage_samples'] = sum(row.get('usage_present') is True or bool(numeric_projection(row.get('usage'), kind='usage')) for row in samples)
            item['retained_prompt_progress_samples'] = sum(row.get('prompt_progress_valid') is True for row in samples)
            item['protocol_counts_are_retained_records'] = True
            native: dict[str, Any] = {}
            native_stamps: dict[str, Any] = {}
            for key in ('timings', 'usage', 'prompt_progress'):
                category = [(row, projected) for row in samples
                    if (projected := numeric_projection(row.get(key), kind=key))]
                if category:
                    native[key] = category[-1][1]
                    native_stamps[key] = timestamp(category[-1][0].get('timestamp'))
            if native:
                item['last_retained_native_counters'] = native
                item['native_counter_sample_timestamps'] = native_stamps
        requests.append(item)
    current = [item for item in requests if item['session_scope'] == 'current']
    current_starts = [row for row in starts if row.get('session_scope') == 'current']
    current_metrics = [_metric(row) for row in metrics if row.get('session_scope') == 'current']
    safe_coverage = [{key: row[key] for key in ('channel', 'session_scope', 'first_timestamp',
        'last_timestamp', 'records_examined', 'log_tail_limited') if key in row}
        for row in coverage if row.get('channel') in {'backend', 'runtime'}]
    audit = {'schema_version': 1, 'status': 'observed' if candidates else 'unrecorded',
        'scope': 'bounded_current_and_previous_session_log_tails',
        'counts_are_retained_records': True, 'requests_retained': len(requests),
        'request_limit': MAX_REQUESTS, 'request_limit_reached': len(starts) > MAX_REQUESTS,
        'current_request_starts_observed': len(current_starts),
        'current_request_completions_observed': sum(row.get('event') == 'request_complete'
            and row.get('session_scope') == 'current' for row in candidates),
        'current_requests_without_completion_observed': sum(item['status'] in
            {'no_completion_observed', 'transport_closed_without_completion'} for item in current),
        'unmatched_start_count_scope': 'retained_request_details',
        'requests': requests, 'completed_metrics': [_metric(row) for row in metrics[-8:]],
        'coverage': safe_coverage,
        'common_index_row_bound_reached': len(rows) >= 20000,
        'protocol_coverage': {'source_present': payload is not None,
            'bytes_examined': len(payload or b''), 'records_examined': len(protocol),
            'malformed_records': malformed, 'tail_limited': stream_limited,
            'records_without_request_identity': sum(_request_id(row) is None for row in protocol),
            'records_without_timestamp': sum(timestamp(row.get('timestamp')) is None for row in protocol)},
        'unmatched_start_is_not_proof_of_backend_hang': True,
    }
    summary = ['Model requests: MODEL_REQUESTS.json distinguishes completed generation metrics from the current wait.']
    if current_starts:
        summary.append(f'  Current session retained receipts: {len(current_starts)} request starts; '
            f'{audit["current_request_completions_observed"]} request completions; '
            f'{audit["current_requests_without_completion_observed"]} starts without a recorded completion.')
    else:
        summary.append('  No model request starts were recorded in the examined current-session logs.')
    if current_metrics:
        metric = current_metrics[-1]
        measured = 'backend-measured' if metric.get('usage_estimated') is False else 'estimated or unverified'
        duration = f'{metric["duration_seconds"]:.3f}' if 'duration_seconds' in metric else 'unrecorded'
        first = f'{metric["ttft_seconds"]:.3f}' if 'ttft_seconds' in metric else 'unrecorded'
        summary.append(f'  Last completed model call: {duration}s total; '
            f'{first}s to first output; '
            f'prompt {metric.get("prompt_tokens", "unrecorded")}, output {metric.get("completion_tokens", "unrecorded")} tokens ({measured}).')
        rate = metric.get('tps')
        if rate is not None:
            summary.append(f'  Last completed decode speed: {rate:.2f} tok/s; source {metric.get("throughput_source", "unrecorded")}. This is not the current request\'s live speed.')
    for item in [item for item in current if item['status'] == 'no_completion_observed'][-3:]:
        wait = item['wait_at_capture_seconds']
        summary.append(f'  Request started {item["started_at"]}: no completion recorded'
            + (f' after {wait:g}s at capture' if wait is not None else '')
            + f'; association {item["association"]}.')
        health = item.get('last_health')
        if health:
            summary.append(f'    Last health observation: backend reachable {health["backend_reachable"]}; '
                f'request state {health["request_state"]}; request-scoped {health["request_scoped"]}; '
                f'generated output seen {health["generated_output_seen"]}. Reachability does not establish inference progress.')
        counters = item['transport_counters']
        if counters:
            summary.append('    Received counters: '
                + '; '.join(f'{key} {counters[key]}' for key in
                    ('protocol_chunks', 'timings_samples', 'prompt_progress_samples', 'usage_samples') if key in counters)
                + '. These count protocol samples, not generated tokens.')
        if item.get('semantic_output_observed') is False:
            summary.append('    No semantic output had arrived at the last recorded transport observation; this is separate from connection and heartbeat activity.')
    if any(item['association'] != 'request_uuid' for item in requests):
        summary.append('  Legacy receipts lack invocation IDs; timestamp candidate associations are not exact request attribution, especially with overlapping calls.')
    bounded_sources = sum(row.get('log_tail_limited') is True for row in safe_coverage)
    summary.append(f'  Coverage: {len(requests)} request details retained (limit {MAX_REQUESTS}); '
        f'{bounded_sources} model log sources have truncated tails; '
        f'protocol tail limited {stream_limited}, malformed records {malformed}.')
    if audit['request_limit_reached'] or audit['common_index_row_bound_reached']:
        summary.append('  A request or shared-row bound was reached; counts and unmatched-start details may exclude older evidence.')
    summary.extend(['  Counts cover retained log tails; missing completion or counter receipts do not establish a hung server or zero generated tokens.',
        '  Transport activity measures decoded stream/queue events, not last network byte; text fragments and character counts are not token counts.', ''])
    return audit, summary
