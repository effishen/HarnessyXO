from __future__ import annotations

from typing import Any


def _provenance_int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError, OverflowError):
        return 0


def _channel_provenance(value: Any) -> dict[str, Any]:
    row = value if isinstance(value, dict) else {}
    raw_fields = row.get('source_fields')
    if isinstance(raw_fields, dict):
        fields = [str(key) for key in raw_fields if str(key)]
        field_counts = {str(key): _provenance_int(count) for key, count in raw_fields.items() if str(key)}
    else:
        fields = [str(item) for item in (raw_fields or []) if str(item)] if isinstance(raw_fields, list) else []
        field_counts = {}
    raw_events = row.get('source_events')
    if isinstance(raw_events, dict):
        events = [str(key) for key in raw_events if str(key)]
        event_counts = {str(key): _provenance_int(count) for key, count in raw_events.items() if str(key)}
    else:
        events = [str(item) for item in (raw_events or []) if str(item)] if isinstance(raw_events, list) else []
        event_counts = {}
    return {
        'source_fields': list(dict.fromkeys(fields)),
        'source_field_counts': field_counts,
        'source_events': list(dict.fromkeys(events)),
        'source_event_counts': event_counts,
        'source_chunks': _provenance_int(row.get('source_chunks') or row.get('chunks')),
        'source_chars': _provenance_int(row.get('source_chars') or row.get('chars')),
        'mixed_text_events': _provenance_int(row.get('mixed_text_events')),
    }


def _merge_channel_provenance(target: dict[str, Any], source: dict[str, Any]) -> None:
    for key in ('source_fields', 'source_events'):
        target[key] = list(dict.fromkeys([*target.get(key, []), *source.get(key, [])]))
    for key in ('source_field_counts', 'source_event_counts'):
        counts = target.setdefault(key, {})
        for name, count in source.get(key, {}).items():
            counts[name] = _provenance_int(counts.get(name)) + _provenance_int(count)
    for key in ('source_chunks', 'source_chars', 'mixed_text_events'):
        target[key] = _provenance_int(target.get(key)) + _provenance_int(source.get(key))


def assistant_stream_groups(
    metadata: dict[str, Any], content: str, reasoning: str, created_at: str,
) -> list[dict[str, Any]]:
    """Group persisted reasoning/answer segments into chronological visual pairs.

    A Thinking card followed by a HarnessyXO card can share one UI pair. Once an
    answer has appeared, a later reasoning segment must begin a new pair so the
    transcript remains reasoning → answer → reasoning → answer after reload.
    """
    raw = metadata.get('stream_segments')
    segments = raw if isinstance(raw, list) else []
    output_provenance = metadata.get('output_provenance')
    output_provenance = output_provenance if isinstance(output_provenance, dict) else {}
    has_provenance = bool(output_provenance)
    valid: list[dict[str, Any]] = []
    for row in segments:
        if not isinstance(row, dict):
            continue
        kind = str(row.get('kind') or '').strip().lower()
        text = str(row.get('content') or '')
        if kind not in {'reasoning', 'answer'} or not text.strip():
            continue
        segment = {
            'kind': kind,
            'content': text,
            'started_at': str(row.get('started_at') or created_at),
            **({k: row.get(k) for k in ('duration_seconds', 'timing_source', 'timing_complete')} if 'timing_source' in row else {}),
        }
        if any(key in row for key in ('source_fields', 'source_events', 'source_chunks', 'source_chars')):
            segment['channel_provenance'] = _channel_provenance(row)
            has_provenance = True
        valid.append(segment)
    if not valid:
        group = {
            'reasoning': reasoning,
            'answer': content,
            'created_at': created_at,
            'reasoning_started_at': str(metadata.get('reasoning_started_at') or created_at),
            'answer_started_at': str(metadata.get('answer_started_at') or created_at),
        }
        if has_provenance:
            group['reasoning_provenance'] = _channel_provenance(output_provenance.get('reasoning'))
            group['answer_provenance'] = _channel_provenance(output_provenance.get('answer'))
            group['output_provenance'] = output_provenance
        return [group]

    groups: list[dict[str, Any]] = []
    group = {
        'reasoning': '', 'answer': '', 'created_at': valid[0]['started_at'],
        'reasoning_started_at': '', 'answer_started_at': '',
    }
    if has_provenance:
        group.update({
            'reasoning_provenance': _channel_provenance({}),
            'answer_provenance': _channel_provenance({}),
            'output_provenance': output_provenance,
        })
    for segment in valid:
        kind = segment['kind']
        if kind == 'reasoning' and group['answer']:
            groups.append(group)
            group = {
                'reasoning': '', 'answer': '', 'created_at': segment['started_at'],
                'reasoning_started_at': '', 'answer_started_at': '',
            }
            if has_provenance:
                group.update({
                    'reasoning_provenance': _channel_provenance({}),
                    'answer_provenance': _channel_provenance({}),
                    'output_provenance': output_provenance,
                })
        if 'timing_source' in segment:
            metric_key = f'{kind}_duration_seconds'
            previous = group.get(metric_key, 0.0)
            duration = segment.get('duration_seconds')
            group[metric_key] = (float(previous) + float(duration)
                                 if previous is not None and duration is not None else None)
            group[f'{kind}_timing_complete'] = (group.get(f'{kind}_timing_complete', True)
                                               and bool(segment.get('timing_complete')))
            group['timing_source'] = 'stream_observed'
        if kind == 'reasoning':
            if not group['reasoning_started_at']:
                group['reasoning_started_at'] = segment['started_at']
            group['reasoning'] += segment['content']
        else:
            if not group['answer_started_at']:
                group['answer_started_at'] = segment['started_at']
            group['answer'] += segment['content']
        if has_provenance and isinstance(segment.get('channel_provenance'), dict):
            _merge_channel_provenance(group[f'{kind}_provenance'], segment['channel_provenance'])
    if group['reasoning'] or group['answer']:
        groups.append(group)
    return groups


def reconcile_transcript_window(
    previous: dict[str, int | bool] | None,
    total: int,
    *,
    tail_messages: int,
    max_messages: int,
    reset: bool = False,
) -> dict[str, int | bool]:
    """Resolve a bounded durable-history window after append/delete changes."""
    total = max(0, int(total))
    tail_messages = max(1, int(tail_messages))
    max_messages = max(tail_messages, int(max_messages))
    if reset or previous is None:
        end = total
        start = max(0, end - tail_messages)
        return {'start': start, 'end': end, 'total': total, 'tail': True}

    old_total = max(0, int(previous.get('total') or 0))
    start = max(0, int(previous.get('start') or 0))
    end = max(start, int(previous.get('end') or 0))
    was_tail = bool(previous.get('tail')) or end >= old_total
    if was_tail:
        size = max(tail_messages, min(max_messages, end - start))
        end = total
        start = max(0, end - size)
    else:
        end = min(end, total)
        start = min(start, end)
        if end - start > max_messages:
            start = max(0, end - max_messages)
    return {'start': start, 'end': end, 'total': total, 'tail': end >= total}


def shift_transcript_window(
    state: dict[str, int | bool],
    direction: str,
    *,
    page_messages: int,
    max_messages: int,
    tail_messages: int,
) -> dict[str, int | bool]:
    """Shift an overlapping bounded window older/newer or jump to the tail."""
    total = max(0, int(state.get('total') or 0))
    start = max(0, int(state.get('start') or 0))
    end = max(start, int(state.get('end') or 0))
    page_messages = max(1, int(page_messages))
    max_messages = max(1, int(max_messages))
    tail_messages = max(1, min(max_messages, int(tail_messages)))
    if direction == 'older' and start > 0:
        start = max(0, start - page_messages)
        end = min(total, start + max_messages)
    elif direction == 'newer' and end < total:
        end = min(total, end + page_messages)
        start = max(0, end - max_messages)
    elif direction == 'earliest':
        start = 0
        end = min(total, max_messages)
    elif direction == 'latest':
        end = total
        start = max(0, end - tail_messages)
    return {'start': start, 'end': end, 'total': total, 'tail': end >= total}


def locate_transcript_window(
    total: int,
    offset: int,
    *,
    page_messages: int,
    max_messages: int,
) -> dict[str, int | bool]:
    """Return a bounded window containing a requested visible-row offset."""
    total = max(0, int(total))
    max_messages = max(1, int(max_messages))
    page_messages = max(0, min(max_messages - 1, int(page_messages)))
    offset = max(0, min(max(0, total - 1), int(offset))) if total else 0
    start = max(0, offset - page_messages)
    end = min(total, start + max_messages)
    if end >= total:
        start = max(0, end - max_messages)
    return {'start': start, 'end': end, 'total': total, 'tail': end >= total}
