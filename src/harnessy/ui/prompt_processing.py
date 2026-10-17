"""Compact, content-free presentation for an individual model request."""
from __future__ import annotations

import math
from datetime import datetime
from typing import Any


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        result = float(value)
    except (ValueError, OverflowError):
        return None
    return result if math.isfinite(result) and result >= 0 else None


def _count(value: Any, estimated: Any = False) -> str:
    count = _number(value)
    return ('~' if estimated is True else '') + f'{int(count):,}' if count is not None else '—'


def _seconds(value: Any) -> str:
    seconds = _number(value)
    if seconds is None:
        return '—'
    if seconds >= 60:
        minutes, remainder = divmod(int(seconds), 60)
        return f'{minutes}m {remainder:02d}s'
    return f'{seconds:.1f}s'


def _rate(value: Any, estimated: Any = False) -> str:
    rate = _number(value)
    return ('~' if estimated is True else '') + f'{rate:,.1f} tok/s' if rate is not None else '—'


def request_duration(details: dict[str, Any], status: str, *, now: datetime | None = None) -> float | None:
    """Tick only a running request, retaining the measured terminal duration."""
    duration = _number(details.get('duration_seconds'))
    if status == 'running' and now is not None:
        try:
            started = datetime.fromisoformat(str(details.get('request_started_at') or '').replace('Z', '+00:00'))
            if started.tzinfo is not None and now.tzinfo is not None:
                duration = max(duration or 0.0, (now - started).total_seconds(), 0.0)
        except (TypeError, ValueError, OverflowError):
            pass
    return duration


def prompt_processing_text(
    activity: dict[str, Any], *, short_time: str, full_time: str,
    now: datetime | None = None,
) -> tuple[str, str]:
    """Render the same line for live output and reopened durable history.

    Prompt processing time is never inferred from first-token latency: a
    backend may spend that interval queuing, loading a model, or buffering.
    """
    details = activity.get('details') if isinstance(activity.get('details'), dict) else {}
    status = str(activity.get('status') or 'interrupted').lower()
    phase = str(details.get('phase') or 'waiting')
    if status == 'running':
        state = {'waiting': 'Waiting', 'prompt_processing': 'Prefilling', 'generating': 'Generating'}.get(phase, 'Waiting')
    else:
        state = {'success': 'Done', 'failed': 'Failed', 'cancelled': 'Cancelled', 'interrupted': 'Interrupted'}.get(status, status.replace('_', ' ').capitalize())
    title = 'Prompt processing'
    if details.get('purpose') == 'completion_check':
        title += ' (completion check)'
    input_tokens = _count(details.get('prompt_tokens'), details.get('prompt_tokens_estimated'))
    prefill_time = _seconds(details.get('prefill_seconds'))
    prefill_rate = _rate(details.get('prefill_tps'), details.get('prefill_estimated'))
    generated = _count(details.get('generated_tokens'), details.get('generated_tokens_estimated'))
    generation_rate = _rate(details.get('generation_tps'), details.get('generation_tps_estimated'))
    generation_time = _seconds(details.get('generation_seconds'))
    if generation_time != '—' and details.get('generation_seconds_estimated') is True:
        generation_time = '~' + generation_time
    duration = _seconds(request_duration(details, status, now=now))
    line = ' · '.join((
        short_time, title, state, f'Input {input_tokens} tok',
        f'PP {prefill_time} / {prefill_rate}', f'Gen {generated} tok / {generation_rate}', f'{duration} total',
    ))
    tooltip = '\n'.join((
        f'Request started: {full_time}',
        f'Model: {str(details.get("model") or "—")}',
        f'Backend: {str(details.get("backend") or "—")}',
        f'Step: {_count(details.get("step"))} · {state}',
        f'Input: {input_tokens} tokens · Processed: {_count(details.get("processed_tokens"))} · Cached: {_count(details.get("cached_tokens"))}',
        f'Prompt processing: {prefill_time} · {prefill_rate}',
        f'Time to first token: {_seconds(details.get("ttft_seconds"))}',
        f'Generated: {generated} tokens · {generation_rate} · {generation_time}',
        f'Total request time: {duration}',
        ('Waiting for backend activity; prompt processing has not been reported.' if status == 'running' and phase == 'waiting' else ''),
        ('Failure: ' + str(details['failure_kind']).replace('_', ' ') if details.get('failure_kind') else ''),
        '~ marks an estimate. — means unavailable. First-token wait is separate from prompt processing.',
    ))
    return line, '\n'.join(row for row in tooltip.splitlines() if row)


def older_activity(candidate: dict[str, Any], current: dict[str, Any]) -> bool:
    """A delayed browser snapshot must not replace a newer durable receipt."""
    candidate_revision, current_revision = candidate.get('revision'), current.get('revision')
    return (type(candidate_revision) is int and type(current_revision) is int
            and candidate_revision >= 0 and candidate_revision < current_revision)


def remember_prompt_processing_event(state: dict[str, Any], event: dict[str, Any]) -> bool:
    """Keep bounded latest snapshots for browser observers without DB rereads."""
    if event.get('activity_type') != 'prompt_processing':
        return False
    message_id = str(event.get('message_id') or '')
    activity = event.get('activity')
    if not isinstance(activity, dict):
        payload = event.get('payload')
        activity = payload.get('activity') if isinstance(payload, dict) else None
    if not message_id or not isinstance(activity, dict) or activity.get('type') != 'prompt_processing':
        return False
    rows = state.setdefault('prompt_processing_rows', {})
    if not isinstance(rows, dict):
        rows = state['prompt_processing_rows'] = {}
    previous = rows.get(message_id)
    if (isinstance(previous, dict) and isinstance(previous.get('activity'), dict)
            and older_activity(activity, previous['activity'])):
        return True
    details = activity.get('details') if isinstance(activity.get('details'), dict) else {}
    rows[message_id] = {
        'activity': {**activity, 'details': dict(details)},
        'created_at': str(event.get('created_at') or ''),
    }
    # Older history is canonical in SQLite. Only the mounted transcript window
    # can need these snapshots; retaining a whole agent run would be unbounded.
    while len(rows) > 96:
        rows.pop(next(iter(rows)))
    return True
