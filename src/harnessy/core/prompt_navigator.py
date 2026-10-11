"""Small, deterministic navigator summaries from Harnessy-owned metadata.

Model prose and tool payload text deliberately never participate. The database
projects only scalar fields, so indexing a long chat does not read large tool
results, reasoning, arguments, or attachment content into Python.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable, Mapping


INDICATOR_LABELS = {
    'error': 'Error / denied tool',
    'context': 'Context resized / compacted',
    'attention': 'Needs attention',
    'stopped': 'Stopped by you',
    'recovery': 'Backend recovery',
}
_ERROR_STOPS = frozenset({
    'backend_failure', 'runner_failure', 'backend_stream_incomplete',
    'backend_finish_reason', 'backend_stream_stalled',
    'workspace_infrastructure_failure',
    'environment_failure', 'tool_protocol_failure', 'missing_final_answer',
})
_ATTENTION_STOPS = frozenset({'max_steps', 'completion_unconfirmed', 'runner_stop'})


def navigator_event_types(source: Mapping[str, Any]) -> list[str]:
    """Classify one exact stored occurrence using Harnessy-owned scalars."""
    row = dict(source)
    role = str(row.get('role') or '')
    if role not in {'assistant', 'tool', 'activity'}:
        return []
    flags: set[str] = set()
    if role == 'assistant' and row.get('assistant_error') == 1:
        flags.add('error')
    if role == 'assistant' and row.get('completion_check_question') == 1:
        flags.add('attention')
    stop = str(row.get('terminal_stop_reason') or '')
    if stop in _ERROR_STOPS:
        flags.add('error')
    elif stop in _ATTENTION_STOPS:
        flags.add('attention')
    elif stop == 'user_cancelled':
        flags.add('stopped')
    if role == 'tool' and (row.get('tool_ok') == 0 or str(row.get('execution_status') or '')
                           in {'failed', 'error', 'denied', 'blocked'}):
        flags.add('error')
    if role == 'activity':
        kind = str(row.get('activity_type') or '')
        status = str(row.get('activity_status') or '')
        if status in {'failed', 'error'}:
            flags.add('error')
        if kind in {'context_compaction', 'live_context_update'}:
            flags.add('context')
        if kind == 'backend_recovery':
            flags.add('recovery')
        if kind == 'run_blocked' or (kind == 'completion_check' and status in {'failed', 'unconfirmed'}):
            flags.add('attention')
    return [kind for kind in INDICATOR_LABELS if kind in flags]


def navigator_prompt_owners(rows: Iterable[Mapping[str, Any]]) -> dict[str, str]:
    """Resolve run ownership independently of an event's chronological place."""
    owners: dict[str, str] = {}
    by_run: dict[str, str] = {}
    latest = ''
    for source in rows:
        row = dict(source)
        role = str(row.get('role') or '')
        run_id = str(row.get('run_id') or '')
        message_id = str(row.get('id') or '')
        if role == 'user':
            latest = message_id
            owners[message_id] = message_id
            if run_id and not row.get('invalid_run_id'):
                by_run[run_id] = latest
        elif not row.get('invalid_run_id'):
            owner = by_run.get(run_id, '') if run_id else latest
            if owner:
                owners[message_id] = owner
    return owners


def timeline_event_navigator_entry(row: Mapping[str, Any], *, prompt_id: str = '') -> dict[str, Any] | None:
    """Keep each selected occurrence reachable at its own bubble, not its prompt."""
    row = dict(row)
    event_types = navigator_event_types(row)
    if row.get('role') == 'activity' and row.get('activity_type') == 'completion_check':
        entry = completion_check_navigator_entry(row)
        entry.update(event_types=['completion_check', *event_types], prompt_id=prompt_id,
                     event_title=entry['preview'], target_kind='bubble',
                     event_updated_at=str(row.get('event_updated_at') or ''),
                     event_revision=int(row.get('event_revision') or 0))
        return entry
    if not event_types:
        return None
    message_id = str(row['id'])
    kind = {'activity': 'event', 'tool': 'tool', 'assistant': 'assistant'}[str(row['role'])]
    title = str(row.get('activity_title') or '') if kind == 'event' else ''
    status = str(row.get('activity_status') or row.get('execution_status') or '')
    tool_name = str(row.get('tool_name') or '').strip() if kind == 'tool' else ''
    if tool_name:
        tool_status = {'denied': 'Denied', 'blocked': 'Blocked', 'error': 'Error'}.get(status, 'Failed')
        title = f'{tool_name} · {tool_status}'
    if not title:
        title = ' / '.join(INDICATOR_LABELS[event_type] for event_type in event_types)
    return {
        'id': f'{message_id}--bubble-{kind}',
        'message_id': message_id, 'prompt_id': prompt_id,
        'kind': kind, 'bookmark_kind': kind, 'is_prompt': False, 'bookmarked': False,
        'created_at': str(row.get('created_at') or ''),
        'preview': title + (f' · {status.replace("_", " ").capitalize()}' if status and not tool_name else ''),
        'event_title': title, 'event_types': event_types, 'activity_status': status,
        'event_updated_at': str(row.get('event_updated_at') or ''),
        'event_revision': int(row.get('event_revision') or 0),
        # Reasoning-only or segmented Assistant messages may not expose a
        # visible first answer bubble. The UI may use this explicit permission
        # to target that exact message wrapper; other bubble kinds stay strict.
        'target_kind': 'message' if kind == 'assistant' else 'bubble',
        'indicators': [],
    }


def completion_check_navigator_entry(
    row: Mapping[str, Any], *, bookmarked: bool = False,
) -> dict[str, Any]:
    """Link directly to a check card using only bounded Harnessy metadata.

    A successful check can ask for more work; it does not by itself mean the
    task completed. Keep the check's state and verdict separate in its label.
    """
    status = str(row.get('activity_status') or '')
    decision = str(row.get('completion_decision') or '')
    label = {
        'running': 'Checking',
        'success': {
            'COMPLETE': 'Completion confirmed',
            'CONTINUE': 'More work requested',
            'NEEDS_INPUT': 'User input requested',
        }.get(decision, 'Checked'),
        'failed': 'Check failed',
        'error': 'Check failed',
        'unconfirmed': 'Completion unconfirmed',
        'cancelled': 'Check stopped',
    }.get(status, 'Status unavailable')
    if row.get('completion_superseded') == 1:
        label = 'Superseded by new input'
    message_id = str(row['id'])
    return {
        'id': f'{message_id}--bubble-event',
        'message_id': message_id,
        'kind': 'completion_check',
        'bookmark_kind': 'event',
        'is_prompt': False,
        'bookmarked': bookmarked,
        'created_at': str(row.get('created_at') or ''),
        'preview': f'Completion Check · {label}',
        'activity_status': status,
        'completion_decision': decision,
        'indicators': [],
    }


def prompt_indicator_index(rows: Iterable[Mapping[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Associate each event with its actual run's preceding User prompt.

    Legacy rows without a run ID use their chronological prompt. A nonempty,
    unknown run ID never contaminates a neighbouring prompt. Counts describe
    history, not an assertion that the last run is currently failing.
    """
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    rows = list(rows)
    owners = navigator_prompt_owners(rows)
    for source in rows:
        row = dict(source)
        owner = owners.get(str(row.get('id') or ''), '')
        if not owner:
            continue
        for flag in navigator_event_types(row):
            counts[owner][flag] += 1
    return {
        owner: [
            {'kind': kind, 'count': values[kind], 'label': label}
            for kind, label in INDICATOR_LABELS.items() if values.get(kind)
        ]
        for owner, values in counts.items()
    }
