"""Deterministic, read-only printable chat snapshots.

The printable record index includes activity without changing the existing
Markdown export's record numbering. No model, file-content or renderer access
is performed here. A compact section contains labels and selected measurements,
never a snippet of its omitted body.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import sqlite3
import threading
import time
from types import MappingProxyType
from typing import Any, Callable, Iterator

from harnessy.diagnostics.sqlite import connect_database
from harnessy.ui.prompt_processing import completed_prefill_snapshot, prompt_processing_timestamp

from .chat_export import ChatSnapshot
from .transcript import assistant_stream_groups


CONTENT_LABELS = {
    'user': 'Your prompts', 'reply': 'Model replies', 'thinking': 'Thinking',
    'tool_calls': 'Tool calls', 'tool_results': 'Tool results',
    'prompt_processing': 'Prompt processing', 'events': 'Events and completion checks',
    'attachments': 'Attachment references',
}
DETAIL_MODES = {'full': 'Full', 'line': 'One line', 'nothing': 'Nothing'}
METADATA_LABELS = {
    'timestamps': 'Timestamps', 'model': 'Model and backend', 'tokens': 'Token counts',
    'speed': 'Token speeds', 'duration': 'Elapsed time', 'cache': 'Cache statistics',
    'title': 'Chat and workspace title', 'ids': 'Message and tool call IDs',
}
DEFAULT_MODES = {
    'user': 'full', 'reply': 'full', 'thinking': 'line', 'tool_calls': 'line',
    'tool_results': 'line', 'prompt_processing': 'line', 'events': 'line',
    'attachments': 'line',
}
DEFAULT_METADATA = frozenset(METADATA_LABELS) - {'ids'}
MAX_FULL_BODY_BYTES = 64 * 1024 * 1024
MAX_SECTIONS = 200_000
_ROLES = "('user','assistant','tool','activity')"
_MAX_IDENTIFIER = 160


class PrintExportError(ValueError):
    """A printable export selection cannot be completed faithfully."""


class PrintExportCancelled(RuntimeError):
    """The caller cancelled an export before a file was published."""


def _check_cancel(cancel: threading.Event | None) -> None:
    if cancel is not None and cancel.is_set():
        raise PrintExportCancelled('Printable export cancelled.')


def _identifier(value: Any) -> bool:
    return (isinstance(value, str) and 0 < len(value) <= _MAX_IDENTIFIER
            and not any(ord(char) < 32 or ord(char) == 127 for char in value))


@dataclass(frozen=True, slots=True)
class PrintExportOptions:
    scope: str = 'all'
    selected_prompt_ids: tuple[str, ...] = ()
    first_record: int = 1
    last_record: int | None = None
    modes: Mapping[str, str] = field(default_factory=lambda: dict(DEFAULT_MODES))
    metadata: frozenset[str] = DEFAULT_METADATA

    def __post_init__(self) -> None:
        # A running job must not inherit later changes to a dialog's draft.
        if isinstance(self.modes, Mapping):
            object.__setattr__(self, 'modes', MappingProxyType(dict(self.modes)))

    def validate(self) -> None:
        if not isinstance(self.scope, str) or self.scope not in {'all', 'prompts', 'range'}:
            raise PrintExportError('Choose the entire chat, selected prompts, or a message range.')
        if (not isinstance(self.selected_prompt_ids, tuple)
                or any(not _identifier(item) for item in self.selected_prompt_ids)
                or len(self.selected_prompt_ids) > MAX_SECTIONS):
            raise PrintExportError('Select valid saved prompts from this chat.')
        if self.scope == 'prompts' and not self.selected_prompt_ids:
            raise PrintExportError('Select at least one prompt to export.')
        if (type(self.first_record) is not int or self.first_record < 1
                or (self.last_record is not None
                    and (type(self.last_record) is not int or self.last_record < self.first_record))):
            raise PrintExportError('Message numbers must be whole numbers, starting at 1, in order.')
        if (not isinstance(self.modes, Mapping) or set(self.modes) != set(CONTENT_LABELS)
                or any(not isinstance(value, str) or value not in DETAIL_MODES for value in self.modes.values())):
            raise PrintExportError('Choose Full, One line or Nothing for each content section.')
        if all(value == 'nothing' for value in self.modes.values()):
            raise PrintExportError('Choose Full or One line for at least one content section.')
        if not isinstance(self.metadata, frozenset) or not self.metadata <= set(METADATA_LABELS):
            raise PrintExportError('Choose valid metadata fields for the printable export.')

    def as_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            'scope': self.scope, 'selected_prompt_ids': list(self.selected_prompt_ids),
            'first_record': self.first_record, 'last_record': self.last_record,
            'modes': dict(self.modes), 'metadata': sorted(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class PrintSection:
    kind: str
    label: str
    body: str
    metadata: tuple[str, ...]
    record_number: int
    message_id: str
    code: bool = False
    compact: bool = False


def _json(value: Any, fallback: Any) -> Any:
    if isinstance(value, type(fallback)):
        return value
    if not isinstance(value, str):
        return fallback
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, type(fallback)) else fallback
    except (ValueError, TypeError, RecursionError):
        return fallback


def _label(value: Any, maximum: int = 160) -> str:
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return ''
    text = ' '.join(str(value or '').split())
    return text if len(text) <= maximum else text[:maximum - 3] + '...'


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        parsed = float(value)
    except (ValueError, OverflowError):
        return None
    return parsed if math.isfinite(parsed) and parsed >= 0 else None


def _count(value: Any, estimated: Any = False) -> str:
    parsed = _number(value)
    if parsed is None or not parsed.is_integer() or parsed > 2 ** 53:
        return 'unavailable'
    return ('~' if estimated is True else '') + f'{int(parsed):,}'


def _seconds(value: Any, estimated: Any = False) -> str:
    parsed = _number(value)
    if parsed is None:
        return 'unavailable'
    prefix = '~' if estimated is True else ''
    if parsed < 60:
        return prefix + (f'{parsed:.2f}s' if parsed >= 0.1 else '<0.1s')
    minutes, seconds = divmod(int(parsed), 60)
    hours, minutes = divmod(minutes, 60)
    return prefix + (f'{hours}h {minutes:02d}m {seconds:02d}s' if hours else f'{minutes}m {seconds:02d}s')


def _rate(value: Any, estimated: Any = False) -> str:
    parsed = _number(value)
    return (('~' if estimated is True else '') + f'{parsed:,.1f} tok/s'
            if parsed is not None else 'unavailable')


def _timestamp(value: Any) -> str:
    text = str(value or '')
    try:
        parsed = datetime.fromisoformat(text.replace('Z', '+00:00'))
        if parsed.tzinfo is not None:
            return parsed.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        return parsed.strftime('%Y-%m-%d %H:%M:%S') + ' (timezone not recorded)'
    except (TypeError, ValueError, OverflowError):
        return 'Time unavailable'


def _read_index(con: sqlite3.Connection, chat_id: str, *, cancel=None) -> dict[str, Any]:
    _check_cancel(cancel)
    con.row_factory = sqlite3.Row
    chat = con.execute('SELECT title FROM chats WHERE id=?', (chat_id,)).fetchone()
    if chat is None:
        raise PrintExportError('This chat is no longer available.')
    count = int(con.execute(
        f'SELECT COUNT(*) FROM messages WHERE chat_id=? AND role IN {_ROLES}', (chat_id,),
    ).fetchone()[0])
    if count > MAX_SECTIONS:
        raise PrintExportError('This chat exceeds the 200,000-message printable index limit.')
    cur = con.execute(
        'WITH numbered AS (SELECT id, role, created_at, '
        'ROW_NUMBER() OVER (ORDER BY created_at ASC, rowid ASC) AS record_number, '
        "substr(COALESCE(content,''),1,140) AS preview "
        f'FROM messages WHERE chat_id=? AND role IN {_ROLES}) '
        'SELECT id,record_number,role,created_at,preview FROM numbered ORDER BY record_number',
        (chat_id,),
    )
    prompts = []
    records = []
    while rows := cur.fetchmany(128):
        _check_cancel(cancel)
        for row in rows:
            item = dict(row)
            records.append(item)
            if item['role'] == 'user':
                prompts.append({key: value for key, value in item.items() if key != 'role'})
    return {'total_records': count, 'prompts': prompts, 'records': records, 'title': str(chat['title'] or '')}


def load_print_index(workspace, chat_id: str, *, cancel=None) -> dict[str, Any]:
    """Read just prompt previews and counts, without opening or repairing a store."""
    if not _identifier(chat_id):
        raise PrintExportError('Choose a valid saved chat.')
    _check_cancel(cancel)
    con = workspace._connect(readonly=True, timeout=2)
    deadline = time.monotonic() + 60
    con.set_progress_handler(lambda: int((cancel is not None and cancel.is_set())
                                         or time.monotonic() > deadline), 1000)
    try:
        con.execute('BEGIN')
        index = _read_index(con, chat_id, cancel=cancel)
        return {**index, 'workspace_name': str(workspace.name)}
    except sqlite3.OperationalError as exc:
        _check_cancel(cancel)
        raise PrintExportError('The chat index is busy or unavailable. Retry shortly.') from exc
    finally:
        con.close()


def _selected_spans(index: dict[str, Any], options: PrintExportOptions) -> list[tuple[int, int]]:
    options.validate()
    total = int(index['total_records'])
    if options.scope == 'all':
        return [(1, total)] if total else []
    if options.scope == 'range':
        end = options.last_record if options.last_record is not None else total
        if options.first_record > total or end > total:
            raise PrintExportError(f'This snapshot has {total:,} saved messages. Choose a range inside it.')
        return [(options.first_record, end)]
    wanted = set(options.selected_prompt_ids)
    prompts = index['prompts']
    known = {row['id'] for row in prompts}
    if not wanted <= known:
        raise PrintExportError('One or more selected prompts are no longer in this chat. Refresh the selection.')
    spans = []
    for position, prompt in enumerate(prompts):
        if prompt['id'] in wanted:
            start = int(prompt['record_number'])
            end = int(prompts[position + 1]['record_number']) - 1 if position + 1 < len(prompts) else total
            if spans and spans[-1][1] + 1 == start:
                spans[-1] = (spans[-1][0], end)
            else:
                spans.append((start, end))
    return spans


def _tool_status(meta: dict[str, Any], body: str) -> str:
    status = str(meta.get('execution_status') or '').lower()
    labels = {
        'success': 'Completed', 'succeeded': 'Completed', 'complete': 'Completed',
        'completed': 'Completed', 'failed': 'Failed', 'error': 'Failed', 'denied': 'Denied',
        'blocked': 'Blocked', 'cancelled': 'Cancelled', 'canceled': 'Cancelled',
        'running': 'Running', 'pending': 'Pending', 'not_run': 'Not executed',
    }
    if status in labels:
        return labels[status]
    ok = meta.get('ok')
    if not isinstance(ok, bool) and len(body) <= 1024 * 1024:
        ok = _json(body, {}).get('ok')
    return 'Completed' if ok is True else 'Failed' if ok is False else 'Status unavailable'


def _pp_values(activity: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    details = activity.get('details') if isinstance(activity.get('details'), dict) else {}
    frozen = completed_prefill_snapshot(activity)
    stats = dict(frozen) if frozen is not None else {
        'cached_tokens': details.get('cached_tokens'), 'prompt_tokens': details.get('prompt_tokens'),
        'cache_hit_rate': details.get('cache_hit_rate'),
        'processed_tokens': details.get('processed_tokens') if 'uncached_total' in details else None,
        'prefill_seconds': details.get('prefill_seconds'), 'prefill_tps': details.get('prefill_tps'),
        'prefill_estimated': details.get('prefill_estimated'),
    }
    cached, prompt = _number(stats.get('cached_tokens')), _number(stats.get('prompt_tokens'))
    if details.get('cache_accounting_available') is False or (cached is not None and prompt is not None and cached > prompt):
        stats['cached_tokens'] = stats['cache_hit_rate'] = None
    elif cached is not None and prompt is not None and prompt > 0:
        stats['cache_hit_rate'] = cached * 100.0 / prompt
    hit = _number(stats.get('cache_hit_rate'))
    if hit is None or hit > 100:
        stats['cache_hit_rate'] = None
    return details, stats


def _stream_groups(meta: dict[str, Any], content: str, reasoning: str, created_at: str) -> list[dict[str, Any]]:
    """Discard malformed timing values while retaining every valid text phase."""
    clean = dict(meta)
    raw = meta.get('stream_segments')
    if isinstance(raw, list):
        segments = []
        for value in raw:
            if not isinstance(value, dict):
                continue
            segment = dict(value)
            if 'duration_seconds' in segment:
                segment['duration_seconds'] = _number(segment['duration_seconds'])
            segments.append(segment)
        clean['stream_segments'] = segments
    return assistant_stream_groups(clean, content, reasoning, created_at)


def _measurements(kind: str, row: dict[str, Any], meta: dict[str, Any], options: PrintExportOptions,
                  *, group: dict[str, Any] | None = None, activity: dict[str, Any] | None = None,
                  call_id: str = '', compact: bool = False) -> tuple[str, ...]:
    fields = options.metadata
    group = group or {}
    metric = meta.get('generation_metric') if isinstance(meta.get('generation_metric'), dict) else {}
    details, prefill = _pp_values(activity or {}) if kind == 'prompt_processing' else ({}, {})
    event_details = (activity or {}).get('details')
    event_details = event_details if isinstance(event_details, dict) else {}
    parts: list[str] = []
    if 'timestamps' in fields:
        timestamp = (prompt_processing_timestamp(activity or {}, str(row.get('created_at') or ''))
                     if kind == 'prompt_processing' else group.get('reasoning_started_at' if kind == 'thinking'
                     else 'answer_started_at') or row.get('created_at'))
        parts.append(_timestamp(timestamp))
    if 'model' in fields and kind != 'user' and kind != 'attachments':
        model = meta.get('model') or meta.get('requested_by_model') or metric.get('model') or event_details.get('model')
        backend = metric.get('backend') or event_details.get('backend')
        parts.append('Model ' + _label(model) if model else 'Model unavailable')
        if backend:
            parts.append('Backend ' + _label(backend))
    if 'tokens' in fields:
        if kind == 'prompt_processing':
            parts.append(_count(prefill.get('processed_tokens')) + ' fresh tok')
            if not compact:
                parts.extend(('Input ' + _count(details.get('prompt_tokens'), details.get('prompt_tokens_estimated')) + ' tok',
                              'Generated ' + _count(details.get('generated_tokens'), details.get('generated_tokens_estimated')) + ' tok'))
        elif kind in {'reply', 'thinking', 'tool_calls'}:
            parts.append('Call input ' + _count(metric.get('prompt_tokens'), metric.get('usage_estimated')) + ' tok')
            parts.append('Call output ' + _count(metric.get('completion_tokens'), metric.get('usage_estimated')) + ' tok')
    if 'speed' in fields:
        if kind == 'prompt_processing':
            parts.append('Prefill ' + _rate(prefill.get('prefill_tps'), prefill.get('prefill_estimated')) + ' (avg)')
            if not compact:
                parts.append('Generation ' + _rate(details.get('generation_tps'), details.get('generation_tps_estimated')))
        elif kind in {'reply', 'thinking', 'tool_calls'}:
            native = metric.get('throughput_source') in {
                'llama.cpp timings', 'oMLX usage metadata', 'oMLX timing counters',
                'Ollama timing counters', 'backend timing counters',
            }
            parts.append('Call ' + _rate(metric.get('tps'), not native))
    if 'duration' in fields:
        if kind == 'prompt_processing':
            parts.append('Prefill ' + _seconds(prefill.get('prefill_seconds'), prefill.get('prefill_estimated')))
            if not compact:
                parts.extend(('First-token wait ' + _seconds(details.get('ttft_seconds')),
                              'Request ' + _seconds(details.get('duration_seconds'))))
        elif kind in {'reply', 'thinking'}:
            phase = 'reasoning' if kind == 'thinking' else 'answer'
            timing = group if group.get('timing_source') else metric
            duration = timing.get(phase + '_duration_seconds') if timing.get('timing_source') == 'stream_observed' else None
            parts.append(('Thinking ' if kind == 'thinking' else 'Reply ') + _seconds(duration, True))
        elif kind == 'tool_calls':
            duration = metric.get('tool_call_generation_seconds') if metric.get('timing_source') == 'stream_observed' else None
            parts.append('Arguments ' + _seconds(duration, True))
        elif kind == 'tool_results':
            if meta.get('timing_source') == 'execution_boundary':
                parts.append('Execution ' + _seconds(meta.get('execution_duration_seconds')))
            else:
                parts.append('Request total ' + _seconds(meta.get('duration_seconds')))
        elif kind == 'events' and 'duration_seconds' in event_details:
            parts.append('Elapsed ' + _seconds(event_details.get('duration_seconds')))
    if 'cache' in fields:
        if kind == 'prompt_processing':
            hit = _number(prefill.get('cache_hit_rate'))
            parts.extend((_count(prefill.get('cached_tokens')) + ' cached',
                          f'Hit {hit:.1f}%' if hit is not None else 'Cache hit unavailable'))
        elif kind in {'reply', 'thinking', 'tool_calls'}:
            parts.append('Call cached ' + _count(metric.get('cached_tokens'), metric.get('usage_estimated')) + ' tok')
    if 'ids' in fields:
        parts.append('Message ' + _label(row.get('id')))
        if call_id:
            parts.append('Call ' + _label(call_id))
    return tuple(parts)


_EVENT_LABELS = {
    'context_compaction': 'Context compaction', 'live_context_update': 'Context update',
    'automatic_continuation': 'Automatic continuation', 'model_slot_wait': 'Model queue wait',
    'run_blocked': 'Run blocked', 'attachment_deferred': 'Attachment deferred',
    'stream_stall': 'Model stream quiet', 'tuning_reminder': 'Tuning reminder',
    'completion_check': 'Completion check', 'backend_recovery': 'Backend recovery',
}
_EVENT_FIELDS = {
    'context_compaction': ('attempt', 'max_attempts', 'old_target_tokens', 'new_target_tokens',
                           'estimated_bytes', 'limit_bytes', 'recovery_count', 'upward_probes'),
    'live_context_update': ('old_target_tokens', 'new_target_tokens'),
    'model_slot_wait': ('wait_seconds',),
    'backend_recovery': ('attempt', 'error_code'),
    'completion_check': ('check_sequence', 'attempt', 'max_attempts', 'decision', 'pause_reason',
                         'continuation_count', 'continuation_limit', 'continuation_total', 'error_code'),
    'run_blocked': ('error_code', 'write_applied', 'skipped_tool_count'),
    'attachment_deferred': ('count',),
    'stream_stall': ('phase', 'request_state', 'silence_seconds'),
    'tuning_reminder': ('setting_name', 'max_output_tokens', 'recommended_tokens'),
}


def _event_body(activity: dict[str, Any], fields: frozenset[str]) -> str:
    details = activity.get('details') if isinstance(activity.get('details'), dict) else {}
    summary = activity.get('summary')
    lines = [summary if isinstance(summary, str) else '']
    for key in _EVENT_FIELDS.get(str(activity.get('type') or ''), ()):
        if key not in details or isinstance(details[key], (dict, list, tuple)):
            continue
        if key.endswith('_seconds') and 'duration' not in fields:
            continue
        if key.endswith('_tokens') and 'tokens' not in fields:
            continue
        lines.append(key.replace('_', ' ').capitalize() + ': ' + str(details[key]))
    return '\n'.join(line for line in lines if line)


@dataclass(frozen=True, slots=True)
class PrintSnapshot:
    _source: ChatSnapshot
    _index: dict[str, Any]

    @classmethod
    def capture(cls, workspace, chat_id: str, directory: Path, *, active: bool = False,
                cancel: threading.Event | None = None) -> 'PrintSnapshot':
        if not _identifier(chat_id):
            raise PrintExportError('Choose a valid saved chat.')
        _check_cancel(cancel)
        snapshot = ChatSnapshot.capture(workspace, chat_id, Path(directory), active=active, cancel=cancel)
        con = connect_database(snapshot.database.as_uri() + '?mode=ro', role='other', uri=True)
        try:
            index = _read_index(con, chat_id, cancel=cancel)
        finally:
            con.close()
        _check_cancel(cancel)
        return cls(snapshot, index)

    @property
    def title(self) -> str: return self._source.title
    @property
    def workspace_name(self) -> str: return self._source.workspace_name
    @property
    def captured_at(self) -> str: return self._source.captured_at
    @property
    def active(self) -> bool: return self._source.active
    @property
    def total_records(self) -> int: return int(self._index['total_records'])

    def index(self) -> dict[str, Any]:
        return {**deepcopy(self._index), 'title': self.title, 'workspace_name': self.workspace_name,
                'captured_at': self.captured_at, 'active': self.active}

    def selected_record_count(self, options: PrintExportOptions) -> int:
        return sum(end - start + 1 for start, end in _selected_spans(self._index, options))

    def sections(self, options: PrintExportOptions, *, cancel=None,
                 progress: Callable[[str], None] | None = None) -> Iterator[PrintSection]:
        """Build a bounded selected document before yielding any of its sections.

        Limit and validation failures therefore cannot produce an apparently
        complete PDF containing only the first portion of a requested export.
        """
        spans = _selected_spans(self._index, options)
        _check_cancel(cancel)
        output: list[PrintSection] = []
        full_bytes = 0
        selected = sum(end - start + 1 for start, end in spans)
        seen_records = 0
        attachment_records: dict[str, dict[str, Any]] = {}

        def emit(kind: str, label: str, body: str, row: dict[str, Any], number: int,
                 meta: dict[str, Any], *, code=False, group=None, activity=None,
                 call_id='', line_label='') -> None:
            nonlocal full_bytes
            _check_cancel(cancel)
            mode = options.modes[kind]
            if mode == 'nothing':
                return
            compact = mode == 'line'
            printed_body = '' if compact else str(body)
            full_bytes += len(printed_body.encode('utf-8'))
            if full_bytes > MAX_FULL_BODY_BYTES:
                raise PrintExportError('The selected full text exceeds 64 MiB. Choose a smaller range or use One line for large sections.')
            if len(output) >= MAX_SECTIONS:
                raise PrintExportError('The selection exceeds 200,000 printable sections. Choose a smaller range.')
            display_label = (line_label or label) if compact else label
            output.append(PrintSection(kind, display_label, printed_body,
                _measurements(kind, row, meta, options, group=group, activity=activity,
                              call_id=call_id, compact=compact), number, str(row.get('id') or ''),
                bool(code), compact))

        con = connect_database(self._source.database.as_uri() + '?mode=ro', role='other', uri=True)
        con.row_factory = sqlite3.Row
        deadline = time.monotonic() + 120
        con.set_progress_handler(lambda: int((cancel is not None and cancel.is_set())
                                             or time.monotonic() > deadline), 1000)
        try:
            if options.modes['attachments'] == 'full':
                attachment_records = {str(row['id']): dict(row) for row in con.execute(
                    'SELECT id,name,mime_type,size,created_at,status FROM attachments WHERE chat_id=?',
                    (self._source.chat_id,),
                )}
            for start, end in spans:
                cursor = con.execute(
                    f'SELECT * FROM messages WHERE chat_id=? AND role IN {_ROLES} '
                    'ORDER BY created_at ASC,rowid ASC LIMIT ? OFFSET ?',
                    (self._source.chat_id, end - start + 1, start - 1),
                )
                number = start
                while rows := cursor.fetchmany(32):
                    _check_cancel(cancel)
                    for stored in rows:
                        row = dict(stored)
                        meta = _json(row.get('metadata_json'), {})
                        content = str(row.get('content') or '')
                        role = str(row.get('role') or '')
                        if role == 'user':
                            emit('user', 'Your prompt', content, row, number, meta,
                                 line_label=f'Your prompt - {len(content):,} characters')
                        elif role == 'assistant':
                            reasoning = str(meta.get('reasoning') or '')
                            groups = _stream_groups(meta, content, reasoning, str(row.get('created_at') or ''))
                            for group in groups:
                                for kind, key, label in (('thinking', 'reasoning', 'Thinking'), ('reply', 'answer', 'Model reply')):
                                    body = str(group.get(key) or '')
                                    if body:
                                        emit(kind, label, body, row, number, meta, group=group,
                                             line_label=f'{label} - {len(body):,} characters')
                            # A legacy saved field can differ from segmented
                            # output. Retain it explicitly rather than silently
                            # dropping source text or inventing its chronology.
                            for kind, key, body, label in (
                                ('thinking', 'reasoning', reasoning, 'Thinking - differing saved field'),
                                ('reply', 'answer', content, 'Model reply - differing saved field'),
                            ):
                                if body and ''.join(str(group.get(key) or '') for group in groups) != body:
                                    emit(kind, label, body, row, number, meta,
                                         line_label=label + f' - {len(body):,} characters')
                            raw_calls = row.get('tool_calls_json')
                            calls = _json(raw_calls, [])
                            if raw_calls and not calls:
                                try:
                                    valid = json.loads(raw_calls) if isinstance(raw_calls, str) else raw_calls
                                    malformed = valid is not None and not isinstance(valid, list)
                                except (ValueError, TypeError, RecursionError):
                                    malformed = True
                                if malformed:
                                    if options.modes['tool_calls'] == 'full':
                                        raise PrintExportError('A saved tool-call record cannot be parsed. Choose One line or Nothing for tool calls, or repair that record before exporting full details.')
                                    emit('tool_calls', 'Unreadable saved tool calls', '', row, number, meta,
                                         line_label='Tool calls - saved data unavailable')
                            for call in calls:
                                if not isinstance(call, dict):
                                    if options.modes['tool_calls'] == 'full':
                                        raise PrintExportError('A saved tool call has an unrecognized structure. Choose One line or Nothing for tool calls, or repair that record before exporting full details.')
                                    emit('tool_calls', 'Unreadable saved tool call', 'The saved tool call has an unrecognized structure.',
                                         row, number, meta, code=True)
                                    continue
                                function = call.get('function') if isinstance(call.get('function'), dict) else {}
                                name = _label(function.get('name') or call.get('name') or 'unknown')
                                arguments = function.get('arguments', call.get('arguments', {}))
                                body = arguments if isinstance(arguments, str) else json.dumps(arguments, ensure_ascii=False, indent=2)
                                emit('tool_calls', 'Tool call - ' + name, body, row, number, meta,
                                     code=True, call_id=str(call.get('id') or ''), line_label='Tool call - ' + name)
                        elif role == 'tool':
                            name = _label(row.get('name') or 'unknown')
                            status = _tool_status(meta, content)
                            emit('tool_results', f'Tool result - {name} - {status}', content,
                                 row, number, meta, code=True, call_id=str(row.get('tool_call_id') or ''),
                                 line_label=f'Tool result - {name} - {status} - {len(content):,} characters')
                        elif role == 'activity':
                            activity = meta.get('activity') if isinstance(meta.get('activity'), dict) else {}
                            event_type = str(activity.get('type') or '')
                            status = {'running': 'Running', 'success': 'Done', 'complete': 'Done',
                                      'completed': 'Done', 'failed': 'Failed', 'cancelled': 'Cancelled',
                                      'interrupted': 'Interrupted', 'unconfirmed': 'Unconfirmed',
                                      'blocked': 'Blocked', 'waiting': 'Waiting'}.get(
                                          str(activity.get('status') or ''), 'Status unavailable')
                            if event_type == 'prompt_processing':
                                details = activity.get('details') if isinstance(activity.get('details'), dict) else {}
                                phase = str(details.get('phase') or '')
                                phase = {'waiting': 'Waiting', 'prompt_processing': 'Prefilling', 'generating': 'Generating'}.get(phase, 'Unavailable')
                                purpose = 'Completion check' if details.get('purpose') == 'completion_check' else 'Model call'
                                body = f'Status: {status}\nPhase: {phase}\nPurpose: {purpose}'
                                emit('prompt_processing', 'Prompt processing', body, row, number, meta,
                                     activity=activity, line_label='PP - ' + status)
                            else:
                                title = _label(activity.get('title') or _EVENT_LABELS.get(event_type, 'Event'))
                                body = _event_body(activity, options.metadata)
                                if not activity and content:
                                    body = content
                                emit('events', title + ' - ' + status, body, row, number, meta,
                                     activity=activity, line_label=_EVENT_LABELS.get(event_type, 'Event') + ' - ' + status)
                                if event_type == 'completion_check' and options.modes['events'] == 'full':
                                    details = activity.get('details') if isinstance(activity.get('details'), dict) else {}
                                    for kind, key, label in (
                                        ('reply', 'candidate_reply', 'Previous model reply (completion check)'),
                                        ('reply', 'check_prompt', 'HarnessyXO check prompt (quotes model reply)'),
                                        ('reply', 'check_reply', 'Model check reply'),
                                        ('thinking', 'check_reasoning', 'Model check thinking'),
                                    ):
                                        value = details.get(key)
                                        if isinstance(value, str) and value:
                                            emit(kind, label, value, row, number, meta, activity=activity,
                                                 line_label=label + f' - {len(value):,} characters')
                        ids = meta.get('attachment_ids')
                        if isinstance(ids, list) and ids and options.modes['attachments'] != 'nothing':
                            unique = list(dict.fromkeys(value for value in ids if isinstance(value, str)))
                            lines = []
                            for identifier in unique:
                                item = attachment_records.get(identifier)
                                if item is None:
                                    lines.append('Attachment reference - saved metadata unavailable')
                                    continue
                                name = Path(str(item.get('name') or '').replace('\\', '/')).name or 'Unnamed attachment'
                                mime = _label(item.get('mime_type') or 'type unavailable')
                                size = _count(item.get('size'))
                                lines.append(f'{name} - {mime} - {size} bytes')
                            emit('attachments', 'Attachment references (metadata only; files are not embedded)',
                                 '\n'.join(lines), row, number, meta,
                                 line_label=f'Attachments - {len(unique):,} reference(s)')
                        seen_records += 1
                        if progress is not None and (seen_records % 32 == 0 or seen_records == selected):
                            progress(f'Preparing saved message {seen_records:,} of {selected:,}')
                        number += 1
            _check_cancel(cancel)
        except sqlite3.OperationalError as exc:
            _check_cancel(cancel)
            raise PrintExportError('The saved snapshot could not be read completely. No partial export was created.') from exc
        finally:
            con.close()
        for section in output:
            _check_cancel(cancel)
            yield section
