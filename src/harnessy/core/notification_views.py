"""Read-only, bounded transcript views used by interactive notifications.

The caller supplies an already admitted WorkspaceStore and an immutable alert
route. These functions never open a workspace, enqueue dialogue, or read files.
Only answer text and explicitly selected counters leave SQLite; reasoning and
raw tool/metric payloads are never deserialized here.
"""
from __future__ import annotations

import math
import sqlite3
import time
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .workspace import WorkspaceStore

ANSWER_PAGE_BYTES = 2400
MAX_PREVIEW_CHARS = 220


class NotificationViewUnavailable(ValueError):
    """A bounded notification view cannot safely be read right now."""


def _identifier(value: str, *, required: bool = False) -> str:
    if (not isinstance(value, str) or len(value) > 160
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
            or (required and not value)):
        raise NotificationViewUnavailable('This notification has no valid chat reference.')
    return value


def _positive(value: int, name: str, *, maximum: int = 1000000) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise NotificationViewUnavailable(f'{name} must be a positive whole number up to {maximum:,}.')
    return value


def _arguments(chat_id: str, run_id: str, prompt_id: str, scope: str) -> tuple[str, str, str]:
    if scope not in {'prompt', 'chat'}:
        raise NotificationViewUnavailable('Unknown answer history scope.')
    values = (_identifier(chat_id, required=True), _identifier(run_id), _identifier(prompt_id))
    if scope == 'prompt' and not (run_id or prompt_id):
        raise NotificationViewUnavailable('This notification has no saved prompt reference.')
    return values


def _context(result: dict[str, Any] | None) -> dict[str, Any]:
    if result is None:
        raise NotificationViewUnavailable('The selected notification prompt or chat is no longer available.')
    return {key: value for key, value in result['context'].items() if not key.startswith('_')}


def _database_error(exc: sqlite3.Error) -> NotificationViewUnavailable:
    # Database errors may contain local paths or internal SQL. Keep them out of
    # the notification service and let normal diagnostics record store health.
    return NotificationViewUnavailable('The workspace is busy or unavailable. Retry this command shortly.')


def notification_answers(
    ws: WorkspaceStore, chat_id: str, *, run_id: str = '', prompt_id: str = '',
    page: int = 1, page_size: int = 6, scope: str = 'prompt',
) -> dict[str, Any]:
    """Numbered answer previews for one prompt, or all replies in this chat.

    Numbering is chronological and includes model completion questions. Empty,
    thinking-only, tool-only and explicitly marked app status/error rows are
    excluded. Legacy unmarked assistant prose remains readable.
    """
    chat_id, run_id, prompt_id = _arguments(chat_id, run_id, prompt_id, scope)
    page = _positive(page, 'Page')
    page_size = _positive(page_size, 'Page size', maximum=10)
    try:
        result = ws.notification_answer_rows(
            chat_id, run_id=run_id, prompt_id=prompt_id, start=(page - 1) * page_size,
            limit=page_size, preview_chars=MAX_PREVIEW_CHARS, scope=scope,
        )
    except sqlite3.Error as exc:
        raise _database_error(exc) from exc
    context = _context(result)
    assert result is not None
    total = int(result['answer_count'])
    answers = [dict(row, number=((page - 1) * page_size) + offset + 1)
               for offset, row in enumerate(result['answers'])]
    return {**context, 'answer_count': total, 'answers': answers, 'page': page,
            'pages': max(1, math.ceil(total / page_size)), 'page_size': page_size,
            'has_more': page * page_size < total, 'truncated': False}


def _decode_page(data: bytes, width: int) -> str:
    """Own characters by their leading UTF-8 byte; never drop split characters."""
    start = 0
    while start < len(data) and data[start] & 0xC0 == 0x80:
        start += 1
    end = min(width, len(data))
    while end < len(data) and data[end] & 0xC0 == 0x80:
        end += 1
    try:
        return data[start:end].decode('utf-8')
    except UnicodeDecodeError as exc:
        raise NotificationViewUnavailable('This saved reply is not valid UTF-8 text.') from exc


def notification_answer(
    ws: WorkspaceStore, chat_id: str, *, run_id: str = '', prompt_id: str = '',
    number: int | None = None, page: int = 1, answer_id: str = '', scope: str = 'prompt',
) -> dict[str, Any]:
    """Read latest/numbered answer as a small UTF-8 page with a stable message ID."""
    chat_id, run_id, prompt_id = _arguments(chat_id, run_id, prompt_id, scope)
    page = _positive(page, 'Page')
    if number is not None:
        number = _positive(number, 'Reply number', maximum=1000000000)
    answer_id = _identifier(answer_id)
    try:
        result = ws.notification_answer_page(
            chat_id, run_id=run_id, prompt_id=prompt_id, number=number, answer_id=answer_id,
            page=page, page_bytes=ANSWER_PAGE_BYTES, scope=scope,
        )
    except sqlite3.Error as exc:
        raise _database_error(exc) from exc
    context = _context(result)
    assert result is not None
    answer = result.get('answer')
    if answer is None:
        if not result['answer_count']:
            raise NotificationViewUnavailable('No model answers are saved for this selection yet.')
        raise NotificationViewUnavailable('That reply is no longer available in this selection.')
    total_bytes = int(answer['content_bytes'])
    tail = bytes(answer['content_tail'])
    final_lead = len(tail) - 1
    while final_lead > 0 and tail[final_lead] & 0xC0 == 0x80:
        final_lead -= 1
    # A character split at the nominal final boundary belongs to the previous
    # page. Count pages by its leading byte to avoid an empty final .more page.
    final_character_offset = total_bytes - len(tail) + max(0, final_lead)
    pages = max(1, (final_character_offset // ANSWER_PAGE_BYTES) + 1)
    if page > pages:
        raise NotificationViewUnavailable('This reply has no more pages.')
    text = _decode_page(bytes(answer['content_chunk']), ANSWER_PAGE_BYTES)
    return {**context, 'answer_count': int(result['answer_count']), 'number': int(result['number']),
            'id': str(answer['id']), 'created_at': str(answer['created_at']), 'text': text,
            'content_bytes': total_bytes, 'page': page, 'pages': pages,
            'has_more': page < pages, 'truncated': page < pages}


def _nonnegative_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    result = float(value)
    return result if math.isfinite(result) and 0 <= result <= 1000000000000000 else None


def notification_stats(
    ws: WorkspaceStore, chat_id: str, *, run_id: str = '', prompt_id: str = '',
    live_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Recorded main model-call totals since the captured prompt.

    Call count deduplicates persisted metric IDs, including calls that produced
    only thinking/tools. Token totals include reasoning/tool generation when
    counted by the backend. Missing counters stay unavailable. Completion check
    control requests and subagent calls are outside these main-call totals.
    Run elapsed time includes tools/waiting and is labelled separately from the
    prompt-scoped counters, because queued follow-ups can share a run.
    """
    chat_id, run_id, prompt_id = _arguments(chat_id, run_id, prompt_id, 'prompt')
    try:
        result = ws.notification_metric_summary(chat_id, run_id=run_id, prompt_id=prompt_id)
    except sqlite3.Error as exc:
        raise _database_error(exc) from exc
    context = _context(result)
    assert result is not None
    calls = int(result['model_calls'])
    known = int(result['recorded_metric_count'])
    fields = ('prompt_tokens', 'completion_tokens', 'total_tokens', 'cached_tokens', 'model_seconds')
    stats: dict[str, Any] = {
        **context, 'answer_count': int(result['answer_count']), 'model_calls': calls,
        'model_calls_source': 'persisted_main_call_metrics', 'metrics_available': bool(known),
        'recorded_metric_count': known, 'missing_metric_count': max(0, calls - known),
        'usage_estimated': (True if result['usage_estimated'] == 1 else
                            False if calls and int(result['usage_estimated_known_calls'] or 0) == calls else None),
        'usage_estimated_known_calls': int(result['usage_estimated_known_calls'] or 0),
        'token_scope': 'main_model_calls_including_reasoning_and_tools',
    }
    for field in fields:
        value = result[field]
        stats[field] = value if _nonnegative_number(value) is not None else None
        stats[field + '_known_calls'] = int(result[field + '_known_calls'] or 0)
        stats[field + '_complete'] = bool(calls and stats[field + '_known_calls'] == calls)
    latest = result.get('latest_metric') or {}
    stats.update(
        latest_tps=_nonnegative_number(latest.get('tps')),
        latest_prefill_tps=_nonnegative_number(latest.get('prefill_tps')),
        throughput_source=str(latest.get('throughput_source') or ''),
        prefill_throughput_source=str(latest.get('prefill_throughput_source') or ''),
    )
    elapsed = _nonnegative_number(result.get('saved_run_elapsed_seconds'))
    elapsed_source = 'saved_run_elapsed' if elapsed is not None else 'unavailable'
    active = False
    if (isinstance(live_state, dict) and context['run_id']
            and live_state.get('run_id') == context['run_id']
            and live_state.get('active') is True and not live_state.get('finished')):
        started = _nonnegative_number(live_state.get('run_started'))
        now = time.perf_counter()
        if started is not None and 0 <= started <= now:
            elapsed, elapsed_source, active = now - started, 'live_run_clock', True
    stats.update(run_elapsed_seconds=elapsed, elapsed_source=elapsed_source,
                 elapsed_scope='run', active=active)
    return stats
