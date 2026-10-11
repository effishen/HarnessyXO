"""Resolve retry attempts to one surviving user bubble without text matching.

This module only supplies presentation references. It does not merge attempts,
rewrite model history, or decide whether a queued job may run.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


MAX_PROMPT_REFERENCE_JOBS = 128


@dataclass(frozen=True, slots=True)
class PromptReference:
    job_id: str
    root_job_id: str
    message_id: str
    message_job_id: str
    latest_message_id: str
    job_ids: tuple[str, ...]
    ancestry_complete: bool


def _job_id(value: Any) -> str:
    # Real queue identifiers are UUID hex strings. Permit older/test IDs while
    # bounding SQL parameters and excluding invalid imported metadata values.
    if (not isinstance(value, str) or not value or len(value) > 128
            or not value.isascii()
            or not all(char.isalnum() or char in '_-' for char in value)):
        return ''
    return value


def resolve_run_prompt_reference(
    machine: Any, ws: Any, chat_id: str, job: Mapping[str, Any] | str,
) -> PromptReference | None:
    """Find the earliest surviving user bubble in this job's retry ancestry.

    ``job`` can be a queue row or its ID, including a saved Message's
    ``metadata['run_queue_job_id']``. Queue rows are reread from the machine
    store: UI snapshots and caller-supplied ownership fields are not trusted.
    All ancestors must belong to the exact same workspace and chat. Cyclic,
    cross-project and overlong chains are rejected rather than guessed.

    Empty ``message_id`` means none of the verified attempts has a surviving
    saved prompt (for example a pre-save cancellation or timeline replacement).
    A missing parent ends the known chain with ``ancestry_complete=False``.
    Deleted messages are never returned, and identical prompt text is ignored.
    """
    current_id = _job_id(job.get('id') if isinstance(job, Mapping) else job)
    workspace_id = getattr(ws, 'id', '')
    if not current_id or not workspace_id or not chat_id or ws.get_chat(chat_id) is None:
        return None

    newest_first: list[str] = []
    seen: set[str] = set()
    ancestry_complete = True
    requested_id = current_id
    while current_id:
        if current_id in seen or len(newest_first) >= MAX_PROMPT_REFERENCE_JOBS:
            return None
        seen.add(current_id)
        row = machine.get_run_job(current_id)
        if row is None:
            if not newest_first:
                return None
            ancestry_complete = False
            break
        if (row.get('id') != current_id or row.get('workspace_id') != workspace_id
                or row.get('chat_id') != chat_id):
            return None
        newest_first.append(current_id)
        parent = row.get('retry_of_job_id')
        if parent is None or parent == '':
            break
        current_id = _job_id(parent)
        if not current_id:
            return None

    oldest_first = tuple(reversed(newest_first))
    saved = ws.queued_prompt_messages(chat_id, oldest_first)
    anchor_job = next((item for item in oldest_first if item in saved), '')
    latest_job = next((item for item in newest_first if item in saved), '')
    return PromptReference(
        job_id=requested_id,
        root_job_id=oldest_first[0],
        message_id=saved.get(anchor_job, ''),
        message_job_id=anchor_job,
        latest_message_id=saved.get(latest_job, ''),
        job_ids=oldest_first,
        ancestry_complete=ancestry_complete,
    )


def resolve_run_origin_message(machine: Any, ws: Any, chat_id: str, run_id: str) -> str:
    """Resolve a run's activity/continue notices to its original user bubble.

    Queued retries share their earliest surviving queue prompt. Legacy queued
    runs without job metadata and direct runs use the first User message whose
    exact run ID matches. A follow-up saved during that same run never steals
    the origin. Existing invalid queue ancestry must not use the fallback.
    """
    run_id = _job_id(run_id)
    if not run_id or not getattr(ws, 'id', '') or not chat_id or ws.get_chat(chat_id) is None:
        return ''
    if run_id.startswith('queue-'):
        queue_id = _job_id(run_id.removeprefix('queue-'))
        if not queue_id:
            return ''
        if machine.get_run_job(queue_id) is not None:
            reference = resolve_run_prompt_reference(machine, ws, chat_id, queue_id)
            if reference is None:
                return ''
            if reference.message_id:
                return reference.message_id
    return ws.run_prompt_message_id(chat_id, run_id)
