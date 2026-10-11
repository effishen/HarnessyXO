"""Prepare an explicit retry without altering the old attempt or composer."""
from __future__ import annotations

import shutil
import uuid
from typing import Any

from harnessy.agent.prompt_references import resolve_run_prompt_reference
from harnessy.core.history import clone_or_copy_file
from harnessy.core.machine import MachineStore
from harnessy.core.workspace import WorkspaceStore, utcnow


def queued_retry_continues(machine: MachineStore, ws: WorkspaceStore, job: dict[str, Any]) -> bool:
    """Continue saved same-chat history; an unsent request has no run to continue."""
    reference = resolve_run_prompt_reference(machine, ws, str(job['chat_id']), job)
    if reference is not None and reference.message_id:
        return True
    if str(job.get('prompt') or '') == 'continue':
        return True
    if job.get('started_at'):
        raise ValueError('The saved conversation is unavailable; continuation was not queued.')
    return False


def retry_queued_run(machine: MachineStore, job_id: str) -> tuple[dict[str, Any], bool]:
    """Blocking preparation, called off the UI loop; never rewind project state."""
    existing = machine.get_run_job_retry(job_id)
    if existing is not None:
        return existing, False
    job = machine.get_run_job(job_id)
    if (job is None or job['status'] not in {'stopped', 'cancelled', 'failed', 'interrupted'}
            or job.get('outcome') == 'archived'):
        raise ValueError('This run is not available for retry.')
    reg = machine.get_workspace(str(job['workspace_id']))
    if reg is None or not reg.path.is_dir():
        raise ValueError('The original workspace is unavailable.')
    ws = WorkspaceStore(reg.path, reg.name)
    chat_id = str(job['chat_id'])
    chat = ws.get_chat(chat_id)
    if chat is None or chat.archived_at is not None:
        raise ValueError('The original Project / Chat is missing or archived.')
    ws.require_chat_unlocked(chat_id)
    settings = machine.load_settings()
    profiles = settings.get('models', {}).get('profiles', [])
    if job.get('profile_id') and not any(p.get('id') == job['profile_id'] for p in profiles if isinstance(p, dict)):
        raise ValueError('The original model profile is no longer available. Restore it before retrying.')
    slot_limit = max(1, min(int((settings.get('agent') or {}).get('global_agent_slots') or 1), 32))
    continuation = queued_retry_continues(machine, ws, job)
    lookup = {a.id: a for a in ws.list_attachments(chat_id)}
    originals = []
    for attachment_id in job['attachment_ids']:
        item = lookup.get(attachment_id)
        if item is None or not item.path.is_file():
            raise ValueError('An original attachment is no longer available; the run was not retried.')
        originals.append(item)

    if continuation:
        # Existing history owns the original input and attachments. Reattaching
        # a pasted-text file would effectively submit the original task again.
        return machine.retry_run_job(job_id, attachment_ids=[], slot_limit=slot_limit, prompt='continue')

    # Each retry owns private copies. Reusing a sent/pending attachment ID
    # could consume a draft or let removing a draft break the queued retry.
    copy_root = ws.uploads_dir / chat_id / f'queue-retry-{uuid.uuid4().hex}'
    copies: list[tuple[str, Any, Any]] = []
    committed = False
    try:
        for item in originals:
            attachment_id = str(uuid.uuid4())
            destination = copy_root / attachment_id / item.path.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            clone_or_copy_file(item.path, destination)
            copies.append((attachment_id, item, destination))
        with ws._connect() as con:
            ws._require_chat_unlocked_in(con, chat_id)
            current = con.execute('SELECT archived_at FROM chats WHERE id=?', (chat_id,)).fetchone()
            if current is None or current['archived_at'] is not None:
                raise ValueError('The original Project / Chat is missing or archived.')
            con.executemany(
                'INSERT INTO attachments(id,chat_id,name,path,mime_type,size,created_at,status) '
                "VALUES(?,?,?,?,?,?,?,'queued')",
                [(aid, chat_id, item.name, path.relative_to(ws.root).as_posix(), item.mime_type,
                  path.stat().st_size, utcnow()) for aid, item, path in copies],
            )
            con.commit()
        retry, created = machine.retry_run_job(
            job_id, attachment_ids=[aid for aid, _item, _path in copies], slot_limit=slot_limit,
        )
        committed = created
        return retry, created
    finally:
        if not committed:
            # Resolve a possible commit/read failure before removing files that
            # a persisted retry may own. On an unreadable queue, retain them.
            try:
                saved = machine.get_run_job_retry(job_id)
                committed = bool(saved and set(saved['attachment_ids']) == {aid for aid, _item, _path in copies})
            except Exception:
                committed = True
            if not committed:
                with ws._connect() as con:
                    con.executemany(
                        "DELETE FROM attachments WHERE chat_id=? AND id=? AND status='queued'",
                        [(chat_id, aid) for aid, _item, _path in copies],
                    )
                    con.commit()
                shutil.rmtree(copy_root, ignore_errors=True)
