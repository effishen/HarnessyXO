"""Explicit phone retries of saved direct runs, through the ordinary queue."""
from __future__ import annotations

from typing import Any

from harnessy.core.machine import MachineStore
from harnessy.core.workspace import WorkspaceStore


def saved_run_retry_payload(machine: MachineStore, ws: WorkspaceStore, chat_id: str,
                            prompt_message_id: str, *, profile_id: str, thinking: str) -> dict[str, Any]:
    """Validate the saved source, including every recorded attachment ID."""
    chat = ws.get_chat(chat_id)
    if chat is None or chat.archived_at is not None:
        raise ValueError('The original Project / Chat is missing or archived.')
    ws.require_chat_unlocked(chat_id)
    messages = ws.get_messages_by_ids(chat_id, [prompt_message_id])
    prompt = next((row for row in messages if row.id == prompt_message_id and row.role == 'user'), None)
    if prompt is None:
        raise ValueError('The original saved prompt is no longer available.')
    ids = list(dict.fromkeys(str(x) for x in (prompt.metadata.get('attachment_ids') or [])))
    lookup = {a.id: a for a in ws.list_attachments(chat_id)}
    if any(aid not in lookup or not lookup[aid].path.is_file() for aid in ids):
        raise ValueError('An original attachment is no longer available; the run was not retried.')
    if not prompt.content and not ids:
        raise ValueError('The saved prompt has no text or attachments to retry.')
    settings = machine.load_settings()
    if profile_id and not any(p.get('id') == profile_id for p in settings.get('models', {}).get('profiles', [])
                              if isinstance(p, dict)):
        raise ValueError('The original model profile is no longer available. Restore it before retrying.')
    return {'prompt': 'continue', 'attachment_ids': [], 'profile_id': profile_id,
            'thinking': thinking or 'default'}


def retry_saved_run(machine: MachineStore, ws: WorkspaceStore, chat_id: str,
                    prompt_message_id: str, *, profile_id: str, thinking: str,
                    job_id: str) -> dict[str, Any]:
    """Queue continue with existing history, without resubmitting original inputs."""
    existing = machine.get_run_job(job_id)
    if existing is not None:
        return existing
    payload = saved_run_retry_payload(machine, ws, chat_id, prompt_message_id,
                                      profile_id=profile_id, thinking=thinking)
    try:
        return machine.enqueue_run_job(workspace_id=ws.id, chat_id=chat_id, lane=1,
            prompt=payload['prompt'], attachment_ids=[], profile_id=profile_id,
            thinking=thinking, job_id=job_id)
    except Exception:
        # Resolve a committed continuation whose first queue readback failed.
        existing = machine.get_run_job(job_id)
        if existing is not None:
            return existing
        raise
