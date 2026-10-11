"""Process-owned timeline restoration; no browser elements belong to this job."""
from __future__ import annotations

import asyncio
import json
import threading
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from harnessy.core.history import HistoryError
from harnessy.core.workspace import WorkspaceStore
from harnessy.agent.processes import PROCESS_JOBS


@dataclass
class TimelineReplacementJob:
    token: str
    chat_id: str
    message_id: str
    prompt: str
    selection: dict[str, str]
    attachment_ids: list[str]
    staged_attachment_ids: list[str]
    staging_token: str
    status: str = 'Waiting to restore the timeline…'
    outcome: str = ''
    restored: bool = False
    queued_job_id: str = ''
    started: bool = False
    cancel_event: threading.Event = field(default_factory=threading.Event)
    task: asyncio.Task[Any] | None = None
    waiting_owner_id: str = ''
    waiting_owner_label: str = ''
    waiting_project_chat_id: str = ''
    waiting_owner_phase: str = ''
    waiting_blockers: list[dict[str, str]] = field(default_factory=list)
    # Lifecycle facts are separate from display text so the UI can retire a
    # cancelled edit without hiding a failed cleanup or a recovered draft.
    cleanup_error: str = ''
    restored_attachment_ids: list[str] = field(default_factory=list)
    draft_recovered: bool = False
    delete_only: bool = False
    resume_from_checkpoint: bool = False
    removed_message_count: int = 0

    @property
    def label(self) -> str:
        if self.resume_from_checkpoint:
            return 'Checkpoint resume'
        return 'Timeline deletion' if self.delete_only else 'Timeline replacement'

    @property
    def running(self) -> bool:
        return not self.outcome

    def cancel(self) -> None:
        if not self.running or self.cancel_event.is_set():
            return
        self.cancel_event.set()
        self.status = f'Cancelling {self.label.lower()}…'
        if self.task is not None and self.started:
            self.task.cancel()

    async def run(
        self, ws: WorkspaceStore, *, coordinator: Any,
        enqueue: Callable[..., dict[str, Any]],
        chat_running: Callable[[], bool], on_restored: Callable[[], None],
        prepare: Callable[[], Awaitable[None]] | None = None,
    ) -> None:
        action = 'resume' if self.resume_from_checkpoint else ('delete' if self.delete_only else 'replace')
        owner = f'timeline-{action}:{self.chat_id}:{self.token}'
        acquired = False
        result = None
        self.started = True

        async def waiting(info: dict[str, Any]) -> None:
            blocker = str(info.get('owner') or '')
            self.waiting_owner_id = str(info.get('owner_id') or '')
            self.waiting_owner_label = blocker
            self.waiting_project_chat_id = str(info.get('owner_project_chat_id') or '')
            self.waiting_owner_phase = str(info.get('owner_phase') or '')
            self.waiting_blockers = [
                {'owner_id': str(row.get('owner_id') or ''),
                 'label': str(row.get('label') or ''),
                 'project_chat_id': str(row.get('project_chat_id') or ''),
                 'phase': str(row.get('phase') or '')}
                for row in info.get('blockers') or [] if isinstance(row, dict)
            ]
            self.status = (
                f'Waiting for {blocker} to release the project write lock.' if blocker else
                'Waiting for the project write lock.'
            )

        def clear_waiting() -> None:
            self.waiting_owner_id = ''
            self.waiting_owner_label = ''
            self.waiting_project_chat_id = ''
            self.waiting_owner_phase = ''
            self.waiting_blockers = []

        def mark_restored() -> None:
            self.restored = True
            self.restored_attachment_ids = list(result.attachment_ids)
            self.removed_message_count = result.removed_message_count
            on_restored()

        async def drain(task: asyncio.Task[Any]) -> Any:
            """Repeated shutdown cancellation must not abandon a live writer."""
            while True:
                try:
                    return await asyncio.shield(task)
                except asyncio.CancelledError:
                    self.cancel_event.set()
                    if task.done():
                        return task.result()

        try:
            if self.cancel_event.is_set():
                raise asyncio.CancelledError
            if prepare is not None:
                # Stop/finalization can itself have a database or file worker.
                # Never release the admission gate until those writers settle,
                # including when Cancel is clicked during this preparation.
                preparation = asyncio.create_task(prepare())
                try:
                    await asyncio.shield(preparation)
                except asyncio.CancelledError:
                    self.cancel_event.set()
                    await drain(preparation)
                    raise
            await coordinator.acquire(
                workspace_id=ws.id, owner_id=owner, label=self.label,
                conflict_keys=ws.project_conflict_ids(self.chat_id), on_wait=waiting,
                project_chat_id=self.chat_id,
            )
            acquired = True
            clear_waiting()
            if self.cancel_event.is_set():
                raise asyncio.CancelledError
            if chat_running():
                raise HistoryError('This Project / Chat became active before restoration started; wait for it to finish.')
            if self.resume_from_checkpoint and any(
                PROCESS_JOBS.has_running(workspace_key=str(ws.root.resolve()), chat_id=scope)
                for scope in ws.project_conflict_ids(self.chat_id)
            ):
                raise HistoryError('A background process is still writing this project or a related project. '
                                   'Stop or wait for it before resuming the checkpoint.')
            self.status = 'Restoring historical files…'
            if self.resume_from_checkpoint:
                worker = asyncio.create_task(asyncio.to_thread(
                    ws.resume_timeline_from_checkpoint, self.chat_id, self.message_id,
                    cancel_event=self.cancel_event,
                ))
            elif self.delete_only:
                worker = asyncio.create_task(asyncio.to_thread(
                    ws.delete_timeline_from_prompt, self.chat_id, self.message_id,
                    cancel_event=self.cancel_event,
                ))
            else:
                worker = asyncio.create_task(asyncio.to_thread(
                    ws.replace_timeline_from_history, self.chat_id, self.message_id,
                    include_attachment_ids=self.attachment_ids,
                    replacement_attachment_ids=self.staged_attachment_ids,
                    replacement_token=self.staging_token, cancel_event=self.cancel_event,
                ))
            try:
                result = await asyncio.shield(worker)
            except asyncio.CancelledError:
                # A thread cannot be killed safely. Keep the writer lease until
                # restoration cancels or finishes its atomic commit boundary.
                self.cancel_event.set()
                try:
                    result = await drain(worker)
                except Exception:
                    pass
                if result is not None:
                    mark_restored()
                raise
            mark_restored()
            if self.delete_only:
                self.outcome = 'deleted'
                self.status = (
                    f'Deleted {self.removed_message_count} timeline entries. Files, memories and task state '
                    'are restored to before this prompt. Undo latest rewind is available from the project menu.'
                )
                return
            if self.cancel_event.is_set():
                raise asyncio.CancelledError
            self.status = 'Queueing continue…' if self.resume_from_checkpoint else 'Queueing the edited prompt…'
            dispatch_prompt = 'continue' if self.resume_from_checkpoint else self.prompt
            ws.set_state(f'chat_runtime:{self.chat_id}', json.dumps({**self.selection, 'skill': 'auto'}))
            ws.set_state(f'chat_composer_draft:{self.chat_id}', dispatch_prompt)
            queued = enqueue(
                ws, self.chat_id, prompt=dispatch_prompt,
                attachment_ids=[] if self.resume_from_checkpoint else list(result.attachment_ids),
                profile_id=self.selection['profile_id'], thinking=self.selection['thinking'],
            )
            self.queued_job_id = str(queued['id'])
            self.outcome = 'queued'
            self.status = ('Checkpoint restored; continue queued.' if self.resume_from_checkpoint else
                           'Timeline restored; edited prompt queued.')
            ws.set_state(f'chat_composer_draft:{self.chat_id}', '')
        except asyncio.CancelledError:
            self.cancel_event.set()
            self.outcome = 'deleted' if self.delete_only and self.restored else 'cancelled'
            if self.resume_from_checkpoint:
                self.status = ('Checkpoint restored; continuation cancelled. Continue remains as a draft.'
                               if self.restored else 'Checkpoint resume cancelled. The timeline was not changed.')
            elif self.delete_only:
                self.status = ('Deletion finished before cancellation. Undo latest rewind is available.'
                               if self.restored else 'Timeline deletion cancelled. The timeline was not changed.')
            else:
                self.status = ('Timeline restored; sending cancelled. The edited prompt remains as a draft.'
                               if self.restored else 'Timeline replacement cancelled. The timeline was not changed.')
        except Exception as exc:
            if self.queued_job_id:
                self.outcome = 'queued'
                self.cleanup_error = str(exc) or type(exc).__name__
                self.status = f'Prompt queued, but draft cleanup failed: {exc}'
            else:
                self.outcome = 'deleted' if self.delete_only and self.restored else 'failed'
                if self.delete_only and self.restored:
                    self.cleanup_error = str(exc) or type(exc).__name__
                if self.resume_from_checkpoint:
                    self.status = (f'Checkpoint restored, but continuation failed: {exc}. Continue remains as a draft.'
                                   if self.restored else f'Checkpoint resume failed: {exc}')
                elif self.delete_only:
                    self.status = (f'Timeline deleted, but cleanup needs attention: {exc}' if self.restored else
                                   f'Timeline deletion failed: {exc}')
                else:
                    self.status = (f'Timeline restored, but sending failed: {exc}. The edited prompt remains as a draft.'
                                   if self.restored else f'Timeline replacement failed: {exc}')
        finally:
            clear_waiting()
            try:
                if self.restored and not self.queued_job_id and not self.delete_only:
                    ws.set_state(f'chat_composer_draft:{self.chat_id}',
                                 'continue' if self.resume_from_checkpoint else self.prompt)
                    self.draft_recovered = True
                if not self.restored and not self.delete_only and not self.resume_from_checkpoint:
                    ws.discard_timeline_staged_attachments(self.chat_id, self.staging_token)
            except Exception as exc:
                self.cleanup_error = str(exc) or type(exc).__name__
                self.status += f' Cleanup needs attention: {exc}'
            finally:
                if acquired:
                    await asyncio.shield(coordinator.release(workspace_id=ws.id, owner_id=owner))
