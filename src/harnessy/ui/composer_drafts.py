"""Coalesce unsent-message persistence without blocking the UI event loop."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
import uuid

from harnessy.core.memory_events import memory_lock
from harnessy.core.workspace import utcnow


@dataclass
class _Draft:
    store: Any
    chat_id: str
    value: str | None
    epoch: str | None = None
    revision: int = 0
    task: asyncio.Task | None = None
    on_error: Callable[[Exception], None] | None = None
    on_saved: Callable[[], None] | None = None
    failed: bool = False


class ComposerDraftWriter:
    """One ordered worker per workspace/chat, independent of browser lifetime.

    A clear is another ordered write, so an older save cannot finish after it
    and resurrect sent text. Rewind callers drain the same worker before their
    transaction and advance its browser epoch after restoration.
    """

    def __init__(self, *, debounce_seconds: float = 0.25) -> None:
        self.debounce_seconds = max(0.0, float(debounce_seconds))
        self._drafts: dict[tuple[str, str], _Draft] = {}
        self._epochs: dict[tuple[str, str], tuple[Any, str]] = {}

    @staticmethod
    def _key(store, chat_id: str) -> tuple[str, str]:
        return str(Path(store.root)), str(chat_id)

    @staticmethod
    def _same_generation(left, right) -> bool:
        return getattr(left, '_workspace_generation', None) == getattr(right, '_workspace_generation', None)

    def pending(self, store, chat_id: str) -> str | None:
        draft = self._drafts.get(self._key(store, chat_id))
        return draft.value if draft is not None and self._same_generation(draft.store, store) else None

    def failed(self, store, chat_id: str) -> bool:
        draft = self._drafts.get(self._key(store, chat_id))
        return bool(draft is not None and draft.failed and self._same_generation(draft.store, store))

    def browser_revision(self, store, chat_id: str) -> str:
        key = self._key(store, chat_id)
        draft = self._drafts.get(key)
        if draft is not None and draft.epoch is not None and self._same_generation(draft.store, store):
            return draft.epoch
        generation = getattr(store, '_workspace_generation', None)
        cached = self._epochs.get(key)
        if cached is not None and cached[0] == generation:
            return cached[1]
        epoch = store.get_state(f'chat_composer_draft_epoch:{chat_id}', '')
        self._epochs[key] = generation, epoch
        return epoch

    def submit(self, store, chat_id: str, value: str | None, *, reset: bool = False,
               on_error: Callable[[Exception], None] | None = None,
               on_saved: Callable[[], None] | None = None) -> str | None:
        key = self._key(store, chat_id)
        draft = self._drafts.get(key)
        if draft is None:
            draft = _Draft(store, str(chat_id), value)
            self._drafts[key] = draft
        draft.store, draft.value, draft.on_error = store, value, on_error
        draft.on_saved = on_saved
        draft.revision += 1
        if reset:
            draft.epoch = uuid.uuid4().hex
            self._epochs[key] = getattr(store, '_workspace_generation', None), draft.epoch
        draft.failed = False
        if draft.task is None or draft.task.done():
            draft.task = asyncio.create_task(self._save(key, draft), name='harnessy-composer-draft')
        return draft.epoch

    @staticmethod
    def _write(store, chat_id: str, value: str | None, epoch: str | None) -> None:
        # Keep existing memory/history serialization, but wait for it in the
        # worker. Checking chat existence in this same transaction prevents a
        # late save from recreating state belonging to a deleted project.
        with memory_lock(store.root):
            with store._connect() as con:
                con.execute('BEGIN IMMEDIATE')
                if con.execute('SELECT 1 FROM chats WHERE id=?', (chat_id,)).fetchone() is None:
                    return
                items = []
                if value is not None:
                    items.append((f'chat_composer_draft:{chat_id}', value))
                if epoch is not None:
                    items.append((f'chat_composer_draft_epoch:{chat_id}', epoch))
                for key, text in items:
                    con.execute(
                        'INSERT INTO workspace_state(key,value,updated_at) VALUES(?,?,?) '
                        'ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at',
                        (key, text, utcnow()),
                    )
                con.commit()

    async def _save(self, key, draft: _Draft) -> None:
        cancelled = False
        while True:
            try:
                await asyncio.sleep(self.debounce_seconds)
            except asyncio.CancelledError:
                cancelled = True
            revision = draft.revision
            store, value, epoch = draft.store, draft.value, draft.epoch
            on_error, on_saved = draft.on_error, draft.on_saved
            try:
                worker = asyncio.create_task(asyncio.to_thread(self._write, store, draft.chat_id, value, epoch))
                await self._drain(worker)
                draft.failed = False
                if on_saved is not None:
                    on_saved()
            except asyncio.CancelledError:
                cancelled = True
            except Exception as exc:
                draft.failed = True
                if on_error is not None:
                    try:
                        on_error(exc)
                    except Exception:
                        pass  # A deleted page's notification cannot strand the worker.
            if revision != draft.revision:
                continue
            draft.task = None
            if not draft.failed and self._drafts.get(key) is draft:
                self._drafts.pop(key, None)
            if cancelled:
                raise asyncio.CancelledError
            return

    @staticmethod
    async def _drain(task: asyncio.Task) -> Any:
        cancelled = False
        while True:
            try:
                result = await asyncio.shield(task)
                break
            except asyncio.CancelledError:
                cancelled = True
                if task.done():
                    result = task.result()
                    break
        if cancelled:
            raise asyncio.CancelledError
        return result

    async def flush(self, store, chat_id: str) -> None:
        draft = self._drafts.get(self._key(store, chat_id))
        if draft is not None and draft.task is not None:
            await self._drain(draft.task)

    async def flush_all(self) -> None:
        while tasks := [draft.task for draft in self._drafts.values() if draft.task is not None]:
            await self._drain(asyncio.create_task(self._join(tasks)))

    @staticmethod
    async def _join(tasks) -> None:
        await asyncio.gather(*tasks)


COMPOSER_DRAFTS = ComposerDraftWriter()
