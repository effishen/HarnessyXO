"""Process-owned, cancellable exports of saved chat history to printable PDFs."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import hashlib
import inspect
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import threading
import time
from typing import Any, Awaitable, Callable
import uuid

from harnessy.core.print_export import PrintExportOptions, PrintSnapshot

_HAS_DIR_FDS = (os.name != 'nt' and os.open in os.supports_dir_fd and os.link in os.supports_dir_fd)


@dataclass(frozen=True, slots=True)
class PrintFileIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int

    @classmethod
    def from_stat(cls, info: os.stat_result) -> 'PrintFileIdentity':
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('The completed PDF must be a regular private file.')
        return cls(info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    def matches(self, info: os.stat_result) -> bool:
        try:
            return self == self.from_stat(info)
        except ValueError:
            return False


Authorize = Callable[[], Awaitable[Any] | Any]


@dataclass
class PrintExportJob:
    workspace: Any
    chat_id: str
    options: PrintExportOptions
    owner_username: str
    active_at_start: bool = False
    authorize: Authorize | None = field(default=None, repr=False)
    state: str = 'queued'
    status: str = 'Preparing printable PDF…'
    error: str = ''
    path: Path | None = None
    task: asyncio.Task | None = field(default=None, repr=False)
    cancel_flag: threading.Event = field(default_factory=threading.Event, repr=False)
    stats: dict[str, Any] = field(default_factory=dict)
    identity: PrintFileIdentity | None = None
    sha256: str = ''
    captured_at: str = ''
    created: float = field(default_factory=time.monotonic)
    job_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.owner_username, str(self.workspace.id), self.chat_id)

    @property
    def running(self) -> bool:
        return self.task is not None and not self.task.done()

    def update(self, text: str) -> None:
        self.status = str(text)

    def start(self) -> None:
        self.options.validate()
        if not self.owner_username:
            raise ValueError('Sign in again before exporting this chat.')
        old = PRINT_EXPORT_JOBS.get(self.key)
        if self.running or (old is not None and old.running):
            raise ValueError('A printable PDF is already being prepared for this chat.')
        _prune_jobs()
        PRINT_EXPORT_JOBS[self.key] = self
        self.task = asyncio.create_task(self.run(), name=f'harnessy-print-{self.chat_id}')

    def cancel(self) -> None:
        if not self.running:
            return
        if self.state == 'publishing':
            self.update('The completed PDF is being saved. It will be ready shortly.')
            return
        self.cancel_flag.set()
        self.state = 'cancelling'
        self.update('Cancelling PDF export…')
        assert self.task is not None
        self.task.cancel()

    async def _authorized(self) -> None:
        if self.cancel_flag.is_set():
            raise asyncio.CancelledError()
        if self.authorize is not None:
            result = self.authorize()
            if inspect.isawaitable(result):
                result = await result
            if result is False:
                raise PermissionError('This chat is no longer available to the signed-in session.')

    async def _worker(self, function: Callable[[], Any], *, publishing: bool = False) -> Any:
        """Join a worker before removing its snapshot or partial output."""
        worker = asyncio.create_task(asyncio.to_thread(function))
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError:
            if not publishing:
                self.cancel_flag.set()
            # Repeated shutdown cancellation must not abandon a live worker
            # while cleanup deletes the snapshot/file it is still using.
            while not worker.done():
                try:
                    await asyncio.shield(worker)
                except asyncio.CancelledError:
                    if not publishing:
                        self.cancel_flag.set()
                except Exception:
                    break
            if publishing:
                return worker.result()
            try:
                worker.result()
            except Exception:
                pass
            raise

    def _destination(self) -> Path:
        root = Path(self.workspace.root).resolve(strict=True)
        artifacts = Path(self.workspace.artifacts_dir)
        if not artifacts.is_absolute():
            artifacts = root / artifacts
        try:
            relative = artifacts.relative_to(root)
        except ValueError:
            raise ValueError('The chat export folder is outside this workspace.') from None
        if not self.chat_id or Path(self.chat_id).name != self.chat_id or self.chat_id in {'.', '..'}:
            raise ValueError('The chat export folder is invalid.')
        current = root
        for component in (*relative.parts, self.chat_id):
            current = current / component
            if current.is_symlink():
                raise ValueError('The chat export folder cannot be redirected by a symlink.')
            current.mkdir(exist_ok=True)
            if not current.is_dir():
                raise ValueError('The chat export folder is not a directory.')
        if not current.resolve(strict=True).is_relative_to(root):
            raise ValueError('The chat export folder is outside this workspace.')
        return current

    def _publish(self, source: Path, destination: Path) -> tuple[Path, PrintFileIdentity, str]:
        """Publish complete bytes once; never expose a .partial file."""
        final = destination / source.name
        staged_name = '.' + source.name + '.' + uuid.uuid4().hex + '.partial'
        staged = destination / staged_name
        digest = hashlib.sha256()
        identity = None
        published_inode = None
        published = False
        directory_fd = None

        def unchanged_directory() -> None:
            if self._destination() != destination:
                raise ValueError('The chat export folder changed while the PDF was saved.')
            if directory_fd is not None:
                current, opened = destination.lstat(), os.fstat(directory_fd)
                if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                    raise ValueError('The chat export folder changed while the PDF was saved.')

        try:
            if _HAS_DIR_FDS:
                # Bind writes to the actual private directory, opening each
                # descendant without following symlinks. A renamed/replaced
                # pathname cannot redirect these writes to a different folder.
                flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0)
                root = Path(self.workspace.root).resolve(strict=True)
                directory_fd = os.open(root, flags)
                for component in destination.relative_to(root).parts:
                    child = os.open(component, flags, dir_fd=directory_fd)
                    os.close(directory_fd)
                    directory_fd = child
            unchanged_directory()
            # A unique exclusive destination prevents replacing a pre-existing
            # file or following a destination symlink during the copy.
            if directory_fd is not None:
                staged_fd = os.open(staged_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                    | getattr(os, 'O_NOFOLLOW', 0), 0o600, dir_fd=directory_fd)
                out = os.fdopen(staged_fd, 'wb')
            else:
                out = staged.open('xb')
            with source.open('rb') as inp, out:
                if inp.read(5) != b'%PDF-':
                    raise ValueError('The renderer did not return a PDF.')
                inp.seek(0)
                while block := inp.read(256 * 1024):
                    digest.update(block)
                    out.write(block)
                out.flush()
                os.fsync(out.fileno())
                copied = os.fstat(out.fileno())
                published_inode = (copied.st_dev, copied.st_ino)
            unchanged_directory()
            if directory_fd is not None:
                # link() fails atomically if the final name already exists.
                # Remove the temporary link before taking the immutable file
                # identity so the finished PDF has exactly one link.
                os.link(staged_name, final.name, src_dir_fd=directory_fd,
                        dst_dir_fd=directory_fd, follow_symlinks=False)
                published = True
                os.unlink(staged_name, dir_fd=directory_fd)
            elif os.name == 'nt':
                # Windows rename is atomic and refuses an existing target.
                os.rename(staged, final)
            else:
                # Other Python/filesystem combinations still get atomic
                # no-overwrite publication; unsupported hard links fail cleanly.
                os.link(staged, final, follow_symlinks=False)
                staged.unlink()
            published = True
            unchanged_directory()
            identity = PrintFileIdentity.from_stat(final.lstat())
            self.workspace.register_artifact_path(self.chat_id, final)
            return final, identity, digest.hexdigest()
        except Exception:
            if published:
                try:
                    if directory_fd is not None:
                        info = os.stat(final.name, dir_fd=directory_fd, follow_symlinks=False)
                        if (identity.matches(info) if identity is not None else
                                (info.st_dev, info.st_ino) == published_inode):
                            os.unlink(final.name, dir_fd=directory_fd)
                    else:
                        info = final.lstat()
                        if (identity.matches(info) if identity is not None else
                                published_inode is not None and published_inode[1] != 0
                                and (info.st_dev, info.st_ino) == published_inode):
                            final.unlink()
                except OSError:
                    pass
            raise
        finally:
            try:
                if directory_fd is not None:
                    try:
                        os.unlink(staged_name, dir_fd=directory_fd)
                    except FileNotFoundError:
                        pass
                else:
                    staged.unlink(missing_ok=True)
            finally:
                if directory_fd is not None:
                    os.close(directory_fd)

    async def run(self) -> None:
        directory = Path(tempfile.mkdtemp(prefix='harnessy-print-'))
        slots = _export_slots()
        acquired = False
        try:
            self.update('Waiting for a PDF export slot…')
            await slots.acquire()
            acquired = True
            await self._authorized()
            self.state = 'snapshotting'
            self.update('Reading a saved-history snapshot…')
            snapshot = await self._worker(lambda: PrintSnapshot.capture(
                self.workspace, self.chat_id, directory,
                active=self.active_at_start, cancel=self.cancel_flag))
            self.captured_at = str(snapshot.captured_at)
            title = re.sub(r'[^\w.-]+', '-', str(snapshot.title), flags=re.UNICODE).strip('-.')[:60] or 'Chat'
            name = f'{title}-Printable-{time.strftime("%Y%m%d-%H%M%S")}-{self.job_id[:12]}.pdf'
            output = directory / name
            self.state = 'rendering'
            self.update('Laying out the printable PDF…')
            # Keep renderer imports lazy: opening the app remains possible
            # while the launcher repairs an incomplete dependency install.
            from harnessy.core.print_pdf import render_print_pdf
            result = await self._worker(lambda: render_print_pdf(
                snapshot, self.options, output, cancel=self.cancel_flag, progress=self.update))
            self.stats = dict(result or {})
            await self._authorized()
            destination = await self._worker(self._destination)
            await self._authorized()
            self.state = 'publishing'
            self.update('Saving the completed PDF…')
            self.path, self.identity, self.sha256 = await self._worker(
                lambda: self._publish(output, destination), publishing=True)
            self.state = 'complete'
            pages = self.stats.get('pages')
            self.update(f'PDF ready · {pages:,} pages' if isinstance(pages, int) else 'PDF ready')
        except asyncio.CancelledError:
            self.state = 'cancelled'
            self.update('PDF export cancelled. Your chat and running model are unchanged.')
        except Exception as exc:
            if self.cancel_flag.is_set():
                self.state = 'cancelled'
                self.update('PDF export cancelled. Your chat and running model are unchanged.')
            else:
                self.error = str(exc)
                self.state = 'failed'
                self.update('PDF export failed: ' + str(exc))
        finally:
            try:
                await self._worker(lambda: shutil.rmtree(directory, ignore_errors=True), publishing=True)
            finally:
                if acquired:
                    slots.release()


PRINT_EXPORT_JOBS: dict[tuple[str, str, str], PrintExportJob] = {}
_SLOTS_LOOP: asyncio.AbstractEventLoop | None = None
_SLOTS: asyncio.Semaphore | None = None


def _export_slots() -> asyncio.Semaphore:
    global _SLOTS_LOOP, _SLOTS
    loop = asyncio.get_running_loop()
    if _SLOTS_LOOP is not loop or _SLOTS is None:
        _SLOTS_LOOP, _SLOTS = loop, asyncio.Semaphore(2)
    return _SLOTS


def _prune_jobs() -> None:
    completed = sorted((job for job in PRINT_EXPORT_JOBS.values() if not job.running), key=lambda job: job.created)
    for job in completed[:-63]:
        if PRINT_EXPORT_JOBS.get(job.key) is job:
            PRINT_EXPORT_JOBS.pop(job.key, None)


async def close_print_exports() -> None:
    jobs = [job for job in PRINT_EXPORT_JOBS.values() if job.running]
    for job in jobs:
        job.cancel()
    if jobs:
        await asyncio.gather(*(job.task for job in jobs if job.task is not None), return_exceptions=True)
