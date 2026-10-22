"""Session-bound access to the exact PDF shown in an open print preview."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from io import BytesIO
import logging
import math
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time
from typing import Any
from urllib.parse import quote

from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response, StreamingResponse

from harnessy.agent.print_exports import PrintExportJob


PREFIX = '/api/harnessy/chat-print/'
_TOKEN = re.compile(r'^[a-f0-9]{64}$')
_MAX_LEASES = 32
_LEASES: dict[str, 'PrintPreviewLease'] = {}
_LEASES_LOCK = threading.RLock()
_ROUTE_APPS: set[int] = set()
_PDFIUM_LOCK = threading.Lock()
_PAGE_RENDER_SLOTS = threading.BoundedSemaphore(2)
_PAGE_RENDER_SCALE = 1.4
_MAX_PAGE_PIXELS = 8_000_000
_MAX_PNG_BYTES = 16 * 1024 * 1024


class _HidePreviewTokens(logging.Filter):
    @staticmethod
    def clean(value: Any) -> Any:
        if isinstance(value, str):
            return re.sub(r'/api/harnessy/chat-print/[a-f0-9]{64}', PREFIX + '<preview>', value)
        return value

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self.clean(record.msg)
        if isinstance(record.args, tuple):
            record.args = tuple(self.clean(item) for item in record.args)
        elif isinstance(record.args, dict):
            record.args = {key: self.clean(value) for key, value in record.args.items()}
        return True


@dataclass(repr=False)
class PrintPreviewLease:
    token: str
    job: PrintExportJob
    accounts: Any
    machine: Any
    created: float = field(default_factory=time.monotonic)
    closed: bool = False
    _streams: set[threading.Event] = field(default_factory=set, repr=False)
    _streams_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def preview_url(self) -> str:
        return f'{PREFIX}{self.token}/preview.pdf'

    @property
    def download_url(self) -> str:
        return f'{PREFIX}{self.token}/download.pdf'

    def page_url(self, page_number: int) -> str:
        if type(page_number) is not int or page_number < 1:
            raise ValueError('PDF page numbers start at 1.')
        return f'{PREFIX}{self.token}/page/{page_number}.png'

    def close(self) -> None:
        with _LEASES_LOCK:
            self.closed = True
            if _LEASES.get(self.token) is self:
                _LEASES.pop(self.token, None)
        with self._streams_lock:
            streams = tuple(self._streams)
        for stop in streams:
            stop.set()

    def active(self) -> bool:
        try:
            return (not self.closed and self.accounts._active()
                    and str(self.accounts.username) == self.job.owner_username)
        except Exception:
            return False

    async def authorized(self, request: Request) -> bool:
        if not self.active():
            self.close()
            return False
        # The normal login middleware has already validated the requesting
        # cookie and supplies this server-owned username on every HTTP route.
        username = str(request.scope.get('state', {}).get('harnessy_username') or '')
        if username != self.job.owner_username:
            return False
        try:
            await self.accounts._require_session()
            if not self.active():
                return False
            valid = await asyncio.to_thread(self._workspace_valid)
            if not valid:
                self.close()
            return valid
        except Exception:
            self.close()
            return False

    def _workspace_valid(self) -> bool:
        job = self.job
        if job.state != 'complete' or job.path is None or job.identity is None:
            return False
        registration = self.machine.get_workspace(str(job.workspace.id))
        root = Path(job.workspace.root).resolve(strict=True)
        if registration is None or Path(registration.path).resolve(strict=True) != root:
            return False
        # A disconnected/deleted workspace must not be recreated merely by
        # requesting an old preview URL. Reads use a short, read-only handle.
        with job.workspace._connect(readonly=True, timeout=.25) as connection:
            if connection.execute('SELECT 1 FROM chats WHERE id=?', (job.chat_id,)).fetchone() is None:
                return False
        path = Path(job.path)
        directory = Path(job.workspace.artifacts_dir) / job.chat_id
        if not path.is_absolute() or path.parent != directory or path.suffix.lower() != '.pdf':
            return False
        if not path.resolve(strict=True).is_relative_to(root):
            return False
        current = root
        for component in path.relative_to(root).parts:
            current = current / component
            if current.is_symlink():
                return False
        return job.identity.matches(path.lstat())


def _prune() -> None:
    with _LEASES_LOCK:
        for lease in list(_LEASES.values()):
            if not lease.active():
                lease.close()
        while len(_LEASES) >= _MAX_LEASES:
            min(_LEASES.values(), key=lambda value: value.created).close()


def _new_lease(job: PrintExportJob, accounts: Any, machine: Any) -> PrintPreviewLease:
    if (job.state != 'complete' or job.path is None or job.identity is None
            or accounts is None or not accounts._active()
            or str(accounts.username) != job.owner_username):
        raise ValueError('This PDF is no longer available to the signed-in session.')
    return PrintPreviewLease(secrets.token_hex(32), job, accounts, machine)


def _register_lease(lease: PrintPreviewLease) -> PrintPreviewLease:
    with _LEASES_LOCK:
        _prune()
        _LEASES[lease.token] = lease
    return lease


def create_print_preview(job: PrintExportJob, accounts: Any, machine: Any) -> PrintPreviewLease:
    """Synchronous factory for worker callers; UI callbacks use the async form."""
    lease = _new_lease(job, accounts, machine)
    if not lease._workspace_valid():
        raise ValueError('The completed PDF is unavailable or has changed. Generate a new preview.')
    return _register_lease(lease)


async def create_print_preview_async(job: PrintExportJob, accounts: Any, machine: Any) -> PrintPreviewLease:
    """Keep filesystem/database reads off the UI loop and registration on it."""
    lease = _new_lease(job, accounts, machine)
    await accounts._require_session()
    if not await asyncio.to_thread(lease._workspace_valid):
        raise ValueError('The completed PDF is unavailable or has changed. Generate a new preview.')
    await accounts._require_session()
    if not lease.active():
        raise ValueError('This PDF is no longer available to the signed-in session.')
    return _register_lease(lease)


def close_print_previews() -> None:
    with _LEASES_LOCK:
        leases = list(_LEASES.values())
    for lease in leases:
        lease.close()


def _range(value: str, size: int) -> tuple[int, int] | None:
    if not value:
        return (0, size - 1)
    if len(value) > 128:
        return None
    found = re.fullmatch(r'bytes=(\d*)-(\d*)', value.strip())
    if found is None or not any(found.groups()):
        return None
    first, last = found.groups()
    if not first:
        count = int(last)
        return (max(0, size - count), size - 1) if count > 0 else None
    start = int(first)
    end = min(size - 1, int(last)) if last else size - 1
    return (start, end) if 0 <= start <= end < size else None


async def _serve(request: Request, token: str, download: bool) -> Response:
    lease = _LEASES.get(token) if _TOKEN.fullmatch(token) else None
    headers = {'Cache-Control': 'no-store, private', 'X-Content-Type-Options': 'nosniff',
               'Referrer-Policy': 'no-referrer'}
    if lease is None or not await lease.authorized(request):
        return PlainTextResponse('PDF preview is unavailable. Generate a new preview.', status_code=404, headers=headers)
    job = lease.job
    assert job.path is not None and job.identity is not None
    fd = None
    try:
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
        fd, info = await _open_completed_pdf(job)
        if not await lease.authorized(request):
            raise ValueError('PDF changed')
        size = info.st_size
        selected = _range(request.headers.get('range', ''), size)
        if selected is None:
            os.close(fd); fd = None
            return Response(status_code=416, headers={**headers, 'Content-Range': f'bytes */{size}'})
        start, end = selected
        length = end - start + 1
        ranged = bool(request.headers.get('range'))
        headers.update({'Content-Length': str(length), 'Accept-Ranges': 'bytes',
                        'Content-Type': 'application/pdf'})
        fallback = re.sub(r'[^A-Za-z0-9._-]', '_', job.path.name) or 'Chat.pdf'
        disposition = 'attachment' if download else 'inline'
        headers['Content-Disposition'] = f'{disposition}; filename="{fallback}"; filename*=UTF-8\'\'{quote(job.path.name, safe="")}'
        if ranged:
            headers['Content-Range'] = f'bytes {start}-{end}/{size}'
        if request.method == 'HEAD':
            os.close(fd); fd = None
            return Response(status_code=206 if ranged else 200, headers=headers)
        # Do not retain an open descriptor if the browser disconnects before
        # StreamingResponse starts iterating. Reopen with the same no-follow
        # flags and identity check inside the iterator itself.
        os.close(fd)
        fd = None
        path = job.path
        identity = job.identity
        stop = threading.Event()

        def stream():
            remaining = length
            stream_fd = None
            try:
                if stop.is_set() or not lease.active():
                    return
                with lease._streams_lock:
                    lease._streams.add(stop)
                stream_fd = os.open(path, flags)
                if not identity.matches(os.fstat(stream_fd)):
                    return
                os.lseek(stream_fd, start, os.SEEK_SET)
                while remaining > 0:
                    if stop.is_set() or not lease.active() or not identity.matches(os.fstat(stream_fd)):
                        break
                    block = os.read(stream_fd, min(64 * 1024, remaining))
                    if not block:
                        break
                    # No response payload leaves the process after close or
                    # revocation observed while this block was being read.
                    if stop.is_set() or not lease.active():
                        break
                    remaining -= len(block)
                    yield block
            finally:
                if stream_fd is not None:
                    os.close(stream_fd)
                with lease._streams_lock:
                    lease._streams.discard(stop)

        return StreamingResponse(stream(), status_code=206 if ranged else 200, headers=headers)
    except (OSError, ValueError):
        lease.close()
        return PlainTextResponse('The completed PDF changed or is no longer available.', status_code=404, headers=headers)
    finally:
        if fd is not None:
            os.close(fd)


async def _open_completed_pdf(job: PrintExportJob) -> tuple[int, os.stat_result]:
    def open_file() -> tuple[int, os.stat_result]:
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
        fd = os.open(job.path, flags)
        try:
            info = os.fstat(fd)
            if job.identity is None or not job.identity.matches(info):
                raise ValueError('The completed PDF changed.')
            return fd, info
        except BaseException:
            os.close(fd)
            raise
    worker = asyncio.create_task(asyncio.to_thread(open_file))
    try:
        return await asyncio.shield(worker)
    except asyncio.CancelledError:
        # The thread may finish opening after its HTTP request is cancelled.
        # Reap its result and close that descriptor instead of leaking it.
        while not worker.done():
            try:
                await asyncio.shield(worker)
            except asyncio.CancelledError:
                pass
            except Exception:
                break
        try:
            fd, _ = worker.result()
            os.close(fd)
        except Exception:
            pass
        raise


def _render_page(lease: PrintPreviewLease, page_number: int) -> bytes:
    """Rasterize one bounded page from the same immutable PDF as download."""
    import pypdfium2 as pdfium

    job = lease.job
    if job.path is None or job.identity is None or not lease.active():
        raise ValueError('PDF preview is unavailable.')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
    fd = os.open(job.path, flags)
    document = page = bitmap = image = None
    try:
        if not job.identity.matches(os.fstat(fd)):
            raise ValueError('The completed PDF changed.')
        with os.fdopen(fd, 'rb') as source:
            fd = None
            # PDFium itself is process-global and not thread-safe. A small
            # request permit pool also bounds threads waiting for this lock.
            with _PDFIUM_LOCK:
                if not lease.active():
                    raise ValueError('PDF preview is unavailable.')
                try:
                    document = pdfium.PdfDocument(source, autoclose=False)
                    if page_number > len(document):
                        raise ValueError('This page is outside the completed PDF.')
                    page = document[page_number - 1]
                    width, height = page.get_size()
                    pixels = math.ceil(width * _PAGE_RENDER_SCALE) * math.ceil(height * _PAGE_RENDER_SCALE)
                    if (not math.isfinite(width) or not math.isfinite(height) or width <= 0 or height <= 0
                            or pixels > _MAX_PAGE_PIXELS):
                        raise ValueError('This PDF page is too large to preview.')
                    bitmap = page.render(scale=_PAGE_RENDER_SCALE, may_draw_forms=False)
                    image = bitmap.to_pil()
                    output = BytesIO()
                    image.save(output, format='PNG')
                    data = output.getvalue()
                    if len(data) > _MAX_PNG_BYTES:
                        raise ValueError('This PDF page is too large to preview.')
                    if not job.identity.matches(os.fstat(source.fileno())) or not lease.active():
                        raise ValueError('The completed PDF changed or the session ended.')
                    return data
                finally:
                    # All native object destruction stays under the same
                    # process-wide lock, including failed/aborted rendering.
                    for item in (image, bitmap, page, document):
                        if item is not None:
                            item.close()
    finally:
        if fd is not None:
            os.close(fd)


async def _serve_page(request: Request, token: str, page_number: int) -> Response:
    headers = {'Cache-Control': 'no-store, private', 'X-Content-Type-Options': 'nosniff',
               'Referrer-Policy': 'no-referrer'}
    lease = _LEASES.get(token) if _TOKEN.fullmatch(token) else None
    if lease is None or not await lease.authorized(request):
        return PlainTextResponse('PDF preview is unavailable. Generate a new preview.', status_code=404, headers=headers)
    pages = lease.job.stats.get('pages')
    if type(page_number) is not int or type(pages) is not int or not 1 <= page_number <= pages:
        return PlainTextResponse('This page is outside the completed PDF.', status_code=404, headers=headers)
    if not _PAGE_RENDER_SLOTS.acquire(blocking=False):
        return PlainTextResponse('PDF preview is busy. Try this page again shortly.', status_code=429,
                                 headers={**headers, 'Retry-After': '1'})
    worker = asyncio.create_task(asyncio.to_thread(_render_page, lease, page_number))
    try:
        try:
            data = await asyncio.shield(worker)
        except asyncio.CancelledError:
            # Do not free a native-rendering permit while its thread is still
            # running. No bytes are returned to a disconnected caller.
            while not worker.done():
                try:
                    await asyncio.shield(worker)
                except asyncio.CancelledError:
                    pass
                except Exception:
                    break
            try:
                worker.result()
            except Exception:
                pass
            raise
        if not await lease.authorized(request):
            return PlainTextResponse('PDF preview is unavailable.', status_code=404, headers=headers)
        if request.method == 'HEAD':
            return Response(status_code=200, media_type='image/png',
                            headers={**headers, 'Content-Length': str(len(data))})
        return Response(data, media_type='image/png', headers=headers)
    except asyncio.CancelledError:
        raise
    except Exception:
        return PlainTextResponse('This PDF page could not be previewed. Generate a new preview or download the PDF.',
                                 status_code=404, headers=headers)
    finally:
        _PAGE_RENDER_SLOTS.release()


def register_print_preview_routes(app: Any, machine: Any) -> None:
    """Register ordinary authenticated routes, with no login-gate exceptions."""
    if id(app) in _ROUTE_APPS:
        return
    _ROUTE_APPS.add(id(app))
    logging.getLogger('uvicorn.access').addFilter(_HidePreviewTokens())

    @app.api_route(PREFIX + '{token}/preview.pdf', methods=['GET', 'HEAD'])
    async def preview(request: Request, token: str) -> Response:
        return await _serve(request, token, False)

    @app.api_route(PREFIX + '{token}/download.pdf', methods=['GET', 'HEAD'])
    async def download(request: Request, token: str) -> Response:
        return await _serve(request, token, True)

    @app.api_route(PREFIX + '{token}/page/{page_number}.png', methods=['GET', 'HEAD'])
    async def page_image(request: Request, token: str, page_number: int) -> Response:
        return await _serve_page(request, token, page_number)

    if hasattr(app, 'on_shutdown'):
        app.on_shutdown(close_print_previews)
