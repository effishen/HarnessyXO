"""Official Windows installer discovery, private caching and verified downloads.

No third-party media, activation changes, or download-protection bypasses are
used. Microsoft can decline a download request; that remains an explicit error.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
import hashlib
from html.parser import HTMLParser
import inspect
import json
import os
from pathlib import Path
import re
import stat
import threading
import time
from urllib.parse import urljoin, urlsplit
import uuid
import weakref

import httpx

MEDIA_TIMEOUT_SECONDS = 7200
MAX_ISO_BYTES = 16 * 1024**3
MIN_ISO_BYTES = 32 * 1024**2
MAX_METADATA_BYTES = 2 * 1024**2
_DOWNLOAD_HOSTS = frozenset({'software.download.prss.microsoft.com',
    'software-download.microsoft.com', 'software.download.microsoft.com', 'download.microsoft.com'})
_SHA256 = re.compile(r'^[0-9a-f]{64}$')
_LOCKS = weakref.WeakValueDictionary()


class WindowsMediaError(RuntimeError):
    def __init__(self, code: str) -> None:
        messages = {
            'WINDOWS_ISO_ARCHITECTURE_UNSUPPORTED': 'Choose x86-64 or ARM64 for Windows 11.',
            'WINDOWS_ISO_METADATA_INVALID': 'Microsoft did not provide matching Windows 11 English (United States) installer details. Retry the download or select your own compatible official ISO.',
            'WINDOWS_ISO_DOWNLOAD_BLOCKED': 'Microsoft could not authorize the automatic ISO download from this host. Retry later or select your own Windows 11 English (United States) multi-edition ISO from Microsoft.',
            'WINDOWS_ISO_NETWORK_FAILED': 'The Windows installer download could not reach Microsoft. Check the host internet connection and retry; completed download bytes are retained when safe.',
            'WINDOWS_ISO_DOWNLOAD_TIMEOUT': 'The Windows installer download reached its time limit. Retry to resume the download.',
            'WINDOWS_ISO_DOWNLOAD_INVALID': 'Microsoft did not return a valid installer download. No VM was created; retry or select your own compatible ISO.',
            'WINDOWS_ISO_CHECKSUM_FAILED': 'The Windows installer does not match Microsoft’s published SHA256 checksum. No VM was created. Retry the download.',
            'WINDOWS_ISO_STORAGE_UNSAFE': 'The Windows installer cache is unavailable or has unsafe files. Check its host storage and permissions.',
            'WINDOWS_ISO_STORAGE_FULL': 'There is not enough free host storage to download the Windows installer ISO.',
            'WINDOWS_ISO_PROXY_UNAVAILABLE': 'The host proxy settings require optional SOCKS support that is unavailable. Check the host proxy configuration or select your own official Windows installer ISO.',
        }
        self.error_code = code if code in messages else 'WINDOWS_ISO_DOWNLOAD_INVALID'
        self.code = self.error_code
        super().__init__(messages[self.error_code])


def normalize_windows_architecture(value: str) -> str:
    result = {'x86_64': 'x86_64', 'amd64': 'x86_64', 'x64': 'x86_64',
              'arm64': 'arm64', 'aarch64': 'arm64'}.get(str(value).lower())
    if result is None:
        raise WindowsMediaError('WINDOWS_ISO_ARCHITECTURE_UNSUPPORTED')
    return result


@dataclass(frozen=True)
class WindowsMedia:
    architecture: str
    url: str
    sha256: str


def _client():
    try:
        return httpx.AsyncClient(timeout=httpx.Timeout(60, connect=20), follow_redirects=False,
                                 headers={'User-Agent': 'HarnessyXO Windows installer downloader'})
    except ImportError:
        raise WindowsMediaError('WINDOWS_ISO_PROXY_UNAVAILABLE') from None


class _Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.select = False
        self.option = None
        self.options = []
        self.row = None
        self.cell = None
        self.rows = []
        self.scripts = []
        self.endpoint = ''

    def handle_starttag(self, tag, attributes):
        data = dict(attributes)
        if tag == 'select':
            self.select = data.get('id') == 'product-edition'
        elif tag == 'option' and self.select:
            self.option = [data.get('value', ''), []]
        elif tag == 'tr':
            self.row = []
        elif tag in {'td', 'th'} and self.row is not None:
            self.cell = []
        elif tag == 'script' and data.get('src'):
            self.scripts.append(data['src'])
        elif tag == 'input' and data.get('id') == 'endpoint-svc':
            self.endpoint = data.get('value', '')

    def handle_data(self, value):
        if self.option is not None:
            self.option[1].append(value)
        if self.cell is not None:
            self.cell.append(value)

    def handle_endtag(self, tag):
        if tag == 'select':
            self.select = False
        elif tag == 'option' and self.option is not None:
            self.options.append((self.option[0], ' '.join(''.join(self.option[1]).split())))
            self.option = None
        elif tag in {'td', 'th'} and self.cell is not None:
            self.row.append(' '.join(''.join(self.cell).split()))
            self.cell = None
        elif tag == 'tr' and self.row is not None:
            self.rows.append(self.row)
            self.row = None


def official_media_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        return (parsed.scheme == 'https' and parsed.hostname in _DOWNLOAD_HOSTS
                and parsed.port in {None, 443} and not parsed.username and not parsed.password
                and parsed.path.lower().endswith('.iso') and not parsed.fragment
                and not any(c in url for c in '\x00\r\n'))
    except (TypeError, ValueError):
        return False


def _metadata_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        return (parsed.scheme == 'https' and parsed.hostname == 'www.microsoft.com'
                and parsed.port in {None, 443} and not parsed.username and not parsed.password
                and not parsed.fragment and not any(c in url for c in '\x00\r\n'))
    except (TypeError, ValueError):
        return False


@asynccontextmanager
async def _response(client, url: str, *, media: bool = False, headers=None):
    allowed = official_media_url if media else _metadata_url
    response = None
    try:
        for _ in range(6):
            if not allowed(url):
                raise WindowsMediaError('WINDOWS_ISO_DOWNLOAD_INVALID' if media else 'WINDOWS_ISO_METADATA_INVALID')
            response = await client.send(client.build_request('GET', url, headers=headers), stream=True)
            if response.status_code not in {301, 302, 303, 307, 308}:
                break
            target = response.headers.get('location')
            await response.aclose()
            if not target:
                raise WindowsMediaError('WINDOWS_ISO_DOWNLOAD_INVALID')
            url = urljoin(url, target)
        else:
            raise WindowsMediaError('WINDOWS_ISO_DOWNLOAD_INVALID')
        if response.status_code in {401, 403, 429}:
            raise WindowsMediaError('WINDOWS_ISO_DOWNLOAD_BLOCKED')
        if not (media and response.status_code == 416):
            response.raise_for_status()
        yield response
    except httpx.HTTPError:
        raise WindowsMediaError('WINDOWS_ISO_NETWORK_FAILED') from None
    finally:
        if response is not None:
            await response.aclose()


async def _metadata(client, url: str, *, json_document=False):
    body = bytearray()
    async with _response(client, url) as response:
        async for chunk in response.aiter_bytes(65536):
            body.extend(chunk)
            if len(body) > MAX_METADATA_BYTES:
                raise WindowsMediaError('WINDOWS_ISO_METADATA_INVALID')
    try:
        return json.loads(body) if json_document else body.decode('utf-8')
    except (ValueError, UnicodeError):
        raise WindowsMediaError('WINDOWS_ISO_METADATA_INVALID') from None


def _page_details(text: str, architecture: str):
    page = _Page()
    try:
        page.feed(text)
    except Exception:
        raise WindowsMediaError('WINDOWS_ISO_METADATA_INVALID') from None
    architecture_word = 'arm64' if architecture == 'arm64' else 'x64'
    editions = [number for number, label in page.options if number.isdecimal()
                and 'windows 11' in label.lower() and 'multi-edition' in label.lower()
                and architecture_word in label.lower()]
    digests = [row[1].lower() for row in page.rows if len(row) == 2
               and row[0] in {'English 64-bit', 'English (United States) 64-bit'}
               and _SHA256.fullmatch(row[1].lower())]
    if len(editions) != 1 or len(set(digests)) != 1:
        raise WindowsMediaError('WINDOWS_ISO_METADATA_INVALID')
    return editions[0], digests[0]


async def resolve_windows_iso(architecture: str, client=None, *, progress=None, cancel_event=None) -> WindowsMedia:
    architecture = normalize_windows_architecture(architecture)
    if client is None:
        async with _client() as owned:
            return await resolve_windows_iso(architecture, owned, progress=progress, cancel_event=cancel_event)
    page_url = 'https://www.microsoft.com/en-us/software-download/windows11' + ('arm64' if architecture == 'arm64' else '')
    _edition, digest = _page_details(await _metadata(client, page_url), architecture)
    # Microsoft's normal public page initializes its own download session.
    # Do not synthesize telemetry or retry a rejected direct download-link API.
    from .windows_media_browser import resolve_windows_iso_link
    url = await resolve_windows_iso_link(architecture, progress=progress, cancel_event=cancel_event)
    if not official_media_url(url):
        raise WindowsMediaError('WINDOWS_ISO_METADATA_INVALID')
    return WindowsMedia(architecture, url, digest)


async def _emit(callback, phase, message, **metadata):
    if callback is None:
        return
    try:
        signature = inspect.signature(callback)
        supports = any(item.kind == item.VAR_KEYWORD for item in signature.parameters.values())
        if not supports:
            metadata = {key: value for key, value in metadata.items() if key in signature.parameters}
    except (TypeError, ValueError):
        metadata = {}
    value = callback(phase, message, **metadata)
    if inspect.isawaitable(value):
        await value


class _Cancellation:
    def __init__(self, requested=None):
        self.requested = requested
        self.local = threading.Event()
    def is_set(self):
        return self.local.is_set() or bool(self.requested is not None and self.requested.is_set())
    def check(self):
        if self.is_set():
            raise asyncio.CancelledError


async def _thread(function, *args, cancellation):
    task = asyncio.create_task(asyncio.to_thread(function, *args))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        cancellation.local.set()
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                continue
        try:
            task.result()
        except BaseException:
            pass
        raise


def _regular(path: Path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o077):
        raise WindowsMediaError('WINDOWS_ISO_STORAGE_UNSAFE')
    return info


def _digest(path, cancellation):
    sha = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(4 * 1024**2):
            cancellation.check()
            sha.update(chunk)
    cancellation.check()
    return sha.hexdigest()


def validate_windows_iso(path: Path, architecture: str) -> dict:
    from .windows_iso_probe import validate_windows_iso as probe
    return probe(Path(path), normalize_windows_architecture(architecture))


def _manifest(root, architecture):
    path = root / ('windows-11-' + architecture + '-en-us.json')
    if _regular(path) is None:
        return None
    if path.stat().st_size > 4096:
        raise WindowsMediaError('WINDOWS_ISO_STORAGE_UNSAFE')
    try:
        value = json.loads(path.read_text())
        if not isinstance(value, dict) or value.get('schema_version') != 1:
            raise ValueError()
        sha = value.get('sha256')
        if not isinstance(sha, str):
            raise ValueError()
        filename = 'windows-11-' + architecture + '-en-us-' + sha[:16] + '.iso'
        if (value.get('architecture') != architecture or not isinstance(sha, str)
                or not _SHA256.fullmatch(sha) or value.get('filename') != filename
                or type(value.get('size_bytes')) is not int
                or not MIN_ISO_BYTES <= value['size_bytes'] <= MAX_ISO_BYTES):
            raise ValueError()
        return value
    except (ValueError, TypeError, KeyError):
        raise WindowsMediaError('WINDOWS_ISO_STORAGE_UNSAFE') from None


def _save_manifest(root, media, path):
    target = root / ('windows-11-' + media.architecture + '-en-us.json')
    _regular(target)
    temporary = root / ('.windows-media-' + uuid.uuid4().hex + '.tmp')
    created = False
    try:
        with temporary.open('x') as stream:
            created = True
            temporary.chmod(0o600)
            json.dump({'schema_version': 1, 'architecture': media.architecture,
                'filename': path.name, 'sha256': media.sha256, 'size_bytes': path.stat().st_size}, stream)
        temporary.replace(target)
    finally:
        if created:
            temporary.unlink(missing_ok=True)


async def _download(media, root, client, callback, cancellation):
    path = root / ('windows-11-' + media.architecture + '-en-us-' + media.sha256[:16] + '.iso')
    partial = path.with_suffix('.iso.part')
    final_info = _regular(path)
    if final_info is not None:
        await _emit(callback, 'windows_media_verifying', 'Verifying the cached Windows installer ISO…')
        if await _thread(_digest, path, cancellation, cancellation=cancellation) == media.sha256:
            await _thread(validate_windows_iso, path, media.architecture, cancellation=cancellation)
            _save_manifest(root, media, path)
            return path
        path.unlink()
    info = _regular(partial)
    offset = info.st_size if info else 0
    if offset > MAX_ISO_BYTES:
        raise WindowsMediaError('WINDOWS_ISO_STORAGE_UNSAFE')
    if offset >= MIN_ISO_BYTES:
        await _emit(callback, 'windows_media_verifying', 'Checking the saved Windows installer download…')
        if await _thread(_digest, partial, cancellation, cancellation=cancellation) == media.sha256:
            return await _finish_download(media, partial, path, root, callback, cancellation, digest_verified=True)
    headers = {'Range': f'bytes={offset}-'} if offset else {}
    await _emit(callback, 'windows_media_downloading', 'Downloading the official Windows 11 installer ISO…',
                detail=f'{offset:,} bytes already downloaded.' if offset else 'Connecting to Microsoft’s download server.',
                stage_timeout_seconds=MEDIA_TIMEOUT_SECONDS)
    cancellation.check()
    async with _response(client, media.url, media=True, headers=headers) as response:
        cancellation.check()
        if response.status_code == 416:
            if not offset:
                raise WindowsMediaError('WINDOWS_ISO_DOWNLOAD_INVALID')
            # A complete corrupt/stale prefix cannot be resumed past EOF.
            # Discard only this owned partial and try one fresh request.
            await response.aclose()
            partial.unlink(missing_ok=True)
            return await _download(media, root, client, callback, cancellation)
        if response.headers.get('content-type', '').split(';')[0].strip().lower() in {'text/html', 'application/json'}:
            raise WindowsMediaError('WINDOWS_ISO_DOWNLOAD_INVALID')
        length = response.headers.get('content-length')
        size = int(length) if length and length.isdecimal() else None
        if response.status_code == 206:
            match = re.fullmatch(r'bytes (\d+)-(\d+)/(\d+)', response.headers.get('content-range', ''))
            if not match or int(match[1]) != offset or int(match[2]) < offset or int(match[3]) <= int(match[2]):
                raise WindowsMediaError('WINDOWS_ISO_DOWNLOAD_INVALID')
            total = int(match[3])
            if size is not None and size != int(match[2]) - offset + 1:
                raise WindowsMediaError('WINDOWS_ISO_DOWNLOAD_INVALID')
        elif response.status_code == 200:
            offset = 0
            total = size
        else:
            raise WindowsMediaError('WINDOWS_ISO_DOWNLOAD_INVALID')
        if total is not None and not MIN_ISO_BYTES <= total <= MAX_ISO_BYTES:
            raise WindowsMediaError('WINDOWS_ISO_DOWNLOAD_INVALID')
        try:
            free = __import__('shutil').disk_usage(root).free
            if total is not None and free < total - offset + 256 * 1024**2:
                raise WindowsMediaError('WINDOWS_ISO_STORAGE_FULL')
            flags = os.O_WRONLY | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
            flags |= os.O_APPEND if offset else os.O_TRUNC
            descriptor = os.open(partial, flags, 0o600)
            with os.fdopen(descriptor, 'ab' if offset else 'wb') as stream:
                os.chmod(partial, 0o600)
                received, last_at, last_bytes = offset, time.monotonic(), offset
                async for chunk in response.aiter_bytes(1024**2):
                    cancellation.check()
                    received += len(chunk)
                    if received > MAX_ISO_BYTES or (total is not None and received > total):
                        raise WindowsMediaError('WINDOWS_ISO_DOWNLOAD_INVALID')
                    await _thread(stream.write, chunk, cancellation=cancellation)
                    now = time.monotonic()
                    if now - last_at >= 1 or received - last_bytes >= 32 * 1024**2:
                        detail = (f'{received:,} / {total:,} bytes downloaded' if total is not None
                                  else f'{received:,} bytes downloaded')
                        await _emit(callback, 'windows_media_downloading', 'Downloading the official Windows 11 installer ISO…',
                            detail=detail, progress_source='download',
                            stage_progress_percent=round(100 * received / total, 1) if total is not None else None)
                        last_at, last_bytes = now, received
                await _thread(stream.flush, cancellation=cancellation)
            if received < MIN_ISO_BYTES or (total is not None and received != total):
                raise WindowsMediaError('WINDOWS_ISO_DOWNLOAD_INVALID')
        except OSError as exc:
            if exc.errno == 28:
                raise WindowsMediaError('WINDOWS_ISO_STORAGE_FULL') from None
            raise WindowsMediaError('WINDOWS_ISO_STORAGE_UNSAFE') from None
    return await _finish_download(media, partial, path, root, callback, cancellation)


async def _finish_download(media, partial, path, root, callback, cancellation, *, digest_verified=False):
    cancellation.check()
    await _emit(callback, 'windows_media_verifying', 'Verifying Microsoft’s Windows installer checksum and architecture…')
    if not digest_verified:
        digest = await _thread(_digest, partial, cancellation, cancellation=cancellation)
        if digest != media.sha256:
            partial.unlink(missing_ok=True)
            raise WindowsMediaError('WINDOWS_ISO_CHECKSUM_FAILED')
    try:
        await _thread(validate_windows_iso, partial, media.architecture, cancellation=cancellation)
    except ValueError:
        partial.unlink(missing_ok=True)
        raise
    cancellation.check()
    if path.exists() or path.is_symlink():
        raise WindowsMediaError('WINDOWS_ISO_STORAGE_UNSAFE')
    partial.replace(path)
    _save_manifest(root, media, path)
    return path


async def _ensure_windows_iso_locked(architecture: str, cache_root: Path, *, progress=None, cancel_event=None) -> Path:
    architecture = normalize_windows_architecture(architecture)
    root = Path(cache_root)
    cancellation = _Cancellation(cancel_event)
    cancellation.check()
    try:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise WindowsMediaError('WINDOWS_ISO_STORAGE_UNSAFE')
        saved = _manifest(root, architecture)
        if saved:
            path = root / saved['filename']
            info = _regular(path)
            if info is not None and info.st_size == saved['size_bytes']:
                await _emit(progress, 'windows_media_verifying', 'Verifying the cached Windows installer ISO…')
                if await _thread(_digest, path, cancellation, cancellation=cancellation) == saved['sha256']:
                    await _thread(validate_windows_iso, path, architecture, cancellation=cancellation)
                    cancellation.check()
                    return path
                # This is an owned, generated installer cache entry, never a
                # user-selected ISO or VM disk. Replace corrupted cached bytes.
                path.unlink()
        async with asyncio.timeout(MEDIA_TIMEOUT_SECONDS):
            await _emit(progress, 'windows_media_resolving', 'Finding the official Windows 11 English (United States) ISO…',
                        stage_timeout_seconds=MEDIA_TIMEOUT_SECONDS)
            async with _client() as client:
                media = await resolve_windows_iso(architecture, client, progress=progress, cancel_event=cancel_event)
                cancellation.check()
                return await _download(media, root, client, progress, cancellation)
    except TimeoutError:
        raise WindowsMediaError('WINDOWS_ISO_DOWNLOAD_TIMEOUT') from None
    except WindowsMediaError:
        raise
    except OSError as exc:
        if exc.errno == 28:
            raise WindowsMediaError('WINDOWS_ISO_STORAGE_FULL') from None
        raise WindowsMediaError('WINDOWS_ISO_STORAGE_UNSAFE') from None


async def ensure_windows_iso(architecture: str, cache_root: Path, *, progress=None, cancel_event=None) -> Path:
    """Resolve and verify one private Windows ISO; serialize shared-cache users."""
    architecture = normalize_windows_architecture(architecture)
    key = str(Path(cache_root).absolute()) + ':' + architecture
    lock = _LOCKS.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _LOCKS[key] = lock
    async with lock:
        return await _ensure_windows_iso_locked(architecture, cache_root,
                                               progress=progress, cancel_event=cancel_event)
