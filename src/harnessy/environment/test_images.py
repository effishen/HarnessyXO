"""Verified guest downloads and bounded extraction into private target state."""
from __future__ import annotations

import asyncio
import gzip
import hashlib
import tarfile
from pathlib import Path

import httpx


async def finish_thread(function, *args):
    """Do not leave a disk-writing worker alive after operation cancellation."""
    task = asyncio.create_task(asyncio.to_thread(function, *args))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        await task
        raise


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


async def download_verified(url: str, digest: str, destination: Path, note=lambda _: None):
    if not url.startswith('https://') or len(digest) != 64:
        raise ValueError('Guest downloads require HTTPS and a pinned SHA256 checksum.')
    if destination.is_symlink():
        raise ValueError('Guest image cache cannot be a symbolic link.')
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if destination.is_file() and await finish_thread(file_sha256, destination) == digest:
        return destination
    temporary = destination.with_suffix(destination.suffix + '.download')
    temporary.unlink(missing_ok=True)
    note('Downloading ' + url.rsplit('/', 1)[-1] + '\n')
    sha, size, last_report = hashlib.sha256(), 0, 0
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=httpx.Timeout(60, connect=30)) as client:
            async with client.stream('GET', url) as response:
                response.raise_for_status()
                if response.url.scheme != 'https':
                    raise RuntimeError('Guest download redirected to an insecure connection.')
                with temporary.open('xb') as output:
                    temporary.chmod(0o600)
                    async for chunk in response.aiter_bytes(1024 * 1024):
                        size += len(chunk)
                        if size > 4 * 1024**3:
                            raise RuntimeError('Guest download exceeds the 4 GiB limit.')
                        sha.update(chunk)
                        output.write(chunk)
                        if size - last_report >= 32 * 1024**2:
                            note(f'Downloaded {size // 1024**2} MiB…\n')
                            last_report = size
        if sha.hexdigest() != digest:
            raise RuntimeError('Guest image checksum does not match the official release. No VM was created.')
        temporary.replace(destination)
        note('Official image checksum verified.\n')
        return destination
    finally:
        temporary.unlink(missing_ok=True)


def _copy_sparse(source, output, limit: int):
    size = 0
    while chunk := source.read(1024 * 1024):
        size += len(chunk)
        if size > limit:
            raise ValueError('Expanded guest image exceeds its size limit.')
        if not chunk.strip(b'\0'):
            output.seek(len(chunk), 1)
        else:
            output.write(chunk)
    output.truncate(size)
    return size


def extract_cloud_disk(archive: Path, destination: Path):
    """Extract one regular disk member, ignoring archive-supplied paths/links."""
    temporary = destination.with_suffix('.extracting')
    temporary.unlink(missing_ok=True)
    try:
        with tarfile.open(archive, 'r:xz') as package:
            candidates = [m for m in package.getmembers() if m.isfile() and
                          Path(m.name).suffix.lower() in {'.raw', '.qcow2', '.img'}]
            if len(candidates) != 1 or not 0 < candidates[0].size <= 32 * 1024**3:
                raise ValueError('Expected exactly one regular raw/qcow2 disk in the cloud image archive.')
            with package.extractfile(candidates[0]) as source, temporary.open('xb') as output:
                _copy_sparse(source, output, 32 * 1024**3)
        temporary.chmod(0o600)
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)


def expand_gzip(archive: Path, destination: Path):
    with gzip.open(archive, 'rb') as source, destination.open('xb') as output:
        _copy_sparse(source, output, 1024**3)
    destination.chmod(0o600)
