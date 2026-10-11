from __future__ import annotations

import os
import shutil
import stat
import tarfile
import zipfile
import threading
from pathlib import Path, PurePosixPath

ARCHIVE_SUFFIXES = ('.zip', '.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz', '.txz')


def is_archive(path: str | Path) -> bool:
    name = str(path).lower()
    return any(name.endswith(suffix) for suffix in ARCHIVE_SUFFIXES)


def safe_extract_archive(source: Path, destination: Path, *, max_members: int = 100_000, max_bytes: int = 8 * 1024**3) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    if source.name.lower().endswith('.zip'):
        _extract_zip(source, destination, max_members=max_members, max_bytes=max_bytes)
    elif is_archive(source):
        _extract_tar(source, destination, max_members=max_members, max_bytes=max_bytes)
    else:
        raise ValueError(f'Unsupported archive format: {source.name}')


def _clean_member_path(name: str) -> Path:
    normalized = name.replace('\\', '/')
    p = PurePosixPath(normalized)
    if p.is_absolute() or any(part in ('', '.', '..') for part in p.parts if part != '.'):
        if '..' in p.parts or p.is_absolute():
            raise ValueError(f'Unsafe archive path: {name!r}')
    # Reject drive-style prefixes such as C:/ on all platforms.
    if p.parts and ':' in p.parts[0]:
        raise ValueError(f'Unsafe archive path: {name!r}')
    return Path(*[part for part in p.parts if part not in ('', '.')])


def _extract_zip(source: Path, destination: Path, *, max_members: int, max_bytes: int) -> None:
    with zipfile.ZipFile(source) as zf:
        infos = zf.infolist()
        if len(infos) > max_members:
            raise ValueError(f'Archive contains too many entries ({len(infos)} > {max_members})')
        total = sum(i.file_size for i in infos)
        if total > max_bytes:
            raise ValueError(f'Archive expands to {total} bytes, above the configured safety limit')
        for info in infos:
            rel = _clean_member_path(info.filename)
            if not rel.parts:
                continue
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                raise ValueError(f'Symlinks are not accepted in uploaded ZIPs: {info.filename}')
            target = destination / rel
            _ensure_inside(destination, target)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, 'r') as src, target.open('wb') as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)
            if mode:
                try:
                    os.chmod(target, mode & 0o777)
                except OSError:
                    pass


def _extract_tar(source: Path, destination: Path, *, max_members: int, max_bytes: int) -> None:
    with tarfile.open(source, 'r:*') as tf:
        members = tf.getmembers()
        if len(members) > max_members:
            raise ValueError(f'Archive contains too many entries ({len(members)} > {max_members})')
        total = sum(m.size for m in members if m.isfile())
        if total > max_bytes:
            raise ValueError(f'Archive expands to {total} bytes, above the configured safety limit')
        for member in members:
            rel = _clean_member_path(member.name)
            if not rel.parts:
                continue
            if member.issym() or member.islnk() or member.isdev():
                raise ValueError(f'Links/devices are not accepted in uploaded TARs: {member.name}')
            target = destination / rel
            _ensure_inside(destination, target)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                continue
            with src, target.open('wb') as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)
            try:
                os.chmod(target, member.mode & 0o777)
            except OSError:
                pass


def _ensure_inside(root: Path, target: Path) -> None:
    root_r = root.resolve()
    target_r = target.resolve(strict=False)
    if target_r != root_r and root_r not in target_r.parents:
        raise ValueError(f'Archive attempted to escape destination: {target}')


def detect_project_root(extracted: Path) -> Path:
    entries = [p for p in extracted.iterdir() if p.name not in {'.DS_Store', '__MACOSX'}]
    files = [p for p in entries if p.is_file()]
    dirs = [p for p in entries if p.is_dir()]
    if not files and len(dirs) == 1:
        return dirs[0]
    return extracted


class ArchiveCancelled(RuntimeError):
    """Raised when a cooperative archive operation is cancelled."""


def make_zip(
    source_dir: Path, output_file: Path, *, exclude_names: set[str] | None = None,
    cancel_event: threading.Event | None = None, chunk_size: int = 1024 * 1024,
) -> Path:
    """Create a ZIP without monopolising one native compression call per file.

    The chunked writer lets callers running this function in a worker thread
    cooperatively cancel between chunks. This matters for HarnessyXO's agent
    packaging tool: Stop must be able to abort a large archive instead of
    leaving a background DEFLATE job running to completion.
    """
    exclude_names = exclude_names or set()
    chunk_size = max(64 * 1024, int(chunk_size or 1024 * 1024))
    output_file.parent.mkdir(parents=True, exist_ok=True)
    tmp = output_file.with_suffix(output_file.suffix + '.tmp')
    if tmp.exists():
        tmp.unlink()

    def check_cancelled() -> None:
        if cancel_event is not None and cancel_event.is_set():
            raise ArchiveCancelled('ZIP creation cancelled')

    try:
        with zipfile.ZipFile(tmp, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
            for path in sorted(source_dir.rglob('*')):
                check_cancelled()
                rel = path.relative_to(source_dir)
                if any(part in exclude_names for part in rel.parts):
                    continue
                if path.is_symlink() or not path.is_file():
                    continue

                # Preserve the same useful metadata as ZipFile.write(), while
                # copying ourselves so cancellation can be observed mid-file.
                info = zipfile.ZipInfo.from_file(path, rel.as_posix())
                info.compress_type = zipfile.ZIP_DEFLATED
                info._compresslevel = 6
                with path.open('rb') as src, zf.open(info, 'w', force_zip64=True) as dst:
                    while True:
                        check_cancelled()
                        chunk = src.read(chunk_size)
                        if not chunk:
                            break
                        dst.write(chunk)
        check_cancelled()
        tmp.replace(output_file)
        return output_file
    except BaseException:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise
