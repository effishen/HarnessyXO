"""Read-only guards for workspace admission and host folder deletion.

A folder containing HarnessyXO metadata is not proof that HarnessyXO owns all
of its contents. In particular, a home directory must never become a workspace.
These checks deliberately run before initialization, database probes or writes.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from .paths import APP_ROOT, settings_path


def _resolved(path: str | Path) -> Path:
    try:
        return Path(path).expanduser().resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError('The folder path could not be verified safely.') from exc


def _same(left: Path, right: Path) -> bool:
    if os.path.normcase(str(left)) == os.path.normcase(str(right)):
        return True
    try:
        # On case-insensitive volumes, differently cased paths can denote the
        # same directory even though pathlib's lexical comparison says not.
        return left.samefile(right)
    except (OSError, ValueError):
        return False


def _within(path: Path, parent: Path) -> bool:
    return any(_same(candidate, parent) for candidate in (path, *path.parents))


def _boundaries(
    *, app_root: str | Path | None = None, state_root: str | Path | None = None,
) -> tuple[list[tuple[Path, str]], list[tuple[Path, str]]]:
    home = _resolved(Path.home())
    roots = [(home, 'your home folder')]
    protected_trees: list[tuple[Path, str]] = []
    application_roots = [APP_ROOT]
    if os.environ.get('HARNESSY_APP_ROOT'):
        application_roots.append(Path(os.environ['HARNESSY_APP_ROOT']))
    if app_root is not None:
        application_roots.append(Path(app_root))
    for value in application_roots:
        protected_trees.append((_resolved(value), 'the HarnessyXO application folder'))
    protected_trees.append((_resolved(state_root if state_root is not None else settings_path()),
                            'the HarnessyXO settings folder'))

    if os.name == 'nt':
        for name in ('SystemRoot', 'ProgramFiles', 'ProgramFiles(x86)', 'ProgramData'):
            if value := os.environ.get(name):
                protected_trees.append((_resolved(value), 'a Windows system folder'))
        if value := os.environ.get('PUBLIC'):
            roots.append((_resolved(value), 'the shared home folder'))
    else:
        for value in ('/System', '/Library', '/Applications', '/usr', '/etc', '/bin',
                      '/sbin', '/dev', '/proc', '/sys', '/run', '/opt'):
            protected_trees.append((_resolved(value), 'a system folder'))
        # /tmp resolves to /private/tmp on macOS. Dedicated temporary
        # workspaces are allowed, while the temporary-folder root is not.
        for value in ('/tmp', '/var/tmp'):
            roots.append((_resolved(value), 'the temporary-folder root'))
        for value in ('/Users', '/home', '/Volumes', '/mnt', '/media', '/private', '/var'):
            roots.append((_resolved(value), 'a system or volume collection folder'))
        protected_trees.append((home / 'Library', 'your Library folder'))
    return roots, protected_trees


def _guard(
    root: str | Path, *, app_root: str | Path | None, state_root: str | Path | None,
    other_workspace_roots: Iterable[str | Path], deleting: bool,
) -> Path:
    candidate = _resolved(root)
    reason: str | None = None
    if candidate == Path(candidate.anchor):
        reason = 'the filesystem root'
    elif os.path.ismount(candidate):
        reason = 'a mounted-volume root'
    elif os.name != 'nt' and any(_same(candidate.parent, _resolved(value)) for value in ('/Users', '/home')):
        reason = 'a user home folder'
    elif os.name == 'nt' and len(candidate.parts) == 3 and candidate.parts[1].casefold() == 'users':
        reason = 'a user home folder'
    elif os.name != 'nt' and _same(candidate.parent, _resolved('/Volumes')):
        # Keep detached/macOS volume roots protected too. A disconnected disk
        # can leave its mount-point directory behind on the startup volume.
        reason = 'a mounted-volume root'

    if reason is None and os.name != 'nt':
        temporary_roots = tuple(_resolved(value) for value in ('/tmp', '/var/tmp'))
        if not any(_within(candidate, temporary) for temporary in temporary_roots):
            for value in ('/var', '/private'):
                if _within(candidate, _resolved(value)):
                    reason = 'a system folder'
                    break

    roots, trees = _boundaries(app_root=app_root, state_root=state_root)
    for boundary, label in roots:
        if _within(boundary, candidate):
            reason = label if _same(candidate, boundary) else f'a parent of {label}'
            break
    if reason is None:
        for boundary, label in trees:
            if _within(candidate, boundary) or _within(boundary, candidate):
                reason = label if _within(candidate, boundary) else f'a parent of {label}'
                break
    if reason is None:
        for value in other_workspace_roots:
            other = _resolved(value)
            if _within(other, candidate) and (deleting or not _same(candidate, other)):
                reason = 'a folder containing a registered workspace'
                break
    if reason:
        if deleting:
            raise ValueError(f'Cannot delete {candidate}: this is {reason}.')
        raise ValueError(
            f'Cannot use {candidate} as a workspace: this is {reason}. '
            'Choose or create a dedicated subfolder for the workspace.'
        )
    return candidate


def validate_workspace_root(
    root: str | Path, *, app_root: str | Path | None = None,
    state_root: str | Path | None = None,
    other_workspace_roots: Iterable[str | Path] = (),
) -> Path:
    """Return a verified canonical root without creating or changing anything."""
    return _guard(root, app_root=app_root, state_root=state_root,
                  other_workspace_roots=other_workspace_roots, deleting=False)


def validate_workspace_delete_target(
    root: str | Path, *, app_root: str | Path | None = None,
    state_root: str | Path | None = None,
    other_workspace_roots: Iterable[str | Path] = (),
) -> Path:
    """Reject broad/protected host deletion targets, including workspace roots.

    This is a path admission check, not an atomic filesystem capability. Call
    it immediately before an operation, and never resolve a symlink selected
    for deletion into a request to delete its target.
    """
    return _guard(root, app_root=app_root, state_root=state_root,
                  other_workspace_roots=other_workspace_roots, deleting=True)
