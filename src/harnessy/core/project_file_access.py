"""Per-source human writes in the model-visible Project Files view.

The synthetic Files root and linked inputs are readable, while an active,
unlocked project's own canonical directory accepts writes.  These helpers do
not grant access to a VM or change the project's existing source policy.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import stat
from typing import Any

from .workspace import FILES_PROBE_DIR_NAME


PROJECT_FILES_SCOPE_PREFIX = '__harnessy_chat_files__:'
_MODEL_FILES_PREFIX = Path('/workspace/Files')


def parse_project_files_scope(scope_id: str) -> tuple[str, str] | None:
    """Decode only the exact project-files scope, never a workspace fallback."""
    if not isinstance(scope_id, str) or not scope_id.startswith(PROJECT_FILES_SCOPE_PREFIX):
        return None
    parts = scope_id[len(PROJECT_FILES_SCOPE_PREFIX):].split(':')
    if len(parts) != 2 or any(not part or '/' in part or '\\' in part for part in parts):
        raise ValueError('Invalid Project Files scope.')
    return parts[0], parts[1]


def _within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


@dataclass(frozen=True, slots=True)
class ProjectFileAccess:
    workspace: Any = field(repr=False, compare=False)
    chat_id: str
    files_root: Path
    own_root: Path
    readonly_roots: tuple[Path, ...]
    live_links: tuple[tuple[str, str], ...]
    source_identities: tuple[tuple[Path, int, int], ...]
    policy_revision: str
    locked: bool = False
    archived: bool = False

    @property
    def read_only(self) -> bool:
        return self.locked or self.archived

    @property
    def readonly_paths(self) -> tuple[Path, ...]:
        """Actual inputs and virtual mount points, including reserved proofs."""
        aliases = tuple(Path(marker) for marker, _target in self.live_links)
        probes = (self.own_root / FILES_PROBE_DIR_NAME,
                  self.own_root / '.git' / 'info' / FILES_PROBE_DIR_NAME)
        return tuple(dict.fromkeys((*self.readonly_roots, *aliases, *probes)))

    def browser_policy(self) -> dict[str, Any]:
        return {'writable_root': None if self.read_only else str(self.own_root),
                'readonly_paths': [str(path) for path in self.readonly_paths],
                'read_only': self.read_only}

    def _host_path(self, value: str | Path) -> Path:
        path = Path(value).expanduser()
        if '..' in path.parts:
            raise ValueError('Project Files paths must not contain parent traversal.')
        if path == _MODEL_FILES_PREFIX or _MODEL_FILES_PREFIX in path.parents:
            path = self.files_root / path.relative_to(_MODEL_FILES_PREFIX)
        elif not path.is_absolute():
            path = self.own_root / path
        return path.absolute()

    def resolve_path(self, value: str | Path) -> Path:
        """Resolve virtual ancestor folders and ordinary filesystem links."""
        candidate = self._host_path(value)
        seen: set[Path] = set()
        # Ordinary symlinks can lead to a virtual ancestor mount marker.  Feed
        # their resolved path back through the same alias lookup rather than
        # treating it as an ordinary writable directory in the origin project.
        for _ in range(len(self.live_links) + 3):
            if candidate in seen:
                raise ValueError('Project Files links form a cycle.')
            seen.add(candidate)
            matches = [(Path(marker), Path(target)) for marker, target in self.live_links
                       if _within(candidate, Path(marker)) and Path(marker) != Path(target)]
            if not matches:
                resolved = candidate.resolve(strict=False)
                if resolved == candidate:
                    return resolved
                candidate = resolved
                continue
            marker, target = max(matches, key=lambda row: len(row[0].parts))
            candidate = target / candidate.relative_to(marker)
        raise ValueError('Project Files links could not be resolved.')

    def check_current(self) -> None:
        """Revalidate saved source identities and current project grants."""
        fresh = project_file_access(self.workspace, self.chat_id)
        if fresh.read_only:
            reason = 'archived' if fresh.archived else 'locked'
            raise PermissionError(f'This Project / Chat is {reason}; its files are read-only.')
        if (fresh.policy_revision != self.policy_revision or fresh.own_root != self.own_root
                or fresh.source_identities != self.source_identities):
            raise PermissionError('Project file access changed; reopen Project Files before editing.')
        # A directory could have been replaced after the fresh policy read.
        for path, device, inode in self.source_identities:
            metadata = path.lstat()
            if (not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
                    or (metadata.st_dev, metadata.st_ino) != (device, inode)):
                raise PermissionError('A project file source changed; reopen Project Files before editing.')

    def require_write(self, value: str | Path, *, structural: bool = False,
                      revalidate: bool = True) -> Path:
        """Authorize a target, or a structural source such as rename/delete.

        An own-root destination can receive children.  A structural operation
        cannot replace or remove that canonical project directory itself.
        Render-only hints can pass revalidate=False on a freshly built policy;
        actual filesystem mutations must keep the default revalidation.
        """
        if self.read_only:
            reason = 'archived' if self.archived else 'locked'
            raise PermissionError(f'This Project / Chat is {reason}; its files are read-only.')
        if revalidate:
            self.check_current()
        host = self._host_path(value)
        if FILES_PROBE_DIR_NAME in host.parts:
            raise PermissionError('Temporary workspace proofs are read-only.')
        # Deny a mount marker before resolution too: its name is reserved even
        # when no physical directory exists at that virtual location.
        if any(_within(host, Path(marker)) for marker, _target in self.live_links
               if Path(marker) != self.own_root):
            raise PermissionError('Linked project inputs are read-only in this Project Files tab.')
        resolved = self.resolve_path(host)
        if not _within(resolved, self.own_root) or any(_within(resolved, root) for root in self.readonly_roots):
            raise PermissionError('Only this project\'s own files are writable in this Project Files tab.')
        if FILES_PROBE_DIR_NAME in resolved.parts:
            raise PermissionError('Temporary workspace proofs are read-only.')
        if structural:
            if resolved == self.own_root:
                raise PermissionError('The canonical project folder cannot be renamed, moved or deleted here.')
            for probe in self.readonly_paths:
                if probe.name == FILES_PROBE_DIR_NAME and probe.exists() and _within(probe, resolved):
                    raise PermissionError('This folder contains an active workspace proof.')
        return resolved

    def can_write(self, value: str | Path, *, structural: bool = False,
                  revalidate: bool = True) -> bool:
        try:
            self.require_write(value, structural=structural, revalidate=revalidate)
            return True
        except (OSError, ValueError, RuntimeError):
            return False


def project_file_access(workspace: Any, chat_id: str) -> ProjectFileAccess:
    """Build a fresh per-folder write policy from authoritative project data."""
    chat = workspace.get_chat(str(chat_id))
    if chat is None:
        raise ValueError('Project / Chat no longer exists.')
    files_root = Path(workspace.files_root).resolve()
    own_root = workspace.active_root_path(chat.id).resolve()
    archived = chat.archived_at is not None
    if archived:
        return ProjectFileAccess(workspace, str(chat.id), files_root, own_root,
                                 (own_root,), (), (), '', bool(chat.locked), True)
    policy = workspace.output_policy(chat.id)
    canonical = Path(policy['project_root']).resolve()
    if own_root != canonical:
        raise ValueError('Project Files does not point to the canonical project directory.')
    readonly = [Path(policy['references_root']).resolve()]
    links: list[tuple[str, str]] = []
    previous = own_root
    for row in policy.get('ancestors') or ():
        target = Path(row['host_path']).resolve()
        links.append((str(previous / str(row['folder'])), str(target)))
        readonly.append(target)
        previous = target
    for row in policy.get('access_projects') or ():
        target = Path(row['host_path']).resolve()
        readonly.append(target)
        if row.get('direct_mount'):
            links.append((str(files_root / str(row['folder'])), str(target)))
    identities = tuple((Path(row['path']), int(row['device']), int(row['inode']))
                       for row in policy.get('source_identities') or ())
    return ProjectFileAccess(workspace, str(chat.id), files_root, own_root,
        tuple(dict.fromkeys(readonly)), tuple(links), identities,
        str(policy.get('policy_revision') or ''), bool(chat.locked), False)


def require_project_write(workspace: Any, chat_id: str, value: str | Path,
                          *, structural: bool = False) -> Path:
    return project_file_access(workspace, chat_id).require_write(value, structural=structural)
