from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from harnessy.core.paths import APP_ROOT
from harnessy.core.workspace import WorkspaceStore

MAX_SKILL_BYTES = 256 * 1024


@dataclass(frozen=True, slots=True)
class SkillRecord:
    key: str
    name: str
    description: str
    tools: tuple[str, ...]
    scope: str
    path: Path
    body: str

    def compact(self) -> dict[str, object]:
        return {
            'key': self.key,
            'name': self.name,
            'description': self.description,
            'tools': list(self.tools),
            'scope': self.scope,
        }


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _parse_inline_list(value: str) -> tuple[str, ...]:
    value = value.strip()
    if value.startswith('[') and value.endswith(']'):
        value = value[1:-1]
    if not value:
        return ()
    return tuple(_strip_quotes(item.strip()) for item in value.split(',') if item.strip())


def _parse_skill_file(path: Path, *, scope: str) -> SkillRecord | None:
    try:
        if not path.is_file() or path.stat().st_size > MAX_SKILL_BYTES:
            return None
        text = path.read_text('utf-8', errors='replace')
    except OSError:
        return None

    metadata: dict[str, object] = {}
    body = text.strip()
    lines = text.splitlines()
    if lines and lines[0].strip() == '---':
        end = next((i for i in range(1, min(len(lines), 200)) if lines[i].strip() == '---'), None)
        if end is not None:
            front = lines[1:end]
            body = '\n'.join(lines[end + 1:]).strip()
            current_list: str | None = None
            for raw in front:
                stripped = raw.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                if current_list and stripped.startswith('- '):
                    values = list(metadata.get(current_list) or [])
                    values.append(_strip_quotes(stripped[2:].strip()))
                    metadata[current_list] = values
                    continue
                current_list = None
                if ':' not in raw:
                    continue
                key, value = raw.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                if key == 'tools':
                    if value:
                        metadata['tools'] = list(_parse_inline_list(value))
                    else:
                        metadata['tools'] = []
                        current_list = 'tools'
                elif key in {'name', 'description'}:
                    metadata[key] = _strip_quotes(value)

    key = path.parent.name.strip().lower()
    if not re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,79}', key):
        return None
    name = str(metadata.get('name') or path.parent.name.replace('-', ' ').replace('_', ' ').title()).strip()
    description = str(metadata.get('description') or '').strip()
    raw_tools = metadata.get('tools') or []
    tools = tuple(
        tool for tool in (str(x).strip() for x in raw_tools if str(x).strip())
        if re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', tool)
    )
    if not description:
        first = next((line.strip().lstrip('#').strip() for line in body.splitlines() if line.strip()), '')
        description = first[:240]
    return SkillRecord(key=key, name=name, description=description, tools=tools, scope=scope, path=path, body=body)


class SkillLibrary:
    """Layered HarnessyXO skill catalogue.

    Resolution order is workspace > machine > built-in for matching directory
    keys. Only SKILL.md is read, and skill bodies are never injected en masse.
    """

    def __init__(
        self,
        workspace: WorkspaceStore,
        *,
        builtin_root: Path | None = None,
        machine_root: Path | None = None,
    ) -> None:
        self.workspace = workspace
        self.builtin_root = (builtin_root or (APP_ROOT / 'skills')).resolve()
        default_settings = Path(os.environ.get('HARNESSY_SETTINGS_DIR') or (APP_ROOT / '.settings')).expanduser()
        self.machine_root = (machine_root or (default_settings / 'skills')).resolve()
        self.workspace_root = (workspace.llm_dir / 'skills').resolve()
        self.workspace_root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _iter_root(root: Path, scope: str) -> Iterable[SkillRecord]:
        if not root.is_dir():
            return []
        records: list[SkillRecord] = []
        try:
            children = sorted(root.iterdir(), key=lambda p: p.name.lower())
        except OSError:
            return []
        for child in children:
            if not child.is_dir() or child.is_symlink():
                continue
            skill_file = child / 'SKILL.md'
            # Skill discovery must not turn a checked-out workspace into an
            # arbitrary host-file reader through symlinks.
            if skill_file.is_symlink():
                continue
            try:
                resolved_file = skill_file.resolve(strict=False)
                resolved_root = root.resolve(strict=False)
            except OSError:
                continue
            if resolved_file != resolved_root and resolved_root not in resolved_file.parents:
                continue
            record = _parse_skill_file(skill_file, scope=scope)
            if record is not None:
                records.append(record)
        return records

    def _resolved(self) -> dict[str, SkillRecord]:
        resolved: dict[str, SkillRecord] = {}
        for root, scope in (
            (self.builtin_root, 'builtin'),
            (self.machine_root, 'machine'),
            (self.workspace_root, 'workspace'),
        ):
            for record in self._iter_root(root, scope):
                resolved[record.key] = record
        return resolved

    def list(self) -> list[SkillRecord]:
        return sorted(self._resolved().values(), key=lambda row: (row.name.lower(), row.key))

    def get(self, name: str) -> SkillRecord | None:
        needle = str(name or '').strip().lower()
        if not needle:
            return None
        resolved = self._resolved()
        if needle in resolved:
            return resolved[needle]
        exact_name = [row for row in resolved.values() if row.name.lower() == needle]
        if len(exact_name) == 1:
            return exact_name[0]
        return None

    def catalogue_text(self, *, max_items: int = 40) -> str:
        rows = self.list()[:max_items]
        if not rows:
            return '(no skills installed)'
        return '\n'.join(
            f'- {row.key}: {row.name} — {row.description} [{row.scope}]'
            for row in rows
        )
