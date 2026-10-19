"""Presentation of server-recorded execution identity on tool activity cards."""
from __future__ import annotations

import re
from typing import Any

_ID = re.compile(r'^[a-f0-9]{32}$')
_MODES = {'live': 'Shared project source (read/write)', 'readonly': 'Shared project source (read-only)', 'copy': 'Separate project copy'}


def tool_environment_label(metadata: dict[str, Any] | None) -> tuple[str, str, str]:
    """Use execution metadata only, never a model's unexecuted tool arguments."""
    metadata = metadata if isinstance(metadata, dict) else {}
    environment_id = str(metadata.get('environment_id') or '')
    name = metadata.get('environment_name')
    if not _ID.fullmatch(environment_id) or not isinstance(name, str) or not name.strip():
        return '', '', ''
    name = ' '.join(name.split())
    mode = _MODES.get(str(metadata.get('project_files_mode') or ''), '')
    detail = f'VM: {name}\nEnvironment ID: {environment_id}'
    if mode:
        detail += '\n' + mode
    return environment_id, 'VM · ' + name, detail
