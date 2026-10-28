"""Content-free observations from the ordinary Windows download browser."""
from __future__ import annotations

import re
from typing import Any


WINDOWS_MEDIA_BROWSER_EVENT = 'windows_media_browser_observation'
WINDOWS_MEDIA_BROWSER_PHASES = frozenset({
    'browser_preparing', 'browser_launch', 'page_open', 'edition',
    'language', 'download_links',
})
WINDOWS_MEDIA_BROWSER_RESULTS = frozenset({
    'info', 'challenge', 'rejected', 'page_error', 'network_error',
    'http_error', 'timeout', 'browser_unavailable',
})
WINDOWS_MEDIA_BROWSER_ERROR_KINDS = frozenset({
    'SentinelReject', 'GenericError', 'Network', 'unknown',
})


def validate_windows_media_browser_observation(value: Any) -> dict[str, Any] | None:
    """Keep only reviewed facts; never retain page text, URLs or browser state."""
    if not isinstance(value, dict) or type(value.get('schema_version')) is not int or value['schema_version'] != 1:
        return None
    phase, result = value.get('phase'), value.get('result')
    if (not isinstance(phase, str) or phase not in WINDOWS_MEDIA_BROWSER_PHASES
            or not isinstance(result, str) or result not in WINDOWS_MEDIA_BROWSER_RESULTS):
        return None
    safe = {'schema_version': 1, 'phase': phase, 'result': result}
    status = value.get('http_status')
    if type(status) is int and 100 <= status <= 599:
        safe['http_status'] = status
    version = value.get('browser_version')
    if isinstance(version, str) and re.fullmatch(r'[0-9]{1,6}(?:\.[0-9]{1,6}){1,3}', version):
        safe['browser_version'] = version
    kind = value.get('error_kind')
    if isinstance(kind, str) and kind in WINDOWS_MEDIA_BROWSER_ERROR_KINDS:
        safe['error_kind'] = kind
    return safe


validate_windows_media_browser = validate_windows_media_browser_observation
