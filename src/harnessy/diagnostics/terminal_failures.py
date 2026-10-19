"""Fixed project-transfer failure facts without project paths or error prose."""
from __future__ import annotations

import hashlib
from typing import Any

PROJECT_SYNC_FAILURE_CODES = frozenset({
    'project_sync_byte_limit', 'project_sync_entry_limit', 'project_sync_limit_exceeded',
})
PROJECT_SYNC_FAILURE_BASES = frozenset({
    'exact_fixed_message', 'fixed_message_fingerprint', 'recorded_code',
})
TERMINAL_MODES = frozenset({'guest_console', 'project_files'})
_MESSAGES = {
    'Project synchronization exceeds its 512 MiB limit; use a smaller project or explicit artifact transfer.': 'project_sync_byte_limit',
    # This older combined guard can mean bytes or entries. Do not guess which.
    'Project synchronization limit exceeded.': 'project_sync_limit_exceeded',
}
_FINGERPRINTS = {(len(message), hashlib.sha256(message.encode('utf-8')).hexdigest()[:12]): code
                 for message, code in _MESSAGES.items()}


def terminal_failure_evidence(value: Any, *, _depth: int = 0) -> dict[str, str]:
    """Recognize exact literals or their existing bounded redaction receipts.

    Fingerprints are compared only with this fixed shipped-message allowlist;
    they never reconstruct arbitrary text. Builtin exception arguments avoid
    invoking a user-controlled exception's __str__ implementation.
    """
    if _depth > 3:
        return {}
    if type(value) in (ValueError, RuntimeError):
        value = value.args[0] if value.args and type(value.args[0]) is str else None
    if isinstance(value, str):
        code = _MESSAGES.get(value)
        if code:
            return {'code': code, 'basis': 'exact_fixed_message'}
        if value in PROJECT_SYNC_FAILURE_CODES:
            return {'code': value, 'basis': 'recorded_code'}
        return {}
    if not isinstance(value, dict):
        return {}
    for key in ('terminal_failure_code',):
        code = value.get(key)
        if isinstance(code, str) and code in PROJECT_SYNC_FAILURE_CODES:
            basis = value.get('terminal_failure_basis')
            return {'code': code, 'basis': basis if isinstance(basis, str)
                    and basis in PROJECT_SYNC_FAILURE_BASES else 'recorded_code'}
    reasons = value.get('reason_codes')
    if isinstance(reasons, list):
        code = next((item for item in reasons[:64]
                     if isinstance(item, str) and item in PROJECT_SYNC_FAILURE_CODES), None)
        if code:
            basis = value.get('project_sync_failure_basis')
            return {'code': code, 'basis': basis if isinstance(basis, str)
                    and basis in PROJECT_SYNC_FAILURE_BASES else 'recorded_code'}
    length, digest = value.get('chars'), value.get('sha256_12')
    if value.get('redacted') is True and type(length) is int and isinstance(digest, str):
        code = _FINGERPRINTS.get((length, digest))
        if code:
            return {'code': code, 'basis': 'fixed_message_fingerprint'}
    for key in ('technical_error', 'error'):
        evidence = terminal_failure_evidence(value.get(key), _depth=_depth + 1)
        if evidence:
            return evidence
    return {}


def terminal_failure_code(value: Any) -> str | None:
    return terminal_failure_evidence(value).get('code')
