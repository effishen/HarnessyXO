"""Best-effort native fault capture and content-free crash locations.

CPython writes directly to an open descriptor when a fatal signal occurs. Raw
output stays in the existing private console-error log; support exports retain
only fixed signal names, counts and source-validated code locations.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from .faults import MAX_FAULT_FRAMES, _module_for_path, _source_symbols, validate_frame_evidence

NATIVE_FAULT_SIGNALS = {
    'bus_error': 'SIGBUS',
    'aborted': 'SIGABRT',
    'segmentation_fault': 'SIGSEGV',
    'floating_point_exception': 'SIGFPE',
    'illegal_instruction': 'SIGILL',
}
_NATIVE_FAULT_MESSAGES = {
    'Bus error': 'bus_error',
    'Aborted': 'aborted',
    'Segmentation fault': 'segmentation_fault',
    'Floating point exception': 'floating_point_exception',
    'Illegal instruction': 'illegal_instruction',
}
_FATAL = re.compile(r'^Fatal Python error: (' + '|'.join(map(re.escape, _NATIVE_FAULT_MESSAGES)) + r')$')
_THREAD = re.compile(r'^(?:Current thread|Thread) 0x[0-9a-fA-F]+ \(most recent call first\):$')
_FRAME = re.compile(r'^  File "([^"\r\n]{1,500})", line ([0-9]{1,8}) in ([^\r\n]{1,500})$')
_MAX_INPUT_BYTES = 512 * 1024
_MAX_LINES = 8192
_MAX_FAULTS = 16
# faulthandler stores a descriptor, not an owning reference to its file. Keep
# our existing console stream alive until interpreter exit even if a manager
# instance is replaced. An externally enabled handler is never redirected.
_CAPTURE_STREAMS: list[Any] = []


def enable_native_fault_capture(stream: Any) -> str:
    """Use the existing persistent stream; never replace configured handlers."""
    try:
        import faulthandler

        if faulthandler.is_enabled():
            return 'already_enabled'
        descriptor = stream.fileno()
        faulthandler.enable(file=descriptor, all_threads=True)
        _CAPTURE_STREAMS.append(stream)
        return 'enabled'
    except Exception:
        # Diagnostics must not prevent application startup on unusual Python
        # builds, unsupported handles or an unavailable diagnostic filesystem.
        return 'unavailable'


def native_fault_signature(line: Any) -> dict[str, str]:
    """Match only CPython's fixed fatal-signal heading, never arbitrary prose."""
    if not isinstance(line, str) or len(line) > 128:
        return {}
    match = _FATAL.fullmatch(line.strip())
    if match is None:
        return {}
    fault_class = _NATIVE_FAULT_MESSAGES[match[1]]
    return {'native_fault_class': fault_class, 'signal': NATIVE_FAULT_SIGNALS[fault_class]}


def _frame(filename: str, number: str, function: str) -> dict[str, Any] | None:
    line = int(number)
    if not 1 <= line <= 10_000_000:
        return None
    try:
        # Do not stat/resolve arbitrary logged paths (for example a detached
        # user disk). Only installed source locations are eligible for review.
        path = Path(filename)
        module = _module_for_path(path)
        if module:
            path = path.resolve()
            if _module_for_path(path) == module and function in _source_symbols(str(path))[0]:
                return validate_frame_evidence({'module': module, 'function': function, 'line': line})
    except (OSError, ValueError, RuntimeError):
        pass
    # Unknown filenames/functions may themselves be user content. Retain no
    # identifier from them, matching ordinary exception frame evidence.
    return {'module': 'external', 'function': '<unknown>', 'line': line,
            'path_sha256': hashlib.sha256(filename.encode('utf-8', errors='replace')).hexdigest()}


def project_native_faults(payload: bytes) -> list[dict[str, Any]]:
    """Project bounded CPython fatal dumps without locals, source or raw paths."""
    if not isinstance(payload, bytes):
        return []
    input_truncated = len(payload) > _MAX_INPUT_BYTES
    lines = payload[-_MAX_INPUT_BYTES:].decode('utf-8', errors='replace').splitlines()
    input_truncated |= len(lines) > _MAX_LINES
    lines = lines[-_MAX_LINES:]
    faults: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    in_thread = False
    for line in lines:
        signature = native_fault_signature(line)
        if signature:
            if len(faults) >= _MAX_FAULTS:
                faults[-1]['truncated'] = True
                break
            current = {'schema_version': 1, **signature, 'observed_thread_count': 0,
                       'observed_frame_count': 0, 'frames': [], 'truncated': input_truncated}
            faults.append(current)
            in_thread = False
            continue
        if current is None:
            continue
        if _THREAD.fullmatch(line):
            current['observed_thread_count'] += 1
            in_thread = True
            continue
        match = _FRAME.fullmatch(line) if in_thread else None
        if match:
            current['observed_frame_count'] += 1
            if len(current['frames']) < MAX_FAULT_FRAMES:
                frame = _frame(*match.groups())
                if frame is not None:
                    current['frames'].append(frame)
            else:
                current['truncated'] = True
        elif line.strip() and not line.startswith('  <no Python frame>'):
            # Extension lists, native C stacks, arbitrary prints and payload
            # continuations are never interpreted as Python frame locations.
            in_thread = False
    return faults
