"""Bounded fault locations without exception text, source text or frame locals.

Code identifiers are validated against installed Python source both when they
are recorded and when an existing diagnostic log is exported. Unknown code is
represented only by a path digest and line number.
"""
from __future__ import annotations

import ast
import builtins
import errno
import hashlib
import json
import math
import re
import signal
import socket
import sqlite3
import ssl
import subprocess
import sys
import sysconfig
import threading
import time
from functools import lru_cache
from pathlib import Path
from types import FrameType
from typing import Any, Callable
from urllib.error import HTTPError

MAX_FAULT_FRAMES = 32
MAX_EXCEPTION_CHAIN = 4
_MODULE_RE = re.compile(r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\Z', re.ASCII)
_HASH_RE = re.compile(r'[0-9a-f]{64}\Z')
_HARNESSY_ROOT = Path(__file__).resolve().parents[1]
_COMPILER_FUNCTIONS = frozenset({'<module>', '<lambda>', '<listcomp>', '<dictcomp>', '<setcomp>', '<genexpr>'})
_BUILTIN_EXCEPTIONS = frozenset(
    name for name, value in vars(builtins).items()
    if isinstance(value, type) and issubclass(value, BaseException)
)
_SQLITE_EXCEPTIONS = frozenset({
    'Error', 'Warning', 'InterfaceError', 'DatabaseError', 'DataError',
    'OperationalError', 'IntegrityError', 'InternalError', 'ProgrammingError', 'NotSupportedError',
})
_SQLITE_ERROR_NAMES = frozenset(
    name for name, value in vars(sqlite3).items()
    if name.startswith('SQLITE_') and isinstance(value, int)
)
_DNS_ERROR_NAMES = {
    getattr(socket, name): name for name in sorted(vars(socket))
    if name.startswith('EAI_') and type(getattr(socket, name)) is int
}
_SSL_ERROR_NAMES = {
    getattr(ssl, name): name for name in sorted(vars(ssl))
    if name.startswith('SSL_ERROR_') and isinstance(getattr(ssl, name), int)
}
_NATIVE_EXCEPTION_TYPES = frozenset(
    (item.__module__, item.__name__) for item in (
        socket.gaierror, socket.herror, ssl.SSLError, ssl.SSLZeroReturnError,
        ssl.SSLWantReadError, ssl.SSLWantWriteError, ssl.SSLSyscallError,
        ssl.SSLEOFError, ssl.SSLCertVerificationError,
    )
)
_MAX_TECHNICAL_NUMBER = 2**53 - 1
RUN_DIAGNOSTIC_STAGES = frozenset({
    'initializing', 'waiting', 'prompt_processing', 'prefill', 'generating',
    'tool', 'model_complete', 'unknown',
})
RUN_DIAGNOSTIC_EVENTS = frozenset({
    'run_start', 'model_step_start', 'model_phase', 'model_runtime_status',
    'model_step_complete', 'model_output_segment_start', 'model_phase_timing',
    'tool_call_building', 'tool_start', 'tool_execution_start', 'tool_complete',
    'attachments_sent', 'context_budget', 'timeline_activity', 'timeline_activity_updated',
    'queued_followups_delivered', 'prefill_memory_recovery', 'run_complete', 'run_stop',
})


@lru_cache(maxsize=1)
def _source_roots() -> tuple[tuple[Path, str], ...]:
    roots: list[tuple[Path, str]] = [(_HARNESSY_ROOT, 'harnessy')]
    # Only the installed application's fixed vendor directory is eligible;
    # never map arbitrary workspace Python files as reviewed dependency source.
    installation = (_HARNESSY_ROOT.parent.parent if _HARNESSY_ROOT.parent.name == 'src'
                    else _HARNESSY_ROOT.parent)
    vendor = installation / '.vendor'
    try:
        if vendor.is_dir() and not vendor.is_symlink():
            roots.append((vendor.resolve(), ''))
    except OSError:
        pass
    # Package roots must precede stdlib: site-packages is commonly inside it.
    for kind in ('purelib', 'platlib', 'stdlib', 'platstdlib'):
        root = sysconfig.get_path(kind)
        if root:
            entry = (Path(root).resolve(), '')
            if entry not in roots:
                roots.append(entry)
    return tuple(roots)


def _module_for_path(path: Path) -> str | None:
    for root, prefix in _source_roots():
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if relative.suffix != '.py':
            return None
        parts = list(relative.with_suffix('').parts)
        if parts and parts[-1] == '__init__':
            parts.pop()
        module = '.'.join(([prefix] if prefix else []) + parts)
        if len(module) <= 256 and _MODULE_RE.fullmatch(module):
            return module
    return None


@lru_cache(maxsize=512)
def _source_symbols(path_text: str) -> tuple[frozenset[str], frozenset[str]]:
    """Only static identifiers are retained; never retain or emit source text."""
    try:
        path = Path(path_text)
        if path.stat().st_size > 4_000_000:
            return frozenset(), frozenset()
        tree = ast.parse(path.read_text(encoding='utf-8'))
        functions = {node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        classes = {node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)}
        return frozenset(functions) | _COMPILER_FUNCTIONS, frozenset(classes)
    except (OSError, ValueError, SyntaxError, UnicodeError):
        return frozenset(), frozenset()


@lru_cache(maxsize=512)
def _path_for_module(module: str) -> Path | None:
    if not isinstance(module, str) or len(module) > 256 or not _MODULE_RE.fullmatch(module):
        return None
    for root, prefix in _source_roots():
        if prefix:
            if module != prefix and not module.startswith(prefix + '.'):
                continue
            suffix = module[len(prefix):].lstrip('.')
        else:
            suffix = module
        stem = root.joinpath(*suffix.split('.')) if suffix else root
        for candidate in (stem.with_suffix('.py'), stem / '__init__.py'):
            try:
                resolved = candidate.resolve()
                resolved.relative_to(root)
                if resolved.is_file() and _module_for_path(resolved) == module:
                    return resolved
            except (OSError, ValueError, RuntimeError):
                continue
    return None


def frame_evidence(frame: FrameType) -> dict[str, Any]:
    """Copy code location only. Frame locals/globals and source lines are unused."""
    filename = frame.f_code.co_filename
    line = max(1, frame.f_lineno)
    try:
        path = Path(filename).resolve()
        module = _module_for_path(path)
        function = frame.f_code.co_name
        if module and function in _source_symbols(str(path))[0]:
            return {'module': module, 'function': function, 'line': line}
    except (OSError, ValueError, RuntimeError):
        pass
    return {
        'module': 'external', 'function': '<unknown>', 'line': line,
        'path_sha256': hashlib.sha256(filename.encode('utf-8', errors='replace')).hexdigest(),
    }


def validate_frame_evidence(value: Any) -> dict[str, Any] | None:
    """Recheck log metadata against source; arbitrary injected strings are dropped."""
    if not isinstance(value, dict):
        return None
    line = value.get('line')
    if type(line) is not int or not 1 <= line <= 10_000_000:
        return None
    module, function = value.get('module'), value.get('function')
    if module == 'external' and function == '<unknown>':
        result = {'module': 'external', 'function': '<unknown>', 'line': line}
        digest = value.get('path_sha256')
        if isinstance(digest, str) and _HASH_RE.fullmatch(digest):
            result['path_sha256'] = digest
        return result
    if not isinstance(module, str) or not isinstance(function, str):
        return None
    path = _path_for_module(module)
    if path is None or function not in _source_symbols(str(path))[0]:
        return None
    return {'module': module, 'function': function, 'line': line}


def validate_frames(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, (list, tuple)):
        return []
    return [safe for frame in value[:MAX_FAULT_FRAMES] if (safe := validate_frame_evidence(frame)) is not None]


def _exception_identifier(exc: BaseException) -> tuple[str, str]:
    cls = type(exc)
    try:
        module, name = cls.__module__, cls.__name__
    except Exception:
        return 'external', 'UnknownException'
    if not isinstance(module, str) or not isinstance(name, str):
        return 'external', 'UnknownException'
    if module == 'builtins' and name in _BUILTIN_EXCEPTIONS:
        return module, name
    if module == 'sqlite3' and name in _SQLITE_EXCEPTIONS:
        return module, name
    if (module, name) in _NATIVE_EXCEPTION_TYPES:
        return module, name
    path = _path_for_module(module)
    if path and name in _source_symbols(str(path))[1]:
        return module, name
    return 'external', 'UnknownException'


def _instance_fields(value: Any) -> dict[str, Any]:
    """Read native instance facts without invoking arbitrary property access."""
    try:
        fields = object.__getattribute__(value, '__dict__')
        return fields if isinstance(fields, dict) else {}
    except Exception:
        return {}


def _signed_code(value: Any) -> int | None:
    return value if type(value) is int and -(2**31) <= value < 2**31 else None


def _nonnegative_number(value: Any) -> int | float | None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    return value if 0 <= value <= _MAX_TECHNICAL_NUMBER and math.isfinite(value) else None


def _validated_native_facts(value: Any) -> dict[str, Any]:
    """Revalidate technical scalars; messages, command data and locations are absent."""
    if not isinstance(value, dict):
        return {}
    safe: dict[str, Any] = {}
    code = _signed_code(value.get('errno'))
    if code is not None:
        safe['errno'] = code
        namespace = value.get('errno_namespace')
        if not isinstance(namespace, str) or namespace not in {'system', 'getaddrinfo', 'gethostbyname'}:
            namespace = 'system'
        if namespace != 'system':
            safe['errno_namespace'] = namespace
        name = (_DNS_ERROR_NAMES.get(code) if namespace == 'getaddrinfo' else
                None if namespace == 'gethostbyname' else errno.errorcode.get(code))
        if name is not None:
            safe['errno_name'] = name
    returncode = _signed_code(value.get('returncode'))
    if returncode is not None:
        safe['returncode'] = returncode
        if returncode < 0:
            try:
                safe['termination_signal'] = signal.Signals(-returncode).name
            except ValueError:
                pass
    timeout = _nonnegative_number(value.get('timeout_seconds'))
    if timeout is not None:
        safe['timeout_seconds'] = timeout
    positions = value.get('json_error')
    if isinstance(positions, dict):
        position: dict[str, int] = {}
        for key, minimum in (('line', 1), ('column', 1), ('char', 0)):
            number = positions.get(key)
            if type(number) is int and minimum <= number <= _MAX_TECHNICAL_NUMBER:
                position[key] = number
        if position:
            safe['json_error'] = position
    status = value.get('http_status_code')
    if type(status) is int and 100 <= status <= 599:
        safe['http_status_code'] = status
    verify = value.get('tls_verify_code')
    if type(verify) is int and 0 <= verify < 2**31:
        safe['tls_verify_code'] = verify
    ssl_code = value.get('ssl_error_code')
    if type(ssl_code) is int and 0 <= ssl_code < 2**31:
        safe['ssl_error_code'] = ssl_code
        if ssl_code in _SSL_ERROR_NAMES:
            safe['ssl_error_name'] = _SSL_ERROR_NAMES[ssl_code]
    return safe


def _native_exception_facts(exc: BaseException) -> dict[str, Any]:
    """Capture typed exception facts, never format an exception or read a body."""
    facts: dict[str, Any] = {}
    # Native descriptors expose numeric facts. Each family is isolated so a
    # malformed subclass cannot suppress useful facts from the remaining ones.
    if isinstance(exc, OSError):
        try:
            key = 'ssl_error_code' if isinstance(exc, ssl.SSLError) else 'errno'
            facts[key] = OSError.errno.__get__(exc)
            if isinstance(exc, socket.gaierror):
                facts['errno_namespace'] = 'getaddrinfo'
            elif isinstance(exc, socket.herror):
                facts['errno_namespace'] = 'gethostbyname'
        except Exception:
            pass
    if isinstance(exc, subprocess.CalledProcessError):
        facts['returncode'] = _instance_fields(exc).get('returncode')
    if isinstance(exc, subprocess.TimeoutExpired):
        facts['timeout_seconds'] = _instance_fields(exc).get('timeout')
    if isinstance(exc, json.JSONDecodeError):
        fields = _instance_fields(exc)
        facts['json_error'] = {'line': fields.get('lineno'), 'column': fields.get('colno'),
                               'char': fields.get('pos')}
    if isinstance(exc, ssl.SSLCertVerificationError):
        try:
            facts['tls_verify_code'] = ssl.SSLCertVerificationError.verify_code.__get__(exc)
        except (AttributeError, TypeError):
            # CPython versions expose these facts as instance attributes.
            facts['tls_verify_code'] = _instance_fields(exc).get('verify_code')
        except Exception:
            pass
    fields = _instance_fields(exc)
    status = fields.get('status_code')
    if status is None and isinstance(exc, HTTPError):
        status = fields.get('code')
    if status is None:
        # httpx/requests status errors retain a response object. Only its
        # explicit numeric status attribute is inspected; URLs, headers, body,
        # request and response representations are never accessed.
        status = _instance_fields(fields.get('response')).get('status_code')
    facts['http_status_code'] = status
    return _validated_native_facts(facts)


def _exception_part(exc: BaseException) -> dict[str, Any]:
    module, name = _exception_identifier(exc)
    result: dict[str, Any] = {'exception_module': module, 'exception_type': name, 'frames': []}
    result.update(_native_exception_facts(exc))
    try:
        code = getattr(exc, 'sqlite_errorcode', None)
        sqlite_name = getattr(exc, 'sqlite_errorname', None)
    except Exception:
        code, sqlite_name = None, None
    if type(code) is int and 0 <= code <= 0x7fffffff:
        result['sqlite_errorcode'] = code
    if isinstance(sqlite_name, str) and sqlite_name in _SQLITE_ERROR_NAMES:
        result['sqlite_errorname'] = sqlite_name
    tb = exc.__traceback__
    # Retain the innermost locations if an unusually deep stack is raised.
    while tb is not None:
        result['frames'].append(frame_evidence(tb.tb_frame))
        result['frames'] = result['frames'][-MAX_FAULT_FRAMES:]
        result['frames'][-1]['line'] = max(1, tb.tb_lineno)
        tb = tb.tb_next
    return result


def exception_evidence(exc: BaseException) -> dict[str, Any]:
    """Capture technical facts and causes without evaluating exception text."""
    result = _exception_part(exc)
    result['chain'] = []
    seen = {id(exc)}
    current = exc
    for _ in range(MAX_EXCEPTION_CHAIN):
        cause = current.__cause__
        relationship = 'cause'
        if cause is None and not current.__suppress_context__:
            cause, relationship = current.__context__, 'context'
        if cause is None:
            break
        if id(cause) in seen:
            result['chain_truncated'] = True
            break
        seen.add(id(cause))
        result['chain'].append({'relationship': relationship, **_exception_part(cause)})
        current = cause
    else:
        if current.__cause__ is not None or (current.__context__ is not None and not current.__suppress_context__):
            result['chain_truncated'] = True
    return result


def _validated_exception_part(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    module, name = value.get('exception_module'), value.get('exception_type')
    if not isinstance(module, str) or not isinstance(name, str):
        return None
    valid = ((module == 'builtins' and name in _BUILTIN_EXCEPTIONS)
             or (module == 'sqlite3' and name in _SQLITE_EXCEPTIONS)
             or (module, name) in _NATIVE_EXCEPTION_TYPES)
    if module == 'external' and name == 'UnknownException':
        valid = True
    if not valid and isinstance(module, str) and isinstance(name, str):
        path = _path_for_module(module)
        valid = bool(path and name in _source_symbols(str(path))[1])
    if not valid:
        return None
    result = {'exception_module': module, 'exception_type': name, 'frames': validate_frames(value.get('frames'))}
    result.update(_validated_native_facts(value))
    code, sqlite_name = value.get('sqlite_errorcode'), value.get('sqlite_errorname')
    if type(code) is int and 0 <= code <= 0x7fffffff:
        result['sqlite_errorcode'] = code
    if isinstance(sqlite_name, str) and sqlite_name in _SQLITE_ERROR_NAMES:
        result['sqlite_errorname'] = sqlite_name
    return result


def validate_fault_evidence(value: Any) -> dict[str, Any] | None:
    result = _validated_exception_part(value)
    if result is None:
        return None
    result['chain'] = []
    chain = value.get('chain')
    if isinstance(chain, list):
        for item in chain[:MAX_EXCEPTION_CHAIN]:
            if not isinstance(item, dict) or not isinstance(item.get('relationship'), str) or item['relationship'] not in {'cause', 'context'}:
                continue
            safe = _validated_exception_part(item)
            if safe is not None:
                result['chain'].append({'relationship': item['relationship'], **safe})
    if value.get('chain_truncated') is True:
        result['chain_truncated'] = True
    return result


def run_stage_evidence(state: dict[str, Any], last_event: str = 'run_start') -> dict[str, Any]:
    """Use fixed runtime stage labels, never status text or a model tool name."""
    event = last_event if last_event in RUN_DIAGNOSTIC_EVENTS else 'run_start'
    if isinstance(state.get('current_tool'), dict):
        stage = 'tool'
    elif state.get('assistant_persisted'):
        stage = 'model_complete'
    else:
        stage = state.get('phase')
        if not isinstance(stage, str) or stage not in RUN_DIAGNOSTIC_STAGES:
            stage = 'initializing' if event == 'run_start' else 'unknown'
    result = {'last_stage': stage, 'last_event': event, 'model_persisted': bool(state.get('assistant_persisted'))}
    step = state.get('step')
    if type(step) is int and 0 <= step <= 1_000_000:
        result['step'] = step
    return result


class EventLoopStallMonitor:
    """An independent thread observes loop heartbeats and samples only code frames.

    It never asks the stalled loop for tasks, task names or other runtime state.
    At most three samples are emitted per stalled heartbeat, at least one
    second apart. Diagnostic failure cannot stop an application run.
    """

    def __init__(self, loop_thread_id: int, emit: Callable[..., Any], *, threshold_seconds: float = 1.75,
                 sample_interval: float = 1.0, poll_interval: float = 0.25) -> None:
        self.loop_thread_id = loop_thread_id
        self.emit = emit
        self.threshold_seconds = max(0.05, threshold_seconds)
        self.sample_interval = max(0.05, sample_interval)
        self.poll_interval = max(0.01, poll_interval)
        self._heartbeat = time.monotonic()
        self._generation = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self.beat()
        self._thread = threading.Thread(target=self._watch, name='harnessy-loop-stall-monitor', daemon=True)
        self._thread.start()

    def beat(self) -> None:
        with self._lock:
            self._heartbeat = time.monotonic()
            self._generation += 1

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=0.5)

    def _watch(self) -> None:
        generation, samples, last_sample = -1, 0, 0.0
        while not self._stop.wait(self.poll_interval):
            with self._lock:
                heartbeat, current_generation = self._heartbeat, self._generation
            if current_generation != generation:
                generation, samples = current_generation, 0
            now = time.monotonic()
            age = max(0.0, now - heartbeat)
            if age < self.threshold_seconds or samples >= 3 or now - last_sample < self.sample_interval:
                continue
            samples += 1
            last_sample = now
            try:
                frame = sys._current_frames().get(self.loop_thread_id)
                frames = []
                while frame is not None and len(frames) < MAX_FAULT_FRAMES:
                    frames.append(frame_evidence(frame))
                    frame = frame.f_back
                del frame
                if frames and math.isfinite(age):
                    self.emit('runtime', 'event_loop_stall_sample', frames=list(reversed(frames)),
                              blocked_seconds=round(max(0.0, age - 1.0), 3),
                              heartbeat_age_seconds=round(age, 3), sample_sequence=samples, thread_id=self.loop_thread_id)
            except Exception:
                # Logging must remain best effort and cannot crash the watcher.
                continue
