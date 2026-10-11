"""Run-private, bounded stdio MCP transport for the local REA installation.

Starting an analysis never installs software. Only ``install_rea`` (startup or
the Settings button) prepares the cached runtime. No server output, arguments, paths or
environment values are written to HarnessyXO diagnostics.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import threading
import uuid
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .. import __version__
from ..core.paths import settings_dir
from ..core.rea_settings import REA_PACKAGE, REA_VERSION, normalize_rea_settings
from ..diagnostics import log_event

MAX_FRAME_BYTES = 12 * 1024 * 1024
MAX_STDERR_BYTES = 64 * 1024
INITIALIZE_TIMEOUT = 30.0
CLOSE_TIMEOUT = 5.0
INSTALL_TIMEOUT = 600.0
GRACEFUL_SHUTDOWN_TIMEOUT = 10.0
_INSTALL_TASK: asyncio.Task[dict[str, Any]] | None = None
_INSTALL_WAITERS = 0
_INSTALL_TASK_WAITERS: dict[asyncio.Task[Any], int] = {}
_INSTALL_CANCELLING: set[asyncio.Task[Any]] = set()
RUNTIME_MARKER = '.harnessy-rea-runtime.json'
SUPPORTED_PROTOCOL_VERSIONS = frozenset({'2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25'})
_METHODS = frozenset({'initialize', 'tools/list', 'tools/call'})
_MESSAGES = {
    'REA_RUNTIME_MISSING': 'Install REA in Settings, or configure an existing local REA command.',
    'REA_NODE_MISSING': 'REA needs Node.js. Restart HarnessyXO or use Install REA in Settings to prepare its private runtime.',
    'REA_NODE_UNSUPPORTED': 'REA needs Node.js 22.19+, 24.11+, or 26+. Restart HarnessyXO or use Install REA in Settings to prepare its private runtime.',
    'REA_VERSION_MISMATCH': 'Install the supported REA 6.4.0 runtime from Settings.',
    'REA_NPM_MISSING': 'Install npm alongside the supported Node.js runtime, then try Install REA again.',
    'REA_START_FAILED': 'The configured local REA process could not start. Check the command and runtime in Settings.',
    'REA_PROTOCOL_ERROR': 'The local REA process returned an invalid or unsupported MCP message.',
    'REA_FRAME_TOO_LARGE': 'A local REA MCP message exceeded the 12 MiB transport limit. Request a smaller analysis result.',
    'REA_TIMEOUT': 'The local REA request timed out. Its owned process was stopped; the failed tool was not repeated.',
    'REA_CONNECTION_CLOSED': 'This local REA session is closed. A later request may open a new session.',
    'REA_RPC_ERROR': 'The local REA server rejected this MCP request.',
    'REA_INVALID_ARGUMENTS': 'REA tool arguments must be a JSON object containing finite JSON values.',
    'REA_CLOSE_FAILED': 'REA reported a provider cleanup failure; its owned process was stopped.',
    'REA_INSTALL_FAILED': 'REA installation failed. Check npm connectivity and the local Node.js installation, then try again.',
    'REA_STORAGE_UNSAFE': 'REA setup was stopped because its settings or runtime directories are unsafe. Use private directories owned by your account without symlink redirects.',
}


class ReaError(RuntimeError):
    """Safe fixed failure text; arbitrary server text is never interpolated."""

    def __init__(self, code: str) -> None:
        self.code = code if code in _MESSAGES else 'REA_PROTOCOL_ERROR'
        self.remediation = _MESSAGES[self.code]
        super().__init__(self.remediation)


class ReaToolError(ReaError):
    """Preserve the server error locally, separately from safe diagnostics text."""

    def __init__(self, rpc_error: dict[str, Any] | None = None, *, code: str = 'REA_RPC_ERROR',
                 tool_result: dict[str, Any] | None = None) -> None:
        super().__init__(code)
        self.rpc_error = rpc_error or {}
        self.tool_result = tool_result


def _event(event: str, **metadata: Any) -> None:
    try:
        log_event('tools', event, **metadata)
    except Exception:
        pass


def _reject_json_constant(_value: str) -> Any:
    raise ValueError('Non-finite JSON constant')


def _runtime_directory() -> Path:
    return settings_dir() / 'rea' / 'runtime'


def _validate_rea_storage() -> None:
    from ..core.auth_users import UserStore, UserStoreError
    try:
        root = settings_dir()
        UserStore(root)  # Directory validation only; creates no account files.
        files = {'rea/node/bin/node', 'rea/node/node.exe', 'rea/node/harnessy-node.json',
                 'rea/node/lib/node_modules/npm/bin/npm-cli.js', 'rea/node/node_modules/npm/bin/npm-cli.js',
                 f'rea/runtime/node_modules/{REA_PACKAGE}/scripts/rea.mjs',
                 f'rea/runtime/node_modules/{REA_PACKAGE}/package.json', f'rea/runtime/{RUNTIME_MARKER}'}
        for relative in ('rea', 'rea/runtime', 'rea/npm-cache', 'rea/node', 'rea/node/bin', 'rea/node/bin/node',
                         'rea/node/node.exe', 'rea/node/harnessy-node.json', 'rea/node/lib', 'rea/node/lib/node_modules',
                         'rea/node/lib/node_modules/npm', 'rea/node/lib/node_modules/npm/bin',
                         'rea/node/lib/node_modules/npm/bin/npm-cli.js', 'rea/node/node_modules',
                         'rea/node/node_modules/npm', 'rea/node/node_modules/npm/bin',
                         'rea/node/node_modules/npm/bin/npm-cli.js', 'rea/runtime/node_modules',
                         f'rea/runtime/node_modules/{REA_PACKAGE}', f'rea/runtime/node_modules/{REA_PACKAGE}/scripts',
                         f'rea/runtime/node_modules/{REA_PACKAGE}/scripts/rea.mjs',
                         f'rea/runtime/node_modules/{REA_PACKAGE}/package.json', f'rea/runtime/{RUNTIME_MARKER}'):
            path = root / relative
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            expected_kind = stat.S_ISREG if relative in files else stat.S_ISDIR
            if not expected_kind(info.st_mode) or (os.name != 'nt' and
                    (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022)):
                raise ReaError('REA_STORAGE_UNSAFE')
    except (OSError, UserStoreError):
        raise ReaError('REA_STORAGE_UNSAFE') from None


def _runtime_identity() -> dict[str, str]:
    from ..core.rea_bootstrap import host_identity
    host = host_identity()
    return {'package': REA_PACKAGE, 'version': REA_VERSION, 'platform': host['platform'], 'arch': host['architecture']}


def _managed_runtime_installed(runtime: Path | None = None) -> bool:
    runtime = runtime or _runtime_directory()
    package = runtime / 'node_modules' / REA_PACKAGE
    if _package_version(package) != REA_VERSION or not (package / 'scripts' / 'rea.mjs').is_file():
        return False
    try:
        marker = runtime / RUNTIME_MARKER
        return marker.stat().st_size <= 16 * 1024 and json.loads(marker.read_text(encoding='utf-8')) == _runtime_identity()
    except (OSError, ValueError, RecursionError):
        return False


def _package_version(root: Path) -> str | None:
    try:
        path = root / 'package.json'
        if path.stat().st_size > 128 * 1024:
            return None
        data = json.loads(path.read_text(encoding='utf-8'))
        version = data.get('version') if isinstance(data, dict) and data.get('name') == REA_PACKAGE else None
        return version if isinstance(version, str) and re.fullmatch(r'\d+\.\d+\.\d+', version) else None
    except (OSError, ValueError, RecursionError):
        return None


def _node_supported(version: str | None) -> bool:
    if not isinstance(version, str) or not re.fullmatch(r'\d+\.\d+\.\d+', version):
        return False
    major, minor, patch = map(int, version.split('.'))
    return (major == 22 and (minor, patch) >= (19, 0) or
            major == 24 and (minor, patch) >= (11, 0) or major >= 26)


def _executable_candidates(name: str) -> list[str]:
    from ..core.rea_bootstrap import cached_node_paths
    _validate_rea_storage()
    private = settings_dir() / 'rea' / 'node'
    cached = cached_node_paths(private) if name in {'node', 'npm'} else None
    managed = cached['node_path' if name == 'node' else 'npm_cli_path'] if cached else None
    candidates = [managed,
                  shutil.which(name), f'/opt/homebrew/bin/{name}', f'/usr/local/bin/{name}']
    result = []
    for path in dict.fromkeys(candidates):
        if not path or not Path(path).is_file():
            continue
        try:
            resolved = Path(path).resolve()
            if name in {'node', 'npm'} and resolved.is_relative_to(private.resolve()) and (
                    managed is None or resolved != Path(managed).resolve()):
                continue
        except (OSError, RuntimeError):
            continue
        result.append(path)
    return result


async def _probe_node(path: str) -> str | None:
    process = None
    try:
        async def spawn_and_register() -> None:
            nonlocal process
            process = await asyncio.create_subprocess_exec(
                path, '--version', stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                env={key: value for key, value in os.environ.items() if key not in {'NODE_OPTIONS', 'NODE_PATH'}},
                **_process_options(),
            )
        await _await_owned_cleanup(asyncio.create_task(spawn_and_register()))
        # --version has a fixed tiny output, but read only a bounded prefix.
        assert process.stdout is not None
        data = await asyncio.wait_for(process.stdout.read(128), 3.0)
        await asyncio.wait_for(process.wait(), 1.0)
        match = re.fullmatch(rb'v?(\d+\.\d+\.\d+)\s*', data)
        return match.group(1).decode('ascii') if process.returncode == 0 and match else None
    except asyncio.CancelledError:
        raise
    except (OSError, asyncio.TimeoutError):
        return None
    finally:
        if process is not None:
            await _await_owned_cleanup(asyncio.create_task(_stop_process(process)))


async def _find_node() -> tuple[str | None, str | None]:
    first_version = None
    for path in _executable_candidates('node'):
        version = await _probe_node(path)
        first_version = first_version or version
        if _node_supported(version):
            return path, version
    return None, first_version


@dataclass(frozen=True)
class _Launcher:
    command: tuple[str, ...]
    kind: str
    version: str | None
    node: str | None = None


def _global_package(binary: str) -> Path | None:
    candidates = (Path(binary).resolve().parent.parent,
                  Path(binary).parent / 'node_modules' / REA_PACKAGE)
    return next((path for path in candidates if _package_version(path) is not None), None)


async def _launcher(settings: dict[str, Any]) -> _Launcher:
    _validate_rea_storage()
    if settings['command']:
        return _Launcher((settings['command'], *settings['arguments']), 'configured', None)
    node, version = await _find_node()
    if node is None:
        raise ReaError('REA_NODE_UNSUPPORTED' if version else 'REA_NODE_MISSING')
    package = _runtime_directory() / 'node_modules' / REA_PACKAGE
    script = package / 'scripts' / 'rea.mjs'
    installed_version = _package_version(package)
    if _managed_runtime_installed():
        return _Launcher((node, str(script), 'mcp'), 'managed', installed_version, node)
    for binary in _executable_candidates('rea'):
        root = _global_package(binary)
        if root is not None and _package_version(root) == REA_VERSION:
            entry = root / 'scripts' / 'rea.mjs'
            if entry.is_file():
                return _Launcher((node, str(entry), 'mcp'), 'global', REA_VERSION, node)
    raise ReaError('REA_VERSION_MISMATCH' if installed_version and installed_version != REA_VERSION else 'REA_RUNTIME_MISSING')


def _child_environment(settings: dict[str, Any], node: str | None = None) -> dict[str, str]:
    environment = dict(os.environ)
    # Upstream opens HOPPER_TARGET_PATH before MCP starts. Never inherit a target
    # or loader input; only an authorized open_binary request selects the target.
    for key in ('HOPPER_TARGET_PATH', 'HOPPER_TARGET_KIND', 'HOPPER_LOADER_ARGS_JSON',
                'REA_GHIDRA_SEED_FILE', 'REA_GHIDRA_NATIVEAOT_JAR', 'REA_IDA_MCP_CONFIG',
                'NODE_OPTIONS', 'NODE_PATH'):
        environment.pop(key, None)
    environment.update(settings['environment'])
    for key in ('HOPPER_TARGET_PATH', 'HOPPER_TARGET_KIND', 'HOPPER_LOADER_ARGS_JSON'):
        environment.pop(key, None)
    environment['REA_ANALYSIS_PROVIDER'] = settings['provider']
    if node:
        environment['PATH'] = str(Path(node).parent) + os.pathsep + environment.get('PATH', '')
    return environment


def _process_options() -> dict[str, Any]:
    if os.name == 'nt':
        return {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP}
    return {'start_new_session': True}


async def _stop_process(process: asyncio.subprocess.Process, *, graceful_timeout: float = 0.0) -> None:
    """Stop only this launch's process group, including surviving children."""
    if graceful_timeout and process.returncode is None:
        # REA owns some detached provider groups (and a user-owned Hopper app).
        # EOF invokes its own cleanup; allow that cleanup to finish before a
        # forced signal. A group kill alone cannot reach detached providers.
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(process.wait(), graceful_timeout)
    if os.name == 'nt':
        # Python has no Windows Job Object API. taskkill /T follows only this
        # owned PID; fall back to killing the root if taskkill is unavailable.
        taskkill = shutil.which('taskkill')
        if taskkill and process.returncode is None:
            killer = None
            try:
                killer = await asyncio.create_subprocess_exec(taskkill, '/PID', str(process.pid), '/T', '/F',
                                                             stdout=asyncio.subprocess.DEVNULL,
                                                             stderr=asyncio.subprocess.DEVNULL)
                await asyncio.wait_for(killer.wait(), 3.0)
            except (OSError, asyncio.TimeoutError):
                pass
            finally:
                if killer is not None and killer.returncode is None:
                    killer.kill()
                    await killer.wait()
        if process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
    else:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(process.pid, signal.SIGTERM)
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(process.wait(), 2.0)
        # The leader can exit before a provider child; kill the owned group even
        # when returncode has already been set by the subprocess watcher.
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(process.pid, signal.SIGKILL)
    with contextlib.suppress(asyncio.TimeoutError):
        await asyncio.wait_for(process.wait(), 2.0)


async def _await_owned_cleanup(task: asyncio.Task[Any], *, suppress_error: bool = False) -> Any:
    """Settle shielded owned cleanup even if the caller is cancelled repeatedly."""
    cancelled = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            cancelled = True
            if task.cancelled():
                break
        except Exception:
            break
    if cancelled:
        # Retrieve a simultaneous cleanup error without replacing cancellation.
        with contextlib.suppress(BaseException):
            task.result()
        raise asyncio.CancelledError
    if suppress_error:
        with contextlib.suppress(ReaError):
            return task.result()
        return None
    return task.result()


class ReaClient:
    """One lazy MCP process and binary session owned by one toolbox/run."""

    def __init__(self, settings: dict[str, Any], *, working_directory: Path) -> None:
        self.settings = normalize_rea_settings(settings)
        self.working_directory = Path(working_directory)
        self.closed = False
        self.server_info: dict[str, Any] = {}
        self.protocol_version: str | None = None
        self._process: asyncio.subprocess.Process | None = None
        self._reader_task: asyncio.Task[Any] | None = None
        self._stderr_task: asyncio.Task[Any] | None = None
        self._close_task: asyncio.Task[Any] | None = None
        self._pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self._stderr_tail: deque[bytes] = deque()
        self._stderr_size = 0
        self._next_id = 1
        self._ready = False
        self._closing = False
        self._start_lock = asyncio.Lock()
        self._ownership_lock = asyncio.Lock()
        self._operation_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()

    async def _write(self, message: dict[str, Any]) -> None:
        try:
            frame = json.dumps(message, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode('utf-8') + b'\n'
        except (ValueError, TypeError, RecursionError) as exc:
            raise ReaError('REA_INVALID_ARGUMENTS') from exc
        if len(frame) > MAX_FRAME_BYTES:
            raise ReaError('REA_FRAME_TOO_LARGE')
        async with self._write_lock:
            if self._process is None or self._process.stdin is None or self._process.returncode is not None:
                raise ReaError('REA_CONNECTION_CLOSED')
            try:
                self._process.stdin.write(frame)
                await self._process.stdin.drain()
            except (OSError, ConnectionError) as exc:
                raise ReaError('REA_CONNECTION_CLOSED') from exc

    async def _stderr_reader(self) -> None:
        assert self._process is not None and self._process.stderr is not None
        while data := await self._process.stderr.read(4096):
            self._stderr_tail.append(data)
            self._stderr_size += len(data)
            while self._stderr_size > MAX_STDERR_BYTES and self._stderr_tail:
                self._stderr_size -= len(self._stderr_tail.popleft())

    async def _reader(self) -> None:
        assert self._process is not None and self._process.stdout is not None
        error = ReaError('REA_CONNECTION_CLOSED')
        try:
            while True:
                try:
                    frame = await self._process.stdout.readuntil(b'\n')
                except asyncio.IncompleteReadError as exc:
                    if exc.partial:
                        raise ReaError('REA_PROTOCOL_ERROR') from None
                    break
                except asyncio.LimitOverrunError:
                    raise ReaError('REA_FRAME_TOO_LARGE') from None
                if len(frame) > MAX_FRAME_BYTES:
                    raise ReaError('REA_FRAME_TOO_LARGE')
                try:
                    message = json.loads(frame, parse_constant=_reject_json_constant)
                except (ValueError, UnicodeError, RecursionError):
                    raise ReaError('REA_PROTOCOL_ERROR') from None
                if not isinstance(message, dict) or message.get('jsonrpc') != '2.0':
                    raise ReaError('REA_PROTOCOL_ERROR')
                if 'method' in message:
                    # No sampling, elicitation or filesystem-roots capability is
                    # advertised. Reject such requests instead of awaiting UI.
                    if 'id' in message:
                        identity = message['id']
                        if not isinstance(identity, (str, int)) or isinstance(identity, bool):
                            raise ReaError('REA_PROTOCOL_ERROR')
                        response = ({'result': {}} if message['method'] == 'ping' else
                                    {'error': {'code': -32601, 'message': 'Client method is unsupported'}})
                        await self._write({'jsonrpc': '2.0', 'id': identity, **response})
                    continue
                identity = message.get('id')
                if type(identity) is not int:
                    raise ReaError('REA_PROTOCOL_ERROR')
                future = self._pending.get(identity)
                if future is None or future.done():
                    continue
                if isinstance(message.get('error'), dict):
                    future.set_exception(ReaToolError(message['error']))
                elif isinstance(message.get('result'), dict):
                    future.set_result(message['result'])
                else:
                    raise ReaError('REA_PROTOCOL_ERROR')
        except asyncio.CancelledError:
            return
        except ReaError as exc:
            error = exc
        except Exception:
            error = ReaError('REA_PROTOCOL_ERROR')
        for future in tuple(self._pending.values()):
            if not future.done():
                future.set_exception(error)
        self.closed = True
        if self._close_task is None:
            self._close_task = asyncio.create_task(self._close_impl(graceful=False))

    async def _request(self, method: str, params: dict[str, Any], timeout: float) -> dict[str, Any]:
        identity, self._next_id = self._next_id, self._next_id + 1
        future = asyncio.get_running_loop().create_future()
        self._pending[identity] = future
        try:
            async def exchange() -> dict[str, Any]:
                await self._write({'jsonrpc': '2.0', 'id': identity, 'method': method, 'params': params})
                return await future
            return await asyncio.wait_for(exchange(), timeout)
        except asyncio.CancelledError:
            try:
                await self._notify_cancelled(identity)
            finally:
                await self._abort()
            raise
        except asyncio.TimeoutError as exc:
            _event('rea_transport_failure', error_code='REA_TIMEOUT', operation=method if method in _METHODS else 'other')
            try:
                await self._notify_cancelled(identity)
            finally:
                await self._abort()
            raise ReaError('REA_TIMEOUT') from exc
        except ReaToolError:
            raise
        except ReaError:
            # During normal close, the owner will terminate after cleanup.
            if not self._closing:
                await self._abort()
            raise
        finally:
            self._pending.pop(identity, None)
            if not future.done():
                future.cancel()
            elif not future.cancelled():
                # A write failure may precede a reader failure; consume any
                # otherwise-unobserved exception when removing the request.
                future.exception()

    async def _notify_cancelled(self, identity: int) -> None:
        # Give the provider its protocol cancellation before stopping the owned
        # group. This is best effort and never waits on the provider's response.
        try:
            await asyncio.wait_for(self._write({'jsonrpc': '2.0', 'method': 'notifications/cancelled',
                                               'params': {'requestId': identity}}), 0.25)
        except (Exception, asyncio.CancelledError):
            pass

    async def _start(self) -> None:
        async with self._start_lock:
            if self.closed or self._closing:
                raise ReaError('REA_CONNECTION_CLOSED')
            if self._ready:
                return
            try:
                launcher = await _launcher(self.settings)
                async with self._ownership_lock:
                    if self.closed or self._closing:
                        raise ReaError('REA_CONNECTION_CLOSED')
                    self.working_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
                    async def spawn_and_register() -> None:
                        self._process = await asyncio.create_subprocess_exec(
                            *launcher.command, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE, cwd=self.working_directory,
                            env=_child_environment(self.settings, launcher.node), limit=MAX_FRAME_BYTES,
                            **_process_options(),
                        )
                    # Complete ownership registration even if cancellation lands
                    # after spawn has created the child but before it returns.
                    spawn = asyncio.create_task(spawn_and_register())
                    await _await_owned_cleanup(spawn)
                if self.closed or self._closing:
                    raise ReaError('REA_CONNECTION_CLOSED')
                self._reader_task = asyncio.create_task(self._reader())
                self._stderr_task = asyncio.create_task(self._stderr_reader())
                result = await self._request('initialize', {
                    'protocolVersion': '2025-11-25', 'capabilities': {},
                    'clientInfo': {'name': 'HarnessyXO', 'version': __version__},
                }, INITIALIZE_TIMEOUT)
                protocol = result.get('protocolVersion')
                if not isinstance(protocol, str) or protocol not in SUPPORTED_PROTOCOL_VERSIONS:
                    raise ReaError('REA_PROTOCOL_ERROR')
                info = result.get('serverInfo')
                if not isinstance(info, dict):
                    raise ReaError('REA_PROTOCOL_ERROR')
                version = info.get('version')
                if version != REA_VERSION:
                    raise ReaError('REA_VERSION_MISMATCH')
                self.server_info, self.protocol_version = info, protocol
                await self._write({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
                self._ready = True
                _event('rea_transport_started', pid=self._process.pid, operation=launcher.kind,
                       version=version if version == REA_VERSION else None)
            except asyncio.CancelledError:
                await self._abort()
                raise
            except ReaError:
                await self._abort()
                raise
            except (OSError, ValueError) as exc:
                await self._abort()
                raise ReaError('REA_START_FAILED') from exc

    async def list_tools(self) -> list[dict[str, Any]]:
        try:
            return await self._list_tools()
        except asyncio.CancelledError:
            await self._abort()
            raise

    async def _list_tools(self) -> list[dict[str, Any]]:
        await self._start()
        async with self._operation_lock:
            if self.closed or self._closing:
                raise ReaError('REA_CONNECTION_CLOSED')
            tools: list[dict[str, Any]] = []
            cursor = None
            seen: set[str] = set()
            for _ in range(100):
                result = await self._request('tools/list', {'cursor': cursor} if cursor else {}, INITIALIZE_TIMEOUT)
                page = result.get('tools')
                if not isinstance(page, list) or any(not isinstance(tool, dict) for tool in page):
                    await self._abort()
                    raise ReaError('REA_PROTOCOL_ERROR')
                tools.extend(page)
                if len(tools) > 5000:
                    await self._abort()
                    raise ReaError('REA_PROTOCOL_ERROR')
                cursor = result.get('nextCursor')
                if cursor is None:
                    return tools
                if not isinstance(cursor, str) or not cursor or cursor in seen or len(cursor) > 4096:
                    await self._abort()
                    raise ReaError('REA_PROTOCOL_ERROR')
                seen.add(cursor)
            await self._abort()
            raise ReaError('REA_PROTOCOL_ERROR')

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        try:
            return await self._call_tool(name, arguments)
        except asyncio.CancelledError:
            await self._abort()
            raise

    async def _call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(name, str) or not name or len(name) > 256 or not isinstance(arguments, dict):
            raise ReaError('REA_INVALID_ARGUMENTS')
        await self._start()
        async with self._operation_lock:
            if self.closed or self._closing:
                raise ReaError('REA_CONNECTION_CLOSED')
            return await self._request('tools/call', {'name': name, 'arguments': arguments},
                                       float(self.settings['timeout_seconds']))

    async def _close_impl(self, *, graceful: bool) -> None:
        self._closing = True
        error = None
        try:
            # Launch holds only this ownership lock while settling spawn. It
            # never holds it while awaiting initialization or error cleanup.
            async with self._ownership_lock:
                pass
            if graceful and self._ready and not self._pending and self._process is not None and self._process.returncode is None:
                try:
                    result = await self._request('tools/call', {'name': 'close_binary', 'arguments': {}}, CLOSE_TIMEOUT)
                    if result.get('isError') is True:
                        error = ReaToolError(code='REA_CLOSE_FAILED', tool_result=result)
                except (ReaError, asyncio.TimeoutError) as exc:
                    error = exc
        finally:
            self.closed = True
            for future in tuple(self._pending.values()):
                if not future.done():
                    future.set_exception(ReaError('REA_CONNECTION_CLOSED'))
            if self._process is not None:
                # An oversized frame can pause stdout's pipe transport. Cancel
                # the protocol reader and discard remaining bytes while stopping
                # the process so EOF closes the transport on this event loop.
                if self._reader_task is not None and self._reader_task is not asyncio.current_task():
                    self._reader_task.cancel()
                    await asyncio.gather(self._reader_task, return_exceptions=True)
                if self._process.stdin is not None:
                    self._process.stdin.close()
                    with contextlib.suppress(OSError, asyncio.TimeoutError):
                        await asyncio.wait_for(self._process.stdin.wait_closed(), 0.5)
                async def discard_stdout() -> None:
                    if self._process is not None and self._process.stdout is not None:
                        while await self._process.stdout.read(65536):
                            pass
                discard = asyncio.create_task(discard_stdout())
                try:
                    await _stop_process(self._process, graceful_timeout=GRACEFUL_SHUTDOWN_TIMEOUT)
                    with contextlib.suppress(asyncio.TimeoutError):
                        await asyncio.wait_for(discard, 1.0)
                finally:
                    discard.cancel()
                    await asyncio.gather(discard, return_exceptions=True)
            tasks = [task for task in (self._reader_task, self._stderr_task)
                     if task is not None and task is not asyncio.current_task()]
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            self._stderr_tail.clear()
            self._stderr_size = 0
            _event('rea_transport_closed', pid=self._process.pid if self._process else None)
        if error is not None:
            raise error

    async def _abort(self) -> None:
        self.closed = True
        if self._close_task is None:
            self._close_task = asyncio.create_task(self._close_impl(graceful=False))
        if self._close_task is asyncio.current_task():
            return
        await _await_owned_cleanup(self._close_task, suppress_error=True)

    async def close(self) -> None:
        self._closing = True
        if self._close_task is None:
            self._close_task = asyncio.create_task(self._close_impl(graceful=True))
        await _await_owned_cleanup(self._close_task)


async def rea_status(settings: dict[str, Any]) -> dict[str, Any]:
    """Read installation state without starting MCP or running setup."""
    config = normalize_rea_settings(settings)
    try:
        _validate_rea_storage()
    except ReaError as exc:
        return {'ok': False, 'status': 'storage_unsafe', 'version': None, 'expected_version': REA_VERSION,
                'node_supported': False, 'node_version': None, 'runtime_installed': False,
                'code': exc.code, 'remediation': exc.remediation}
    node, node_version = await _find_node()
    root = _runtime_directory() / 'node_modules' / REA_PACKAGE
    version = _package_version(root)
    runtime_installed = _managed_runtime_installed()
    state = {'ok': False, 'status': 'runtime_missing', 'version': version, 'expected_version': REA_VERSION,
             'node_supported': node is not None, 'node_version': node_version,
             'runtime_installed': runtime_installed, 'remediation': _MESSAGES['REA_RUNTIME_MISSING']}
    if config['command']:
        state.update(ok=True, status='configured', remediation='The configured command will be checked when analysis starts.')
    elif node is None:
        code = 'REA_NODE_UNSUPPORTED' if node_version else 'REA_NODE_MISSING'
        state.update(status='node_unsupported' if node_version else 'node_missing', remediation=_MESSAGES[code])
    else:
        try:
            launch = await _launcher(config)
            state.update(ok=True, status='ready', version=launch.version, remediation='REA is ready for local analysis.')
        except ReaError as exc:
            state.update(status='version_mismatch' if exc.code == 'REA_VERSION_MISMATCH' else 'runtime_missing',
                         remediation=exc.remediation)
    if os.name == 'nt':
        state['process_cleanup'] = 'owned_tree_best_effort_without_job_objects'
    return state


async def install_rea() -> dict[str, Any]:
    """Share startup/Settings setup; cancelling its last waiter settles setup."""
    global _INSTALL_TASK, _INSTALL_WAITERS
    # A new dialog must not inherit cancellation from an installation whose
    # final owner has already cancelled it. Wait for that generation's owned
    # process/staging cleanup, then join or create a fresh installation.
    while _INSTALL_TASK is not None and not _INSTALL_TASK.done() and _INSTALL_TASK in _INSTALL_CANCELLING:
        previous = _INSTALL_TASK
        # A completion future receives no previous-task exception. Cancelling
        # this new caller still propagates normally, including on Python 3.10.
        completion = asyncio.get_running_loop().create_future()
        def settled(_task: asyncio.Task[Any]) -> None:
            if not completion.done():
                completion.set_result(None)
        previous.add_done_callback(settled)
        try:
            await completion
        finally:
            previous.remove_done_callback(settled)
    if _INSTALL_TASK is None or _INSTALL_TASK.done():
        _INSTALL_TASK = asyncio.create_task(_install_rea())
    task = _INSTALL_TASK
    _INSTALL_WAITERS += 1
    _INSTALL_TASK_WAITERS[task] = _INSTALL_TASK_WAITERS.get(task, 0) + 1
    released = False
    def release_waiter() -> int:
        global _INSTALL_WAITERS
        remaining = _INSTALL_TASK_WAITERS.get(task, 1) - 1
        if remaining:
            _INSTALL_TASK_WAITERS[task] = remaining
        else:
            _INSTALL_TASK_WAITERS.pop(task, None)
        _INSTALL_WAITERS -= 1
        return remaining
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        remaining = release_waiter()
        released = True
        if remaining == 0 and not task.done():
            _INSTALL_CANCELLING.add(task)
            task.add_done_callback(_INSTALL_CANCELLING.discard)
            task.cancel()
            await _await_owned_cleanup(task, suppress_error=True)
        raise
    finally:
        if not released:
            release_waiter()


def _find_npm_cli(node: str) -> Path | None:
    binary = Path(node)
    paths = [binary.parent / 'node_modules' / 'npm' / 'bin' / 'npm-cli.js',
             binary.parent.parent / 'lib' / 'node_modules' / 'npm' / 'bin' / 'npm-cli.js']
    for candidate in _executable_candidates('npm'):
        paths.extend((Path(candidate).resolve(), Path(candidate).parent / 'node_modules' / 'npm' / 'bin' / 'npm-cli.js'))
    return next((path for path in paths if path.is_file() and path.name in {'npm-cli.js', 'npm-cli.cjs'}), None)


async def _settle_worker(task: asyncio.Task[Any]) -> None:
    async def retrieve() -> None:
        await asyncio.gather(task, return_exceptions=True)
    await _await_owned_cleanup(asyncio.create_task(retrieve()))


async def _bootstrap_node() -> dict[str, Any]:
    from ..core.rea_bootstrap import ensure_node_runtime
    cancelled = threading.Event()
    worker = asyncio.create_task(asyncio.to_thread(ensure_node_runtime, cancel_event=cancelled))
    try:
        return await asyncio.shield(worker)
    except asyncio.CancelledError:
        cancelled.set()
        # to_thread cancellation cannot stop a running worker. Set its explicit
        # cancellation flag and retain ownership until publication/cleanup ends.
        with contextlib.suppress(asyncio.CancelledError):
            await _settle_worker(worker)
        raise


@contextlib.asynccontextmanager
async def _installation_lock():
    from ..core.rea_bootstrap import installation_lock
    loop = asyncio.get_running_loop()
    ready = loop.create_future()
    cancelled, release = threading.Event(), threading.Event()
    def signal_ready(error: Exception | None = None) -> None:
        if not ready.done():
            if error is None:
                ready.set_result(None)
            else:
                ready.set_exception(error)
    def hold() -> None:
        try:
            with installation_lock(cancel_event=cancelled):
                loop.call_soon_threadsafe(signal_ready)
                release.wait()
        except Exception as exc:
            loop.call_soon_threadsafe(signal_ready, exc)
    worker = asyncio.create_task(asyncio.to_thread(hold))
    try:
        await asyncio.shield(ready)
        yield
    finally:
        cancelled.set()
        release.set()
        try:
            await _settle_worker(worker)
        finally:
            if ready.done() and not ready.cancelled():
                ready.exception()  # Retrieve a failure that raced caller cancellation.


async def _install_rea() -> dict[str, Any]:
    """Install into a verified staged tree, then publish without editing live files."""
    existing = await rea_status({})
    if existing['status'] == 'storage_unsafe':
        return existing
    if existing['ok'] and existing['status'] == 'ready':
        return existing
    node, version = await _find_node()
    npm_cli = _find_npm_cli(node) if node is not None else None
    if node is None or npm_cli is None:
        from ..core.rea_bootstrap import ReaBootstrapError
        try:
            prepared = await _bootstrap_node()
            node, version = prepared['node_path'], prepared['node_version']
            npm_cli = Path(prepared['npm_cli_path'])
        except ReaBootstrapError as exc:
            existing.update(ok=False, status='install_failed', code=exc.code, remediation=exc.remediation)
            return existing
        # Node preparation can make an existing marked runtime usable; npm is
        # unnecessary when its package was already cached for this host.
        existing = await rea_status({})
        if existing['ok'] and existing['status'] == 'ready':
            return existing
    from ..core.rea_bootstrap import ReaBootstrapError
    try:
        async with _installation_lock():
            # A second app may have completed setup while this one waited.
            existing = await rea_status({})
            if existing['status'] == 'storage_unsafe' or existing['ok'] and existing['status'] == 'ready':
                return existing
            return await _install_package(node, version, npm_cli)
    except ReaBootstrapError as exc:
        existing.update(ok=False, status='install_failed', code=exc.code, remediation=exc.remediation)
        return existing
    except ReaError as exc:
        existing.update(ok=False, status='storage_unsafe', code=exc.code, remediation=exc.remediation)
        return existing


async def _install_package(node: str, version: str | None, npm_cli: Path) -> dict[str, Any]:
    runtime = _runtime_directory()
    cache = runtime.parent / 'npm-cache'
    staging = runtime.parent / ('runtime-install-' + uuid.uuid4().hex)
    process = None
    drain = None
    try:
        cache.mkdir(mode=0o700, exist_ok=True)
        _validate_rea_storage()
        staging.mkdir(parents=True, exist_ok=False, mode=0o700)
        async def spawn_and_register() -> None:
            nonlocal process
            process = await asyncio.create_subprocess_exec(
                node, str(npm_cli), 'install', '--prefix', str(staging), '--no-audit', '--no-fund',
                '--cache', str(cache), '--registry', 'https://registry.npmjs.org',
                f'{REA_PACKAGE}@{REA_VERSION}', stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                env=_child_environment(normalize_rea_settings({}), node), cwd=staging, **_process_options(),
            )
        await _await_owned_cleanup(asyncio.create_task(spawn_and_register()))
        async def discard_output() -> None:
            assert process is not None and process.stdout is not None
            while await process.stdout.read(4096):
                pass
        drain = asyncio.create_task(discard_output())
        async def wait_root_exit() -> None:
            # Process.wait can wait on EOF from a surviving child's inherited
            # stdout even after the npm root has exited. Observe root exit first.
            assert process is not None
            while process.returncode is None:
                await asyncio.sleep(0.05)
        await asyncio.wait_for(wait_root_exit(), INSTALL_TIMEOUT)
        await _await_owned_cleanup(asyncio.create_task(_stop_process(process)))
        await asyncio.wait_for(drain, 2.0)
        package = staging / 'node_modules' / REA_PACKAGE
        verified = _package_version(package) == REA_VERSION and (package / 'scripts' / 'rea.mjs').is_file()
        if process.returncode == 0 and verified:
            (staging / RUNTIME_MARKER).write_text(json.dumps(_runtime_identity(), sort_keys=True), encoding='utf-8')
            # If another process installed a valid runtime while npm ran, leave
            # that live installation unchanged. Only publish a verified tree.
            if not _managed_runtime_installed(runtime):
                backup = runtime.parent / ('runtime-replaced-' + uuid.uuid4().hex)
                moved = False
                try:
                    if runtime.exists():
                        runtime.replace(backup)
                        moved = True
                    staging.replace(runtime)
                except OSError:
                    if moved and not runtime.exists():
                        backup.replace(runtime)
                    raise
                finally:
                    if moved and runtime.exists():
                        shutil.rmtree(backup, ignore_errors=True)
        result = await rea_status({})
        if process.returncode != 0 or not verified or not result['runtime_installed']:
            result.update(ok=False, status='install_failed', remediation=_MESSAGES['REA_INSTALL_FAILED'])
        _event('rea_install_finished', returncode=process.returncode, version=REA_VERSION, ok=result['ok'])
        return result
    except asyncio.CancelledError:
        if process is not None:
            cleanup = asyncio.create_task(_stop_process(process))
            await _await_owned_cleanup(cleanup)
        raise
    except (OSError, asyncio.TimeoutError):
        if process is not None:
            await _await_owned_cleanup(asyncio.create_task(_stop_process(process)))
        return {'ok': False, 'status': 'install_failed', 'version': None, 'expected_version': REA_VERSION,
                'node_supported': True, 'node_version': version, 'runtime_installed': False,
                'remediation': _MESSAGES['REA_INSTALL_FAILED']}
    finally:
        if drain is not None:
            drain.cancel()
            await asyncio.gather(drain, return_exceptions=True)
        shutil.rmtree(staging, ignore_errors=True)
