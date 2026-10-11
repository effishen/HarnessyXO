from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any


class ProjectRevisionWorkerError(RuntimeError):
    """Raised when the isolated project-history worker cannot publish a revision."""


def _install_termination_handler() -> None:
    if os.name != 'posix':
        return

    def interrupted(_signum, _frame) -> None:
        # Raise through Python context managers first so an in-progress copied
        # object/temp index is cleaned before the parent escalates to SIGKILL.
        raise KeyboardInterrupt('Project history worker was stopped')

    try:
        signal.signal(signal.SIGTERM, interrupted)
    except (OSError, ValueError):
        pass


def _lower_worker_priority() -> None:
    """Best-effort background priority without making any platform mandatory.

    History capture is correctness work, but it must not compete with the WebUI
    as though it were latency-sensitive.  CPU niceness is portable across the
    Unix hosts HarnessyXO supports.  Linux and macOS receive an additional
    best-effort I/O/background hint when their native utility is available.
    Every hint is deliberately fail-open: history correctness never depends on
    an optional operating-system command.
    """
    try:
        if hasattr(os, 'nice'):
            os.nice(10)
    except OSError:
        pass

    command: list[str] = []
    if sys.platform == 'darwin' and shutil.which('taskpolicy'):
        command = ['taskpolicy', '-b', '-p', str(os.getpid())]
    elif sys.platform.startswith('linux') and shutil.which('ionice'):
        command = ['ionice', '-c', '3', '-p', str(os.getpid())]
    if command:
        try:
            subprocess.run(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=2, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            pass


def _worker_payload(args: argparse.Namespace) -> dict[str, Any]:
    # Import only inside the worker.  The parent WebUI does not need another
    # WorkspaceStore, and the child remains a small stdlib-first process.
    from harnessy.core.workspace import WorkspaceStore

    _install_termination_handler()
    _lower_worker_priority()
    workspace = WorkspaceStore(Path(args.workspace))
    revision = workspace.publish_project_revision(
        str(args.chat_id), status=str(args.status),
        message_head_id=str(args.message_head_id or ''),
    )
    baseline_committed = False
    if args.upstream_fingerprint and str(args.status) == 'success':
        baseline_committed = workspace.commit_upstream_baseline(
            str(args.chat_id), str(args.upstream_fingerprint),
        )
    return {
        'ok': True,
        'revision_id': str(revision.get('id') or ''),
        'shadow_commit': str(revision.get('shadow_commit') or ''),
        'baseline_committed': bool(baseline_committed),
    }


def _worker_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('--workspace', required=True)
    parser.add_argument('--chat-id', required=True)
    parser.add_argument('--status', required=True)
    parser.add_argument('--message-head-id', default='')
    parser.add_argument('--upstream-fingerprint', default='')
    args = parser.parse_args(argv)
    try:
        payload = _worker_payload(args)
    except BaseException as exc:
        payload = {
            'ok': False,
            'error': f'{type(exc).__name__}: {exc}',
        }
        print(json.dumps(payload, ensure_ascii=False), flush=True)
        return 1
    print(json.dumps(payload, ensure_ascii=False), flush=True)
    return 0


def _worker_environment() -> dict[str, str]:
    env = dict(os.environ)
    # run.py/harnessy_app.py prepend src/ to the current interpreter's
    # sys.path.  That in-memory change is not inherited by a fresh Python
    # process, so make the canonical package root explicit for the worker.
    source_root = str(Path(__file__).resolve().parents[2])
    existing = str(env.get('PYTHONPATH') or '')
    values: list[str] = []
    # Include the launcher's resolved in-memory import roots as well as the
    # canonical source root. This preserves the supported canonical, legacy,
    # and accidentally flattened release layouts in the fresh interpreter.
    for value in (source_root, *sys.path, *existing.split(os.pathsep)):
        text = str(value or '').strip()
        if text and Path(text).is_dir() and text not in values:
            values.append(text)
    env['PYTHONPATH'] = os.pathsep.join(values)
    env['HARNESSY_REVISION_WORKER'] = '1'
    return env


async def _terminate_worker(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    try:
        if os.name == 'posix':
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
    except (LookupError, OSError, ProcessLookupError):
        pass
    try:
        await asyncio.wait_for(process.wait(), timeout=3.0)
        return
    except asyncio.TimeoutError:
        pass
    try:
        if os.name == 'posix':
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except (LookupError, OSError, ProcessLookupError):
        pass
    try:
        await process.wait()
    except Exception:
        pass


async def publish_project_revision_isolated(
    workspace_root: Path,
    chat_id: str,
    *,
    status: str,
    message_head_id: str = '',
    upstream_fingerprint: str = '',
) -> dict[str, Any]:
    """Publish history outside the WebUI process and return its small receipt."""
    command = [
        sys.executable, '-m', 'harnessy.agent.revision_finalizer', '--worker',
        '--workspace', str(Path(workspace_root).resolve()),
        '--chat-id', str(chat_id),
        '--status', str(status),
        '--message-head-id', str(message_head_id or ''),
        '--upstream-fingerprint', str(upstream_fingerprint or ''),
    ]
    launch = asyncio.create_task(asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=_worker_environment(),
        start_new_session=(os.name == 'posix'),
    ))
    process = None
    try:
        process = await asyncio.shield(launch)
        stdout, stderr = await process.communicate()
    except asyncio.CancelledError:
        # Cancellation can arrive while the OS is still creating the worker.
        # Reap it even then, and survive repeated Stop/shutdown cancellation.
        while not launch.done():
            try:
                await asyncio.shield(launch)
            except (asyncio.CancelledError, Exception):
                pass
        if not launch.cancelled() and launch.exception() is None:
            process = launch.result()
            cleanup = asyncio.create_task(_terminate_worker(process))
            while not cleanup.done():
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError:
                    pass
            cleanup.result()
        raise

    stdout_text = stdout.decode('utf-8', errors='replace').strip()
    stderr_text = stderr.decode('utf-8', errors='replace').strip()
    payload: dict[str, Any] = {}
    if stdout_text:
        try:
            decoded = json.loads(stdout_text.splitlines()[-1])
            if isinstance(decoded, dict):
                payload = decoded
        except json.JSONDecodeError:
            payload = {}
    if process.returncode != 0 or not bool(payload.get('ok')):
        detail = str(payload.get('error') or stderr_text or stdout_text or 'unknown worker failure')
        raise ProjectRevisionWorkerError(detail[-4000:])
    return payload


if __name__ == '__main__':
    raise SystemExit(_worker_main())
