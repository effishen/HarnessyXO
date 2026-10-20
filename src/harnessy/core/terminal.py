from __future__ import annotations

import fcntl
import os
import pty
import json
import select
import re
import shlex
import signal
import struct
import subprocess
import sys
import termios
import threading
from pathlib import Path

from harnessy.environment.activity import acquire_activity


_CHILD_BOOTSTRAP = r'''
import fcntl
import json
import os
import sys
import termios

# Become a new session leader and claim fd 0 (the PTY slave) as the
# controlling terminal before replacing this helper with the user's shell.
os.setsid()
fcntl.ioctl(0, termios.TIOCSCTTY, 0)
argv = json.loads(sys.argv[1])
if not isinstance(argv, list) or not argv:
    raise SystemExit('missing terminal command')
os.execvpe(argv[0], argv, os.environ)
'''



# This wrapper exists only in the guest shell's rc stream; it never writes to
# the user's dotfiles or executes workspace commands on the host. OSC 133 marks
# actual command/prompt transitions even for silent commands and across reloads.
_GUEST_ACTIVITY_RC = r'''[ -r "$HOME/.bashrc" ] && . "$HOME/.bashrc"
PS0=$'\e]133;C\a'"${PS0-}"
_harnessy_prompt_done() {
    local status=$?
    printf '\033]133;D;%s\007\033]133;A\007' "$status"
    return "$status"
}
if [[ $(declare -p PROMPT_COMMAND 2>/dev/null) == 'declare -a '* ]]; then
    PROMPT_COMMAND+=(_harnessy_prompt_done)
else
    PROMPT_COMMAND="${PROMPT_COMMAND:+$PROMPT_COMMAND; }_harnessy_prompt_done"
fi
'''


def guest_activity_shell_command() -> str:
    return 'exec /bin/bash --rcfile <(printf %s ' + shlex.quote(_GUEST_ACTIVITY_RC) + ') -i'


class TerminalSession:
    """Persistent Unix PTY session for the browser terminal emulator.

    The shell is started through a tiny child bootstrap instead of using a
    ``preexec_fn`` or ``forkpty`` inside HarnessyXO's web-server process. This is
    safer in a threaded/async application and still gives the shell a genuine
    controlling terminal, so terminal job control and Ctrl-key sequences work
    normally.
    """

    def __init__(
        self, cwd: Path, *, cols: int = 120, rows: int = 34,
        command_argv: list[str] | None = None, env: dict[str, str] | None = None,
        workspace_root: Path | None = None,
        environment_id: str = '',
        project_id: str | None = None,
        owner_id: str = '',
    ) -> None:
        self.workspace_root = workspace_root
        self.environment_id = environment_id
        self.project_id = project_id
        self.owner_id = owner_id
        self._activity_release = None
        self.cwd = cwd.resolve()
        self.command_argv = list(command_argv) if command_argv else None
        self.env_override = dict(env) if env is not None else None
        self.master_fd: int | None = None
        self.process: subprocess.Popen[bytes] | None = None
        self.cols = max(20, int(cols))
        self.rows = max(5, int(rows))
        self._history = bytearray()
        self._history_base = 0
        self._history_limit = 2 * 1024 * 1024
        self._history_lock = threading.Lock()
        self._reader_stop = threading.Event()
        self._reader_thread: threading.Thread | None = None
        self._legacy_cursor = 0
        self._activity_tail = b''
        self._command_busy: bool | None = None
        self.start()

    def _release_activity(self) -> None:
        release, self._activity_release = getattr(self, '_activity_release', None), None
        if release is not None:
            release()

    def start(self) -> None:
        if self.process and self.process.poll() is None:
            return
        self._release_activity()
        root = getattr(self, 'workspace_root', None)
        release = acquire_activity(root, 'VM terminal (close it before changing this VM)',
                                   environment_id=self.environment_id,
                                   project_id=getattr(self, 'project_id', None), owner_id=getattr(self, 'owner_id', '')) if root else None
        self._activity_release = release
        try:
            self._start_child()
        except BaseException:
            self._release_activity()
            raise
        process = self.process
        if release is not None and process is not None:
            # Capture this generation's release; an old watcher must never
            # release the token of a subsequently restarted terminal.
            def watch_exit():
                try:
                    process.wait()
                finally:
                    release()
            threading.Thread(target=watch_exit, name='harnessy-terminal-lifecycle', daemon=True).start()

    def _start_child(self) -> None:
        if self.process and self.process.poll() is None:
            return
        self._stop_reader()
        self._command_busy = None
        self._activity_tail = b''
        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.master_fd = None

        master, slave = pty.openpty()
        flags = fcntl.fcntl(master, fcntl.F_GETFL)
        fcntl.fcntl(master, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        shell = os.environ.get('SHELL') or ('/bin/zsh' if Path('/bin/zsh').exists() else '/bin/bash')
        argv = self.command_argv or [shell, '-i']
        env = dict(self.env_override) if self.env_override is not None else os.environ.copy()
        env.setdefault('TERM', 'xterm-256color')
        env.setdefault('COLORTERM', 'truecolor')
        try:
            self.process = subprocess.Popen(
                [sys.executable, '-c', _CHILD_BOOTSTRAP, json.dumps(argv)],
                cwd=self.cwd,
                stdin=slave,
                stdout=slave,
                stderr=slave,
                close_fds=True,
                env=env,
            )
        except BaseException:
            os.close(master)
            raise
        finally:
            os.close(slave)
        self.master_fd = master
        self.resize(self.cols, self.rows)
        self._start_reader(master)

    def _alive(self) -> bool:
        return bool(self.process and self.process.poll() is None)

    @property
    def busy(self) -> bool:
        """Running command, not merely an open shell or a running VM.

        Local shells expose their foreground process group. Lima's host process
        is only a transport, so guest terminals use their shell OSC markers.
        """
        if not self._alive():
            return False
        marked = getattr(self, '_command_busy', None)
        if getattr(self, 'command_argv', None):
            return marked if marked is not None else True  # startup until first prompt
        try:
            foreground = os.tcgetpgrp(self.master_fd)
            return foreground > 0 and foreground != os.getpgid(self.process.pid)
        except (OSError, TypeError, ProcessLookupError):
            return bool(marked)

    def _observe_activity(self, data: bytes) -> None:
        combined = getattr(self, '_activity_tail', b'') + data
        pattern = rb'\x1b\]133;([ACD])(?:;[^\x07\x1b]{0,128})?(?:\x07|\x1b\\)'
        for match in re.finditer(pattern, combined):
            self._command_busy = match.group(1) == b'C'
        # Retain just a possible split marker, never unbounded terminal output.
        start = combined.rfind(b'\x1b]133;')
        self._activity_tail = combined[start:][-256:] if start >= 0 else combined[-6:]

    def send(self, text: str) -> None:
        self.send_bytes(text.encode('utf-8', errors='replace'))

    def send_bytes(self, data: bytes) -> None:
        if self.master_fd is None or not self._alive():
            if getattr(self, 'project_id', None) not in {None, '__guest_console__'}:
                raise RuntimeError('This project terminal has ended. Reopen it to prepare the current project file view.')
            self.start()
        assert self.master_fd is not None
        os.write(self.master_fd, data)

    def send_line(self, text: str) -> None:
        self.send(text.rstrip('\n') + '\n')

    def interrupt(self) -> None:
        # ETX is exactly what a terminal sends for Ctrl+C. Because the shell
        # owns a controlling PTY, the terminal driver signals its foreground
        # process group (e.g. a running build, ping, sleep, editor, etc.).
        try:
            self.send_bytes(b'\x03')
        except Exception:
            if self.process and self.process.poll() is None:
                try:
                    os.killpg(self.process.pid, signal.SIGINT)
                except ProcessLookupError:
                    pass

    def resize(self, cols: int, rows: int) -> None:
        self.cols = max(20, int(cols))
        self.rows = max(5, int(rows))
        if self.master_fd is None:
            return
        winsize = struct.pack('HHHH', self.rows, self.cols, 0, 0)
        try:
            fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, winsize)
        except OSError:
            pass

    def _history_mutex(self):
        # A few unit tests construct TerminalSession with __new__ so they can
        # exercise replay logic without launching a PTY. Keep those lightweight
        # objects compatible while real sessions always use the lock.
        lock = getattr(self, '_history_lock', None)
        if lock is None:
            class _Noop:
                def __enter__(self): return self
                def __exit__(self, *_args): return False
            return _Noop()
        return lock

    def _append_history(self, data: bytes) -> None:
        if not data:
            return
        self._observe_activity(data)
        with self._history_mutex():
            self._history.extend(data)
            overflow = len(self._history) - self._history_limit
            if overflow > 0:
                del self._history[:overflow]
                self._history_base += overflow

    def _reader_loop(self, master_fd: int, stop: threading.Event) -> None:
        # Continuously drain the PTY into bounded server-side scrollback. This
        # is deliberately independent of any browser page: a terminal command
        # must not block merely because the user reloads/disconnects and no
        # xterm.js poller is temporarily consuming stdout.
        while not stop.is_set():
            try:
                readable, _, _ = select.select([master_fd], [], [], 0.25)
                if not readable:
                    continue
                chunk = os.read(master_fd, 16_384)
            except (OSError, ValueError):
                break
            except BlockingIOError:
                continue
            if not chunk:
                break
            self._append_history(chunk)

    def _start_reader(self, master_fd: int) -> None:
        self._reader_stop = threading.Event()
        thread = threading.Thread(
            target=self._reader_loop, args=(master_fd, self._reader_stop),
            name='harnessy-terminal-reader', daemon=True,
        )
        self._reader_thread = thread
        thread.start()

    def _stop_reader(self) -> None:
        stop = getattr(self, '_reader_stop', None)
        thread = getattr(self, '_reader_thread', None)
        if stop is not None:
            stop.set()
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=0.25)
        self._reader_thread = None

    def _pump_history(self, limit: int = 256_000) -> None:
        # Real PTYs are continuously drained by _reader_loop. Preserve the old
        # opportunistic pump only for lightweight/test sessions without a reader.
        thread = getattr(self, '_reader_thread', None)
        if thread is not None and thread.is_alive():
            return
        if self.master_fd is None:
            return
        chunks: list[bytes] = []
        total = 0
        while total < limit:
            try:
                chunk = os.read(self.master_fd, min(16_384, limit - total))
            except BlockingIOError:
                break
            except OSError:
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if chunks:
            self._append_history(b''.join(chunks))

    def history_snapshot(self) -> tuple[int, str]:
        """Return buffered terminal output and the cursor after that output.

        The PTY is backend-owned, while xterm.js is browser-owned. Keeping a
        bounded server-side scrollback means a browser refresh can reconstruct
        the terminal screen and then continue reading the same PTY session.
        """
        self._pump_history()
        with self._history_mutex():
            end = self._history_base + len(self._history)
            data = bytes(self._history)
        return end, data.decode('utf-8', errors='replace')

    def read_since(self, cursor: int, limit: int = 256_000) -> tuple[int, str]:
        self._pump_history(limit=limit)
        with self._history_mutex():
            start = max(int(cursor), self._history_base)
            end = self._history_base + len(self._history)
            if start >= end:
                return end, ''
            offset = start - self._history_base
            data = bytes(self._history[offset:])
        return end, data.decode('utf-8', errors='replace')

    def read_available(self, limit: int = 256_000) -> str:
        self._legacy_cursor, text = self.read_since(self._legacy_cursor, limit=limit)
        return text

    def clear_scrollback(self) -> None:
        self.send('\x1b[3J\x1b[H\x1b[2J')

    def close(self) -> None:
        process = self.process
        if process and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                # The PTY bootstrap may not have called setsid yet.
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                try:
                    process.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    pass
        if process is None or process.poll() is not None:
            self._release_activity()
        self.process = None
        self._stop_reader()
        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.master_fd = None
