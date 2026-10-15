"""Bounded startup updates which preserve the installed application's state.

This module uses only the standard library and Git. Import it before Harnessy
or its vendored dependencies. The installation lock belongs to the running app,
not merely to the network check, and remains held across launcher exec calls.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import secrets
import signal
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

REPOSITORY_URL = "https://github.com/effishen/HarnessyXO.git"
UPDATE_BRANCH = "main"
GIT_TIMEOUT_SECONDS = 15.0
LOCK_FILENAME = ".harnessy-update.lock"
LOCK_ENV = "HARNESSY_INSTALL_LOCK_FD"
HANDOFF_ENV = "HARNESSY_UPDATE_HANDOFF"
PENDING_FILENAME = ".harnessy-update-pending.json"
MAX_TREE_FILES = 4096
MAX_TREE_BYTES = 64 * 1024 * 1024
MAX_COMMAND_OUTPUT = 2 * 1024 * 1024
MAX_ARCHIVE_MISMATCHES = 8
MAX_ARCHIVE_MODE_REPAIRS = 128
_HELD_LOCKS: dict[str, "InstallLock"] = {}
_RUNTIME_FORK_HOOK_REGISTERED = False
_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
_PROTECTED = {".settings", ".vendor", ".logs", ".venv", ".harnessy", ".git", ".env"}
_ROOT_FILES = {
    ".gitignore", ".gitattributes", "README.md", "FEATURES.md", "CHANGELOG.md",
    "VERSION", "run.py", "harnessy_app.py", "harnessy_update.py", "run_harnessy.sh",
    "requirements.txt", "requirements-dev.txt", "pytest.ini", "RELEASE_MANIFEST.json",
    "LICENSE", "LICENSE.txt", "NOTICE", "NOTICE.txt",
}
_SOURCE_DIRS = {"src", "skills", "tests", "assets", "static", "scripts", ".github"}
_REQUIRED = {"run.py", "harnessy_app.py", "harnessy_update.py", "VERSION",
             "requirements.txt", "src/harnessy/__init__.py"}


class StartupAlreadyRunning(RuntimeError):
    """Another process holds this installation's lifetime lock."""


class StartupLockUnsafe(RuntimeError):
    """The installation lock cannot be established safely."""


class _GitFailure(Exception):
    pass


class _UnsupportedTree(Exception):
    pass


def _lock_file_safe(info: os.stat_result) -> bool:
    return (stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and (os.name == "nt" or (info.st_uid == os.geteuid()
                                    and not stat.S_IMODE(info.st_mode) & 0o077)))


class InstallLock:
    def __init__(self, root: Path, fd: int, nonce: str):
        self.root, self.fd, self.nonce = root, fd, nonce
        self._runtime_only = False

    def prevent_child_inheritance(self) -> None:
        """Keep the final app's lock private; launcher exec handoffs stay opt-in."""
        global _RUNTIME_FORK_HOOK_REGISTERED
        if self.fd < 0:
            return
        try:
            os.set_inheritable(self.fd, False)
        except OSError as exc:
            raise StartupLockUnsafe("HarnessyXO's installation lock could not be isolated from child processes.") from exc
        self._runtime_only = True
        if os.environ.get(LOCK_ENV) == str(self.fd):
            os.environ.pop(LOCK_ENV, None)
        register = getattr(os, 'register_at_fork', None)
        if os.name != 'nt' and callable(register) and not _RUNTIME_FORK_HOOK_REGISTERED:
            try:
                register(after_in_child=_close_runtime_locks_after_fork)
            except (AttributeError, NotImplementedError):
                pass  # No fork callback support; close-on-exec still applies.
            else:
                _RUNTIME_FORK_HOOK_REGISTERED = True

    def close(self) -> None:
        if self.fd < 0:
            return
        fd, self.fd = self.fd, -1
        _HELD_LOCKS.pop(str(self.root), None)
        if os.environ.get(LOCK_ENV) == str(fd):
            os.environ.pop(LOCK_ENV, None)
        os.close(fd)

    def __enter__(self) -> "InstallLock":
        return self

    def __exit__(self, *_args) -> None:
        self.close()


def _close_runtime_locks_after_fork() -> None:
    # flock belongs to the shared open file description. Only close the child's
    # copy: LOCK_UN here would also release the still-running parent's lock.
    for lock in tuple(_HELD_LOCKS.values()):
        if lock._runtime_only:
            try:
                lock.close()
            except OSError:
                pass


def acquire_install_lock(app_dir: Path) -> InstallLock:
    """Acquire a private process-life lock, or adopt its validated exec handoff.

    Keep the returned object alive until the app exits. Never unlink the lock
    file: removing it allows another process to lock a different inode.
    """
    root = Path(app_dir).resolve()
    existing = _HELD_LOCKS.get(str(root))
    if existing is not None and existing.fd >= 0:
        return existing
    path = root / LOCK_FILENAME
    fd = -1
    inherited = False
    candidate = os.environ.pop(LOCK_ENV, "")
    try:
        if candidate.isdecimal():
            number = int(candidate)
            try:
                info, target = os.fstat(number), path.lstat()
                if (_lock_file_safe(info) and _lock_file_safe(target)
                        and (info.st_dev, info.st_ino) == (target.st_dev, target.st_ino)):
                    fd, inherited = number, True
            except OSError:
                pass
        if fd < 0:
            flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags, 0o600)
        info, target = os.fstat(fd), path.lstat()
        if (not _lock_file_safe(info) or not _lock_file_safe(target)
                or (info.st_dev, info.st_ino) != (target.st_dev, target.st_ino)):
            raise StartupLockUnsafe("HarnessyXO's installation lock is unsafe.")
        if os.name == "nt":
            import msvcrt
            if info.st_size == 0:
                os.write(fd, b"0")
            os.lseek(fd, 0, os.SEEK_SET)
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            except OSError:
                raise StartupAlreadyRunning("HarnessyXO is already running from this folder.") from None
        else:
            import fcntl
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno in {errno.EAGAIN, errno.EWOULDBLOCK}:
                    raise StartupAlreadyRunning("HarnessyXO is already running from this folder.") from None
                raise StartupLockUnsafe("HarnessyXO's installation lock could not be acquired.") from exc
        if inherited:
            os.lseek(fd, 0, os.SEEK_SET)
            nonce = os.read(fd, 128).decode("ascii", errors="ignore").strip()
            if not re.fullmatch(r"[0-9a-f]{64}", nonce):
                raise StartupLockUnsafe("HarnessyXO's inherited installation lock is invalid.")
        else:
            nonce = secrets.token_hex(32)
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            os.write(fd, nonce.encode("ascii"))
        os.set_inheritable(fd, True)
        lock = InstallLock(root, fd, nonce)
        _HELD_LOCKS[str(root)] = lock
        os.environ[LOCK_ENV] = str(fd)
        return lock
    except (StartupAlreadyRunning, StartupLockUnsafe):
        if fd >= 0:
            os.close(fd)
        raise
    except OSError as exc:
        if fd >= 0:
            os.close(fd)
        raise StartupLockUnsafe("HarnessyXO's installation lock could not be opened.") from exc


def _git_env(*, anonymous: bool = False) -> dict[str, str]:
    env = dict(os.environ)
    for name in list(env):
        if (name in {"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
                     "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG_PARAMETERS",
                     "GIT_CONFIG_COUNT", "GIT_QUARANTINE_PATH"}
                or name.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_", "GIT_TRACE"))):
            env.pop(name, None)
    if anonymous:
        for name in ('GIT_ASKPASS', 'SSH_ASKPASS', 'SSH_ASKPASS_REQUIRE'):
            env.pop(name, None)
    env.update({"GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "Never",
                "GIT_SSH_COMMAND": "ssh -o BatchMode=yes -o ConnectTimeout=8",
                "LC_ALL": "C"})
    return env


def _git(root: Path, *args: str, timeout: float = GIT_TIMEOUT_SECONDS,
         anonymous: bool = False) -> bytes:
    command = ["git", "-c", f"core.hooksPath={os.devnull}", "-c", "core.fsmonitor=false",
               "-c", "fetch.recurseSubmodules=false", "-c", "maintenance.auto=false",
               "-c", "gc.auto=0"]
    if anonymous:
        # Public downloads need no account or credential helper. Keep trusted
        # proxy/CA configuration while avoiding stale saved authorization.
        command += ["-c", "credential.helper=", "-c", "credential.interactive=false",
                    "-c", "core.askPass=", "-c", "http.extraHeader=",
                    "-c", f"http.{REPOSITORY_URL}.extraHeader="]
    command += ["-C", str(root), *args]
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   env=_git_env(anonymous=anonymous), start_new_session=os.name != "nt")
        try:
            output, _ = process.communicate(timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            if os.name != "nt":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                process.kill()
            try:
                process.communicate(timeout=1.0)
            except subprocess.TimeoutExpired:
                # A helper can detach from Git's process group while retaining
                # its pipe. Never turn the original timeout into an endless drain.
                if process.stdout is not None:
                    process.stdout.close()
                try:
                    process.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    pass
            raise
        if process.returncode or len(output) > MAX_COMMAND_OUTPUT:
            raise _GitFailure()
        return output
    except (OSError, subprocess.TimeoutExpired):
        raise _GitFailure() from None


def _git_text(root: Path, *args: str) -> str:
    try:
        return _git(root, *args).decode("utf-8").strip()
    except UnicodeDecodeError:
        raise _GitFailure() from None


def _head(root: Path) -> str:
    value = _git_text(root, "rev-parse", "--verify", "HEAD")
    if not _SHA.fullmatch(value):
        raise _GitFailure()
    return value


def _clean(root: Path) -> bool:
    # These flags deliberately hide working-tree changes from Git status. A
    # startup updater must not treat such an index as an ordinary clean checkout.
    flags = _git(root, "ls-files", "-v", "-z")
    if any(row and not row.startswith(b"H ") for row in flags.split(b"\0")):
        return False
    return not _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=no")


def _github_identity(value: str) -> str | None:
    if value.startswith("git@github.com:"):
        path = value[len("git@github.com:"):]
    else:
        try:
            parsed = urlsplit(value)
            if (parsed.scheme != "https" or parsed.hostname != "github.com"
                    or parsed.port not in (None, 443) or parsed.username is not None
                    or parsed.password is not None or parsed.query or parsed.fragment):
                return None
            path = parsed.path.lstrip("/")
        except ValueError:
            return None
    if path.endswith(".git"):
        path = path[:-4]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", path):
        return None
    return path.lower()


def _remote_matches(value: str, expected: str, allow_local: bool) -> bool:
    if allow_local:
        return value == expected
    identity = _github_identity(expected)
    return identity is not None and _github_identity(value) == identity


def _tree(root: Path, commit: str) -> list[tuple[str, str, str, int]]:
    rows = _git(root, "ls-tree", "-r", "-z", "--long", commit)
    entries: list[tuple[str, str, str, int]] = []
    seen: set[str] = set()
    total = 0
    try:
        for row in rows.split(b"\0"):
            if not row:
                continue
            fields, raw_path = row.split(b"\t", 1)
            mode, kind, oid, raw_size = fields.decode("ascii").split()
            name = raw_path.decode("utf-8")
            parts = PurePosixPath(name).parts
            if (mode not in {"100644", "100755"} or kind != "blob" or not _SHA.fullmatch(oid)
                    or not parts or name.startswith("/") or "\\" in name or ":" in name
                    or any(part in {"", ".", ".."} for part in name.split("/"))
                    or any(part.casefold() in _PROTECTED for part in parts)
                    or parts[0].casefold().startswith(".harnessy-update")
                    or name.casefold() in seen):
                raise _UnsupportedTree()
            if len(parts) > 1:
                if parts[0] not in _SOURCE_DIRS:
                    raise _UnsupportedTree()
            elif name not in _ROOT_FILES and not re.fullmatch(r"release-[A-Za-z0-9_.-]+\.txt", name):
                raise _UnsupportedTree()
            size = int(raw_size)
            total += size
            if size < 0 or total > MAX_TREE_BYTES or len(entries) >= MAX_TREE_FILES:
                raise _UnsupportedTree()
            seen.add(name.casefold())
            entries.append((name, mode, oid, size))
    except (ValueError, UnicodeError):
        raise _UnsupportedTree() from None
    if not _REQUIRED.issubset({entry[0] for entry in entries}):
        raise _UnsupportedTree()
    return entries


def _open_installed_file(root: Path, name: str) -> int:
    """Pin every directory component; never follow archive-provided symlinks."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    parent = os.open(root, flags | getattr(os, "O_DIRECTORY", 0))
    try:
        parts = PurePosixPath(name).parts
        for part in parts[:-1]:
            child = os.open(part, flags | getattr(os, "O_DIRECTORY", 0), dir_fd=parent)
            os.close(parent)
            parent = child
        return os.open(parts[-1], flags | getattr(os, "O_NONBLOCK", 0), dir_fd=parent)
    finally:
        os.close(parent)


def _blob_matches(descriptor: int, oid: str, size: int) -> bool:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha1() if len(oid) == 40 else hashlib.sha256()
    digest.update(f"blob {size}\0".encode("ascii"))
    remaining = size
    while remaining:
        chunk = os.read(descriptor, min(65536, remaining))
        if not chunk:
            return False
        digest.update(chunk)
        remaining -= len(chunk)
    return not os.read(descriptor, 1) and digest.hexdigest() == oid


def _archive_version(root: Path) -> str:
    try:
        descriptor = _open_installed_file(root, "VERSION")
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 64:
                return "invalid"
            value = os.read(descriptor, 65).decode("ascii").strip()
            return value if _VERSION.fullmatch(value) else "invalid"
        finally:
            os.close(descriptor)
    except FileNotFoundError:
        return "missing"
    except (OSError, UnicodeError):
        return "unreadable"


def _archive_mismatch(report: dict, name: str, reason: str) -> None:
    report["mismatch_count"] += 1
    if len(report["mismatches"]) < MAX_ARCHIVE_MISMATCHES:
        safe_name = re.sub(r"[^A-Za-z0-9_./+@ -]", "?", name)[:180]
        report["mismatches"].append({"path": safe_name, "reason": reason})


def _inspect_archive(root: Path, entries: list[tuple[str, str, str, int]]) -> tuple[dict, list]:
    report = {"mismatch_count": 0, "mismatches": [], "executable_repairs": 0,
              "only_executable_metadata": False}
    repairs = []
    mode_mismatches = 0
    for name, mode, oid, size in entries:
        descriptor = -1
        try:
            descriptor = _open_installed_file(root, name)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                _archive_mismatch(report, name, "not_regular_file")
            elif info.st_size != size:
                _archive_mismatch(report, name, "content_size")
            elif not _blob_matches(descriptor, oid, size):
                _archive_mismatch(report, name, "content_hash")
            elif bool(info.st_mode & stat.S_IXUSR) != (mode == "100755"):
                _archive_mismatch(report, name, "executable_mode")
                mode_mismatches += 1
                # Only restore lost archive execute flags. Extra executable
                # flags remain an explicit local difference.
                if mode == "100755":
                    repairs.append((name, oid, size))
        except FileNotFoundError:
            _archive_mismatch(report, name, "missing")
        except OSError as exc:
            reason = "unsafe_path" if exc.errno in {errno.ELOOP, errno.ENOTDIR} else "unreadable"
            _archive_mismatch(report, name, reason)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    report["only_executable_metadata"] = bool(mode_mismatches and mode_mismatches == report["mismatch_count"])
    return report, repairs


def _restore_archive_execute_bits(root: Path, repairs: list) -> bool:
    if len(repairs) > MAX_ARCHIVE_MODE_REPAIRS:
        return False
    opened = []
    changed = []
    try:
        # Verify every candidate again before changing any file metadata. Each
        # descriptor stays pinned, so rename/symlink races cannot redirect chmod.
        for name, oid, size in repairs:
            descriptor = _open_installed_file(root, name)
            opened.append((descriptor, name))
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.geteuid() or info.st_size != size
                    or not _blob_matches(descriptor, oid, size)):
                return False
        for descriptor, _name in opened:
            mode = stat.S_IMODE(os.fstat(descriptor).st_mode)
            # Preserve read/write restrictions: private 0600 becomes 0700;
            # ordinary extracted 0644 becomes 0755.
            desired = mode | stat.S_IXUSR | ((mode & 0o044) >> 2)
            os.fchmod(descriptor, desired)
            changed.append((descriptor, mode))
        return True
    except OSError:
        for descriptor, mode in changed:
            try:
                os.fchmod(descriptor, mode)
            except OSError:
                pass
        return False
    finally:
        for descriptor, _name in opened:
            os.close(descriptor)


def _matches_installed(root: Path, entries: list[tuple[str, str, str, int]]) -> bool:
    report, _repairs = _inspect_archive(root, entries)
    return report["mismatch_count"] == 0


def _result(outcome: str, *, changed: bool = False, fatal: bool = False,
            old: str | None = None, new: str | None = None) -> dict:
    result = {"outcome": outcome, "changed": changed, "fatal": fatal}
    if old is not None:
        result["old_commit"] = old
    if new is not None:
        result["new_commit"] = new
    return result


def _read_pending(root: Path) -> dict | None:
    path = root / PENDING_FILENAME
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                             | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(descriptor)
        if not _lock_file_safe(info) or info.st_size > 512:
            raise ValueError()
        value = json.loads(os.read(descriptor, 513))
        if (not isinstance(value, dict) or set(value) != {"old", "target"}
                or not all(isinstance(item, str) and _SHA.fullmatch(item) for item in value.values())):
            raise ValueError()
        return value
    finally:
        os.close(descriptor)


def _write_pending(root: Path, old: str, target: str) -> None:
    descriptor, name = tempfile.mkstemp(prefix=".harnessy-update-pending-", dir=root)
    path = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(json.dumps({"old": old, "target": target}).encode("ascii"))
            handle.flush()
            os.fsync(handle.fileno())
        path.replace(root / PENDING_FILENAME)
        directory = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        path.unlink(missing_ok=True)


def _clear_pending(root: Path) -> None:
    try:
        (root / PENDING_FILENAME).unlink(missing_ok=True)
    except OSError:
        # The next launch can verify and reconcile a completed update again.
        pass


def _updates_supported() -> bool:
    return os.name != "nt"


def _public_transport_url(repository: str) -> str:
    # Git's explicit helper syntax passes the canonical URL directly to HTTPS,
    # including when the user's insteadOf rules normally rewrite GitHub to SSH.
    return f"https::{repository}"


def _bootstrap(root: Path, version: str, repository: str, *, anonymous: bool = True,
               archive_check: dict | None = None) -> dict | None:
    if not _VERSION.fullmatch(version):
        return _result("zip_version_unrecognized")
    tag = f"v{version}"
    report = archive_check if archive_check is not None else {}
    report.update(expected_version=version, installed_version=_archive_version(root))

    def inspect(staged: Path, commit: str, comparison: str) -> bool:
        entries = _tree(staged, commit)
        details, repairs = _inspect_archive(root, entries)
        report.update(details, comparison=comparison, verified_commit=commit)
        if report["mismatch_count"] == 0:
            return True
        if (report["only_executable_metadata"]
                and len(repairs) == report["mismatch_count"]):
            if _restore_archive_execute_bits(root, repairs):
                report["executable_repairs"] = len(repairs)
                return True
            _archive_mismatch(report, repairs[0][0], "mode_repair_failed")
            report["only_executable_metadata"] = False
        return False

    def mismatch_result() -> dict:
        result = _result("zip_local_changes")
        result["archive_check"] = dict(report)
        return result

    try:
        with tempfile.TemporaryDirectory(prefix=".harnessy-update-stage-", dir=root) as temp:
            staged = Path(temp) / "repository"
            source = _public_transport_url(repository) if anonymous else repository
            comparison = "release_tag"
            try:
                _git(root, "clone", "--no-checkout", "--no-hardlinks", "--single-branch",
                     "--branch", tag, "--", source, str(staged), anonymous=anonymous)
            except _GitFailure:
                # A Code ZIP may be newer than the latest released tag. Verify
                # it against current main instead of guessing at edited files.
                if staged.exists():
                    shutil.rmtree(staged)
                _git(root, "clone", "--no-checkout", "--no-hardlinks", "--single-branch",
                     "--branch", UPDATE_BRANCH, "--", source, str(staged), anonymous=anonymous)
                comparison = "current_main"
            if anonymous:
                # This is newly created metadata. Existing checkout remotes are
                # left intact; only network operations use the helper syntax.
                _git(staged, "config", "remote.origin.url", repository)
            baseline = _head(staged)
            if comparison == "release_tag":
                release_baseline = baseline
                target_ref = f"refs/remotes/origin/{UPDATE_BRANCH}"
                try:
                    _git(staged, "fetch", "--no-tags", "--no-recurse-submodules", source,
                         f"+refs/heads/{UPDATE_BRANCH}:{target_ref}", anonymous=anonymous)
                    current = _git_text(staged, "rev-parse", "--verify", target_ref)
                    if not _SHA.fullmatch(current):
                        raise _GitFailure()
                except _GitFailure:
                    current = release_baseline
                if current != release_baseline and inspect(staged, current, "current_main"):
                    baseline = current
                else:
                    current_report = dict(report)
                    if not inspect(staged, release_baseline, "release_tag"):
                        if current != release_baseline:
                            report.update(current_report)
                        return mismatch_result()
            elif not inspect(staged, baseline, comparison):
                return mismatch_result()
            _git(staged, "update-ref", f"refs/heads/{UPDATE_BRANCH}", baseline)
            _git(staged, "symbolic-ref", "HEAD", f"refs/heads/{UPDATE_BRANCH}")
            _git(staged, "read-tree", baseline)
            _git(staged, "config", "remote.origin.fetch",
                 f"+refs/heads/{UPDATE_BRANCH}:refs/remotes/origin/{UPDATE_BRANCH}")
            _git(staged, "config", f"branch.{UPDATE_BRANCH}.remote", "origin")
            _git(staged, "config", f"branch.{UPDATE_BRANCH}.merge", f"refs/heads/{UPDATE_BRANCH}")
            if (root / ".git").exists() or (root / ".git").is_symlink():
                return _result("installation_changed")
            (staged / ".git").rename(root / ".git")
    except _UnsupportedTree:
        return _result("unsupported_source_tree")
    except (_GitFailure, OSError):
        return _result("zip_bootstrap_unavailable")
    return None


def check_for_updates(app_dir: Path, release_version: str) -> dict:
    """Check the public GitHub main branch without login; preserve local state.

    Failure before source mutation is a safe skip; a mixed tree is fatal.
    """
    return _check_for_updates(app_dir, release_version, repository_url=REPOSITORY_URL)


def validate_direct_start(app_dir: Path) -> dict:
    """Require launcher reconciliation of a pending update, without network/Git."""
    root = Path(app_dir).resolve()
    lock = _HELD_LOCKS.get(str(root))
    if lock is None or lock.fd < 0:
        return _result("installation_lock_required", fatal=True)
    try:
        (root / PENDING_FILENAME).lstat()
    except FileNotFoundError:
        return _result("direct_start_ready")
    except OSError:
        return _result("update_state_unsafe", fatal=True)
    return _result("update_verification_required", fatal=True)


def _check_for_updates(app_dir: Path, release_version: str, *, repository_url: str,
                       allow_local_transport: bool = False) -> dict:
    """Private injection point for real local-Git tests, never CLI configuration."""
    root = Path(app_dir).resolve()
    archive_check: dict = {}

    def finish(outcome: str, **kwargs) -> dict:
        result = _result(outcome, **kwargs)
        if archive_check:
            result["archive_check"] = dict(archive_check)
        return result
    lock = _HELD_LOCKS.get(str(root))
    if lock is None or lock.fd < 0:
        return finish("installation_lock_required", fatal=True)
    if not _updates_supported():
        return finish("windows_updates_unsupported")
    if not allow_local_transport and _github_identity(repository_url) is None:
        return finish("repository_configuration_invalid")
    marker = root / ".git"
    if marker.is_symlink():
        return finish("repository_metadata_unsafe")
    try:
        pending = _read_pending(root)
    except (OSError, ValueError):
        return finish("update_state_unsafe", fatal=True)
    if not marker.exists():
        if pending is not None:
            return finish("update_state_unsafe", fatal=True)
        result = _bootstrap(root, release_version, repository_url,
                            anonymous=not allow_local_transport, archive_check=archive_check)
        if result is not None:
            if archive_check:
                result["archive_check"] = dict(archive_check)
            return result
    try:
        if Path(_git_text(root, "rev-parse", "--show-toplevel")).resolve() != root:
            return finish("repository_root_mismatch", fatal=pending is not None)
        if _git_text(root, "symbolic-ref", "--quiet", "--short", "HEAD") != UPDATE_BRANCH:
            return finish("branch_not_managed", fatal=pending is not None)
        if not _remote_matches(_git_text(root, "config", "--get", "remote.origin.url"),
                               repository_url, allow_local_transport):
            return finish("repository_remote_mismatch", fatal=pending is not None)
        if pending is not None:
            actual, clean = _head(root), _clean(root)
            if actual == pending["target"] and clean:
                _tree(root, actual)
                _clear_pending(root)
                return finish("updated", changed=True, old=pending["old"], new=actual)
            if actual != pending["old"] or not clean:
                return finish("update_incomplete", fatal=True,
                               old=pending["old"], new=pending["target"])
            _clear_pending(root)
            pending = None
        old = _head(root)
        _tree(root, old)
        if not _clean(root):
            return finish("local_changes", old=old)
        target_ref = f"refs/remotes/origin/{UPDATE_BRANCH}"
        # Validate the saved origin above, then use HTTPS directly even for an
        # SSH checkout. Never rewrite the user's stored origin or require login
        # to download the public repository.
        _git(root, "fetch", "--no-tags", "--no-recurse-submodules",
             repository_url if allow_local_transport else _public_transport_url(repository_url),
             f"+refs/heads/{UPDATE_BRANCH}:{target_ref}",
             anonymous=not allow_local_transport)
        target = _git_text(root, "rev-parse", "--verify", target_ref)
        if not _SHA.fullmatch(target):
            raise _GitFailure()
        _tree(root, target)
        if old == target:
            return finish("up_to_date", old=old, new=target)
        try:
            _git(root, "merge-base", "--is-ancestor", old, target)
        except _GitFailure:
            return finish("history_not_fast_forward", old=old, new=target)
        # Recheck after the network request: a user may have edited meanwhile.
        if _head(root) != old or not _clean(root):
            return finish("installation_changed", old=old, new=target)
    except _UnsupportedTree:
        return finish("unsupported_source_tree", fatal=pending is not None)
    except _GitFailure:
        return finish("check_unavailable", fatal=pending is not None)
    try:
        _write_pending(root, old, target)
    except OSError:
        return finish("update_state_unavailable", old=old, new=target)
    try:
        _git(root, "merge", "--ff-only", "--no-overwrite-ignore", "--no-stat", target)
    except _GitFailure:
        pass
    except KeyboardInterrupt:
        # Do not continue startup after cancellation, including a cancelled merge.
        raise
    try:
        actual, clean = _head(root), _clean(root)
        if actual == target and clean:
            _clear_pending(root)
            return finish("updated", changed=True, old=old, new=target)
        if actual == old and clean:
            _clear_pending(root)
            return finish("update_not_applied", old=old, new=target)
    except _GitFailure:
        pass
    return finish("update_incomplete", fatal=True, old=old, new=target)


def make_update_handoff(app_dir: Path) -> None:
    """Prepare a validated one-use update-check skip for exec of the new launcher."""
    root = Path(app_dir).resolve()
    lock = _HELD_LOCKS.get(str(root))
    if lock is None or lock.fd < 0:
        raise StartupLockUnsafe("The startup update lock is not held.")
    os.environ[HANDOFF_ENV] = json.dumps({"root": str(root), "pid": os.getpid(),
                                        "fd": lock.fd, "nonce": lock.nonce, "head": _head(root)},
                                       separators=(",", ":"))


def consume_update_handoff(app_dir: Path) -> bool:
    """Consume an exec handoff only for this locked process and exact Git commit."""
    raw = os.environ.pop(HANDOFF_ENV, "")
    if not raw or len(raw) > 4096:
        return False
    root = Path(app_dir).resolve()
    lock = _HELD_LOCKS.get(str(root))
    if lock is None or lock.fd < 0:
        return False
    try:
        handoff = json.loads(raw)
        return (isinstance(handoff, dict) and handoff.get("root") == str(root)
                and handoff.get("pid") == os.getpid() and handoff.get("fd") == lock.fd
                and handoff.get("nonce") == lock.nonce and handoff.get("head") == _head(root)
                and _clean(root))
    except (ValueError, _GitFailure):
        return False
