"""Local HarnessyXO login accounts; intentionally depends on the standard library only.

All accounts are trusted controller users, not isolated workspace tenants. Password
hashes live outside model-visible workspaces, in the machine settings directory.
"""
from __future__ import annotations

import base64
import binascii
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
import time
from typing import Any, Callable, Iterator


USER_FILE = 'login_users.json'
STORE_VERSION = 1
PBKDF2_ITERATIONS = 600_000
MIN_PASSWORD_LENGTH = 1
MAX_PASSWORD_LENGTH = 1024
MAX_STORE_BYTES = 1_048_576
_USERNAME = re.compile(r'[A-Za-z0-9_.-]{1,64}', re.ASCII)
_REVISION = re.compile(r'[0-9a-f]{64}', re.ASCII)
_DUMMY_SALT = b'HarnessyXO-unknown-user-padding!!'


class UserStoreError(ValueError):
    """An account operation was refused; messages never include credentials."""


def canonical_username(value: str) -> str:
    if not isinstance(value, str) or _USERNAME.fullmatch(value) is None:
        raise UserStoreError('Username must be 1–64 letters, numbers, underscores, dots or hyphens.')
    return value.lower()


def _password_bytes(password: str) -> bytes:
    if not isinstance(password, str) or not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        raise UserStoreError(f'Password must not be empty and must be at most {MAX_PASSWORD_LENGTH} characters.')
    try:
        return password.encode('utf-8')
    except UnicodeError:
        raise UserStoreError('Password contains unsupported characters.') from None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def _new_password(password: str) -> dict[str, Any]:
    password_bytes = _password_bytes(password)
    salt = secrets.token_bytes(32)
    digest = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, PBKDF2_ITERATIONS)
    return {
        'algorithm': 'pbkdf2_sha256',
        'iterations': PBKDF2_ITERATIONS,
        'salt': base64.b64encode(salt).decode('ascii'),
        'digest': base64.b64encode(digest).decode('ascii'),
    }


def _decode_b64(value: Any) -> bytes:
    if not isinstance(value, str):
        raise UserStoreError('Login account file is invalid; refusing to use it.')
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise UserStoreError('Login account file is invalid; refusing to use it.') from None
    if len(decoded) != 32:
        raise UserStoreError('Login account file is invalid; refusing to use it.')
    return decoded


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise UserStoreError('Login account file has duplicate fields; refusing to use it.')
        result[key] = value
    return result


class UserStore:
    """A locked, atomically replaced credential file with immediate revocation.

    Reads never reuse cached credentials, so account changes revoke sessions while
    the server is running. Atomic replacement makes concurrent reads consistent.
    Mutations share an OS-level sidecar lock across processes and threads.
    """

    def __init__(self, settings_root: Path | str) -> None:
        # Do not resolve the final component: a symlink here must not silently
        # redirect credentials somewhere else. Existing ancestors such as macOS
        # /var -> /private/var may legitimately be symlinks.
        self.root = Path(settings_root).expanduser().absolute()
        self.path = self.root / USER_FILE
        self.lock_path = self.root / 'login_users.lock'
        try:
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            self._check_root()
        except OSError:
            raise UserStoreError('Cannot open the login settings directory.') from None

    def _check_root(self) -> None:
        info = self.root.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise UserStoreError('Login settings directory must be a real directory, not a symlink.')
        if os.name != 'nt' and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022):
            raise UserStoreError('Login settings directory must be owned by you and not writable by other users.')

    @staticmethod
    def _check_info(info: os.stat_result, *, allow_detached_read: bool = False) -> None:
        valid_link_count = info.st_nlink == 1 or (allow_detached_read and info.st_nlink == 0)
        if not stat.S_ISREG(info.st_mode) or not valid_link_count:
            raise UserStoreError('Login files must be regular files, not links or special files.')
        if os.name != 'nt':
            if info.st_uid != os.geteuid():
                raise UserStoreError('Login files must be owned by the current operating-system user.')
            if stat.S_IMODE(info.st_mode) & 0o077:
                raise UserStoreError('Login files must be private. Set their permissions to 600 and try again.')

    def _open_private(self, path: Path, flags: int) -> int:
        self._check_root()
        reading = (flags & getattr(os, 'O_ACCMODE', 3)) == os.O_RDONLY
        try:
            before = path.lstat()
        except FileNotFoundError:
            before = None
        if before is not None:
            # lstat can itself observe nlink=0 if replacement lands between
            # pathname lookup and fetching inode metadata. Read-only access to
            # either private generation is safe; hardlinks still fail closed.
            self._check_info(before, allow_detached_read=reading)
        fd = os.open(path, flags | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0), 0o600)
        try:
            opened = os.fstat(fd)
            self._check_info(opened, allow_detached_read=reading)
            after = path.lstat()
            self._check_info(after, allow_detached_read=reading)
            # The opened descriptor may legitimately refer to the preceding
            # atomically replaced generation. Both generations are private,
            # regular files and are safe to read; the descriptor is authoritative.
            return fd
        except BaseException:
            os.close(fd)
            raise

    @contextmanager
    def _locked(self) -> Iterator[None]:
        fd = -1
        acquired = False
        try:
            fd = self._open_private(self.lock_path, os.O_CREAT | os.O_RDWR)
            if os.name == 'nt':
                import msvcrt
                if os.fstat(fd).st_size == 0:
                    os.write(fd, b'\0')
                os.lseek(fd, 0, os.SEEK_SET)
                def acquire() -> None:
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                def release() -> None:
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                def acquire() -> None:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                def release() -> None:
                    fcntl.flock(fd, fcntl.LOCK_UN)
            deadline = time.monotonic() + 10.0
            while True:
                try:
                    acquire()
                    acquired = True
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise UserStoreError('Another account operation is in progress; try again shortly.') from None
                    time.sleep(0.05)
            yield
        except OSError:
            raise UserStoreError('Cannot safely read or write the login account files.') from None
        finally:
            if fd >= 0:
                try:
                    if acquired:
                        release()
                finally:
                    os.close(fd)

    def _read(self) -> dict[str, Any]:
        try:
            fd = self._open_private(self.path, os.O_RDONLY)
        except FileNotFoundError:
            return {'version': STORE_VERSION, 'users': []}
        except OSError:
            raise UserStoreError('Cannot safely read the login account file.') from None
        try:
            with os.fdopen(fd, 'rb') as stream:
                raw = stream.read(MAX_STORE_BYTES + 1)
            if len(raw) > MAX_STORE_BYTES:
                raise UserStoreError('Login account file is too large; refusing to use it.')
            data = json.loads(raw.decode('utf-8'), object_pairs_hook=_json_object)
        except (UnicodeError, ValueError, RecursionError, OSError):
            raise UserStoreError('Login account file is invalid; refusing to use it.') from None
        if not isinstance(data, dict) or type(data.get('version')) is not int or data['version'] != STORE_VERSION:
            raise UserStoreError('Login account file has an unsupported format; refusing to use it.')
        users = data.get('users')
        if not isinstance(users, list):
            raise UserStoreError('Login account file is invalid; refusing to use it.')
        seen: set[str] = set()
        for user in users:
            if not isinstance(user, dict):
                raise UserStoreError('Login account file is invalid; refusing to use it.')
            username = canonical_username(user.get('username'))
            if username != user.get('username') or username in seen or type(user.get('enabled')) is not bool:
                raise UserStoreError('Login account file is invalid; refusing to use it.')
            if user.get('role') != 'admin':
                raise UserStoreError('Login account file has an unsupported account role.')
            seen.add(username)
            revision = user.get('revision')
            password = user.get('password')
            if not isinstance(revision, str) or _REVISION.fullmatch(revision) is None:
                raise UserStoreError('Login account file is invalid; refusing to use it.')
            if not all(isinstance(user.get(key), str) for key in ('created_at', 'updated_at')):
                raise UserStoreError('Login account file is invalid; refusing to use it.')
            if not isinstance(password, dict) or password.get('algorithm') != 'pbkdf2_sha256':
                raise UserStoreError('Login account file is invalid; refusing to use it.')
            if type(password.get('iterations')) is not int or password['iterations'] != PBKDF2_ITERATIONS:
                raise UserStoreError('Login account file has unsupported password hashing settings.')
            _decode_b64(password.get('salt'))
            _decode_b64(password.get('digest'))
        return data

    def _write(self, data: dict[str, Any]) -> None:
        raw = (json.dumps(data, indent=2, ensure_ascii=True) + '\n').encode('utf-8')
        if len(raw) > MAX_STORE_BYTES:
            raise UserStoreError('There are too many login accounts to save safely.')
        self._check_root()
        try:
            self._check_info(self.path.lstat())
        except FileNotFoundError:
            pass
        fd, temporary = tempfile.mkstemp(prefix='.login-users-', suffix='.tmp', dir=self.root)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            self._check_root()
            # Refuse unsafe targets even though replace itself does not follow
            # symlinks; this also catches accidental misconfiguration.
            try:
                self._check_info(self.path.lstat())
            except FileNotFoundError:
                pass
            os.replace(temporary, self.path)
            if os.name != 'nt':
                try:
                    directory = os.open(self.root, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
                    try:
                        os.fsync(directory)
                    finally:
                        os.close(directory)
                except OSError:
                    # Some filesystems cannot open/fsync directories. The file
                    # fsync and replacement have committed: do not misreport
                    # that a password change failed after it already succeeded.
                    pass
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def list_users(self) -> list[dict[str, Any]]:
        return [
            {key: user[key] for key in ('username', 'role', 'enabled', 'created_at', 'updated_at')}
            for user in sorted(self._read()['users'], key=lambda item: item['username'])
        ]

    def has_users(self) -> bool:
        # An existing but manually disabled database is NOT a new installation.
        # Reopening first-run setup there would let another person claim it.
        return bool(self._read()['users'])

    def authenticate(self, username: str, password: str) -> dict[str, str] | None:
        try:
            password_bytes = _password_bytes(password)
        except UserStoreError:
            return None
        try:
            name = canonical_username(username)
        except UserStoreError:
            name = ''
        try:
            users = self._read()['users']
        except (UserStoreError, OSError):
            return None
        user = next((item for item in users if item['username'] == name), None)
        salt = _decode_b64(user['password']['salt']) if user else _DUMMY_SALT
        expected = _decode_b64(user['password']['digest']) if user else bytes(32)
        actual = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, PBKDF2_ITERATIONS)
        matches = hmac.compare_digest(actual, expected)
        if not matches or not user or not user['enabled']:
            return None
        # A reset/disable may complete while the expensive KDF runs. Do not
        # issue a valid session using credentials that were just revoked.
        if not self.session_valid(user['username'], user['revision']):
            return None
        return {'username': user['username'], 'revision': user['revision'], 'role': user['role']}

    def session_valid(self, username: str, revision: str) -> bool:
        try:
            name = canonical_username(username)
            if not isinstance(revision, str) or _REVISION.fullmatch(revision) is None:
                return False
            return any(
                user['username'] == name and user['enabled'] and hmac.compare_digest(user['revision'], revision)
                for user in self._read()['users']
            )
        except (UserStoreError, OSError):
            return False

    @staticmethod
    def _find(data: dict[str, Any], name: str) -> dict[str, Any]:
        for user in data['users']:
            if user['username'] == name:
                return user
        raise UserStoreError('That username does not exist.')

    @staticmethod
    def _prevent_last_enabled(data: dict[str, Any], user: dict[str, Any]) -> None:
        if user['enabled'] and sum(item['enabled'] for item in data['users']) <= 1:
            raise UserStoreError('Cannot remove or disable the last enabled user. Add another user first.')

    @staticmethod
    def _check_actor(data: dict[str, Any], actor: dict[str, str] | None,
                     session_guard: Callable[[], bool] | None = None) -> None:
        # Called under the write lock, after potentially expensive new-password
        # hashing and lock acquisition. A logged-out/expired browser may not
        # finish an account mutation merely because its earlier password check
        # succeeded. The store revision check below independently handles resets.
        if session_guard is not None and not session_guard():
            raise UserStoreError('Your session has expired; sign in again.')
        if actor is None:
            return
        if not isinstance(actor, dict) or not isinstance(actor.get('revision'), str):
            raise UserStoreError('Your session has expired; sign in again.')
        try:
            name = canonical_username(actor.get('username'))
        except UserStoreError:
            raise UserStoreError('Your session has expired; sign in again.') from None
        if not _REVISION.fullmatch(actor['revision']) or not any(
            user['username'] == name and user['enabled'] and user['role'] == 'admin'
            and hmac.compare_digest(user['revision'], actor['revision'])
            for user in data['users']
        ):
            raise UserStoreError('Your session has expired; sign in again.')

    def add_user(self, username: str, password: str, *, actor: dict[str, str] | None = None,
                 session_guard: Callable[[], bool] | None = None) -> None:
        self._add_user(username, password, first_only=False, actor=actor, session_guard=session_guard)

    def add_first_user(self, username: str, password: str) -> None:
        """Create the initial account exactly once, even with concurrent setup requests."""
        self._add_user(username, password, first_only=True, actor=None, session_guard=None)

    def _add_user(self, username: str, password: str, *, first_only: bool, actor: dict[str, str] | None,
                  session_guard: Callable[[], bool] | None) -> None:
        name = canonical_username(username)
        password_record = _new_password(password)
        with self._locked():
            data = self._read()
            self._check_actor(data, actor, session_guard)
            if first_only and data['users']:
                raise UserStoreError('Initial login setup is already complete.')
            if any(user['username'] == name for user in data['users']):
                raise UserStoreError('That username already exists (usernames are case-insensitive).')
            now = _now()
            data['users'].append({
                'username': name, 'role': 'admin', 'enabled': True, 'password': password_record,
                'revision': secrets.token_hex(32), 'created_at': now, 'updated_at': now,
            })
            self._write(data)

    def reset_password(self, username: str, password: str, *, actor: dict[str, str] | None = None,
                       session_guard: Callable[[], bool] | None = None) -> None:
        name = canonical_username(username)
        password_record = _new_password(password)
        with self._locked():
            data = self._read()
            self._check_actor(data, actor, session_guard)
            user = self._find(data, name)
            user.update(password=password_record, revision=secrets.token_hex(32), updated_at=_now())
            self._write(data)

    def set_enabled(self, username: str, enabled: bool, *, actor: dict[str, str] | None = None,
                    session_guard: Callable[[], bool] | None = None) -> None:
        name = canonical_username(username)
        if type(enabled) is not bool:
            raise UserStoreError('Enabled must be true or false.')
        with self._locked():
            data = self._read()
            self._check_actor(data, actor, session_guard)
            user = self._find(data, name)
            if user['enabled'] == enabled:
                return
            if not enabled:
                self._prevent_last_enabled(data, user)
            user.update(enabled=enabled, revision=secrets.token_hex(32), updated_at=_now())
            self._write(data)

    def delete_user(self, username: str, *, actor: dict[str, str] | None = None,
                    session_guard: Callable[[], bool] | None = None) -> None:
        name = canonical_username(username)
        with self._locked():
            data = self._read()
            self._check_actor(data, actor, session_guard)
            user = self._find(data, name)
            self._prevent_last_enabled(data, user)
            data['users'].remove(user)
            self._write(data)
