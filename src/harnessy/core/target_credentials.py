"""Host-only SSH passwords, kept out of workspace databases and model context."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from .auth_users import UserStore, UserStoreError
from .paths import settings_dir


class TargetCredentialError(ValueError):
    """A credential operation failed without including its secret in the error."""


class TargetCredentialStore:
    """Private, atomically replaced host settings; passwords are plaintext at rest.

    The settings directory is owned by the controller user and mode 0700; this
    file and its temporary replacements are mode 0600. Nothing here is placed
    in the workspace database, Files directory, VM or a model tool result.
    """

    def __init__(self, root: Path | None = None) -> None:
        self.guard = UserStore(root if root is not None else settings_dir())
        self.path = self.guard.root / 'external_target_passwords.json'

    @staticmethod
    def _key(workspace_id: str, target_id: str) -> str:
        return f'{workspace_id}:{target_id}'

    def _read(self) -> dict[str, str]:
        try:
            fd = self.guard._open_private(self.path, os.O_RDONLY)
        except FileNotFoundError:
            return {}
        except (OSError, UserStoreError):
            raise TargetCredentialError('Cannot safely read external-target passwords.') from None
        try:
            with os.fdopen(fd, 'rb') as stream:
                raw = stream.read(1_048_577)
            if len(raw) > 1_048_576:
                raise ValueError('oversized')
            entries = json.loads(raw.decode('utf-8'))
            if not isinstance(entries, dict) or not all(
                isinstance(key, str) and isinstance(value, str) for key, value in entries.items()
            ):
                raise ValueError('invalid')
            return entries
        except (OSError, ValueError, UnicodeError):
            raise TargetCredentialError('External-target password file is invalid or unreadable.') from None

    def _write(self, entries: dict[str, str]) -> None:
        raw = (json.dumps(entries, ensure_ascii=True) + '\n').encode('utf-8')
        if len(raw) > 1_048_576:
            raise TargetCredentialError('Too many external-target passwords to save.')
        try:
            self.guard._check_root()
            try:
                self.guard._check_info(self.path.lstat())
            except FileNotFoundError:
                pass
            fd, temporary = tempfile.mkstemp(prefix='.target-passwords-', dir=self.guard.root)
            try:
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                self.guard._check_root()
                try:
                    self.guard._check_info(self.path.lstat())
                except FileNotFoundError:
                    pass
                os.replace(temporary, self.path)
            finally:
                Path(temporary).unlink(missing_ok=True)
        except (OSError, UserStoreError):
            raise TargetCredentialError('Cannot safely save external-target passwords.') from None

    def get(self, workspace_id: str, target_id: str) -> str | None:
        return self._read().get(self._key(workspace_id, target_id))

    def set(self, workspace_id: str, target_id: str, password: str) -> None:
        if not isinstance(password, str) or not password or len(password) > 1024 or any(
            char in password for char in ('\x00', '\r', '\n')
        ):
            raise TargetCredentialError('SSH password must contain 1–1024 characters and no line breaks or NUL byte.')
        try:
            with self.guard._locked():
                entries = self._read()
                entries[self._key(workspace_id, target_id)] = password
                self._write(entries)
        except UserStoreError:
            raise TargetCredentialError('Cannot safely save external-target passwords.') from None

    def delete(self, workspace_id: str, target_id: str) -> None:
        try:
            with self.guard._locked():
                entries = self._read()
                if entries.pop(self._key(workspace_id, target_id), None) is not None:
                    self._write(entries)
        except UserStoreError:
            raise TargetCredentialError('Cannot safely delete external-target passwords.') from None
