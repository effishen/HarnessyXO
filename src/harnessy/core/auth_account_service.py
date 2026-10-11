"""Server-only account capability bound to one authenticated browser session.

NiceGUI callbacks use this object rather than trusting a browser-supplied actor
name or retaining credentials in application settings. It is never serialized
to the browser. Authentication, rate limits and worker bounds are shared with
the HTTP login gate.
"""
from __future__ import annotations

import asyncio
from typing import Any

from .auth_account_routes import _perform_mutation
from .auth_users import UserStoreError


class AccountSessionExpired(UserStoreError):
    def __init__(self) -> None:
        super().__init__('Your session has expired; sign in again.')


class AccountOperationError(UserStoreError):
    """Safe user-facing operational failure, also usable by compatibility HTTP."""

    def __init__(self, message: str, *, status_code: int, retry_after: int = 0) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.retry_after = retry_after


_FIELDS = {
    'password': {'current_password', 'password', 'password_confirm'},
    'add': {'current_password', 'username', 'password', 'password_confirm'},
    'reset': {'current_password', 'username', 'password', 'password_confirm'},
    'enable': {'current_password', 'username'},
    'disable': {'current_password', 'username'},
    'delete': {'current_password', 'username', 'confirm_delete'},
}


def _validated_form(action: str, form: dict[str, str]) -> dict[str, str]:
    from .access import MAX_LOGIN_BODY

    if type(action) is not str or action not in _FIELDS:
        raise UserStoreError('Choose a valid account action.')
    if type(form) is not dict or set(form) != _FIELDS[action]:
        raise UserStoreError('Invalid account form. Complete the required fields.')
    size = 0
    for key, value in form.items():
        maximum = 64 if key in {'username', 'confirm_delete'} else 1024
        if type(value) is not str or not 1 <= len(value) <= maximum:
            raise UserStoreError('Invalid account form. Check the required fields and their lengths.')
        try:
            size += len(key.encode('utf-8')) + len(value.encode('utf-8'))
        except UnicodeError:
            raise UserStoreError('Account form contains unsupported characters.') from None
    if size > MAX_LOGIN_BODY:
        raise UserStoreError('Account form is too large.')
    # Copy to avoid a caller mutating values while asynchronous work is running.
    return dict(form)


class AccountSession:
    """A capability created only by middleware after it validates a session."""

    __slots__ = ('_auth', '_scope', '_token', '_session')

    def __init__(self, auth: Any, scope: dict[str, Any], token: str, session: Any) -> None:
        self._auth = auth
        # Rate limits use the server-observed client address, never a forwarded
        # header. Avoid retaining cookies, request objects or mutable UI state.
        self._scope = {'client': tuple(scope.get('client') or ('unknown', 0))}
        self._token = token
        self._session = session

    @property
    def username(self) -> str:
        return self._session.username

    def _active(self) -> bool:
        return (self._auth._sessions.get(self._token) is self._session
                and self._session.expires > self._auth._clock())

    async def _require_session(self) -> None:
        if not await self._auth._valid_session(self._token, self._session):
            raise AccountSessionExpired()

    async def _work(self, function: Any, *args: Any, **kwargs: Any) -> Any:
        from .access import AuthBusyError

        try:
            return await self._auth._run_auth_work(function, *args, **kwargs)
        except AuthBusyError:
            raise AccountOperationError('Account management is busy. Try again shortly.',
                                        status_code=429, retry_after=5) from None
        except asyncio.TimeoutError:
            raise AccountOperationError(
                'Account operation is taking longer than expected. It may still finish; '
                'check the account list or try signing in before repeating it.', status_code=503) from None
        except OSError:
            raise AccountOperationError('Account storage unavailable. Check the local settings folder.',
                                        status_code=503) from None

    async def list_users(self) -> list[dict[str, Any]]:
        await self._require_session()
        users = await self._work(self._auth.store.list_users)
        # Do not reveal a list if logout/revocation completed while it was read.
        await self._require_session()
        return users

    def _mutate(self, action: str, form: dict[str, str]) -> str:
        result = _perform_mutation(
            self._auth.store, self.username, '/password' if action == 'password' else '/users',
            {**form, 'action': action}, expected_revision=self._session.revision,
            session_guard=self._active,
        )
        if result == 'password_changed':
            # Also revoke explicitly when an awaiting UI disconnected/timed out.
            # All other browsers are invalidated by the store revision change.
            self._auth._sessions.pop(self._token, None)
        return result

    async def mutate(self, action: str, form: dict[str, str]) -> str:
        await self._require_session()
        if not self._auth._allow_login(self._scope):
            raise AccountOperationError('Too many account attempts. Please wait a minute.',
                                        status_code=429, retry_after=60)
        values = _validated_form(action, form)
        try:
            return await self._work(self._mutate, action, values)
        except UserStoreError:
            # Store actor-lock rejection is a session expiry for the native UI,
            # not merely a form error. Keep unrelated safe validation messages.
            if not await self._auth._valid_session(self._token, self._session):
                raise AccountSessionExpired() from None
            raise
        finally:
            values = None
