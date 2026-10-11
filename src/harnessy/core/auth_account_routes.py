"""Account mutations and compatibility routes for the integrated Settings UI.

There is deliberately no standalone account-management application here. Old
bookmarks return to HarnessyXO Settings; authenticated legacy form POSTs remain
supported through the same service used by the native Settings controls.
"""
from __future__ import annotations

import hmac
from typing import Any, Callable

from .auth_users import UserStore, UserStoreError, canonical_username


def _perform_mutation(store: UserStore, username: str, path: str, form: dict[str, str], *,
                      expected_revision: str | None = None,
                      session_guard: Callable[[], bool] | None = None) -> str:
    """Reauthenticate the originating admin, then use the store's actor lock.

    Checking the originating revision matters even if the submitted password is
    correct: a stale browser must not acquire a newly reset account's authority.
    The session guard also rejects logout/expiry while authentication was running.
    """
    from .auth_account_service import AccountSessionExpired

    if session_guard is not None and not session_guard():
        raise AccountSessionExpired()
    actor = store.authenticate(username, form.get('current_password', ''))
    if session_guard is not None and not session_guard():
        raise AccountSessionExpired()
    if actor is None or actor.get('role') != 'admin':
        raise UserStoreError('Your current password was not accepted. No changes were made.')
    if expected_revision is not None and not hmac.compare_digest(str(actor.get('revision', '')), expected_revision):
        raise AccountSessionExpired()
    action = 'password' if path == '/password' else form.get('action', '')
    if action not in {'password', 'add', 'reset', 'enable', 'disable', 'delete'}:
        raise UserStoreError('Choose a valid account action.')
    target = username if action == 'password' else canonical_username(form.get('username', ''))
    if action in {'disable', 'delete'} and target == username:
        raise UserStoreError('You cannot disable or remove your own account.')
    if action == 'reset' and target == username:
        raise UserStoreError('Use Change my password to update your own password.')
    if action in {'password', 'add', 'reset'}:
        password = form.get('password', '')
        if password != form.get('password_confirm', ''):
            raise UserStoreError('The new passwords did not match. No changes were made.')
        if action == 'add':
            store.add_user(target, password, actor=actor, session_guard=session_guard)
            return 'added'
        store.reset_password(target, password, actor=actor, session_guard=session_guard)
        return 'password_changed' if action == 'password' else 'reset'
    if action == 'delete':
        if form.get('confirm_delete', '') != target:
            raise UserStoreError('Type the exact username to confirm removal. No changes were made.')
        store.delete_user(target, actor=actor, session_guard=session_guard)
        return 'deleted'
    store.set_enabled(target, action == 'enable', actor=actor, session_guard=session_guard)
    return 'enabled' if action == 'enable' else 'disabled'


async def handle_account_route(scope: dict[str, Any], receive: Any, send: Any, *,
                               auth: Any, username: str) -> bool:
    """Compatibility entry point after middleware enforces session and Origin."""
    from .auth_account_service import AccountOperationError, AccountSession, AccountSessionExpired

    path = str(scope.get('path') or '')
    if scope.get('type') != 'http' or path not in {'/users', '/password'}:
        return False
    method = str(scope.get('method') or 'GET').upper()
    if method not in {'GET', 'POST'}:
        await auth._reply(send, 405, b'Method not allowed.', headers=[(b'allow', b'GET, POST')])
        return True
    if method == 'GET':
        # No account data or caller-supplied query values are put in this URL.
        await auth._reply(send, 303, headers=[(b'location', b'/?settings=users')])
        return True

    form = await auth._form_or_error(scope, receive, send)
    if form is None:
        return True
    pair = auth._cookie_session(scope)
    if pair is None or pair[1].username != username:
        await auth._reply(send, 401, b'Your session has expired; sign in again.')
        return True
    service = AccountSession(auth, scope, *pair)
    action = 'password' if path == '/password' else form.pop('action', '')
    try:
        result = await service.mutate(action, form)
    except AccountSessionExpired as exc:
        await auth._reply(send, 401, str(exc).encode('utf-8'))
        return True
    except AccountOperationError as exc:
        headers = [(b'retry-after', str(exc.retry_after).encode('ascii'))] if exc.retry_after else []
        await auth._reply(send, exc.status_code, str(exc).encode('utf-8'), headers=headers)
        return True
    except UserStoreError as exc:
        await auth._reply(send, 400, str(exc).encode('utf-8'))
        return True
    finally:
        form = None
    if result == 'password_changed':
        await auth._reply(send, 303, headers=[
            (b'location', b'/login?notice=password_changed'),
            (b'set-cookie', auth._session_cookie(scope, '', clear=True)),
        ])
    else:
        await auth._reply(send, 303, headers=[(b'location', f'/users?notice={result}'.encode('ascii'))])
    return True
