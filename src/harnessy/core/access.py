"""Password login gate for every controller HTTP and WebSocket endpoint."""
from __future__ import annotations

import asyncio
from collections import OrderedDict, deque
from dataclasses import dataclass
from html import escape
import hmac
from http.cookies import SimpleCookie
import secrets
import time
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit

from .auth_users import UserStore
from .theme import THEME_CSS

SESSION_COOKIE = 'harnessy_session'
SESSION_SECONDS = 12 * 60 * 60
# Use a bounded long-lived cookie. The server's session deadline remains
# authoritative; a long-lived cookie permits a live policy change from
# a finite timeout to Never without the old browser deadline deleting it.
SESSION_COOKIE_SECONDS = 400 * 24 * 60 * 60
MAX_SESSION_TIMEOUT_SECONDS = SESSION_COOKIE_SECONDS
MAX_SESSIONS = 1024
MAX_LOGIN_BODY = 8192
MAX_RATE_CLIENTS = 4096
LOGIN_WINDOW = 60.0
LOGIN_IP_LIMIT = 10
LOGIN_GLOBAL_LIMIT = 60
MAX_AUTH_WORKERS = 4
BODY_TIMEOUT = 5.0
AUTH_TIMEOUT = 15.0
REVOCATION_POLL_SECONDS = 1.0

AUTH_CSS = r'''
*{box-sizing:border-box}
body{font:14px var(--hy-font);background:var(--hy-page-surface);color:var(--hy-text);
margin:0;min-height:100vh;min-height:100dvh;padding:32px 20px;
display:grid;place-items:center;color-scheme:light}
body.body--dark{color-scheme:dark}
main{width:min(440px,100%)}
.hy-auth-brand{font-size:18px;font-weight:600;line-height:1.5;margin-bottom:18px}
.hy-auth-card{background:var(--hy-dialog-surface);border:1px solid var(--hy-dialog-border);
border-radius:10px;padding:24px}
h1{font-size:22px;font-weight:600;line-height:1.3;margin:0 0 10px}
p{line-height:1.6;color:var(--hy-muted-text);margin:10px 0 0}
label{display:block;margin:18px 0 7px;font-weight:500}
input,button{width:100%;padding:11px 12px;border-radius:8px;font:inherit}
input{background:transparent;border:1px solid var(--hy-dialog-border);color:var(--hy-text);min-height:44px}
input:hover{border-color:var(--hy-muted-text)}
input:focus-visible,button:focus-visible,a:focus-visible{outline:2px solid var(--hy-primary);outline-offset:3px}
input:focus-visible{border-color:var(--hy-primary)}
button{margin-top:24px;background:var(--hy-primary);color:#052e24;border:0;
min-height:44px;font-weight:600;cursor:pointer}
button:hover{filter:brightness(.96)}
.error{color:var(--hy-error-text);border-left:3px solid currentColor;padding:8px 12px;margin-top:18px;
background:var(--hy-soft);border-radius:0 6px 6px 0}
.hy-auth-status{border:1px solid var(--hy-border);border-radius:8px;padding:10px 12px;
background:var(--hy-soft);margin-top:18px;color:var(--hy-text)}
.hy-auth-note{font-size:12px;line-height:1.5;margin-top:16px}
a{color:inherit;text-decoration:underline;text-decoration-color:var(--hy-primary);text-underline-offset:3px}
@media(max-width:480px){body{padding:24px 16px}.hy-auth-card{padding:20px}}
'''


def _page_start(title: str, *, dark: bool = False) -> str:
    mode = 'dark' if dark else 'light'
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<meta name="referrer" content="same-origin">'
            f'<title>{escape(title)} · HarnessyXO</title><style>{THEME_CSS}{AUTH_CSS}</style>'
            f'</head><body class="body--{mode}"><main>'
            '<header class="hy-auth-brand">HarnessyXO</header>'
            '<section class="hy-auth-card" aria-labelledby="auth-title">')


_PAGE_END = '</section></main></body></html>'
_NETWORK_NOTE = '<p class="hy-auth-note">Use only a trusted network. HTTP connections are not encrypted.</p>'


def _login_html(message: str = '', *, password_changed: bool = False, dark: bool = False) -> bytes:
    error = f'<p class="error" role="alert">{escape(message)}</p>' if message else ''
    if password_changed:
        error += '<p class="hy-auth-status" role="status">Password changed. Sign in with your new password.</p>'
    return (_page_start('Sign in', dark=dark) + '<h1 id="auth-title">Sign in</h1><p>Continue to your workspaces and chats.</p>' + error + '''
<form action="/login" method="post"><label for="username">Username</label>
<input id="username" name="username" autocomplete="username" required maxlength="128" autofocus>
<label for="password">Password</label><input id="password" name="password" type="password"
autocomplete="current-password" required maxlength="1024"><button type="submit">Sign in</button></form>
''' + _NETWORK_NOTE + _PAGE_END).encode('utf-8')


def _setup_html(message: str = '', *, dark: bool = False) -> bytes:
    error = f'<p class="error" role="alert">{escape(message)}</p>' if message else ''
    return (_page_start('Set up', dark=dark) + '<h1 id="auth-title">Set up HarnessyXO</h1><p>Create your first administrator account. '
            'Enter the one-time setup code shown in the HarnessyXO startup window. '
            'All accounts are administrators of this shared instance.</p>' + error + '''
<form action="/setup" method="post"><label for="setup_code">Setup code</label>
<input id="setup_code" name="setup_code" autocomplete="off" required maxlength="128" autofocus>
<label for="username">Username</label><input id="username" name="username" autocomplete="username" required maxlength="128">
<label for="password">Password</label><input id="password" name="password" type="password"
autocomplete="new-password" required maxlength="1024">
<label for="confirmation">Confirm password</label><input id="confirmation" name="confirmation" type="password"
autocomplete="new-password" required maxlength="1024">
<button type="submit">Create administrator</button></form>
''' + _NETWORK_NOTE + _PAGE_END).encode('utf-8')


def _logout_html(*, dark: bool = False) -> bytes:
    return (_page_start('Sign out', dark=dark) + '<h1 id="auth-title">Sign out?</h1>'
            '<p>You can sign in again to return to HarnessyXO.</p>'
            '<form method="post" action="/logout"><button type="submit">Sign out</button></form>'
            '<p><a href="/">Return to HarnessyXO</a></p>' + _PAGE_END).encode('utf-8')


@dataclass
class _Session:
    username: str
    revision: str
    expires: float


class _SessionRevoked(Exception):
    pass


class AuthBusyError(Exception):
    """Bounded password worker capacity is currently exhausted."""


class HarnessyLoginMiddleware:
    """Persistent accounts, process-local random sessions, same-origin actions.

    Loopback, URL fragments and old launch tokens never bypass this gate. User
    changes take effect on the next request and on established socket traffic.
    """

    def __init__(self, app: Any, *, store: UserStore, setup_code: str | None = None,
                 dark_mode: Callable[[], bool] | None = None,
                 session_timeout_seconds: Callable[[], int] | None = None) -> None:
        self.app = app
        self.store = store
        self._setup_code = str(setup_code or '')
        self._dark_mode = dark_mode
        self._session_timeout_seconds = session_timeout_seconds
        self._session_seconds = SESSION_SECONDS
        self._clock = time.monotonic
        self._sessions: OrderedDict[str, _Session] = OrderedDict()
        self._attempts: OrderedDict[str, deque[float]] = OrderedDict()
        self._global_attempts: deque[float] = deque()
        self._auth_workers = 0

    def _refresh_session_policy(self) -> None:
        """Apply a valid changed policy without replacing session capabilities.

        A settings read failure retains the last accepted policy. Expired
        sessions are removed before extending any deadlines, so changing to
        Never cannot bring a signed-out browser back to life.
        """
        if self._session_timeout_seconds is None:
            return
        try:
            seconds = self._session_timeout_seconds()
        except Exception:
            return
        if type(seconds) is not int or not 0 <= seconds <= MAX_SESSION_TIMEOUT_SECONDS:
            return
        if seconds == self._session_seconds:
            return
        now = self._clock()
        for token, session in list(self._sessions.items()):
            if session.expires <= now:
                self._sessions.pop(token, None)
            else:
                # WebSockets and account actions hold this exact object.
                session.expires = now + seconds if seconds else float('inf')
        self._session_seconds = seconds

    def _is_dark(self) -> bool:
        """Appearance is optional; an unreadable preference must not block login."""
        try:
            return bool(self._dark_mode()) if self._dark_mode is not None else False
        except Exception:
            return False

    @staticmethod
    def _headers(scope: dict[str, Any]) -> dict[bytes, bytes]:
        result: dict[bytes, bytes] = {}
        for key, value in scope.get('headers', []):
            key, value = bytes(key).lower(), bytes(value)
            # Reject ambiguous security headers rather than differing from the
            # proxy/browser/downstream interpretation.
            if key in result and key in {b'host', b'origin', b'cookie', b'content-length', b'content-type'}:
                result[key] = b'\x00'
            else:
                result[key] = value
        return result

    @classmethod
    def _same_origin(cls, scope: dict[str, Any], *, required: bool) -> bool:
        headers = cls._headers(scope)
        if headers.get(b'sec-fetch-site', b'').lower() == b'cross-site':
            return False
        raw = headers.get(b'origin')
        if raw is None:
            return not required
        try:
            origin = urlsplit(raw.decode('ascii'))
            scheme = {'ws': 'http', 'wss': 'https'}.get(str(scope.get('scheme')), str(scope.get('scheme', 'http')))
            host_raw = headers.get(b'host', b'').decode('ascii')
            if not host_raw or any(c in host_raw for c in '\x00/\\?#@ \r\n\t'):
                return False
            host = urlsplit(f'{scheme}://{host_raw}')
            if (origin.scheme not in {'http', 'https'} or origin.scheme != scheme or
                    origin.username is not None or origin.password is not None or
                    origin.path or origin.query or origin.fragment or not origin.hostname):
                return False
            default_port = 443 if scheme == 'https' else 80
            return (origin.hostname.lower(), origin.port or default_port) == (host.hostname.lower(), host.port or default_port)
        except (ValueError, UnicodeError, AttributeError):
            return False

    def _cookie_session(self, scope: dict[str, Any]) -> tuple[str, _Session] | None:
        self._refresh_session_policy()
        try:
            raw = self._headers(scope).get(b'cookie', b'').decode('latin-1')
            if len(raw) > 8192 or '\x00' in raw:
                return None
            jar = SimpleCookie()
            jar.load(raw)
            morsel = jar.get(SESSION_COOKIE)
            token = morsel.value if morsel else ''
            session = self._sessions.get(token)
            if not session:
                return None
            if session.expires <= self._clock():
                self._sessions.pop(token, None)
                return None
            return token, session
        except Exception:
            return None

    async def _valid_session(self, token: str, session: _Session) -> bool:
        self._refresh_session_policy()
        if self._sessions.get(token) is not session or session.expires <= self._clock():
            self._sessions.pop(token, None)
            return False
        try:
            valid = await asyncio.to_thread(self.store.session_valid, session.username, session.revision)
        except Exception:
            valid = False
        # Logout/replacement can occur while the on-disk check is in flight.
        self._refresh_session_policy()
        valid = bool(valid and self._sessions.get(token) is session and session.expires > self._clock())
        if not valid:
            self._sessions.pop(token, None)
        return bool(valid)

    @staticmethod
    def _session_cookie(scope: dict[str, Any], token: str, *, clear: bool = False) -> bytes:
        cookie = f'{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={0 if clear else SESSION_COOKIE_SECONDS}'
        if scope.get('scheme') in {'https', 'wss'}:
            cookie += '; Secure'
        return cookie.encode('ascii')

    async def _reply(self, send: Any, status: int, body: bytes = b'', *,
                     headers: list[tuple[bytes, bytes]] | None = None, html: bool = False) -> None:
        base = [
            (b'content-type', b'text/html; charset=utf-8' if html else b'text/plain; charset=utf-8'),
            # Native form POSTs use navigation mode. Under no-referrer, Fetch
            # serializes their Origin as "null", even on this same-origin form,
            # which our CSRF gate correctly rejects. Keep local origin evidence
            # without sending referrer information to other sites. The matching
            # HTML meta policy on every account page must agree with this header.
            (b'cache-control', b'no-store'), (b'referrer-policy', b'same-origin'),
            (b'x-content-type-options', b'nosniff'), (b'x-frame-options', b'DENY'),
            (b'content-security-policy', b"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
        ]
        await send({'type': 'http.response.start', 'status': status, 'headers': base + list(headers or [])})
        await send({'type': 'http.response.body', 'body': body})

    def _allow_login(self, scope: dict[str, Any]) -> bool:
        now = self._clock()
        threshold = now - LOGIN_WINDOW
        while self._global_attempts and self._global_attempts[0] <= threshold:
            self._global_attempts.popleft()
        address = str((scope.get('client') or ('unknown', 0))[0])[:128]
        attempts = self._attempts.get(address, deque())
        while attempts and attempts[0] <= threshold:
            attempts.popleft()
        if len(self._global_attempts) >= LOGIN_GLOBAL_LIMIT or len(attempts) >= LOGIN_IP_LIMIT:
            return False
        attempts.append(now)
        self._global_attempts.append(now)
        self._attempts[address] = attempts
        self._attempts.move_to_end(address)
        while len(self._attempts) > MAX_RATE_CLIENTS:
            self._attempts.popitem(last=False)
        return True

    async def _read_form(self, scope: dict[str, Any], receive: Any) -> dict[str, str]:
        """Bounded, strict URL-encoded form parser shared by account pages."""
        headers = self._headers(scope)
        if headers.get(b'content-type', b'').split(b';', 1)[0].strip().lower() != b'application/x-www-form-urlencoded':
            raise ValueError('Invalid form')
        length = headers.get(b'content-length')
        if length is not None:
            if not length.isdigit():
                raise ValueError('Invalid length')
            if len(length) > 8 or int(length) > MAX_LOGIN_BODY:
                raise OverflowError('Form too large')
        body = bytearray()
        async def read() -> None:
            while True:
                event = await receive()
                if event.get('type') != 'http.request':
                    raise ValueError('Request disconnected')
                body.extend(event.get('body', b''))
                if len(body) > MAX_LOGIN_BODY:
                    raise OverflowError('Form too large')
                if not event.get('more_body', False):
                    return
        await asyncio.wait_for(read(), timeout=BODY_TIMEOUT)
        form = parse_qs(body.decode('utf-8', errors='strict'), keep_blank_values=True, strict_parsing=True, max_num_fields=16, errors='strict')
        if any(len(values) != 1 for values in form.values()):
            raise ValueError('Duplicate fields')
        return {key: values[0] for key, values in form.items()}

    async def _run_auth_work(self, function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """No unbounded hashing threads, including disconnected callers."""
        if self._auth_workers >= MAX_AUTH_WORKERS:
            raise AuthBusyError()
        self._auth_workers += 1
        work = asyncio.create_task(asyncio.to_thread(function, *args, **kwargs))
        def completed(task: asyncio.Task[Any]) -> None:
            self._auth_workers -= 1
            if not task.cancelled():
                task.exception()
        work.add_done_callback(completed)
        return await asyncio.wait_for(asyncio.shield(work), timeout=AUTH_TIMEOUT)

    async def _form_or_error(self, scope: dict[str, Any], receive: Any, send: Any) -> dict[str, str] | None:
        try:
            return await self._read_form(scope, receive)
        except OverflowError:
            await self._reply(send, 413, b'Form too large.')
        except asyncio.TimeoutError:
            await self._reply(send, 408, b'Request timed out.')
        except (ValueError, UnicodeError):
            await self._reply(send, 400, b'Invalid form.')
        return None

    async def _login(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if not self._same_origin(scope, required=True):
            await self._reply(send, 403, b'Same-origin sign-in required.')
            return
        if not self._allow_login(scope):
            await self._reply(send, 429, _login_html('Too many sign-in attempts. Please wait a minute.', dark=self._is_dark()), headers=[(b'retry-after', b'60')], html=True)
            return
        form = await self._form_or_error(scope, receive, send)
        if form is None:
            return
        username, password = form.get('username', ''), form.get('password', '')
        if set(form) != {'username', 'password'} or not username or not password or len(username) > 128 or len(password) > 1024:
            await self._reply(send, 400, _login_html('Invalid sign-in form.', dark=self._is_dark()), html=True)
            return
        try:
            account = await self._run_auth_work(self.store.authenticate, username, password)
        except AuthBusyError:
            await self._reply(send, 429, b'Sign-in busy. Try again shortly.', headers=[(b'retry-after', b'5')])
            return
        except Exception:
            account = None
        if not isinstance(account, dict) or not account.get('username') or not account.get('revision'):
            await self._reply(send, 401, _login_html('Username or password not accepted.', dark=self._is_dark()), html=True)
            return
        token = secrets.token_urlsafe(32)
        self._refresh_session_policy()
        now = self._clock()
        for old_token, session in list(self._sessions.items()):
            if session.expires <= now:
                self._sessions.pop(old_token, None)
        prior = self._cookie_session(scope)
        if prior:
            self._sessions.pop(prior[0], None)
        while len(self._sessions) >= MAX_SESSIONS:
            self._sessions.popitem(last=False)
        expires = now + self._session_seconds if self._session_seconds else float('inf')
        self._sessions[token] = _Session(str(account['username']), str(account['revision']), expires)
        await self._reply(send, 303, headers=[(b'location', b'/'), (b'set-cookie', self._session_cookie(scope, token))])

    async def _setup(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        try:
            has_users = await asyncio.to_thread(self.store.has_users)
        except Exception:
            await self._reply(send, 503, b'Account storage unavailable. Check the local settings folder.')
            return
        if has_users or not self._setup_code:
            await self._reply(send, 404, b'Setup is not available.')
            return
        method = str(scope.get('method', 'GET')).upper()
        if method == 'GET':
            await self._reply(send, 200, _setup_html(dark=self._is_dark()), html=True)
            return
        if method != 'POST':
            await self._reply(send, 405, b'Method not allowed.', headers=[(b'allow', b'GET, POST')])
            return
        if not self._same_origin(scope, required=True):
            await self._reply(send, 403, b'Same-origin setup required.')
            return
        if not self._allow_login(scope):
            await self._reply(send, 429, b'Too many attempts. Please wait a minute.', headers=[(b'retry-after', b'60')])
            return
        form = await self._form_or_error(scope, receive, send)
        if form is None:
            return
        supplied = form.get('setup_code', '')
        if not hmac.compare_digest(supplied.encode('utf-8'), self._setup_code.encode('utf-8')):
            await self._reply(send, 403, _setup_html('Setup code not accepted.', dark=self._is_dark()), html=True)
            return
        username, password = form.get('username', ''), form.get('password', '')
        if set(form) != {'setup_code', 'username', 'password', 'confirmation'} or password != form.get('confirmation'):
            await self._reply(send, 400, _setup_html('Complete all fields and enter matching passwords.', dark=self._is_dark()), html=True)
            return
        try:
            await self._run_auth_work(self.store.add_first_user, username, password)
        except AuthBusyError:
            await self._reply(send, 429, b'Setup busy. Try again shortly.', headers=[(b'retry-after', b'5')])
            return
        except asyncio.TimeoutError:
            await self._reply(send, 503, b'Setup is still processing. Check whether sign-in is available before trying setup again.')
            return
        except Exception:
            await self._reply(send, 400, _setup_html('Could not create the account. Use a valid username and a non-empty password of at most 1024 characters; setup may already be complete.', dark=self._is_dark()), html=True)
            return
        self._setup_code = ''
        await self._reply(send, 303, headers=[(b'location', b'/login')])

    async def _websocket(self, scope: dict[str, Any], receive: Any, send: Any,
                         token: str, session: _Session) -> None:
        revoked = asyncio.Event()
        closed = False
        async def check() -> None:
            if not await self._valid_session(token, session):
                revoked.set()
                raise _SessionRevoked()
        async def guarded_receive() -> dict[str, Any]:
            await check()
            event = await receive()
            await check()
            return event
        async def guarded_send(event: dict[str, Any]) -> None:
            nonlocal closed
            await check()
            await send(event)
            if event.get('type') == 'websocket.close':
                closed = True
        async def watch() -> None:
            while not revoked.is_set():
                try:
                    await asyncio.wait_for(revoked.wait(), REVOCATION_POLL_SECONDS)
                except asyncio.TimeoutError:
                    if not await self._valid_session(token, session):
                        revoked.set()
        app_task = asyncio.create_task(self.app(scope, guarded_receive, guarded_send))
        guard_task = asyncio.create_task(watch())
        try:
            await asyncio.wait({app_task, guard_task}, return_when=asyncio.FIRST_COMPLETED)
            if revoked.is_set():
                if not closed:
                    await send({'type': 'websocket.close', 'code': 4401, 'reason': 'Sign-in expired or account changed'})
            elif app_task.done():
                await app_task
        except _SessionRevoked:
            if not closed:
                await send({'type': 'websocket.close', 'code': 4401, 'reason': 'Sign-in expired or account changed'})
        finally:
            for task in (app_task, guard_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(app_task, guard_task, return_exceptions=True)

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        kind = str(scope.get('type') or '')
        if kind not in {'http', 'websocket'}:
            await self.app(scope, receive, send)
            return
        path = str(scope.get('path') or '')
        method = str(scope.get('method') or 'GET').upper()
        # Target displays run in an opaque-origin sandbox, which deliberately
        # cannot carry this controller's login cookie. Only this exact scoped
        # route delegates authentication to its captured AccountSession. It
        # validates the session, registered workspace and enabled target on
        # every HTTP request and throughout the display websocket lifetime.
        # No other HarnessyXO API accepts opaque/null-origin requests.
        if path.startswith('/api/harnessy/target-view/'):
            from ..ui.target_views import delegated_target_view_path
            if delegated_target_view_path(path):
                await self.app(scope, receive, send)
                return
        if kind == 'http' and path == '/setup':
            await self._setup(scope, receive, send)
            return
        if kind == 'http' and path == '/login':
            try:
                has_users = await asyncio.to_thread(self.store.has_users)
            except Exception:
                await self._reply(send, 503, b'Account storage unavailable.')
                return
            if not has_users:
                await self._reply(send, 303, headers=[(b'location', b'/setup')])
            elif method == 'GET':
                await self._reply(send, 200, _login_html(password_changed=scope.get('query_string') == b'notice=password_changed', dark=self._is_dark()), html=True)
            elif method == 'POST':
                await self._login(scope, receive, send)
            else:
                await self._reply(send, 405, b'Method not allowed.', headers=[(b'allow', b'GET, POST')])
            return
        if not self._same_origin(scope, required=kind == 'websocket' or method not in {'GET', 'HEAD', 'OPTIONS'}):
            if kind == 'websocket':
                await send({'type': 'websocket.close', 'code': 4403, 'reason': 'Same-origin connection required'})
            else:
                await self._reply(send, 403, b'Same-origin request required.')
            return
        found = self._cookie_session(scope)
        authorized = bool(found and await self._valid_session(*found))
        if not authorized:
            if kind == 'websocket':
                await send({'type': 'websocket.close', 'code': 4401, 'reason': 'Sign-in required'})
            elif path == '/__harnessy_session':
                # Browser-owned recovery must work after the protected socket
                # has closed, without clearing a newer login's cookie or ever
                # mistaking a login-page redirect for a valid session.
                await self._reply(send, 401, b'Sign-in required.')
            elif method == 'GET' and (path == '/' or b'text/html' in self._headers(scope).get(b'accept', b'')):
                location = b'/login'
                try:
                    if not await asyncio.to_thread(self.store.has_users):
                        location = b'/setup'
                except Exception:
                    await self._reply(send, 503, b'Account storage unavailable.')
                    return
                await self._reply(send, 303, headers=[(b'location', location)])
            else:
                await self._reply(send, 401, b'Sign-in required. Open /login in your browser.')
            return
        assert found is not None
        token, session = found
        if kind == 'http' and path == '/__harnessy_session':
            if method in {'GET', 'HEAD'}:
                # Refresh only an authenticated cookie, never a server deadline.
                # In particular, an unauthorized probe must not clear or replace
                # a newer browser login's cookie.
                await self._reply(send, 204, headers=[(b'set-cookie', self._session_cookie(scope, token))])
            else:
                await self._reply(send, 405, b'Method not allowed.', headers=[(b'allow', b'GET, HEAD')])
            return
        if kind == 'http' and path == '/logout':
            if method == 'POST':
                self._sessions.pop(token, None)
                await self._reply(send, 303, headers=[(b'location', b'/login'), (b'set-cookie', self._session_cookie(scope, '', clear=True))])
            elif method == 'GET':
                await self._reply(send, 200, _logout_html(dark=self._is_dark()), html=True)
            else:
                await self._reply(send, 405, b'Method not allowed.', headers=[(b'allow', b'GET, POST')])
            return
        scope.setdefault('state', {})['harnessy_username'] = session.username
        # Server-only, request-bound capability for native Settings callbacks.
        # Every operation revalidates this session, never a browser-supplied role.
        if kind == 'http' and path == '/':
            from .auth_account_service import AccountSession
            scope['state']['harnessy_accounts'] = AccountSession(self, scope, token, session)
        if kind == 'http' and path in {'/users', '/password'}:
            from .auth_account_routes import handle_account_route
            if await handle_account_route(scope, receive, send, auth=self, username=session.username):
                return
        if kind == 'websocket':
            await self._websocket(scope, receive, send, token, session)
        else:
            await self.app(scope, receive, send)
