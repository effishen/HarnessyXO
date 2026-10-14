"""Session-bound, isolated browser access to managed test VM displays.

The LuCI proxy is deliberately a capability endpoint: its opaque-origin iframe
cannot send the controller's SameSite login cookie. The login gate delegates
only the exact route below; the captured server-side AccountSession remains
authoritative on every request. Guest HTML never shares the controller origin.
"""
from __future__ import annotations

import asyncio
import html
import json
import logging
import re
import secrets
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import httpx
from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse, Response
from starlette.websockets import WebSocket, WebSocketDisconnect

from harnessy.diagnostics import log_event

PREFIX = '/api/harnessy/target-view/'
_TOKEN = re.compile(r'^[a-f0-9]{64}$')
_LEASE_PATH = re.compile(r'^/api/harnessy/target-view/[a-f0-9]{64}/(?:web(?:/.*)?|vnc(?:/.*)?|assets/.*)$')
_ASSETS = Path(__file__).with_name('target_view_assets') / 'novnc'
_LEASES: dict[str, 'TargetViewHandle'] = {}
_MACHINE: Any = None
_PRUNER_TASK: asyncio.Task | None = None
_MAX_BODY = 16 * 1024 * 1024
_MAX_RESPONSE = 32 * 1024 * 1024
_SAFE_HEADERS = {'accept', 'content-type', 'x-requested-with', 'range', 'if-none-match', 'if-modified-since'}
_ALLOWED_METHODS = {'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'}


class _HideViewPaths(logging.Filter):
    """Uvicorn's optional access log must not persist display capabilities."""
    @staticmethod
    def clean(value: Any) -> Any:
        if isinstance(value, str):
            return re.sub(r'''/api/harnessy/target-view/[a-f0-9]{64}[^\s"'<>]*''',
                          '/api/harnessy/target-view/<view>', value)
        return value

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self.clean(record.msg)
        if isinstance(record.args, tuple):
            record.args = tuple(self.clean(item) for item in record.args)
        elif isinstance(record.args, dict):
            record.args = {key: self.clean(value) for key, value in record.args.items()}
        return True


def delegated_target_view_path(path: str) -> bool:
    """Exact login-middleware delegation; never a general API prefix bypass."""
    return bool(_LEASE_PATH.fullmatch(path))


@dataclass(repr=False)
class TargetViewHandle:
    token: str
    manager: Any
    username: str
    accounts: Any
    kind: str
    port: int
    release: Any
    client: httpx.AsyncClient
    closed: bool = False
    created: float = field(default_factory=time.monotonic)
    tasks: set[asyncio.Task] = field(default_factory=set)
    slots: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(6))
    verified_at: float = 0.0
    verification_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    @property
    def iframe_url(self) -> str:
        return f'{PREFIX}{self.token}/' + ('web/' if self.kind == 'web' else 'vnc/')

    @property
    def sandbox(self) -> str:
        # Even the first-party VNC viewer needs no origin privileges. CORS and
        # the session-bound capability route also protect its ES modules/socket.
        return 'allow-scripts allow-forms' if self.kind == 'web' else 'allow-scripts'

    @property
    def active(self) -> bool:
        try:
            return not self.closed and bool(self.accounts._active())
        except Exception:
            return False

    async def authorized(self) -> bool:
        if not self.active:
            self.close()
            return False
        try:
            await self.accounts._require_session()
            if str(self.accounts.username) != self.username:
                raise ValueError('Account changed')
            reg = _MACHINE.get_workspace(self.manager.workspace.id) if _MACHINE is not None else None
            if reg is None or Path(reg.path).resolve() != self.manager.workspace.root.resolve():
                raise ValueError('Workspace unavailable')
            target = await asyncio.to_thread(self.manager.workspace.get_external_target, self.manager.target.id)
            # enabled controls model access, not the human's own VM console.
            if not target or target.managed_vm != self.manager.target.managed_vm:
                raise ValueError('Target unavailable')
            # Native VM checks are shared across parallel assets/display frames.
            # A dead guest or changed forwarded port must never silently turn
            # this lease into a proxy to a later, unrelated loopback service.
            if time.monotonic() - self.verified_at >= 1:
                async with self.verification_lock:
                    if time.monotonic() - self.verified_at >= 1:
                        status = await asyncio.wait_for(self.manager.status(), 5)
                        info = await asyncio.wait_for(asyncio.to_thread(self.manager.desktop_info), 5)
                        if not status.get('running') or int(info['port']) != self.port:
                            raise ValueError('Display generation changed')
                        self.verified_at = time.monotonic()
            if not self.active:
                self.close()
                return False
            return True
        except Exception:
            self.close()
            return False

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        _LEASES.pop(self.token, None)
        self.release()
        try:
            current = asyncio.current_task()
        except RuntimeError:
            current = None
        for task in tuple(self.tasks):
            if task is not current and not task.done():
                task.cancel()
        try:
            asyncio.get_running_loop().create_task(self.client.aclose())
        except RuntimeError:
            pass

    async def aclose(self) -> None:
        self.close()
        await self.client.aclose()


async def create_target_view(manager: Any, username: str, accounts: Any) -> TargetViewHandle:
    """Open one fixed managed display; callers cannot supply a host or port."""
    if accounts is None or not username or str(getattr(accounts, 'username', '')) != username:
        raise RuntimeError('Sign in again before opening this test target.')
    await accounts._require_session()
    if manager.busy or not (await manager.status()).get('running'):
        raise RuntimeError('Start this test target and wait until it is ready.')
    info = await asyncio.to_thread(manager.desktop_info)
    kind = 'web' if info.get('kind') == 'web' else 'vnc'
    try:
        port = int(info['port'])
        address = urlsplit(str(info['url']))
        if not 1024 <= port <= 65535 or address.hostname != '127.0.0.1' or address.port != port:
            raise ValueError()
        if address.username or address.password or address.scheme != ('http' if kind == 'web' else 'vnc'):
            raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise RuntimeError('The test target did not provide a valid local display address.') from None
    # Bound abandoned browser leases, including ones whose pages vanished before
    # a close callback. Existing handles keep their original authenticated owner.
    for item in tuple(_LEASES.values()):
        if not item.active:
            item.close()
    if len(_LEASES) >= 64:
        raise RuntimeError('Too many test target views are open. Close an existing view first.')
    # No await separates this second busy check from acquiring the human-view
    # lease. A destructive operation could have begun during status/info reads.
    if manager.busy:
        raise RuntimeError('Wait for the current test target operation to finish.')
    handle = TargetViewHandle(
        token=secrets.token_hex(32), manager=manager, username=username, accounts=accounts,
        kind=kind, port=port, release=manager.acquire(),
        client=httpx.AsyncClient(trust_env=False, follow_redirects=False,
            timeout=httpx.Timeout(30, connect=5, pool=5),
            limits=httpx.Limits(max_connections=6, max_keepalive_connections=3)),
    )
    _LEASES[handle.token] = handle
    try:
        if not await handle.authorized():
            raise RuntimeError('This test target is no longer available in the signed-in workspace.')
    except BaseException:
        await handle.aclose()
        raise
    return handle


async def close_target_views() -> None:
    global _PRUNER_TASK
    pruner, _PRUNER_TASK = _PRUNER_TASK, None
    if pruner is not None and not pruner.done():
        pruner.cancel()
        await asyncio.gather(pruner, return_exceptions=True)
    await asyncio.gather(*(item.aclose() for item in tuple(_LEASES.values())), return_exceptions=True)


async def _start_pruner() -> None:
    global _PRUNER_TASK
    if _PRUNER_TASK is not None and not _PRUNER_TASK.done():
        return
    async def prune():
        while True:
            for item in tuple(_LEASES.values()):
                if not item.active:
                    item.close()
            await asyncio.sleep(2)
    _PRUNER_TASK = asyncio.create_task(prune(), name='harnessy-target-view-pruner')


def close_manager_views(manager_key: str) -> None:
    """Backend lifecycle hook: invalidate displays before VM state changes."""
    for item in tuple(_LEASES.values()):
        if str(getattr(item.manager, 'key', '')) == str(manager_key):
            item.close()


def _view_failure(handle: TargetViewHandle, code: str) -> None:
    # Fixed fields only: no display capability, URL, guest body or credentials.
    family = str(getattr(getattr(handle.manager, 'guest', None), 'family', ''))
    log_event('harnessy', 'test_target_view_failed', target_id=str(handle.manager.target.id),
              workspace_id=str(handle.manager.workspace.id),
              target_backend='qemu' if family == 'openwrt' or handle.kind == 'web' else 'lima',
              target_action='desktop', target_stage=handle.kind + '_transport',
              target_outcome='failed', target_interface=handle.kind, target_view_failure_code=code)


def _headers(*, origin: str = '', web: bool = False, base: str = '') -> dict[str, str]:
    result = {
        'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
        'X-Content-Type-Options': 'nosniff', 'Access-Control-Allow-Origin': 'null',
        # LuCI sets xhr.withCredentials=true for ubus. The scoped endpoint
        # still authenticates solely via its captured session capability;
        # controller Cookie headers are never sent to the guest.
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Methods': ', '.join(sorted(_ALLOWED_METHODS)),
        'Access-Control-Allow-Headers': ', '.join(sorted(_SAFE_HEADERS)),
        'Cross-Origin-Resource-Policy': 'cross-origin', 'Vary': 'Origin',
    }
    if web:
        source = origin + base
        result['Content-Security-Policy'] = (
            "default-src 'none'; script-src 'unsafe-inline' 'unsafe-eval' " + source + '; '
            "style-src 'unsafe-inline' " + source + '; img-src data: blob: ' + source + '; '
            'font-src data: ' + source + '; connect-src ' + source + '; form-action ' + source + '; '
            "frame-src 'none'; object-src 'none'; base-uri " + source + '; '
            "frame-ancestors 'self'; sandbox allow-scripts allow-forms"
        )
    return result


def _safe_path(path: str) -> str:
    if len(path) > 4096 or '\\' in path or '\x00' in path or path.startswith('/'):
        raise ValueError('Invalid target path')
    decoded = path
    for _ in range(3):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    if '\\' in decoded or '\x00' in decoded or any(p in {'.', '..'} for p in decoded.split('/')):
        raise ValueError('Invalid target path')
    return path


def _rewrite_location(value: str, base: str, port: int) -> str:
    parts = urlsplit(value)
    if parts.scheme or parts.netloc:
        if parts.scheme != 'http' or parts.hostname not in {'127.0.0.1', 'localhost'} or parts.port != port:
            raise ValueError('The target redirected outside its own interface')
        value = parts.path + ('?' + parts.query if parts.query else '') + ('#' + parts.fragment if parts.fragment else '')
    if value.startswith('//') or '\\' in value:
        raise ValueError('Invalid target redirect')
    if value.startswith('/'):
        return base + value.lstrip('/')
    _safe_path(value.split('?', 1)[0].split('#', 1)[0])
    return value


def _scope_url(value: str, base: str, port: int) -> str:
    if value.startswith(base):
        return value
    for host in ('127.0.0.1', 'localhost'):
        if value.startswith(f'http://{host}:{port}/'):
            return base + value.split('/', 3)[3]
    return base + value.lstrip('/') if value.startswith('/') and not value.startswith('//') else value


def _rewrite_css(text: str, base: str, port: int) -> str:
    def url(match):
        quote, value = match.group(1), match.group(2)
        return 'url(' + quote + _scope_url(value, base, port) + quote + ')'
    text = re.sub(r"""url\(\s*(['"]?)([^)'"\s]+)\1\s*\)""", url, text, flags=re.I)
    return re.sub(r"""(@import\s+)(['"])([^'"]+)\2""",
        lambda m: m.group(1) + m.group(2) + _scope_url(m.group(3), base, port) + m.group(2), text, flags=re.I)


class _ScopedHTML(HTMLParser):
    """Rewrite URL-valued HTML attributes, preserving all guest script bytes."""
    def __init__(self, base: str, port: int):
        super().__init__(convert_charrefs=False)
        self.base, self.port, self.output = base, port, []
        self.in_style = False

    def _tag(self, tag, attrs, closed=False):
        if tag.lower() == 'base':
            return
        parts = ['<' + tag]
        for key, value in attrs:
            if value is None:
                parts.append(' ' + key)
                continue
            if key.lower() in {'href', 'src', 'action', 'formaction', 'poster', 'background', 'xlink:href'}:
                value = _scope_url(value, self.base, self.port)
            elif key.lower() == 'style':
                value = _rewrite_css(value, self.base, self.port)
            parts.append(' ' + key + '="' + html.escape(value, quote=True) + '"')
        parts.append('/>' if closed else '>')
        self.output.append(''.join(parts))
    def handle_starttag(self, tag, attrs):
        self._tag(tag, attrs)
        if tag.lower() == 'style':
            self.in_style = True
    def handle_startendtag(self, tag, attrs):
        self._tag(tag, attrs, True)
    def handle_endtag(self, tag):
        if tag.lower() != 'base':
            self.output.append('</' + tag + '>')
        if tag.lower() == 'style':
            self.in_style = False
    def handle_data(self, data):
        self.output.append(_rewrite_css(data, self.base, self.port) if self.in_style else data)
    def handle_entityref(self, name):
        self.output.append('&' + name + ';')
    def handle_charref(self, name):
        self.output.append('&#' + name + ';')
    def handle_comment(self, data):
        self.output.append('<!--' + data + '-->')
    def handle_decl(self, decl):
        self.output.append('<!' + decl + '>')
    def handle_pi(self, data):
        self.output.append('<?' + data + '>')


def _rewrite_text(text: str, base: str, port: int, *, is_html: bool = False, is_css: bool = False) -> str:
    if is_css:
        return _rewrite_css(text, base, port)
    if not is_html:
        # JavaScript is intentionally unchanged: regex/string substitution can
        # corrupt regex literals. Runtime HTTP and DOM URL hooks scope LuCI's
        # dynamically created RPC requests and module/static resource loads.
        return text
    parser = _ScopedHTML(base, port)
    parser.feed(text)
    parser.close()
    text = ''.join(parser.output)
    # Keep the proxied document's own URL as document.baseURI. Injecting a root
    # <base> would break relative RPC URLs and same-page fragment navigation.
    bootstrap = '<script>' + (
        '(function(){const b=' + json.dumps(base) + ';'
        'const own=new URL(b,location.href);'
        'function scoped(v){const u=new URL(String(v),document.baseURI);'
        'if(u.origin!==own.origin)throw new TypeError("External target request blocked");'
        'if(!u.pathname.startsWith(b)){u.pathname=b+u.pathname.replace(/^\\/+/,"");}'
        'return u.href;}'
        'const f=window.fetch;window.fetch=function(u,o){return f.call(this,u instanceof Request?new Request(scoped(u.url),u):scoped(u),o);};'
        'const x=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u,...a){return x.call(this,m,scoped(u),...a);};'
        'function domURL(n,v){const s=String(v);if((n==="src"||n==="poster")&&/^(data:|blob:)/i.test(s))return s;if(n==="href"&&s.startsWith("#"))return s;return scoped(s);}'
        'for(const [c,p] of [[HTMLScriptElement,"src"],[HTMLLinkElement,"href"],[HTMLImageElement,"src"],[HTMLAnchorElement,"href"],[HTMLFormElement,"action"]]){'
        'const d=Object.getOwnPropertyDescriptor(c.prototype,p);if(d&&d.set)Object.defineProperty(c.prototype,p,{...d,set(v){return d.set.call(this,domURL(p,v));}});}'
        'const a=Element.prototype.setAttribute;Element.prototype.setAttribute=function(n,v){const key=String(n).toLowerCase();if(["src","href","action","formaction","poster"].includes(key))v=domURL(key,v);return a.call(this,n,v);};'
        '})();'
    ) + '</script>'
    match = re.search(r'<head(?:\s[^>]*)?>', text, flags=re.I)
    return text[:match.end()] + bootstrap + text[match.end():] if match else bootstrap + text


async def _get_handle(token: str, kind: str | None = None) -> TargetViewHandle | None:
    handle = _LEASES.get(token) if _TOKEN.fullmatch(token) else None
    if handle is None or (kind is not None and handle.kind != kind) or not await handle.authorized():
        return None
    return handle


async def _proxy_http(request: Request, token: str, path: str) -> Response:
    handle = await _get_handle(token, 'web')
    if handle is None:
        return PlainTextResponse('This target view has closed or sign-in expired.', 401, headers=_headers())
    origin = request.headers.get('origin')
    # A sandboxed document has Origin:null. A top-level same-origin initial
    # navigation has no Origin; reject unrelated sites even if a path leaked.
    expected_origin = str(request.base_url).rstrip('/')
    if origin not in {None, 'null', expected_origin}:
        return PlainTextResponse('Target view origin rejected.', 403, headers=_headers())
    base = f'{PREFIX}{token}/web/'
    headers = _headers(origin=expected_origin, web=True, base=base)
    if request.method not in _ALLOWED_METHODS:
        return PlainTextResponse('Method not allowed.', 405, headers=headers)
    if request.method == 'OPTIONS':
        return Response(status_code=204, headers=headers)
    if len(handle.tasks) >= 12:
        return PlainTextResponse('Too many concurrent target requests.', 429, headers=headers)
    task = asyncio.current_task()
    if task is not None:
        handle.tasks.add(task)
    try:
        _safe_path(path)
        query = request.scope.get('query_string', b'')
        if len(query) > 8192:
            raise ValueError('Query too long')
        async def read_body() -> bytearray:
            data = bytearray()
            async for chunk in request.stream():
                data.extend(chunk)
                if len(data) > _MAX_BODY:
                    raise OverflowError()
            return data
        try:
            data = await asyncio.wait_for(read_body(), 30)
        except OverflowError:
            _view_failure(handle, 'request_size_limit')
            return PlainTextResponse('Target request is too large.', 413, headers=headers)
        upstream = f'http://127.0.0.1:{handle.port}/' + path
        if query:
            upstream += '?' + query.decode('ascii')
        forwarded = {k: v for k, v in request.headers.items() if k.lower() in _SAFE_HEADERS}
        forwarded['accept-encoding'] = 'identity'
        if request.method not in {'GET', 'HEAD'}:
            forwarded['origin'] = f'http://127.0.0.1:{handle.port}'
            forwarded['referer'] = f'http://127.0.0.1:{handle.port}/'
        try:
            await asyncio.wait_for(handle.slots.acquire(), 5)
            try:
                async with handle.client.stream(request.method, upstream, headers=forwarded, content=bytes(data)) as upstream_response:
                    if upstream_response.status_code >= 500:
                        _view_failure(handle, 'web_http_error')
                    # Identity was requested. Reject compressed replies before
                    # httpx decompresses them and defeats the response bound.
                    if upstream_response.headers.get('content-encoding', '').strip().lower() not in {'', 'identity'}:
                        _view_failure(handle, 'compressed_response_rejected')
                        return PlainTextResponse('The target sent an unsupported compressed response.', 502, headers=headers)
                    body = bytearray()
                    async for chunk in upstream_response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > _MAX_RESPONSE:
                            _view_failure(handle, 'response_size_limit')
                            return PlainTextResponse('Target response is too large.', 502, headers=headers)
                    if not await handle.authorized():
                        return PlainTextResponse('This target view has closed or sign-in expired.', 401, headers=_headers())
                    content_type = upstream_response.headers.get('content-type', 'application/octet-stream')
                    headers['Content-Type'] = content_type
                    if 'location' in upstream_response.headers:
                        headers['Location'] = _rewrite_location(upstream_response.headers['location'], base, handle.port)
                    for field_name in ('content-disposition', 'content-range', 'accept-ranges'):
                        if field_name in upstream_response.headers:
                            headers[field_name] = upstream_response.headers[field_name]
                    media = content_type.split(';', 1)[0].lower().strip()
                    if media in {'text/html', 'text/css', 'application/javascript', 'text/javascript'}:
                        if len(body) > 8 * 1024 * 1024:
                            return PlainTextResponse('Target document is too large.', 502, headers=headers)
                        text = bytes(body).decode('utf-8', errors='replace')
                        body = bytearray(_rewrite_text(text, base, handle.port,
                            is_html=media == 'text/html', is_css=media == 'text/css').encode())
                        headers['Content-Type'] = media + '; charset=utf-8'
                    return Response(bytes(body), upstream_response.status_code, headers=headers)
            finally:
                handle.slots.release()
        finally:
            if task is not None:
                handle.tasks.discard(task)
    except (httpx.HTTPError, OSError, ValueError, UnicodeError, asyncio.TimeoutError):
        # Never return httpx exception URLs: they contain the view capability.
        _view_failure(handle, 'web_transport_unavailable')
        return PlainTextResponse('The target web interface is unavailable. Check its status and VM diagnostics.', 502, headers=headers)
    finally:
        if task is not None:
            handle.tasks.discard(task)


def _vnc_document(token: str) -> str:
    base = f'{PREFIX}{token}/'
    return '''<!doctype html><html><head><meta name="referrer" content="no-referrer"><meta charset="utf-8">
<style>html,body,#screen{height:100%;margin:0;background:#16191d;color:#eee;font:14px sans-serif}#bar{height:32px;display:flex;align-items:center;padding:0 8px;gap:12px}#screen{height:calc(100% - 32px)}button{cursor:pointer}</style></head><body>
<div id="bar"><span id="status">Connecting to test VM display…</span><button id="ctrl">Ctrl+Alt+Delete</button></div><div id="screen"></div>
<script type="module">
import RFB from "''' + base + '''assets/core/rfb.js";
import {initLogging} from "''' + base + '''assets/core/util/logging.js";initLogging('none');
const status=document.querySelector('#status');
const u=new URL("''' + base + '''vnc/socket",location.href);u.protocol=location.protocol==='https:'?'wss:':'ws:';
const rfb=new RFB(document.querySelector('#screen'),u.href);rfb.scaleViewport=true;rfb.resizeSession=false;
rfb.addEventListener('connect',()=>status.textContent='Connected to test VM display');
rfb.addEventListener('disconnect',()=>status.textContent='Display disconnected. Close and reopen this tab to reconnect.');
rfb.addEventListener('credentialsrequired',async()=>{try{const r=await fetch("''' + base + '''vnc/credentials",{credentials:'omit'});if(!r.ok)throw 0;rfb.sendCredentials(await r.json());}catch(_){status.textContent='Sign in again and reopen this display.';}});
document.querySelector('#ctrl').onclick=()=>rfb.sendCtrlAltDel();
</script></body></html>'''


async def _vnc_socket(websocket: WebSocket, token: str) -> None:
    handle = await _get_handle(token, 'vnc')
    if handle is None or websocket.headers.get('origin') != 'null':
        await websocket.close(code=4401)
        return
    reader = writer = None
    tasks: list[asyncio.Task] = []
    owner = asyncio.current_task()
    if owner:
        handle.tasks.add(owner)
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection('127.0.0.1', handle.port, limit=256 * 1024), 5)
        await websocket.accept(subprotocol='binary' if 'binary' in websocket.headers.get('sec-websocket-protocol', '').split(',') else None)
        async def from_vm():
            while True:
                chunk = await reader.read(64 * 1024)
                if not chunk:
                    if not handle.closed:
                        _view_failure(handle, 'vnc_transport_unavailable')
                    return
                # The guard below performs full session/VM validation every
                # two seconds. Per-frame checks stay in memory so a busy VNC
                # screen cannot launch hundreds of account/SQLite probes.
                if not handle.active:
                    return
                await asyncio.wait_for(websocket.send_bytes(chunk), 30)
        async def to_vm():
            while True:
                event = await websocket.receive()
                if event['type'] == 'websocket.disconnect':
                    return
                data = event.get('bytes')
                if data is None or len(data) > 1024 * 1024 or not handle.active:
                    return
                writer.write(data)
                await asyncio.wait_for(writer.drain(), 30)
        async def guard():
            while await handle.authorized():
                await asyncio.sleep(2)
        tasks = [asyncio.create_task(f()) for f in (from_vm, to_vm, guard)]
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    except (OSError, asyncio.TimeoutError, WebSocketDisconnect, RuntimeError):
        if not handle.closed:
            _view_failure(handle, 'vnc_transport_unavailable')
        pass
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if writer:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 2)
            except (OSError, asyncio.TimeoutError):
                pass
        if owner:
            handle.tasks.discard(owner)
        try:
            await websocket.close()
        except RuntimeError:
            pass


def register_target_view_routes(app: Any, machine: Any, user_store: Any = None) -> None:
    global _MACHINE
    _MACHINE = machine
    from harnessy.environment.test_targets import register_target_view_cleanup
    register_target_view_cleanup(close_manager_views)
    route = PREFIX + '{token}/web/{path:path}'
    if any(getattr(item, 'path', '') == route for item in app.routes):
        return
    for name in ('uvicorn.access', 'uvicorn.error'):
        logger = logging.getLogger(name)
        if not any(isinstance(item, _HideViewPaths) for item in logger.filters):
            logger.addFilter(_HideViewPaths())
    app.add_api_route(route, _proxy_http, methods=sorted(_ALLOWED_METHODS))

    @app.get(PREFIX + '{token}/vnc/')
    async def vnc_page(token: str):
        if await _get_handle(token, 'vnc') is None:
            return PlainTextResponse('This target view has closed or sign-in expired.', 401, headers=_headers())
        return HTMLResponse(_vnc_document(token), headers=_headers())

    @app.get(PREFIX + '{token}/vnc/credentials')
    async def vnc_credentials(token: str, request: Request):
        handle = await _get_handle(token, 'vnc')
        if handle is None or request.headers.get('origin') != 'null':
            return PlainTextResponse('This target view has closed or sign-in expired.', 401, headers=_headers())
        from starlette.responses import JSONResponse
        info = await asyncio.to_thread(handle.manager.desktop_info)
        return JSONResponse({'username': str(info.get('username', '')), 'password': str(info.get('password', ''))}, headers=_headers())

    @app.get(PREFIX + '{token}/assets/{path:path}')
    async def vnc_asset(token: str, path: str):
        if await _get_handle(token, 'vnc') is None:
            return PlainTextResponse('This target view has closed or sign-in expired.', 401, headers=_headers())
        try:
            _safe_path(path)
            target = (_ASSETS / path).resolve()
            if _ASSETS.resolve() not in target.parents or not target.is_file() or target.suffix not in {'.js'}:
                raise ValueError()
            return Response(await asyncio.to_thread(target.read_bytes), media_type='application/javascript', headers=_headers())
        except (OSError, ValueError):
            return PlainTextResponse('Display asset not found.', 404, headers=_headers())

    app.add_api_websocket_route(PREFIX + '{token}/vnc/socket', _vnc_socket)
    if hasattr(app, 'on_startup'):
        app.on_startup(_start_pruner)
    else:
        app.router.add_event_handler('startup', _start_pruner)
    app.on_shutdown(close_target_views)
