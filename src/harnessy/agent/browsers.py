from __future__ import annotations

import asyncio
import os
import platform
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .web_access import WebAccessError, _normalize_url, _validate_url_target


@dataclass(slots=True)
class BrowserSession:
    id: str
    workspace_key: str
    browser: Any
    context: Any
    page: Any
    headless: bool
    created_at: float
    last_used_at: float
    launch_source: str


class BrowserSessionManager:
    """Runtime-owned Playwright browser sessions, isolated by workspace.

    The Playwright import and browser launch are lazy so HarnessyXO can still
    start and use non-browser tools if Playwright or a browser executable is
    unavailable. Each HarnessyXO session owns a fresh browser context, so cookies,
    local storage, cache state, and permissions do not bleed between sessions.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, BrowserSession] = {}
        self._playwright: Any | None = None
        self._lock = asyncio.Lock()

    @staticmethod
    def _now() -> float:
        return time.monotonic()

    @staticmethod
    def _is_blank_url(url: str) -> bool:
        value = str(url or '').strip().lower()
        return value == 'about:blank' or value.startswith('about:blank#')

    async def _validate_public_network_url(self, url: str) -> None:
        value = str(url or '').strip()
        parsed = urlparse(value)
        scheme = parsed.scheme.lower()
        if scheme in {'http', 'https'}:
            normalized = _normalize_url(value)
        elif scheme in {'ws', 'wss'}:
            translated = ('https' if scheme == 'wss' else 'http') + '://' + value.split('://', 1)[1]
            normalized = _normalize_url(translated)
        else:
            raise WebAccessError('Browser automation only permits public http/https destinations.')
        try:
            await _validate_url_target(normalized, allow_private=False)
        except WebAccessError as exc:
            raise WebAccessError('Browser automation blocks host/local/private/reserved network destinations.') from exc

    async def _validate_top_level_url(self, url: str) -> None:
        if self._is_blank_url(url):
            return
        await self._validate_public_network_url(url)

    async def _assert_page_safe(self, session: BrowserSession) -> None:
        current = str(getattr(session.page, 'url', '') or '')
        if self._is_blank_url(current):
            return
        await self._validate_public_network_url(current)

    async def _install_network_guard(self, context: Any) -> None:
        # Browser automation is a host-side HarnessyXO service, so it must never
        # become a side door to localhost, HarnessyXO's own HTTP API, host files,
        # metadata services, or other private networks. Guard every HTTP request
        # (including redirects/subresources), not just browser_open's first URL.
        if hasattr(context, 'route'):
            async def route_handler(route: Any, request: Any) -> None:
                url = str(getattr(request, 'url', '') or '')
                scheme = urlparse(url).scheme.lower()
                if scheme in {'data', 'blob', 'about'}:
                    await route.continue_()
                    return
                try:
                    await self._validate_public_network_url(url)
                except Exception:
                    await route.abort('blockedbyclient')
                    return
                await route.continue_()
            await context.route('**/*', route_handler)

        # Playwright 1.48+ can route WebSockets separately. Without an explicit
        # connect_to_server call a routed socket stays mocked and cannot reach
        # the host/private network.
        if hasattr(context, 'route_web_socket'):
            async def websocket_handler(ws: Any) -> None:
                try:
                    await self._validate_public_network_url(str(getattr(ws, 'url', '') or ''))
                except Exception:
                    close = getattr(ws, 'close', None)
                    if close is not None:
                        result = close(code=1008, reason='Blocked by HarnessyXO public-network guard')
                        if hasattr(result, '__await__'):
                            await result
                    return
                ws.connect_to_server()
            await context.route_web_socket('**/*', websocket_handler)

    async def _ensure_playwright(self) -> Any:
        if self._playwright is not None:
            return self._playwright
        async with self._lock:
            if self._playwright is not None:
                return self._playwright
            try:
                from playwright.async_api import async_playwright
            except ModuleNotFoundError as exc:
                raise RuntimeError(
                    'Browser automation requires Playwright. Run python3 run.py so HarnessyXO can install its dependencies.'
                ) from exc
            self._playwright = await async_playwright().start()
            return self._playwright

    @staticmethod
    def _system_browser_candidates() -> list[Path]:
        system = platform.system().lower()
        candidates: list[Path] = []
        if system == 'darwin':
            candidates.extend([
                Path('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'),
                Path('/Applications/Chromium.app/Contents/MacOS/Chromium'),
                Path('/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge'),
            ])
        elif system == 'windows':
            roots = [os.environ.get('PROGRAMFILES'), os.environ.get('PROGRAMFILES(X86)'), os.environ.get('LOCALAPPDATA')]
            for root in [r for r in roots if r]:
                base = Path(root)
                candidates.extend([
                    base / 'Google/Chrome/Application/chrome.exe',
                    base / 'Microsoft/Edge/Application/msedge.exe',
                ])
        else:
            candidates.extend([
                Path('/usr/bin/google-chrome'), Path('/usr/bin/google-chrome-stable'),
                Path('/usr/bin/chromium'), Path('/usr/bin/chromium-browser'),
                Path('/usr/bin/microsoft-edge'), Path('/usr/bin/microsoft-edge-stable'),
            ])
        return [p for p in candidates if p.is_file()]

    async def _launch(self, *, headless: bool) -> tuple[Any, str]:
        playwright = await self._ensure_playwright()
        errors: list[str] = []

        # Prefer the Playwright-managed Chromium build when it is available.
        try:
            browser = await playwright.chromium.launch(headless=headless)
            return browser, 'playwright-chromium'
        except Exception as exc:
            errors.append(f'Playwright Chromium: {exc}')

        # Portable HarnessyXO installations may not have downloaded the large
        # Playwright browser bundle. Reuse a normal local browser when possible.
        for channel in ('chrome', 'msedge'):
            try:
                browser = await playwright.chromium.launch(channel=channel, headless=headless)
                return browser, f'channel:{channel}'
            except Exception as exc:
                errors.append(f'{channel}: {exc}')

        for executable in self._system_browser_candidates():
            try:
                browser = await playwright.chromium.launch(executable_path=str(executable), headless=headless)
                return browser, str(executable)
            except Exception as exc:
                errors.append(f'{executable}: {exc}')

        tail = '\n'.join(errors[-3:])
        raise RuntimeError(
            'HarnessyXO could not launch a Chromium-compatible browser. Install Chrome/Chromium/Edge, '
            'or install Playwright Chromium with `python -m playwright install chromium`.'
            + (f'\nLaunch attempts:\n{tail}' if tail else '')
        )

    def _require(self, *, workspace_key: str, session_id: str) -> BrowserSession:
        session = self._sessions.get(session_id)
        if session is None or session.workspace_key != workspace_key:
            raise ValueError(f'Unknown browser session for this workspace: {session_id}')
        session.last_used_at = self._now()
        return session

    def owns(self, *, workspace_key: str, session_id: str) -> bool:
        session = self._sessions.get(session_id)
        return bool(session is not None and session.workspace_key == workspace_key)

    async def open(
        self,
        *,
        workspace_key: str,
        url: str,
        session_id: str | None = None,
        headless: bool = True,
        wait_until: str = 'domcontentloaded',
        timeout_seconds: float = 30.0,
    ) -> dict[str, Any]:
        url = str(url or '').strip()
        if not url:
            raise ValueError('url must not be empty')
        if len(url) > 100_000:
            raise ValueError('url is too long')
        wait_until = str(wait_until or 'domcontentloaded').lower()
        if wait_until not in {'commit', 'domcontentloaded', 'load', 'networkidle'}:
            raise ValueError('wait_until must be commit, domcontentloaded, load, or networkidle')
        timeout_ms = max(100, min(int(float(timeout_seconds) * 1000), 120_000))
        await self._validate_top_level_url(url)

        created = False
        if session_id:
            session = self._require(workspace_key=workspace_key, session_id=session_id)
        else:
            browser, launch_source = await self._launch(headless=bool(headless))
            try:
                context = await browser.new_context()
                await self._install_network_guard(context)
                page = await context.new_page()
            except Exception:
                await browser.close()
                raise
            session_id = uuid.uuid4().hex
            now = self._now()
            session = BrowserSession(
                id=session_id,
                workspace_key=workspace_key,
                browser=browser,
                context=context,
                page=page,
                headless=bool(headless),
                created_at=now,
                last_used_at=now,
                launch_source=launch_source,
            )
            self._sessions[session_id] = session
            created = True

        try:
            response = await session.page.goto(url, wait_until=wait_until, timeout=timeout_ms)
            await self._assert_page_safe(session)
            title = await session.page.title()
            return {
                'ok': True,
                'session_id': session.id,
                'created_session': created,
                'headless': session.headless,
                'launch_source': session.launch_source,
                'url': session.page.url,
                'title': title,
                'http_status': getattr(response, 'status', None) if response is not None else None,
            }
        except BaseException:
            if created:
                # __aenter__/tool cancellation can arrive while the first
                # navigation is in flight. Close a newly-created session before
                # propagating so Stop does not leave Chromium running.
                try:
                    await asyncio.shield(self.close(workspace_key=workspace_key, session_id=session.id))
                except Exception:
                    pass
            raise

    async def click(
        self,
        *,
        workspace_key: str,
        session_id: str,
        selector: str,
        button: str = 'left',
        click_count: int = 1,
        timeout_seconds: float = 15.0,
    ) -> dict[str, Any]:
        session = self._require(workspace_key=workspace_key, session_id=session_id)
        selector = str(selector or '').strip()
        if not selector:
            raise ValueError('selector must not be empty')
        if button not in {'left', 'right', 'middle'}:
            raise ValueError('button must be left, right, or middle')
        timeout_ms = max(100, min(int(float(timeout_seconds) * 1000), 120_000))
        await self._assert_page_safe(session)
        await session.page.locator(selector).click(
            button=button, click_count=max(1, min(int(click_count), 3)), timeout=timeout_ms,
        )
        await self._assert_page_safe(session)
        return {'ok': True, 'session_id': session.id, 'url': session.page.url, 'selector': selector}

    async def type_text(
        self,
        *,
        workspace_key: str,
        session_id: str,
        selector: str,
        text: str,
        clear: bool = True,
        press_enter: bool = False,
        timeout_seconds: float = 15.0,
    ) -> dict[str, Any]:
        session = self._require(workspace_key=workspace_key, session_id=session_id)
        selector = str(selector or '').strip()
        if not selector:
            raise ValueError('selector must not be empty')
        timeout_ms = max(100, min(int(float(timeout_seconds) * 1000), 120_000))
        await self._assert_page_safe(session)
        locator = session.page.locator(selector)
        if clear:
            await locator.fill(str(text), timeout=timeout_ms)
        else:
            await locator.press_sequentially(str(text), timeout=timeout_ms)
        if press_enter:
            await locator.press('Enter', timeout=timeout_ms)
            await self._assert_page_safe(session)
        return {
            'ok': True, 'session_id': session.id, 'url': session.page.url,
            'selector': selector, 'characters_typed': len(str(text)), 'pressed_enter': bool(press_enter),
        }

    async def dom(
        self,
        *,
        workspace_key: str,
        session_id: str,
        selector: str | None = None,
        mode: str = 'text',
        max_chars: int = 50_000,
    ) -> dict[str, Any]:
        session = self._require(workspace_key=workspace_key, session_id=session_id)
        await self._assert_page_safe(session)
        mode = str(mode or 'text').lower()
        if mode not in {'text', 'html', 'both'}:
            raise ValueError('mode must be text, html, or both')
        limit = max(1000, min(int(max_chars), 200_000))
        selector = str(selector or '').strip() or None

        if selector:
            locator = session.page.locator(selector)
            count = await locator.count()
            if count == 0:
                raise ValueError(f'No element matches selector: {selector}')
            if count > 1:
                raise ValueError(f'Selector matches {count} elements; provide a more specific selector: {selector}')
            text_value = await locator.inner_text() if mode in {'text', 'both'} else None
            html_value = await locator.evaluate('(el) => el.outerHTML') if mode in {'html', 'both'} else None
        else:
            text_value = await session.page.locator('body').inner_text() if mode in {'text', 'both'} else None
            html_value = await session.page.content() if mode in {'html', 'both'} else None

        result: dict[str, Any] = {
            'ok': True, 'session_id': session.id, 'url': session.page.url,
            'title': await session.page.title(), 'selector': selector, 'mode': mode,
        }
        if text_value is not None:
            text_value = str(text_value)
            result['text'] = text_value[:limit]
            result['text_truncated'] = len(text_value) > limit
            result['text_total_characters'] = len(text_value)
        if html_value is not None:
            html_value = str(html_value)
            result['html'] = html_value[:limit]
            result['html_truncated'] = len(html_value) > limit
            result['html_total_characters'] = len(html_value)
        return result

    async def screenshot(
        self,
        *,
        workspace_key: str,
        session_id: str,
        output_path: Path,
        full_page: bool = True,
        selector: str | None = None,
    ) -> dict[str, Any]:
        session = self._require(workspace_key=workspace_key, session_id=session_id)
        await self._assert_page_safe(session)
        output_path = output_path.resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        selector = str(selector or '').strip() or None
        if selector:
            locator = session.page.locator(selector)
            count = await locator.count()
            if count != 1:
                raise ValueError(f'Screenshot selector must match exactly one element; matched {count}: {selector}')
            await locator.screenshot(path=str(output_path))
        else:
            await session.page.screenshot(path=str(output_path), full_page=bool(full_page))
        return {
            'ok': True, 'session_id': session.id, 'url': session.page.url,
            'selector': selector, 'full_page': bool(full_page) if not selector else False,
            'bytes': output_path.stat().st_size,
        }

    async def wait(
        self,
        *,
        workspace_key: str,
        session_id: str,
        selector: str | None = None,
        state: str = 'visible',
        seconds: float | None = None,
        timeout_seconds: float = 15.0,
    ) -> dict[str, Any]:
        session = self._require(workspace_key=workspace_key, session_id=session_id)
        await self._assert_page_safe(session)
        selector = str(selector or '').strip() or None
        if selector:
            state = str(state or 'visible').lower()
            if state not in {'attached', 'detached', 'visible', 'hidden'}:
                raise ValueError('state must be attached, detached, visible, or hidden')
            timeout_ms = max(100, min(int(float(timeout_seconds) * 1000), 120_000))
            await session.page.locator(selector).wait_for(state=state, timeout=timeout_ms)
            return {'ok': True, 'session_id': session.id, 'waited_for': 'selector', 'selector': selector, 'state': state}
        delay = 0.5 if seconds is None else max(0.0, min(float(seconds), 30.0))
        await asyncio.sleep(delay)
        return {'ok': True, 'session_id': session.id, 'waited_for': 'time', 'seconds': delay}

    async def back(
        self,
        *,
        workspace_key: str,
        session_id: str,
        wait_until: str = 'domcontentloaded',
        timeout_seconds: float = 30.0,
    ) -> dict[str, Any]:
        session = self._require(workspace_key=workspace_key, session_id=session_id)
        wait_until = str(wait_until or 'domcontentloaded').lower()
        if wait_until not in {'commit', 'domcontentloaded', 'load', 'networkidle'}:
            raise ValueError('wait_until must be commit, domcontentloaded, load, or networkidle')
        timeout_ms = max(100, min(int(float(timeout_seconds) * 1000), 120_000))
        response = await session.page.go_back(wait_until=wait_until, timeout=timeout_ms)
        await self._assert_page_safe(session)
        return {
            'ok': True, 'session_id': session.id, 'url': session.page.url,
            'title': await session.page.title(),
            'http_status': getattr(response, 'status', None) if response is not None else None,
        }

    async def reload(
        self,
        *,
        workspace_key: str,
        session_id: str,
        wait_until: str = 'domcontentloaded',
        timeout_seconds: float = 30.0,
    ) -> dict[str, Any]:
        session = self._require(workspace_key=workspace_key, session_id=session_id)
        wait_until = str(wait_until or 'domcontentloaded').lower()
        if wait_until not in {'commit', 'domcontentloaded', 'load', 'networkidle'}:
            raise ValueError('wait_until must be commit, domcontentloaded, load, or networkidle')
        timeout_ms = max(100, min(int(float(timeout_seconds) * 1000), 120_000))
        response = await session.page.reload(wait_until=wait_until, timeout=timeout_ms)
        await self._assert_page_safe(session)
        return {
            'ok': True, 'session_id': session.id, 'url': session.page.url,
            'title': await session.page.title(),
            'http_status': getattr(response, 'status', None) if response is not None else None,
        }

    async def close(self, *, workspace_key: str, session_id: str) -> dict[str, Any]:
        session = self._require(workspace_key=workspace_key, session_id=session_id)
        self._sessions.pop(session.id, None)
        try:
            await session.context.close()
        finally:
            await session.browser.close()
        return {'ok': True, 'session_id': session.id, 'status': 'closed'}

    def list(self, *, workspace_key: str) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for session in self._sessions.values():
            if session.workspace_key != workspace_key:
                continue
            rows.append({
                'session_id': session.id,
                'url': getattr(session.page, 'url', ''),
                'headless': session.headless,
                'launch_source': session.launch_source,
                'age_seconds': max(0.0, self._now() - session.created_at),
                'idle_seconds': max(0.0, self._now() - session.last_used_at),
            })
        return rows

    async def close_all(self) -> None:
        sessions = list(self._sessions.values())
        self._sessions.clear()
        for session in sessions:
            try:
                await session.context.close()
            except Exception:
                pass
            try:
                await session.browser.close()
            except Exception:
                pass
        if self._playwright is not None:
            try:
                await self._playwright.stop()
            except Exception:
                pass
            self._playwright = None


BROWSER_SESSIONS = BrowserSessionManager()
