"""Use Microsoft's ordinary anonymous download page, without changing browser identity."""
from __future__ import annotations

import asyncio
import inspect
import json
import os
from pathlib import Path
import platform
import re
import signal
import sys
import time
from urllib.parse import urlsplit

from harnessy.diagnostics.windows_media import validate_windows_media_browser


class WindowsMediaBrowserError(RuntimeError):
    def __init__(self, code: str, *, windows_media_browser=None):
        messages = {
            'WINDOWS_ISO_BROWSER_MISSING': 'Windows automatic download needs Playwright. Restart HarnessyXO through run.py to prepare its dependencies.',
            'WINDOWS_ISO_BROWSER_UNAVAILABLE': 'The Windows download browser could not start. Install Chrome, Chromium or Edge on this host, or choose an ISO on this host.',
            'WINDOWS_ISO_BROWSER_INSTALL_FAILED': 'The Windows download browser could not be downloaded. Check host internet access and retry, or choose an ISO on this host.',
            'WINDOWS_ISO_BROWSER_TIMEOUT': 'Microsoft’s Windows download page did not finish in time. Retry later, or choose an ISO on this host.',
            'WINDOWS_ISO_DOWNLOAD_BLOCKED': 'Microsoft declined this host’s Windows download request or requires a browser challenge. HarnessyXO stopped the request. Use Microsoft’s download page in your browser, then choose the downloaded ISO on this host.',
            'WINDOWS_ISO_PAGE_ERROR': 'Microsoft’s Windows download page reported a request error. Retry later, or choose an ISO on this host.',
            'WINDOWS_ISO_NETWORK_ERROR': 'The Windows download browser could not complete its connection to Microsoft. Check host internet access and retry, or choose an ISO on this host.',
            'WINDOWS_ISO_HTTP_ERROR': 'Microsoft’s Windows download page returned an HTTP error. Retry later, or choose an ISO on this host.',
            'WINDOWS_ISO_LINK_UNAVAILABLE': 'Microsoft’s Windows download page did not provide a compatible English (United States) ISO. Retry later, or choose an ISO on this host.',
        }
        self.error_code = code if code in messages else 'WINDOWS_ISO_LINK_UNAVAILABLE'
        self.windows_media_browser = validate_windows_media_browser(windows_media_browser)
        super().__init__(messages[self.error_code])


_PAGES = {
    'x86_64': 'https://www.microsoft.com/en-us/software-download/windows11',
    'arm64': 'https://www.microsoft.com/en-us/software-download/windows11arm64',
}
_INSTALL_TIMEOUT = 900.0
_FLOW_TIMEOUT = 180.0


async def _emit(callback, message: str, *, detail: str = '', timeout: float = _INSTALL_TIMEOUT + _FLOW_TIMEOUT,
                windows_media_browser=None) -> None:
    if callback is None:
        return
    metadata = {'detail': detail, 'stage_timeout_seconds': timeout}
    observation = validate_windows_media_browser(windows_media_browser)
    if observation is not None:
        metadata['windows_media_browser'] = observation
    try:
        parameters = inspect.signature(callback).parameters
        if not any(p.kind == p.VAR_KEYWORD for p in parameters.values()):
            metadata = {key: value for key, value in metadata.items() if key in parameters}
    except (TypeError, ValueError):
        metadata = {}
    value = callback('windows_media_resolving', message, **metadata)
    if inspect.isawaitable(value):
        await value


def _check_cancelled(cancel_event) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise asyncio.CancelledError


async def _drain(task: asyncio.Task) -> None:
    interrupted = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            interrupted = True
    task.result()
    if interrupted:
        raise asyncio.CancelledError


def _browser_candidates() -> list[Path]:
    system = platform.system().lower()
    if system == 'darwin':
        values = ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
                  '/Applications/Chromium.app/Contents/MacOS/Chromium',
                  '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge']
    elif system == 'windows':
        values = [str(Path(root) / suffix) for root in (
            os.environ.get('PROGRAMFILES'), os.environ.get('PROGRAMFILES(X86)'), os.environ.get('LOCALAPPDATA'))
            if root for suffix in ('Google/Chrome/Application/chrome.exe', 'Microsoft/Edge/Application/msedge.exe')]
    else:
        values = ['/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium',
                  '/usr/bin/chromium-browser', '/usr/bin/microsoft-edge', '/usr/bin/microsoft-edge-stable']
    return [Path(value) for value in values if Path(value).is_file()]


async def _install_browser(progress=None, cancel_event=None) -> None:
    _check_cancelled(cancel_event)
    # Lima Windows guests run on Linux/macOS hosts. On native Windows, use an
    # already installed browser rather than a provisioner whose descendant
    # lifetime cannot be owned by a POSIX session.
    if os.name != 'posix':
        raise WindowsMediaBrowserError('WINDOWS_ISO_BROWSER_UNAVAILABLE')
    await _emit(progress, 'Preparing the Windows download browser…',
                detail='Downloading the official Playwright Chromium browser on this host.')
    import playwright as package
    env = os.environ.copy()
    # HarnessyXO normally imports Playwright from .vendor, rather than the
    # interpreter's site-packages. The installer must use that same package.
    vendor = str(Path(package.__file__).resolve().parent.parent)
    env['PYTHONPATH'] = os.pathsep.join(value for value in (vendor, env.get('PYTHONPATH', '')) if value)
    try:
        process = await asyncio.create_subprocess_exec(
            sys.executable, '-m', 'playwright', 'install', 'chromium', env=env,
            start_new_session=True,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    except OSError:
        raise WindowsMediaBrowserError('WINDOWS_ISO_BROWSER_INSTALL_FAILED') from None

    async def read_output():
        # Installer output can include remote URLs. Drain it without exporting it.
        while await process.stdout.read(16384):
            pass

    output = asyncio.create_task(read_output())
    waiter = asyncio.create_task(process.wait())
    started = time.monotonic()

    def signal_group(signum):
        # start_new_session gives this invocation its own SID/PGID equal to
        # the returned PID. Never signal this application's process group.
        if process.pid <= 0 or process.pid == os.getpgrp():
            return
        try:
            os.killpg(process.pid, signum)
        except ProcessLookupError:
            pass

    async def cleanup():
        async def settle():
            await asyncio.gather(waiter, output, return_exceptions=True)
        settled = asyncio.create_task(settle())
        try:
            # Python's Playwright CLI owns a Node child. Its parent may have
            # exited already while Node still holds the output pipe open.
            signal_group(signal.SIGTERM)
            try:
                await asyncio.wait_for(asyncio.shield(settled), 5)
            except asyncio.TimeoutError:
                signal_group(signal.SIGKILL)
                try:
                    await asyncio.wait_for(asyncio.shield(settled), 5)
                except asyncio.TimeoutError:
                    # Bound even a broken output transport. The owned group
                    # has already received SIGKILL; no process is replayed.
                    pass
        finally:
            # A silent descendant can close stdout before exiting. Stop any
            # remaining member of this same owned group as well.
            signal_group(signal.SIGKILL)
            for task in (waiter, output, settled):
                if not task.done():
                    task.cancel()
            await asyncio.gather(waiter, output, settled, return_exceptions=True)

    try:
        while not waiter.done():
            _check_cancelled(cancel_event)
            remaining = _INSTALL_TIMEOUT - (time.monotonic() - started)
            if remaining <= 0:
                raise WindowsMediaBrowserError('WINDOWS_ISO_BROWSER_INSTALL_FAILED')
            try:
                await asyncio.wait_for(asyncio.shield(waiter), min(5, remaining))
            except asyncio.TimeoutError:
                await _emit(progress, 'Preparing the Windows download browser…',
                            detail=f'Browser download is running · {int(time.monotonic() - started)} seconds elapsed.')
        if waiter.result() != 0:
            raise WindowsMediaBrowserError('WINDOWS_ISO_BROWSER_INSTALL_FAILED')
    finally:
        await _drain(asyncio.create_task(cleanup()))


async def _launch_browser(playwright, progress=None, cancel_event=None):
    _check_cancelled(cancel_event)
    missing = False
    try:
        return await playwright.chromium.launch(headless=True)
    except Exception as error:
        missing = "executable doesn't exist" in str(error).lower()
    for channel in ('chrome', 'msedge'):
        _check_cancelled(cancel_event)
        try:
            return await playwright.chromium.launch(headless=True, channel=channel)
        except Exception:
            pass
    for candidate in _browser_candidates():
        _check_cancelled(cancel_event)
        try:
            return await playwright.chromium.launch(headless=True, executable_path=str(candidate))
        except Exception:
            pass
    if not missing:
        raise WindowsMediaBrowserError('WINDOWS_ISO_BROWSER_UNAVAILABLE')
    await _install_browser(progress, cancel_event)
    _check_cancelled(cancel_event)
    try:
        return await playwright.chromium.launch(headless=True)
    except Exception:
        raise WindowsMediaBrowserError('WINDOWS_ISO_BROWSER_UNAVAILABLE') from None


def _allowed_resource(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or '').lower()
        return (parsed.scheme == 'https' and not parsed.username and not parsed.password
                and parsed.port in (None, 443)
                and (host == 'microsoft.com' or host.endswith('.microsoft.com') or host == 'ajax.aspnetcdn.com'))
    except ValueError:
        return False


def _edition_value(options) -> str | None:
    values = [str(row.get('value') or '') for row in options if isinstance(row, dict)
              and str(row.get('value') or '') not in {'', 'null'}]
    return values[0] if len(values) == 1 and values[0].isdigit() else None


def _english_value(options) -> str | None:
    choices = []
    for row in options:
        if not isinstance(row, dict):
            continue
        value = str(row.get('value') or '')
        try:
            language = str(json.loads(value).get('language') or '').casefold()
        except (ValueError, TypeError, AttributeError):
            continue
        label = str(row.get('text') or '').strip().casefold()
        if language in {'english', 'english (united states)', 'en-us'} and label in {
                'english', 'english (united states)'}:
            choices.append(value)
    return choices[0] if len(choices) == 1 else None


def _download_link(links, architecture: str) -> str | None:
    choices = []
    for row in links:
        if not isinstance(row, dict):
            continue
        value = str(row.get('href') or '')
        if not _allowed_resource(value):
            continue
        path = urlsplit(value).path.lower()
        if not path.endswith('.iso'):
            continue
        if ('arm64' in path and architecture != 'arm64') or ('x64' in path and architecture != 'x86_64'):
            continue
        choices.append(value)
    return choices[0] if len(set(choices)) == 1 else None


def _page_error(code: str, result: str, observation=None, *, error_kind='unknown') -> WindowsMediaBrowserError:
    current = dict(observation or {})
    current.update(schema_version=1, phase=current.get('phase', 'page_open'),
                   result=result, error_kind=error_kind)
    return WindowsMediaBrowserError(code, windows_media_browser=current)


def _request_api(url: str) -> bool:
    """Observe only the page's normal language/link requests, never log URLs."""
    try:
        parsed = urlsplit(url)
        return (_allowed_resource(url) and parsed.hostname == 'www.microsoft.com'
                and parsed.path.rstrip('/').rsplit('/', 1)[-1] in {
                    'GetSkuInformationByProductEdition', 'GetProductDownloadLinksBySku'}
                and parsed.path.startswith('/software-download-connector/api/'))
    except ValueError:
        return False


async def _check_page_error(page, observation=None) -> None:
    challenge = page.locator('iframe[src*="captcha" i], iframe[src*="challenge" i], [id*="captcha" i]')
    for index in range(min(await challenge.count(), 16)):
        if await challenge.nth(index).is_visible():
            raise _page_error('WINDOWS_ISO_DOWNLOAD_BLOCKED', 'challenge', observation)
    error = page.locator('#errorModalMessage')
    for index in range(min(await error.count(), 16)):
        if not await error.nth(index).is_visible():
            continue
        text = (await error.nth(index).inner_text()).strip()
        if not text:
            continue
        # Microsoft's own SDS script uses this modal for SentinelReject,
        # GenericError and Network. A generic message is not evidence of a ban.
        if re.search(r'(?<!\d)(?:715-123130|123130-715)(?!\d)', text):
            raise _page_error('WINDOWS_ISO_DOWNLOAD_BLOCKED', 'rejected', observation,
                              error_kind='SentinelReject')
        generic = ' '.join(text.split()).casefold() == (
            'we encountered a problem processing your request. please try again later.')
        error_kind = 'GenericError' if generic else 'unknown'
        if observation and observation.get('_network_failed'):
            raise _page_error('WINDOWS_ISO_NETWORK_ERROR', 'network_error', observation,
                              error_kind='Network')
        if observation and type(observation.get('http_status')) is int and observation['http_status'] >= 400:
            raise _page_error('WINDOWS_ISO_HTTP_ERROR', 'http_error', observation, error_kind=error_kind)
        raise _page_error('WINDOWS_ISO_PAGE_ERROR', 'page_error', observation, error_kind=error_kind)
    if observation and observation.get('_network_failed'):
        raise _page_error('WINDOWS_ISO_NETWORK_ERROR', 'network_error', observation,
                          error_kind='Network')
    if observation and type(observation.get('http_status')) is int and observation['http_status'] >= 400:
        raise _page_error('WINDOWS_ISO_HTTP_ERROR', 'http_error', observation)


_OPTIONS_JS = "selector => Array.from(document.querySelectorAll(selector + ' option')).map(e => ({value:e.value,text:e.textContent}))"
_LINKS_JS = "() => Array.from(document.querySelectorAll('#download-links a[href]')).map(e => ({href:e.href,text:e.textContent}))"


async def _wait_value(page, read, *, cancel_event=None, timeout=45.0, observation=None):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        _check_cancelled(cancel_event)
        await _check_page_error(page, observation)
        value = await read()
        if value is not None:
            return value
        await asyncio.sleep(0.25)
    raise _page_error('WINDOWS_ISO_BROWSER_TIMEOUT', 'timeout', observation)


async def resolve_windows_iso_link(architecture: str, *, progress=None, cancel_event=None) -> str:
    """Perform one normal Microsoft page workflow; a challenge ends this request."""
    if architecture not in _PAGES:
        raise ValueError('Windows ISO architecture must be x86_64 or arm64.')
    _check_cancelled(cancel_event)
    try:
        from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError
    except ImportError:
        raise WindowsMediaBrowserError('WINDOWS_ISO_BROWSER_MISSING') from None
    playwright = browser = context = manager = None
    watcher = None
    observation = {'schema_version': 1, 'phase': 'browser_launch', 'result': 'info'}

    async def report(phase, message, *, detail=''):
        observation.update(phase=phase, result='info')
        observation.pop('http_status', None)
        observation.pop('error_kind', None)
        observation.pop('_network_failed', None)
        await _emit(progress, message, detail=detail, windows_media_browser=observation)

    async def preparation_progress(_stage, message, **metadata):
        await report('browser_preparing', message, detail=str(metadata.get('detail') or ''))

    async def cleanup():
        if watcher is not None:
            watcher.cancel()
            await asyncio.gather(watcher, return_exceptions=True)
        for item, method in ((context, 'close'), (browser, 'close')):
            if item is not None:
                try:
                    await asyncio.wait_for(getattr(item, method)(), 10)
                except Exception:
                    pass
        if manager is not None:
            try:
                await asyncio.wait_for(manager.__aexit__(None, None, None), 10)
            except Exception:
                pass

    async def flow():
        nonlocal playwright, browser, context, manager
        manager = async_playwright()
        playwright = await manager.start()
        await report('browser_launch', 'Starting the Windows download browser…')
        browser = await _launch_browser(playwright, preparation_progress, cancel_event)
        version = getattr(browser, 'version', None)
        if isinstance(version, str):
            checked = validate_windows_media_browser({**observation, 'browser_version': version})
            if checked and 'browser_version' in checked:
                observation['browser_version'] = checked['browser_version']
        context = await browser.new_context(accept_downloads=False)

        async def route(request_route):
            if _allowed_resource(request_route.request.url):
                await request_route.continue_()
            else:
                await request_route.abort()
        await context.route('**/*', route)
        page = await context.new_page()
        page.set_default_timeout(15000)

        def response_received(response):
            if _request_api(response.url) and type(response.status) is int and 100 <= response.status <= 599:
                observation['http_status'] = response.status

        def request_failed(request):
            if _request_api(request.url):
                observation['_network_failed'] = True

        page.on('response', response_received)
        page.on('requestfailed', request_failed)
        await report('page_open', 'Opening Microsoft’s Windows download page…',
                     detail='Using a fresh browser session to request the selected architecture and English (United States).')
        response = await page.goto(_PAGES[architecture], wait_until='load', timeout=45000)
        if response is not None and type(response.status) is int and 100 <= response.status <= 599:
            observation['http_status'] = response.status
        await _check_page_error(page, observation)
        # The native SDS initializer prepares its views and browser session
        # before showing body.loaded. Do not click a pre-initialized template.
        await page.locator('body.loaded').wait_for(state='visible', timeout=15000)
        await report('edition', 'Selecting the Windows installation edition…')

        async def edition():
            return _edition_value(await page.evaluate(_OPTIONS_JS, '#product-edition'))
        value = await _wait_value(page, edition, cancel_event=cancel_event, observation=observation)
        await page.locator('#product-edition').select_option(value)
        await report('language', 'Checking available installation languages…')
        await page.locator('#submit-product-edition').click()

        async def language():
            return _english_value(await page.evaluate(_OPTIONS_JS, '#product-languages'))
        value = await _wait_value(page, language, cancel_event=cancel_event, observation=observation)
        await page.locator('#product-languages').select_option(value)
        await report('download_links', 'Waiting for Microsoft’s Windows download link…')
        await page.locator('#submit-sku').click()

        async def link():
            return _download_link(await page.evaluate(_LINKS_JS), architecture)
        return await _wait_value(page, link, cancel_event=cancel_event, observation=observation)

    work = asyncio.create_task(flow())

    async def watch_cancellation():
        while not work.done():
            if cancel_event is not None and cancel_event.is_set():
                work.cancel()
                return
            await asyncio.sleep(0.25)

    watcher = asyncio.create_task(watch_cancellation()) if cancel_event is not None else None
    try:
        # Browser provisioning has its own bounded deadline. The whole normal
        # page interaction remains bounded as well, including launch/cleanup.
        return await asyncio.wait_for(work, _INSTALL_TIMEOUT + _FLOW_TIMEOUT)
    except asyncio.TimeoutError:
        raise _page_error('WINDOWS_ISO_BROWSER_TIMEOUT', 'timeout', observation) from None
    except PlaywrightTimeoutError:
        raise _page_error('WINDOWS_ISO_BROWSER_TIMEOUT', 'timeout', observation) from None
    except WindowsMediaBrowserError as error:
        if error.windows_media_browser is None:
            result = ('timeout' if error.error_code == 'WINDOWS_ISO_BROWSER_TIMEOUT' else
                      'browser_unavailable' if error.error_code.startswith('WINDOWS_ISO_BROWSER_') else 'page_error')
            error.windows_media_browser = validate_windows_media_browser({**observation, 'result': result})
        raise
    except asyncio.CancelledError:
        raise
    except Exception:
        raise _page_error('WINDOWS_ISO_LINK_UNAVAILABLE', 'page_error', observation) from None
    finally:
        await _drain(asyncio.create_task(cleanup()))
