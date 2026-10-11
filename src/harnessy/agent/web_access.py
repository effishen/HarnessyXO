from __future__ import annotations

import asyncio
import hashlib
import html
import ipaddress
import json
import mimetypes
import re
import socket
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote_plus, unquote, urljoin, urlparse

import httpx

from harnessy import __version__


DEFAULT_SEARCH_ENDPOINT = 'https://html.duckduckgo.com/html/'
USER_AGENT = f'HarnessyXO/{__version__} (+local agent web research)'
_REDIRECT_CODES = {301, 302, 303, 307, 308}
_TEXT_CONTENT_TYPES = (
    'text/',
    'application/json',
    'application/xml',
    'application/xhtml+xml',
    'application/javascript',
    'application/x-javascript',
    'application/ld+json',
)


def _retrieved_at() -> str:
    """Transport observation time, never a source publication/verification date."""
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


class WebAccessError(RuntimeError):
    pass


class _ReadableHTMLParser(HTMLParser):
    _SKIP_TAGS = {'script', 'style', 'noscript', 'svg', 'canvas', 'template'}
    _BLOCK_TAGS = {
        'address', 'article', 'aside', 'blockquote', 'br', 'dd', 'div', 'dl', 'dt', 'fieldset',
        'figcaption', 'figure', 'footer', 'form', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'header',
        'hr', 'li', 'main', 'nav', 'ol', 'p', 'pre', 'section', 'table', 'tbody', 'td', 'th',
        'thead', 'tr', 'ul',
    }

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.title_parts: list[str] = []
        self.text_parts: list[str] = []
        self.links: list[dict[str, str]] = []
        self._skip_depth = 0
        self._in_title = False
        self._current_link: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in self._SKIP_TAGS:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if tag == 'title':
            self._in_title = True
        if tag in self._BLOCK_TAGS:
            self.text_parts.append('\n')
        if tag == 'a':
            values = dict(attrs)
            href = str(values.get('href') or '').strip()
            if href:
                absolute = urljoin(self.base_url, href)
                if absolute.startswith(('http://', 'https://')):
                    self._current_link = {'url': absolute, 'text_parts': []}

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in self._SKIP_TAGS:
            if self._skip_depth:
                self._skip_depth -= 1
            return
        if self._skip_depth:
            return
        if tag == 'title':
            self._in_title = False
        if tag == 'a' and self._current_link is not None:
            text = _clean_inline(' '.join(self._current_link['text_parts']))
            self.links.append({'text': text, 'url': self._current_link['url']})
            self._current_link = None
        if tag in self._BLOCK_TAGS:
            self.text_parts.append('\n')

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        text = data.strip()
        if not text:
            return
        if self._in_title:
            self.title_parts.append(text)
        self.text_parts.append(text + ' ')
        if self._current_link is not None:
            self._current_link['text_parts'].append(text)

    @property
    def title(self) -> str:
        return _clean_inline(' '.join(self.title_parts))

    @property
    def text(self) -> str:
        raw = ''.join(self.text_parts)
        lines = [_clean_inline(line) for line in raw.splitlines()]
        return '\n'.join(line for line in lines if line)


class _DuckSearchParser(HTMLParser):
    """Small parser for DuckDuckGo's HTML search page.

    The endpoint is deliberately configurable so HarnessyXO can later support
    alternate providers without changing the tool contract.
    """

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.results: list[dict[str, str]] = []
        self._anchor: dict[str, Any] | None = None
        self._snippet_parts: list[str] | None = None
        self._snippet_for_index: int | None = None

    @staticmethod
    def _classes(attrs: list[tuple[str, str | None]]) -> set[str]:
        values = dict(attrs)
        return set(str(values.get('class') or '').split())

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        classes = self._classes(attrs)
        values = dict(attrs)
        if tag == 'a' and ('result__a' in classes or 'result-link' in classes):
            href = str(values.get('href') or '').strip()
            if href:
                self._anchor = {'href': href, 'parts': []}
        if 'result__snippet' in classes or 'result-snippet' in classes:
            self._snippet_parts = []
            self._snippet_for_index = len(self.results) - 1 if self.results else None

    def handle_endtag(self, tag: str) -> None:
        if tag == 'a' and self._anchor is not None:
            title = _clean_inline(' '.join(self._anchor['parts']))
            url = _decode_search_url(self._anchor['href'], self.base_url)
            if title and url:
                self.results.append({'title': title, 'url': url, 'snippet': ''})
            self._anchor = None
        if self._snippet_parts is not None and tag in {'a', 'div', 'span', 'td'}:
            snippet = _clean_inline(' '.join(self._snippet_parts))
            if snippet and self.results:
                index = self._snippet_for_index
                if index is None or index < 0 or index >= len(self.results):
                    index = len(self.results) - 1
                if not self.results[index].get('snippet'):
                    self.results[index]['snippet'] = snippet
            self._snippet_parts = None
            self._snippet_for_index = None

    def handle_data(self, data: str) -> None:
        text = data.strip()
        if not text:
            return
        if self._anchor is not None:
            self._anchor['parts'].append(text)
        if self._snippet_parts is not None:
            self._snippet_parts.append(text)


@dataclass(slots=True)
class WebResearchClient:
    workspace_meta: Path
    artifacts_dir: Path
    chat_id: str
    allow_private: bool = False
    search_endpoint: str = DEFAULT_SEARCH_ENDPOINT
    timeout_seconds: float = 30.0

    @property
    def cache_dir(self) -> Path:
        path = self.workspace_meta / 'web' / self.chat_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    async def search(self, query: str, *, max_results: int = 8) -> dict[str, Any]:
        query = query.strip()
        if not query:
            raise ValueError('query is required')
        max_results = max(1, min(int(max_results), 20))
        endpoint = self.search_endpoint.strip() or DEFAULT_SEARCH_ENDPOINT
        final_url, response = await self._request(
            'GET', endpoint, params={'q': query}, max_bytes=3_000_000,
        )
        retrieved_at = _retrieved_at()
        content_type = _content_type(response)
        body = response.content.decode(response.encoding or 'utf-8', errors='replace')
        if 'html' not in content_type and not body.lstrip().startswith('<'):
            raise WebAccessError(f'Search provider returned unsupported content type: {content_type or "unknown"}')
        parser = _DuckSearchParser(final_url)
        parser.feed(body)
        seen: set[str] = set()
        results: list[dict[str, str]] = []
        for row in parser.results:
            url = row['url']
            if url in seen:
                continue
            seen.add(url)
            results.append(row)
            if len(results) >= max_results:
                break
        return {
            'ok': True,
            'query': query,
            'provider': 'duckduckgo_html',
            'retrieved_at': retrieved_at,
            'results': results,
            'result_count': len(results),
        }

    async def open(self, url: str, *, max_chars: int = 80_000) -> dict[str, Any]:
        max_chars = max(1_000, min(int(max_chars), 200_000))
        final_url, response = await self._request('GET', url, max_bytes=8_000_000)
        retrieved_at = _retrieved_at()
        content_type = _content_type(response)
        if not _is_text_content_type(content_type):
            raise WebAccessError(
                f'web_open only reads text/HTML resources; got {content_type or "unknown"}. Use web_download for binary files.'
            )
        encoding = response.encoding or 'utf-8'
        body = response.content.decode(encoding, errors='replace')
        title = ''
        links: list[dict[str, str]] = []
        if 'html' in content_type or body.lstrip().lower().startswith(('<!doctype html', '<html')):
            parser = _ReadableHTMLParser(final_url)
            parser.feed(body)
            text = parser.text
            title = parser.title
            links = _dedupe_links(parser.links)[:100]
        else:
            text = body.replace('\r\n', '\n').replace('\r', '\n')
        text = text.strip()
        truncated = len(text) > max_chars
        visible_text = text[:max_chars]
        source_id = f'web-{uuid.uuid4().hex[:12]}'
        cached = {
            'source_id': source_id,
            'retrieved_at': retrieved_at,
            'url': url,
            'final_url': final_url,
            'title': title,
            'content_type': content_type,
            'text': text,
            'links': links,
        }
        (self.cache_dir / f'{source_id}.json').write_text(json.dumps(cached, ensure_ascii=False), encoding='utf-8')
        return {
            'ok': True,
            'source_id': source_id,
            'url': url,
            'retrieved_at': retrieved_at,
            'final_url': final_url,
            'title': title,
            'content_type': content_type,
            'text': visible_text,
            'text_chars': len(text),
            'truncated': truncated,
            'links': links,
        }

    async def find(
        self,
        source_id: str,
        query: str,
        *,
        max_results: int = 8,
        context_chars: int = 350,
    ) -> dict[str, Any]:
        source_id = source_id.strip()
        query = query.strip()
        if not re.fullmatch(r'web-[A-Fa-f0-9]{12}', source_id):
            raise ValueError('Invalid source_id')
        if not query:
            raise ValueError('query is required')
        path = self.cache_dir / f'{source_id}.json'
        if not path.is_file():
            raise FileNotFoundError(f'Unknown web source: {source_id}')
        data = json.loads(path.read_text('utf-8'))
        text = str(data.get('text') or '')
        max_results = max(1, min(int(max_results), 30))
        context_chars = max(80, min(int(context_chars), 2_000))
        matches = _find_matches(text, query, max_results=max_results, context_chars=context_chars)
        return {
            'ok': True,
            'source_id': source_id,
            'query': query,
            'retrieved_at': data.get('retrieved_at'),
            'url': data.get('final_url') or data.get('url'),
            'title': data.get('title') or '',
            'matches': matches,
            'match_count': len(matches),
        }

    async def download(
        self,
        url: str,
        *,
        name: str | None = None,
        max_bytes: int = 50_000_000,
    ) -> dict[str, Any]:
        max_bytes = max(1_000, min(int(max_bytes), 100_000_000))
        final_url, response = await self._request('GET', url, max_bytes=max_bytes)
        content = response.content
        filename = _download_filename(name, final_url, response.headers.get('content-disposition'), _content_type(response))
        out_dir = self.artifacts_dir / self.chat_id
        out_dir.mkdir(parents=True, exist_ok=True)
        path = _unique_path(out_dir / filename)
        path.write_bytes(content)
        return {
            'ok': True,
            'url': url,
            'final_url': final_url,
            'path': str(path),
            'name': path.name,
            'content_type': _content_type(response),
            'size': len(content),
            'sha256': hashlib.sha256(content).hexdigest(),
        }

    async def _request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        max_bytes: int,
    ) -> tuple[str, httpx.Response]:
        current = _normalize_url(url)
        params_for_request = params
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=httpx.Timeout(self.timeout_seconds),
            headers={
                'User-Agent': USER_AGENT,
                'Accept': 'text/html,application/xhtml+xml,application/json,text/plain,*/*;q=0.5',
            },
        ) as client:
            for _ in range(8):
                await _validate_url_target(current, allow_private=self.allow_private)
                async with client.stream(method, current, params=params_for_request) as response:
                    params_for_request = None
                    if response.status_code in _REDIRECT_CODES:
                        location = response.headers.get('location')
                        if not location:
                            raise WebAccessError(f'HTTP {response.status_code} redirect without Location header')
                        current = _normalize_url(urljoin(str(response.url), location))
                        continue
                    try:
                        response.raise_for_status()
                    except httpx.HTTPStatusError as exc:
                        raise WebAccessError(f'HTTP {response.status_code} for {current}') from exc
                    chunks: list[bytes] = []
                    total = 0
                    try:
                        # HTTPX applies HTTP Content-Encoding here. Count decoded
                        # bytes so compression cannot bypass the existing limit.
                        async for chunk in response.aiter_bytes():
                            total += len(chunk)
                            if total > max_bytes:
                                raise WebAccessError(f'Response exceeded the {max_bytes:,}-byte safety limit')
                            chunks.append(chunk)
                    except httpx.DecodingError as exc:
                        coding = _clean_inline(response.headers.get('content-encoding') or 'unspecified')[:80]
                        raise WebAccessError(
                            f'Could not decode the response from {response.url.host} '
                            f'(HTTP {response.status_code}; Content-Encoding: {coding}; DecodingError). '
                            'No usable content was returned for this request. Other sources may still work.'
                        ) from exc
                    # The stream closes here. This new response contains decoded
                    # bytes, NOT the original compressed/transfer-framed body.
                    # Retaining Content-Encoding makes Response(content=...) try
                    # to decompress it again. Copy (do not mutate) the headers and
                    # let HTTPX calculate Content-Length for the detached body.
                    headers = response.headers.copy()
                    for name in ('content-encoding', 'content-length', 'transfer-encoding'):
                        headers.pop(name, None)
                    detached = httpx.Response(
                        status_code=response.status_code,
                        headers=headers,
                        content=b''.join(chunks),
                        request=httpx.Request(method, str(response.url)),
                    )
                    return str(response.url), detached
            raise WebAccessError('Too many HTTP redirects')


def _clean_inline(value: str) -> str:
    return re.sub(r'\s+', ' ', html.unescape(value or '')).strip()


def _decode_search_url(href: str, base_url: str) -> str:
    absolute = urljoin(base_url, html.unescape(href))
    parsed = urlparse(absolute)
    if parsed.netloc.endswith('duckduckgo.com') and parsed.path.startswith('/l/'):
        target = parse_qs(parsed.query).get('uddg', [''])[0]
        if target:
            return unquote(target)
    return absolute if absolute.startswith(('http://', 'https://')) else ''


def _dedupe_links(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for row in rows:
        url = str(row.get('url') or '')
        if not url or url in seen:
            continue
        seen.add(url)
        out.append({'text': str(row.get('text') or ''), 'url': url})
    return out


def _content_type(response: httpx.Response) -> str:
    return str(response.headers.get('content-type') or '').split(';', 1)[0].strip().lower()


def _is_text_content_type(content_type: str) -> bool:
    return not content_type or any(content_type.startswith(prefix) for prefix in _TEXT_CONTENT_TYPES)


def _normalize_url(url: str) -> str:
    value = str(url or '').strip()
    if not value:
        raise ValueError('URL is required')
    parsed = urlparse(value)
    if parsed.scheme.lower() not in {'http', 'https'}:
        raise ValueError('Only http:// and https:// URLs are allowed')
    if not parsed.hostname:
        raise ValueError('URL must include a hostname')
    if parsed.username or parsed.password:
        raise ValueError('Credentials in URLs are not allowed')
    return value


async def _validate_url_target(url: str, *, allow_private: bool) -> None:
    if allow_private:
        return
    parsed = urlparse(url)
    host = str(parsed.hostname or '').strip().rstrip('.').lower()
    if host in {'localhost', 'localhost.localdomain'} or host.endswith('.localhost'):
        raise WebAccessError('Local/private network URLs are blocked for model web access.')
    try:
        direct_ip = ipaddress.ip_address(host)
    except ValueError:
        direct_ip = None
    if direct_ip is not None:
        if not direct_ip.is_global:
            raise WebAccessError('Local/private/reserved network addresses are blocked for web research.')
        return
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    try:
        infos = await asyncio.to_thread(socket.getaddrinfo, host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise WebAccessError(f'Could not resolve hostname: {host}') from exc
    addresses = {row[4][0] for row in infos if row and row[4]}
    if not addresses:
        raise WebAccessError(f'Could not resolve hostname: {host}')
    for value in addresses:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if not address.is_global:
            raise WebAccessError('Hostname resolves to a local/private/reserved network address, which is blocked for web research.')


def _find_matches(text: str, query: str, *, max_results: int, context_chars: int) -> list[dict[str, Any]]:
    lower = text.lower()
    needle = query.lower()
    positions: list[int] = []
    start = 0
    while len(positions) < max_results:
        index = lower.find(needle, start)
        if index < 0:
            break
        positions.append(index)
        start = index + max(1, len(needle))
    if not positions:
        terms = [term for term in re.findall(r'[\w.-]{3,}', needle) if term]
        scored: list[tuple[int, int]] = []
        for match in re.finditer(r'[^\n]{1,1200}', text):
            paragraph = match.group(0)
            paragraph_lower = paragraph.lower()
            score = sum(1 for term in terms if term in paragraph_lower)
            if score:
                scored.append((score, match.start()))
        scored.sort(key=lambda row: (-row[0], row[1]))
        positions = [position for _, position in scored[:max_results]]
    out: list[dict[str, Any]] = []
    for position in positions[:max_results]:
        left = max(0, position - context_chars)
        right = min(len(text), position + max(len(query), 1) + context_chars)
        snippet = text[left:right].strip()
        out.append({'start_char': left, 'end_char': right, 'snippet': snippet})
    return out


def _download_filename(name: str | None, url: str, content_disposition: str | None, content_type: str) -> str:
    candidate = Path(str(name or '')).name.strip()
    if not candidate and content_disposition:
        match = re.search(r"filename\*=UTF-8''([^;]+)", content_disposition, re.I)
        if match:
            candidate = unquote(match.group(1).strip().strip('"'))
        else:
            match = re.search(r'filename="?([^";]+)', content_disposition, re.I)
            if match:
                candidate = match.group(1).strip()
    if not candidate:
        candidate = Path(urlparse(url).path).name
    if not candidate:
        extension = mimetypes.guess_extension(content_type) or ''
        candidate = f'web-download{extension}'
    candidate = re.sub(r'[^A-Za-z0-9._-]+', '_', Path(candidate).name).strip('._') or 'web-download'
    return candidate[:180]


def _unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    for index in range(2, 10_000):
        candidate = path.with_name(f'{stem}-{index}{suffix}')
        if not candidate.exists():
            return candidate
    return path.with_name(f'{stem}-{uuid.uuid4().hex[:8]}{suffix}')
