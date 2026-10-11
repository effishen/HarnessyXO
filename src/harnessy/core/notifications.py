from __future__ import annotations

import asyncio
import base64
import io
import json
import re
import secrets
from collections import deque
from dataclasses import dataclass
from typing import Any, Awaitable, Callable
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

import httpx
import segno


DEFAULT_NTFY_SETTINGS: dict[str, Any] = {
    'enabled': False,
    'server_url': 'https://ntfy.sh',
    'topic_secret': '',
    'notify_on_success': True,
    'notify_on_error': True,
    'notify_on_stopped': False,
    'minimum_success_seconds': 0,
    'include_names': True,
    'receive_replies': False,
    'reply_window_minutes': 1_440,
}

_TOPIC_RE = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
_OUTCOME_OPTIONS = {'success', 'error', 'stopped'}
NTFY_OUTBOUND_TAG = 'harnessyxo_outbound'
MAX_NTFY_REPLY_CHARS = 4_000


class NotificationConfigurationError(ValueError):
    """Raised when notification settings cannot identify a safe ntfy target."""


class NotificationDeliveryError(RuntimeError):
    """A privacy-safe ntfy delivery failure which never embeds the topic URL."""

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


class NotificationSubscriptionError(RuntimeError):
    """A privacy-safe subscription failure which never embeds the topic URL."""

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class NtfyTarget:
    server_url: str
    topic: str
    publish_url: str
    subscribe_url: str
    phone_subscription_url: str


@dataclass(frozen=True, slots=True)
class NotificationDelivery:
    status_code: int
    message_id: str = ''


@dataclass(frozen=True, slots=True)
class NtfyIncomingMessage:
    message_id: str
    message: str
    title: str
    tags: tuple[str, ...]
    timestamp: int


def generate_ntfy_topic() -> str:
    """Return an ntfy-compatible topic with 192 bits of randomness."""
    return f'hxo-{secrets.token_urlsafe(24)}'


def normalize_ntfy_settings(value: Any) -> dict[str, Any]:
    raw = value if isinstance(value, dict) else {}
    result = dict(DEFAULT_NTFY_SETTINGS)
    result.update({key: raw[key] for key in result if key in raw})
    result['enabled'] = bool(result.get('enabled'))
    result['server_url'] = str(result.get('server_url') or DEFAULT_NTFY_SETTINGS['server_url']).strip()[:2048]
    result['topic_secret'] = str(result.get('topic_secret') or '').strip()[:256]
    for key in (
        'notify_on_success', 'notify_on_error', 'notify_on_stopped', 'include_names', 'receive_replies',
    ):
        result[key] = bool(result.get(key))
    try:
        seconds = int(result.get('minimum_success_seconds') or 0)
    except (TypeError, ValueError):
        seconds = 0
    result['minimum_success_seconds'] = max(0, min(seconds, 604_800))
    try:
        reply_minutes = int(result.get('reply_window_minutes') or 1_440)
    except (TypeError, ValueError):
        reply_minutes = 1_440
    result['reply_window_minutes'] = max(1, min(reply_minutes, 10_080))
    return result


def resolve_ntfy_target(settings: Any) -> NtfyTarget:
    config = normalize_ntfy_settings(settings)
    topic = config['topic_secret']
    if not _TOPIC_RE.fullmatch(topic):
        raise NotificationConfigurationError(
            'ntfy topic must contain 1–64 letters, numbers, hyphens, or underscores. '
            'Use “Generate secure topic” for a safe value.'
        )

    raw_server = config['server_url'].rstrip('/')
    try:
        parsed = urlsplit(raw_server)
        # Accessing ``port`` also validates malformed numeric port strings.
        _ = parsed.port
    except ValueError as exc:
        raise NotificationConfigurationError('ntfy server URL has an invalid port.') from exc
    if parsed.scheme not in {'https', 'http'} or not parsed.hostname:
        raise NotificationConfigurationError('ntfy server URL must be a complete HTTP or HTTPS URL.')
    if parsed.username or parsed.password:
        raise NotificationConfigurationError('Put no username or password in the ntfy server URL.')
    if parsed.query or parsed.fragment:
        raise NotificationConfigurationError('ntfy server URL cannot contain a query string or fragment.')

    base_path = parsed.path.rstrip('/')
    server_url = urlunsplit((parsed.scheme, parsed.netloc, base_path, '', ''))
    topic_path = quote(topic, safe='')
    publish_url = f'{server_url}/{topic_path}'
    phone_query: dict[str, str] = {'display': 'HarnessyXO'}
    if parsed.scheme == 'http':
        phone_query['secure'] = 'false'
    phone_path = f'{base_path}/{topic_path}' if base_path else f'/{topic_path}'
    phone_subscription_url = urlunsplit(('ntfy', parsed.netloc, phone_path, urlencode(phone_query), ''))
    return NtfyTarget(server_url, topic, publish_url, f'{publish_url}/json', phone_subscription_url)


def validate_ntfy_settings(settings: Any, *, require_target: bool | None = None) -> dict[str, Any]:
    config = normalize_ntfy_settings(settings)
    required = config['enabled'] if require_target is None else bool(require_target)
    if required:
        resolve_ntfy_target(config)
    return config


def ntfy_qr_data_url(settings: Any) -> str:
    """Render the phone deep link locally; the secret never reaches a QR service."""
    target = resolve_ntfy_target(settings)
    stream = io.BytesIO()
    segno.make(target.phone_subscription_url, error='m').save(
        stream, kind='svg', scale=4, border=2, xmldecl=False,
    )
    payload = base64.b64encode(stream.getvalue()).decode('ascii')
    return f'data:image/svg+xml;base64,{payload}'


def should_send_run_notification(settings: Any, outcome: str, elapsed_seconds: float) -> bool:
    config = normalize_ntfy_settings(settings)
    normalized_outcome = str(outcome or '').strip().lower()
    if not config['enabled'] or normalized_outcome not in _OUTCOME_OPTIONS:
        return False
    if not bool(config.get(f'notify_on_{normalized_outcome}')):
        return False
    # Fast failures are useful; the duration threshold is primarily an
    # anti-noise control for successful or manually stopped runs.
    if normalized_outcome != 'error':
        return float(elapsed_seconds or 0.0) >= float(config['minimum_success_seconds'])
    return True


def _one_line(value: Any, *, limit: int = 160) -> str:
    text = re.sub(r'[\x00-\x1f\x7f]+', ' ', str(value or ''))
    return re.sub(r'\s+', ' ', text).strip()[:limit]


def notification_error_summary(value: Any, *, reason: str = '', secret: str = '') -> str:
    """Keep a useful, bounded first-line error without forwarding request bodies."""
    text = str(value or '').splitlines()[0] if str(value or '').splitlines() else ''
    # Provider errors can embed the submitted prompt or an entire response.
    # Report the classified reason in that case, never the echoed body.
    http_body = re.search(r'(?i)\bHTTP\s+[1-5]\d{2}\s*:', text)
    if http_body:
        text = text[:http_body.end() - 1].rstrip() + ' ' + str(reason or 'Backend request failed').replace('_', ' ')
    if re.search(r'(?i)[\"\']?(messages|prompt|content|reasoning|tool_calls)[\"\']?\s*[:=]', text):
        text = str(reason or 'Backend request failed').replace('_', ' ')
    elif re.search(r'[\[{]\s*[\"{\[]', text):
        text = text.split('{', 1)[0].split('[', 1)[0].strip() + ' ' + str(reason or 'Backend request failed').replace('_', ' ')
    if secret:
        text = text.replace(secret, '[secret]')
    text = re.sub(r'(?i)\b(?:https?|ntfy)://\S+', '[server]', text)
    text = re.sub(r'(?i)\b(?:bearer\s+\S+|(?:api[_-]?key|token|password|secret)\s*[:=]\s*\S+)', '[credential]', text)
    text = re.sub(r'(?<!\w)(?:[A-Za-z]:\\|/)(?:[^\s,;:]+)', '[path]', text)
    return _one_line(text, limit=480) or str(reason or 'Run failed').replace('_', ' ')


def parse_ntfy_recovery_command(text: str) -> tuple[str, str] | None:
    """Reserve recovery commands; malformed commands must never reach the LLM."""
    parts = str(text or '').strip().split()
    if not parts or parts[0].upper() not in {'RETRY', 'STATUS'}:
        return None
    if len(parts) != 2 or not re.fullmatch(r'[A-Fa-f0-9]{8}', parts[1]):
        return parts[0].upper(), ''
    return parts[0].upper(), parts[1].upper()


def _duration_text(seconds: float) -> str:
    whole = max(0, int(round(float(seconds or 0.0))))
    if whole < 60:
        return f'{whole}s'
    minutes, remaining = divmod(whole, 60)
    if minutes < 60:
        return f'{minutes}m {remaining:02d}s'
    hours, minutes = divmod(minutes, 60)
    return f'{hours}h {minutes:02d}m'


def build_run_notification(
    outcome: str,
    *,
    workspace_name: str,
    chat_title: str,
    elapsed_seconds: float,
    include_names: bool,
    error_summary: str = '',
) -> tuple[str, str, str, str]:
    normalized_outcome = str(outcome or '').strip().lower()
    if normalized_outcome == 'success':
        title, lead, tags, priority = 'HarnessyXO finished', 'Work completed.', 'white_check_mark', 'default'
    elif normalized_outcome == 'error':
        title, lead, tags, priority = 'HarnessyXO needs attention', 'The run ended with an error.', 'warning', 'high'
    elif normalized_outcome == 'stopped':
        title, lead, tags, priority = 'HarnessyXO stopped', 'The run stopped before normal completion.', 'stop_sign', 'default'
    else:
        raise ValueError(f'Unsupported notification outcome: {outcome!r}')

    lines = [lead]
    if normalized_outcome == 'error' and error_summary:
        lines.append('Error: ' + _one_line(error_summary, limit=480))
    if include_names:
        workspace = _one_line(workspace_name)
        chat = _one_line(chat_title)
        if workspace:
            lines.append(f'Workspace: {workspace}')
        if chat:
            lines.append(f'Project / Chat: {chat}')
    lines.append(f'Duration: {_duration_text(elapsed_seconds)}')
    # Error alerts may include a sanitized reason; never send run content.
    return title, '\n'.join(lines), tags, priority


async def send_ntfy_message(
    settings: Any,
    *,
    title: str,
    message: str,
    tags: str = '',
    priority: str = 'default',
    client: httpx.AsyncClient | None = None,
) -> NotificationDelivery:
    target = resolve_ntfy_target(settings)
    headers = {
        'Content-Type': 'text/plain; charset=utf-8',
        # Keep headers ASCII. User-controlled Unicode names belong in the body.
        'Title': _one_line(title, limit=250) or 'HarnessyXO',
        'Priority': priority if priority in {'min', 'low', 'default', 'high', 'urgent'} else 'default',
    }
    supplied_tags = [part for part in re.findall(r'[A-Za-z0-9_+-]+', str(tags or '')) if part]
    # Put the loop-prevention marker first so even a pathological long tag list
    # cannot truncate it from ntfy's bounded header value.
    tag_parts = [NTFY_OUTBOUND_TAG, *(part for part in supplied_tags if part != NTFY_OUTBOUND_TAG)]
    safe_tags = ','.join(tag_parts)[:250]
    if safe_tags:
        headers['Tags'] = safe_tags
    body = str(message or '').encode('utf-8')[:16_384]

    owns_client = client is None
    transport = client or httpx.AsyncClient(timeout=httpx.Timeout(8.0), follow_redirects=False)
    try:
        response = await transport.post(target.publish_url, content=body, headers=headers)
    except httpx.TimeoutException as exc:
        raise NotificationDeliveryError('The ntfy server timed out.', reason='timeout') from exc
    except httpx.HTTPError as exc:
        raise NotificationDeliveryError('The ntfy server could not be reached.', reason='network') from exc
    finally:
        if owns_client:
            await transport.aclose()
    if not 200 <= response.status_code < 300:
        raise NotificationDeliveryError(
            f'ntfy rejected the notification with HTTP {response.status_code}.',
            reason=f'http_{response.status_code}',
        )
    message_id = ''
    try:
        payload = response.json()
        if isinstance(payload, dict):
            message_id = str(payload.get('id') or '')[:128]
    except (TypeError, ValueError, json.JSONDecodeError):
        pass
    return NotificationDelivery(status_code=response.status_code, message_id=message_id)


def parse_ntfy_message(value: Any) -> NtfyIncomingMessage | None:
    """Return one bounded ntfy message event, ignoring protocol chatter."""
    if not isinstance(value, dict) or str(value.get('event') or '') != 'message':
        return None
    message_id = str(value.get('id') or '').strip()[:128]
    if not message_id:
        return None
    raw_tags = value.get('tags')
    tags = tuple(
        str(tag)[:80] for tag in raw_tags
        if isinstance(tag, (str, int, float))
    ) if isinstance(raw_tags, list) else ()
    try:
        timestamp = max(0, int(value.get('time') or 0))
    except (TypeError, ValueError):
        timestamp = 0
    return NtfyIncomingMessage(
        message_id=message_id,
        message=str(value.get('message') or '')[:65_536],
        title=str(value.get('title') or '')[:1_024],
        tags=tags,
        timestamp=timestamp,
    )


async def _bounded_subscription_pause(stop_event: asyncio.Event | None, seconds: float) -> None:
    if stop_event is None:
        await asyncio.sleep(seconds)
        return
    try:
        await asyncio.wait_for(stop_event.wait(), timeout=seconds)
    except asyncio.TimeoutError:
        pass


async def listen_ntfy_messages(
    settings: Any,
    on_message: Callable[[NtfyIncomingMessage], Awaitable[None]],
    *,
    client: httpx.AsyncClient | None = None,
    stop_event: asyncio.Event | None = None,
    reconnect: bool = True,
) -> None:
    """Subscribe without replaying pre-start messages, then recover bounded gaps.

    The initial ``since=latest`` poll establishes a cursor but deliberately does
    not deliver that cached event. Subsequent streams replay only events after
    the cursor, so a short reconnect does not silently lose a phone reply.
    """
    target = resolve_ntfy_target(settings)
    owns_client = client is None
    transport = client or httpx.AsyncClient(
        timeout=httpx.Timeout(connect=8.0, read=None, write=8.0, pool=8.0),
        follow_redirects=False,
    )
    last_id = ''
    recent_ids: deque[str] = deque(maxlen=256)
    recent_lookup: set[str] = set()

    def remember(message_id: str) -> None:
        if message_id in recent_lookup:
            return
        if len(recent_ids) == recent_ids.maxlen:
            oldest = recent_ids.popleft()
            recent_lookup.discard(oldest)
        recent_ids.append(message_id)
        recent_lookup.add(message_id)

    async def ensure_ok(response: httpx.Response) -> None:
        if not 200 <= response.status_code < 300:
            raise NotificationSubscriptionError(
                f'ntfy rejected the subscription with HTTP {response.status_code}.',
                reason=f'http_{response.status_code}',
            )

    try:
        # Establish a non-delivering cursor. Messages sent before this listener
        # started are never converted into surprise model runs.
        try:
            baseline = await transport.get(
                target.subscribe_url,
                params={'poll': '1', 'since': 'latest'},
            )
            await ensure_ok(baseline)
            for line in baseline.text.splitlines():
                try:
                    event = parse_ntfy_message(json.loads(line))
                except (TypeError, json.JSONDecodeError):
                    event = None
                if event is not None:
                    last_id = event.message_id
                    remember(event.message_id)
        except NotificationSubscriptionError:
            if not reconnect:
                raise
        except (httpx.TimeoutException, httpx.HTTPError):
            if not reconnect:
                raise NotificationSubscriptionError(
                    'The ntfy subscription could not be established.', reason='network',
                )

        delay = 1.0
        while stop_event is None or not stop_event.is_set():
            # If the topic cache was empty during the baseline poll, keep
            # ``since=latest`` on the first stream request. That closes the
            # tiny poll-to-stream race: a message published in that gap is now
            # the latest cached message and is delivered, while an actually
            # empty topic simply continues as a live subscription.
            params = {'since': last_id or 'latest'}
            try:
                async with transport.stream('GET', target.subscribe_url, params=params) as response:
                    await ensure_ok(response)
                    delay = 1.0
                    async for line in response.aiter_lines():
                        if stop_event is not None and stop_event.is_set():
                            return
                        try:
                            event = parse_ntfy_message(json.loads(line))
                        except (TypeError, json.JSONDecodeError):
                            event = None
                        if event is None:
                            continue
                        last_id = event.message_id
                        if event.message_id in recent_lookup:
                            continue
                        remember(event.message_id)
                        await on_message(event)
            except asyncio.CancelledError:
                raise
            except NotificationSubscriptionError:
                if not reconnect:
                    raise
            except httpx.TimeoutException as exc:
                if not reconnect:
                    raise NotificationSubscriptionError(
                        'The ntfy subscription timed out.', reason='timeout',
                    ) from exc
            except httpx.HTTPError as exc:
                if not reconnect:
                    raise NotificationSubscriptionError(
                        'The ntfy subscription could not be reached.', reason='network',
                    ) from exc
            if not reconnect:
                return
            await _bounded_subscription_pause(stop_event, delay)
            delay = min(delay * 2.0, 30.0)
    finally:
        if owns_client:
            await transport.aclose()
