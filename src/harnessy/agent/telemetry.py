"""Best-effort generation telemetry, never model input or a host-shell tool.

The user's patched Ollama emits progress to its server log, not /api/chat.
Only appended, timestamped progress records are read; content/log lines are
never sent to the browser, the model, or HarnessyXO's diagnostic log.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import math
import os
import re
import socket
import stat
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

RATE_TTL = 3.0
MAX_READ = 64 * 1024
_FIELDS = re.compile(r'(?:^|\s)([A-Za-z_][\w]*)=("(?:\\.|[^"\\])*"|[^\s]+)')
_OMLX_PREFIX_CACHE = re.compile(
    r'prefix cache: request ([0-9a-fA-F-]+) re-prefills (\d+) of (\d+) tokens \(reused (\d+)\)'
)
_ACTIVE_LOG_READERS: dict[str, set['OllamaLogReader']] = {}
_ACTIVE_UNSCOPED_REQUESTS: dict[str, set['UnscopedTelemetryLease']] = {}


class UnscopedTelemetryLease:
    """Mark backend-wide progress ambiguous as soon as requests overlap.

    Model calls may have distinct chat histories but the server's activity
    endpoint may show only one active row without an ID joined to our POST.
    Once overlap occurs, keep both calls ambiguous until they finish, even if
    the backend briefly reports only one prefill row.
    """

    def __init__(self, base_url: str, backend: str) -> None:
        parsed = urlsplit(base_url)
        host = str(parsed.hostname or '').lower()
        if host in {'localhost', '127.0.0.1', '::1'}:
            host = 'local'
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        self.key = f'{backend}:{host}:{port}'
        self.ambiguous = False
        self.overlap = asyncio.Event()
        active = _ACTIVE_UNSCOPED_REQUESTS.setdefault(self.key, set())
        if active:
            self.ambiguous = True
            self.overlap.set()
            for other in active:
                other.ambiguous = True
                other.overlap.set()
        active.add(self)

    def close(self) -> None:
        active = _ACTIVE_UNSCOPED_REQUESTS.get(self.key)
        if active is not None:
            active.discard(self)
            if not active:
                _ACTIVE_UNSCOPED_REQUESTS.pop(self.key, None)


def number(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        n = float(value)
        return n if math.isfinite(n) and n >= 0 else None
    except (ValueError, TypeError, OverflowError):
        return None


def local_endpoint(base_url: str) -> bool:
    """No DNS, subprocess, or outbound probe. A bind proves numeric ownership."""
    host = str(urlsplit(base_url).hostname or '').lower()
    own = socket.gethostname().lower()
    if host in {'localhost', own, own.split('.')[0] + '.local'}:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if ip.is_loopback or ip.is_unspecified:
        return True
    try:
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.bind((str(ip), 0))
        return True
    except OSError:
        return False


def generation_rate(values: dict[str, Any], previous: dict[str, Any] | None = None) -> dict[str, Any]:
    """Preserve rate provenance. A reported zero live rate is NOT missing."""
    for key in ('live_tps', 'avg_tps', 'tps', 'tokens_per_second', 'tokens_per_sec',
                'token_per_second', 'eval_tps', 'decode_tps', 'generation_tps', 'generation_rate',
                'predicted_per_second'):
        rate = number(values.get(key))
        if rate is not None:
            return {'tps': rate, 'tps_kind': 'average' if key in {'avg_tps', 'predicted_per_second'} else 'live'}
    generated = number(values.get('generated', values.get('generated_tokens', values.get('eval_count'))))
    elapsed = number(values.get('elapsed_ms'))
    duration = number(values.get('eval_duration'))
    if duration and generated is not None:
        return {'tps': generated / (duration / 1e9), 'tps_kind': 'average'}
    if previous and generated is not None and elapsed is not None:
        old_generated, old_elapsed = number(previous.get('generated')), number(previous.get('elapsed_ms'))
        if old_generated is not None and old_elapsed is not None and generated >= old_generated and elapsed > old_elapsed:
            return {'tps': (generated - old_generated) / ((elapsed - old_elapsed) / 1000), 'tps_kind': 'delta'}
    return {}


def llama_cpp_stream_status(data: Any, *, observed_at: float | None = None) -> dict[str, Any] | None:
    """Normalize request-scoped llama.cpp ``timings`` into HarnessyXO telemetry.

    llama-server can attach cumulative timing counters to every streamed
    OpenAI-compatible chunk when ``timings_per_token`` is enabled.  Keep only
    documented numeric fields: never copy response content, prompts, tool
    arguments, or other payload data into live telemetry.
    """
    if not isinstance(data, dict) or not isinstance(data.get('timings'), dict):
        return None
    raw = data['timings']
    keys = (
        'cache_n', 'prompt_n', 'prompt_ms', 'prompt_per_token_ms', 'prompt_per_second',
        'predicted_n', 'predicted_ms', 'predicted_per_token_ms', 'predicted_per_second',
        'draft_n', 'draft_n_accepted',
    )
    timings = {key: value for key in keys if (value := number(raw.get(key))) is not None}
    if not timings:
        return None

    predicted = number(timings.get('predicted_n'))
    prompt = number(timings.get('prompt_n'))
    cached = number(timings.get('cache_n'))
    decode_tps = number(timings.get('predicted_per_second'))
    prefill_tps = number(timings.get('prompt_per_second'))
    predicted_count = int(predicted or 0)
    prompt_count = int(prompt or 0)
    cached_count = int(cached or 0)
    generating = predicted_count > 0
    status: dict[str, Any] = {
        'backend': 'llama.cpp',
        'phase': 'generating' if generating else 'prompt_processing',
        'processed': prompt_count,
        'total': prompt_count + cached_count,
        'generated': predicted_count,
        'context_used': prompt_count + cached_count + predicted_count,
        'prefill_tps': prefill_tps,
        'tps_source': 'llama.cpp_stream',
        'tps_observed_at': time.perf_counter() if observed_at is None else float(observed_at),
        'backend_timings': timings,
    }
    if generating and decode_tps is not None:
        # llama.cpp reports a cumulative request average here. It is refreshed
        # with streamed timing samples, while remaining an average by meaning.
        status['tps'] = decode_tps
        status['tps_kind'] = 'average'
    else:
        status['tps'] = 0.0
        status['tps_kind'] = 'unavailable'
    return status



def omlx_stream_status(data: Any, *, observed_at: float | None = None) -> dict[str, Any] | None:
    """Normalize oMLX's final streaming ``usage`` timing extension.

    Current oMLX exposes authoritative prompt/decode throughput in the final
    OpenAI-compatible usage chunk when ``stream_options.include_usage`` is
    requested. Keep telemetry numeric-only; response content and tool data are
    never copied into the runtime status channel.
    """
    if not isinstance(data, dict) or not isinstance(data.get('usage'), dict):
        return None
    usage = data['usage']
    decode_tps = number(usage.get('generation_tokens_per_second'))
    prefill_tps = number(usage.get('prompt_tokens_per_second'))
    decode_seconds = number(usage.get('generation_duration'))
    prefill_seconds = number(usage.get('prompt_eval_duration'))
    prompt = number(usage.get('prompt_tokens'))
    completion = number(usage.get('completion_tokens'))
    total = number(usage.get('total_tokens'))
    details = usage.get('prompt_tokens_details') if isinstance(usage.get('prompt_tokens_details'), dict) else {}
    cached = number(details.get('cached_tokens'))

    # Do not claim oMLX-native telemetry merely because a generic OpenAI usage
    # object exists. At least one oMLX timing/rate extension must be present.
    if all(value is None for value in (decode_tps, prefill_tps, decode_seconds, prefill_seconds,
                                       number(usage.get('time_to_first_token')), number(usage.get('total_time')))):
        return None

    prompt_count = int(prompt or 0)
    completion_count = int(completion or 0)
    total_count = int(total or (prompt_count + completion_count))
    cached_count = int(cached or 0)
    status: dict[str, Any] = {
        'backend': 'oMLX',
        'phase': 'generating' if completion_count > 0 else 'prompt_processing',
        'processed': max(0, prompt_count - cached_count),
        'total': prompt_count,
        'generated': completion_count,
        'context_used': total_count,
        'prefill_tps': prefill_tps,
        'tps_source': 'omlx_usage',
        'tps_observed_at': time.perf_counter() if observed_at is None else float(observed_at),
    }
    if completion_count > 0 and decode_tps is not None:
        status['tps'] = decode_tps
        status['tps_kind'] = 'average'
    else:
        status['tps'] = 0.0
        status['tps_kind'] = 'unavailable'
    return status



def omlx_activity_status(
    data: Any,
    *,
    model_id: str = '',
    request_id: str = '',
    observed_at: float | None = None,
) -> dict[str, Any] | None:
    """Normalize current oMLX ``/admin/api/activity`` request telemetry.

    oMLX exposes per-request prefill/generation progress independently from the
    OpenAI chat stream.  Unlike the final ``usage`` chunk, this endpoint is a
    genuinely live source: ``prefilling[].speed`` reports prompt throughput and
    ``generating[].tokens_per_second`` reports cumulative decode throughput.

    The admin surface can contain activity from unrelated clients.  Prefer an
    exact model-id match; when an API alias maps to a different canonical model
    id, accept a fallback only when exactly one model is active.  Likewise, do
    not guess between multiple concurrent requests for the same model.
    """
    if not isinstance(data, dict):
        return None
    active = data.get('active_models')
    if not isinstance(active, dict):
        return None
    models = active.get('models')
    if not isinstance(models, list):
        return None

    rows = [row for row in models if isinstance(row, dict)]
    wanted_request = str(request_id or '').strip()
    if wanted_request:
        # The request ID was observed before overlap. Select only that exact
        # backend request even when other chats now share the same model row.
        matches = [
            (row, phase, item)
            for row in rows for phase in ('prefilling', 'generating')
            for item in (row.get(phase) if isinstance(row.get(phase), list) else [])
            if isinstance(item, dict) and str(item.get('request_id') or '').strip() == wanted_request
        ]
        if len(matches) != 1:
            return None
        row, phase, item = matches[0]
        generating = [item] if phase == 'generating' else []
        prefilling = [item] if phase == 'prefilling' else []
    else:
        wanted = str(model_id or '').strip().casefold()
        exact = [row for row in rows if str(row.get('id') or '').strip().casefold() == wanted] if wanted else []
        candidates = exact
        if not candidates:
            active_rows = [row for row in rows if (row.get('prefilling') or row.get('generating'))]
            if len(active_rows) == 1:
                candidates = active_rows
        if len(candidates) != 1:
            return None
        row = candidates[0]
        generating = [item for item in (row.get('generating') or []) if isinstance(item, dict)]
        prefilling = [item for item in (row.get('prefilling') or []) if isinstance(item, dict)]
    now = time.perf_counter() if observed_at is None else float(observed_at)

    # A model row can contain one prefill and one generating request at once.
    # Choosing one by phase would attribute its counters to another chat.
    if len(prefilling) + len(generating) > 1:
        return None
    if generating:
        if len(generating) != 1:
            return None
        item = generating[0]
        rate = number(item.get('tokens_per_second'))
        generated = int(number(item.get('generated_tokens')) or 0)
        prompt = int(number(item.get('prompt_tokens')) or 0)
        status: dict[str, Any] = {
            'backend': 'oMLX',
            'phase': 'generating',
            'request_id': str(item.get('request_id') or ''),
            'generated': generated,
            'context_used': max(0, prompt + generated),
            'tps_source': 'omlx_activity',
            'tps_observed_at': now,
        }
        if rate is not None and rate > 0:
            status['tps'] = rate
            status['tps_kind'] = 'average'
        else:
            status['tps'] = 0.0
            status['tps_kind'] = 'unavailable'
        return status

    if prefilling:
        if len(prefilling) != 1:
            return None
        item = prefilling[0]
        processed = int(number(item.get('processed')) or 0)
        total = int(number(item.get('total')) or 0)
        speed = number(item.get('speed'))
        # Accept a direct reused-prefix field if an oMLX build exposes one.
        # Current upstream activity rows may omit it; the transport then uses a
        # request-ID-correlated, numeric-only local server-log fallback. Keep
        # either backend-derived value separate from HarnessyXO's privacy-safe
        # consecutive-request prefix estimate.
        cached_raw = number(item.get('cached_tokens'))
        if cached_raw is None:
            cached_raw = number(item.get('reused_tokens'))
        cached_tokens = max(0, int(cached_raw or 0))
        if total > 0:
            cached_tokens = min(cached_tokens, total)
        uncached_total = max(0, total - cached_tokens) if total > 0 else 0
        cache_hit_rate = (cached_tokens * 100.0 / total) if total > 0 and cached_raw is not None else None
        status = {
            'backend': 'oMLX',
            'phase': 'prompt_processing',
            'request_id': str(item.get('request_id') or ''),
            'processed': processed,
            'total': total,
            'context_used': max(processed, total),
            'prefill_tps': speed,
            'tps': 0.0,
            'tps_kind': 'unavailable',
            'tps_source': 'omlx_activity',
            'tps_observed_at': now,
        }
        if cached_raw is not None:
            status['cached_tokens'] = cached_tokens
            status['uncached_total'] = uncached_total
            status['cache_hit_rate'] = cache_hit_rate
            status['cache_hit_source'] = 'omlx_activity'
        return status
    return None


def omlx_request_health(
    data: Any,
    *,
    model_id: str = '',
    request_id: str = '',
) -> dict[str, Any]:
    """Classify request-scoped oMLX activity without copying prompt content.

    The dashboard is a best-effort activity snapshot, not an authoritative
    request-status API. Presence is positive evidence; absence cannot prove a
    request was abandoned, including across queue/phase transitions or a
    partial scheduler snapshot. Missing and malformed entries stay unknown.
    """
    unknown = {
        'backend_reachable': True,
        'request_state': 'unknown',
        'request_scoped': False,
        'evidence': 'activity_ambiguous',
    }
    if not isinstance(data, dict):
        return unknown
    active = data.get('active_models')
    models = active.get('models') if isinstance(active, dict) else None
    if not isinstance(models, list):
        return unknown

    rows = [row for row in models if isinstance(row, dict)]
    wanted_model = str(model_id or '').strip().casefold()
    exact = [row for row in rows if str(row.get('id') or '').strip().casefold() == wanted_model] if wanted_model else []
    if len(exact) > 1:
        return unknown
    selected = exact[0] if exact else None

    wanted_request = str(request_id or '').strip()
    all_request_ids: set[str] = set()
    selected_request_ids: set[str] = set()
    for row in rows:
        row_ids: set[str] = set()
        for key in ('prefilling', 'generating', 'waiting', 'activities'):
            entries = row.get(key)
            for item in entries if isinstance(entries, list) else []:
                if not isinstance(item, dict):
                    continue
                candidate = str(item.get('request_id') or '').strip()
                if candidate:
                    row_ids.add(candidate)
                    all_request_ids.add(candidate)
        if row is selected:
            selected_request_ids = row_ids

    if wanted_request:
        if wanted_request in all_request_ids:
            return {
                'backend_reachable': True,
                'request_state': 'active',
                'request_scoped': True,
                'evidence': 'request_id_present',
            }
        # Do not cancel a stream merely because its last telemetry UUID is
        # absent. It may have been requeued, changed phase, or belonged to an
        # unrelated client selected by the model-level telemetry heuristic.
        return {
            'backend_reachable': True,
            'request_state': 'unknown',
            'request_scoped': False,
            'evidence': 'request_id_not_in_activity',
        }

    if selected is not None and len(selected_request_ids) == 1:
        return {
            'backend_reachable': True,
            'request_state': 'active',
            'request_scoped': False,
            'evidence': 'single_model_activity',
        }
    return unknown


class OmlxPrefixCacheLogReader:
    """Request-scoped, numeric-only reader for local oMLX prefix-cache decisions.

    Current oMLX ``/admin/api/activity`` exposes live prefill progress but not the
    request's reused-prefix count.  The server log emits that count once, before
    prefill starts, and includes the same request UUID that the activity endpoint
    exposes.  This reader starts at EOF before transport, reads only appended
    bytes, and retains only four integers per matching request.  It never stores
    prompt text, tool content, paths from the log, or arbitrary log lines.
    """

    def __init__(self, base_url: str) -> None:
        self.path = Path.home() / '.omlx/logs/server.log'
        self.enabled = local_endpoint(base_url)
        self.offset = 0
        self.inode: int | None = None
        self.partial = b''
        self.matches: dict[str, dict[str, Any]] = {}
        if not self.enabled:
            return
        try:
            st = self.path.stat()
            if not stat.S_ISREG(st.st_mode):
                self.enabled = False
                return
            self.inode = st.st_ino
            self.offset = st.st_size
        except OSError:
            self.enabled = False

    def poll(self) -> None:
        if not self.enabled:
            return
        try:
            st = self.path.stat()
            if not stat.S_ISREG(st.st_mode):
                return
            if self.inode != st.st_ino or st.st_size < self.offset:
                # Rotation/truncation after request start: do not scan historical
                # content. Resume only from the new file's current beginning.
                self.inode = st.st_ino
                self.offset = 0 if st.st_size <= MAX_READ else st.st_size - MAX_READ
                self.partial = b''
            if st.st_size <= self.offset:
                return
            to_read = min(MAX_READ, st.st_size - self.offset)
            with self.path.open('rb') as handle:
                handle.seek(self.offset)
                chunk = handle.read(to_read)
            self.offset += len(chunk)
            data = self.partial + chunk
            lines = data.split(b'\n')
            self.partial = lines.pop() if lines else b''
            for raw in lines:
                try:
                    line = raw.decode('utf-8', errors='replace')
                except Exception:
                    continue
                match = _OMLX_PREFIX_CACHE.search(line)
                if not match:
                    continue
                request_id, reprefill, total, reused = match.groups()
                reprefill_n = int(reprefill)
                total_n = int(total)
                reused_n = int(reused)
                if total_n <= 0 or reprefill_n < 0 or reused_n < 0:
                    continue
                self.matches[request_id] = {
                    'request_id': request_id,
                    'reprefill_tokens': min(reprefill_n, total_n),
                    'total_prompt_tokens': total_n,
                    'cached_tokens': min(reused_n, total_n),
                    'cache_hit_rate': min(100.0, max(0.0, reused_n * 100.0 / total_n)),
                    'cache_hit_source': 'omlx_server_log',
                }
        except OSError:
            return

    def for_request(self, request_id: str) -> dict[str, Any] | None:
        request_id = str(request_id or '').strip()
        if not request_id:
            return None
        self.poll()
        value = self.matches.get(request_id)
        return dict(value) if value else None

def parse_progress_line(line: str) -> dict[str, Any] | None:
    """Parse Ollama slog text or JSON, admitting only numeric progress fields."""
    try:
        if line.lstrip().startswith('{'):
            raw = json.loads(line)
        else:
            raw = {}
            for key, value in _FIELDS.findall(line):
                raw[key] = json.loads(value) if value.startswith('"') else value
        if not isinstance(raw, dict):
            return None
        label = str(raw.get('msg') or raw.get('message') or '').lower()
        if label == 'generation progress':
            phase = 'generating'
        elif label in {'prompt processing progress', 'prompt processing', 'prefill progress'}:
            phase = 'prompt_processing'
        else:
            return None
        stamp = str(raw.get('time') or raw.get('timestamp') or '')
        parsed = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            return None  # do not guess the server clock's timezone
        result: dict[str, Any] = {'phase': phase, 'sample_time': parsed.timestamp()}
        for key in ('generated', 'elapsed_ms', 'live_tps', 'avg_tps', 'processed', 'total'):
            n = number(raw.get(key))
            if n is not None:
                result[key] = n
        if raw.get('model'):
            result['model'] = str(raw['model'])
        if phase == 'generating' and ('generated' not in result or 'elapsed_ms' not in result):
            return None
        return result
    except (ValueError, TypeError, OverflowError):
        return None


class OllamaLogReader:
    """Request-scoped tail cursor. No historical scan, no tail subprocess.

    Unlabelled server logs cannot identify concurrent requests. Disable them
    for ALL overlapping HarnessyXO requests to an endpoint and reject generation
    origins/counter resets that indicate another stream. External clients remain
    a limitation of an upstream log format without request IDs.
    """
    def __init__(self, base_url: str, model: str, profile: dict[str, Any], *, started_at: float | None = None) -> None:
        parsed = urlsplit(base_url)
        self.endpoint = f'{parsed.hostname}:{parsed.port or (443 if parsed.scheme == "https" else 80)}'
        # All local aliases share one registry key at a given server port.
        is_local = local_endpoint(base_url)
        if is_local:
            self.endpoint = f'local:{parsed.port or 11434}'
        self.model = model.removesuffix(':latest')
        self.started_at = time.time() if started_at is None else started_at
        self.enabled = bool(profile.get('ollama_live_log_enabled', True))
        configured = str(profile.get('ollama_live_log_path') or '').strip()
        self.paths = ([Path(configured).expanduser()] if configured else
                      [Path('/tmp/ollama.err'), Path.home() / '.ollama/logs/server.log']) if (configured or is_local) and self.enabled else []
        self.cursors: dict[Path, tuple[int, int, int, bytes]] = {}
        self.latest: dict[str, Any] | None = None
        self.last_sample: dict[str, Any] | None = None
        self.origin: float | None = None
        self.source_path: Path | None = None
        self.ambiguous = False
        self.overlap = asyncio.Event()
        self.closed = False
        # Register even when this request doesn't read a log, to inhibit a
        # concurrent reader which would otherwise claim its progress as its own.
        active = _ACTIVE_LOG_READERS.setdefault(self.endpoint, set())
        if active:
            self.ambiguous = True
            self.overlap.set()
            for reader in active:
                reader.ambiguous = True
                reader.overlap.set()
                reader.latest = None
        active.add(self)

    def prime(self) -> None:
        for path in self.paths:
            try:
                st = path.stat()
                if stat.S_ISREG(st.st_mode):
                    self.cursors[path] = (st.st_dev, st.st_ino, st.st_size, b'')
            except OSError:
                pass

    def close(self) -> None:
        self.closed = True
        self.latest = None
        readers = _ACTIVE_LOG_READERS.get(self.endpoint)
        if readers is not None:
            readers.discard(self)
            if not readers:
                _ACTIVE_LOG_READERS.pop(self.endpoint, None)

    def poll(self, *, now: float | None = None) -> dict[str, Any] | None:
        now = time.time() if now is None else now
        if self.closed or self.ambiguous or not self.paths:
            return None
        for path in self.paths:
            if self.source_path is not None and path != self.source_path:
                continue
            try:
                # O_NONBLOCK protects even a racing replacement with a FIFO.
                fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0))
                with os.fdopen(fd, 'rb') as handle:
                    st = os.fstat(handle.fileno())
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    dev, inode, pos, partial = self.cursors.get(path, (st.st_dev, st.st_ino, 0, b''))
                    if (dev, inode) != (st.st_dev, st.st_ino) or st.st_size < pos:
                        pos, partial = 0, b''
                        self.latest = None
                    if st.st_size - pos > MAX_READ:
                        pos, partial = st.st_size - MAX_READ, b''
                        handle.seek(pos)
                        handle.readline(MAX_READ)  # skip the first partial record
                    else:
                        handle.seek(pos)
                    blob = partial + handle.read(MAX_READ)
                    pieces = blob.split(b'\n')
                    self.cursors[path] = (st.st_dev, st.st_ino, handle.tell(), pieces.pop()[-MAX_READ:])
                for raw in pieces:
                    sample = parse_progress_line(raw.decode('utf-8', errors='replace'))
                    if not sample:
                        continue
                    stamp = sample['sample_time']
                    if stamp < self.started_at or stamp > now + .25 or now - stamp > RATE_TTL:
                        continue
                    if sample.get('model') and str(sample['model']).removesuffix(':latest') != self.model:
                        continue
                    if sample['phase'] == 'generating':
                        origin = stamp - sample['elapsed_ms'] / 1000
                        if origin < self.started_at - .05:
                            continue  # another request was already running when we started
                        if self.origin is not None and abs(origin - self.origin) > 1.5:
                            self.ambiguous = True; self.latest = None
                            return None
                        previous = self.last_sample
                        if previous and (sample['generated'] < previous.get('generated', 0) or
                                         sample['elapsed_ms'] < previous.get('elapsed_ms', 0)):
                            self.ambiguous = True; self.latest = None
                            return None
                        sample.update(generation_rate(sample, previous))
                        self.origin = origin
                        self.last_sample = sample
                    self.source_path = path
                    # Keep the observation clock stable when no new log record
                    # arrived: polling the same sample is not fresh telemetry.
                    sample['tps_observed_at'] = time.perf_counter() - max(0.0, now - stamp)
                    self.latest = sample
            except OSError:
                continue
        if self.latest and 0 <= now - self.latest['sample_time'] <= RATE_TTL:
            result = {k: v for k, v in self.latest.items() if k not in {'sample_time', 'model'}}
            result['tps_source'] = 'ollama_log'
            return result
        return None


class LiveRateSelection:
    """Merge optional sources without letting a context-only ping erase TPS."""
    def __init__(self) -> None:
        self.samples: dict[str, dict[str, Any]] = {}

    def update(self, source: str, sample: dict[str, Any], now: float) -> None:
        rate = number(sample.get('tps'))
        if rate is not None:
            self.samples[source] = {
                'tps': rate, 'tps_kind': sample.get('tps_kind') or 'live',
                'tps_source': source,
                'tps_observed_at': sample.get('tps_observed_at', now),
            }

    def current(self, now: float) -> dict[str, Any]:
        fresh = [s for s in self.samples.values() if 0 <= now - float(s['tps_observed_at']) <= RATE_TTL]
        if not fresh:
            return {'tps': 0.0, 'tps_kind': 'unavailable', 'tps_source': '', 'tps_observed_at': 0.0}
        rank = {'live': 0, 'average': 1, 'delta': 2}
        return dict(min(fresh, key=lambda s: (rank.get(str(s['tps_kind']), 3), -float(s['tps_observed_at']))))
