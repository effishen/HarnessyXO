from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import time
import uuid
from copy import deepcopy
from collections.abc import AsyncIterator
from contextlib import aclosing
from typing import Any

import httpx

from harnessy.diagnostics import log_event, log_stream_event
from harnessy.agent.telemetry import (LiveRateSelection, OllamaLogReader, OmlxPrefixCacheLogReader, UnscopedTelemetryLease, generation_rate,
    llama_cpp_stream_status, llama_cpp_prompt_progress, _LLAMA_TIMING_FIELDS, omlx_stream_status, omlx_activity_status, omlx_request_health, number)
from harnessy.agent.stream_watchdog import StreamProgressWatchdog, watched_queue
from harnessy.core.thinking import (canonical, resolve_thinking, thinking_payload, model_family, level_label,
    detected_profile, control_description, model_default_status, ThinkingConfigurationError)
from harnessy.agent.thinking_probe import verify_native_thinking


def _optional_float(value: Any) -> float | None:
    if value is None or value == '':
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _optional_int(value: Any) -> int | None:
    if value is None or value == '':
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class LLMServerError(RuntimeError):
    """Structured HTTP error from an LLM backend.

    Preserve the provider's machine-readable error code/fields so the agent
    runtime can recover from specific backend conditions without brittle text
    matching. The human-readable RuntimeError string remains compatible with
    existing callers and diagnostics.
    """

    def __init__(self, status_code: int, body: str, *, provider_label: str = 'LLM server') -> None:
        self.status_code = int(status_code)
        self.body = str(body or '')
        self.payload: dict[str, Any] = {}
        self.error: dict[str, Any] = {}
        try:
            parsed = json.loads(self.body)
        except (TypeError, json.JSONDecodeError):
            parsed = {}
        if isinstance(parsed, dict):
            self.payload = parsed
            candidate = parsed.get('error')
            if isinstance(candidate, dict):
                self.error = candidate
            elif isinstance(candidate, str):
                self.error = {'message': candidate}
        self.code = str(self.error.get('omlx_code') or self.error.get('code') or '').strip()
        provider_codes = {
            str(self.error.get(field) or '').strip().casefold()
            for field in ('omlx_code', 'code')
        }
        # Some oMLX streaming failures are delivered as an SSE error object
        # after HTTP 200 rather than as an HTTP error response. Older builds may
        # omit the structured omlx_code on that path, or expose only a generic
        # numeric HTTP-ish code such as 500. Classify only the very specific
        # prefill-capacity wording that oMLX itself emits. Admission rejection
        # and a guard abort during prefill share the same context-tuning path.
        # Keep the raw provider fields/body intact for diagnostics; unrelated
        # memory errors and ordinary cancellation must not trigger tuning.
        error_text = ' '.join(str(x or '') for x in (
            self.error.get('message'), self.error.get('detail'), self.body,
        )).casefold()
        if (
            provider_codes & {'prefill_memory_exceeded', 'prefill_memory_aborted'}
            or 'prefill context too large for available memory' in error_text
            or 'prefill capacity rejected' in error_text
            or ('prefill' in error_text and 'memory guard' in error_text and 'rejected' in error_text)
            or 'memory guard aborted this request mid-prefill' in error_text
        ):
            self.code = 'prefill_memory_exceeded'
        self.estimated_bytes = _optional_int(self.error.get('estimated_bytes'))
        self.limit_bytes = _optional_int(self.error.get('limit_bytes'))
        capacity_codes = provider_codes | {str(self.error.get('type') or '').strip().casefold()}
        if capacity_codes & {'context_length_exceeded', 'exceed_context_size_error'}:
            self.code = 'context_length_exceeded'
        self.context_tokens = _optional_int(self.error.get('n_ctx'))
        self.prompt_tokens = _optional_int(self.error.get('n_prompt_tokens'))
        # This oMLX admission error has code=null. Its numbers describe model
        # loading, not the submitted prompt's prefill peak. Keep them separate
        # so context tuning cannot learn a fictitious bytes/token slope.
        self.model_load_memory: dict[str, int] = {}
        load_match = re.search(
            r'cannot load .+?:\s*projected memory\s+([\d.]+)\s*gb\s+'
            r'would exceed the metalcap memory ceiling\s+([\d.]+)\s*gb\s*'
            r'\(current:\s*([\d.]+)\s*gb,\s*model:\s*([\d.]+)\s*gb\)',
            str(self.error.get('message') or ''), re.IGNORECASE,
        )
        if self.status_code == 507 and load_match and not self.code:
            try:
                values = [int(float(value) * 1024 ** 3) for value in load_match.groups()]
            except (ValueError, OverflowError):
                values = []
            if len(values) == 4 and all(value >= 0 for value in values) and values[1] > 0:
                self.code = 'model_load_memory_exceeded'
                self.model_load_memory = dict(zip(
                    ('projected_bytes', 'ceiling_bytes', 'current_bytes', 'model_bytes'), values,
                ))
        # A fatal Metal command-buffer hang is distinct from capacity pressure.
        # Keep this narrow: generic HTTP 500s, slow prefill, and ordinary GPU
        # allocation failures must not activate the backend recovery queue gate.
        gpu_error_text = ' '.join(str(value or '') for value in (
            self.error.get('message'), self.error.get('detail'),
            self.payload.get('message'), self.payload.get('detail'),
        )).casefold()
        if not self.payload:
            gpu_error_text = self.body.casefold()
        if ('kiogpucommandbuffercallbackerrorhang' in gpu_error_text
                or ('[metal]' in gpu_error_text and 'caused gpu hang error' in gpu_error_text)):
            self.code = 'backend_gpu_hang'
        super().__init__(f'{provider_label} returned HTTP {self.status_code}: {self.body[:2000]}')


class _StreamObservation:
    """Bounded numeric receipts for one invocation, never prompts or output."""
    def __init__(self, client_request_id: str | None = None):
        self.client_request_id = client_request_id or uuid.uuid4().hex
        self.started = time.perf_counter()
        self.counts = dict(protocol_chunks=0, timings_samples=0,
                           prompt_progress_samples=0, usage_samples=0,
                           transport_events=0, malformed_json_events=0)
        self.first_payload_seconds: float | None = None
        self.first_output_seconds: float | None = None
        self.last_output_seconds: float | None = None
        self.last_payload_seconds: float | None = None
        self.accepted_seconds: float | None = None

    def event(self, payload: dict[str, Any]) -> None:
        log_stream_event({**payload, 'client_request_id': self.client_request_id})

    def transport(self, *, accepted: bool = False, malformed: bool = False) -> None:
        self.counts['transport_events'] += 1
        if accepted and self.accepted_seconds is None:
            self.accepted_seconds = max(0.0, time.perf_counter() - self.started)
        if malformed:
            self.counts['malformed_json_events'] += 1

    def observe(self, data: Any, *, provider: str) -> None:
        if not isinstance(data, dict):
            return
        elapsed = max(0.0, time.perf_counter() - self.started)
        self.counts['protocol_chunks'] += 1
        self.last_payload_seconds = elapsed
        if self.first_payload_seconds is None:
            self.first_payload_seconds = elapsed
        if StreamProgressWatchdog._payload_has_output(data):
            if self.first_output_seconds is None:
                self.first_output_seconds = elapsed
            self.last_output_seconds = elapsed
        raw_timings = data.get('timings')
        timings = {key: value for key in _LLAMA_TIMING_FIELDS
                   if isinstance(raw_timings, dict) and (value := number(raw_timings.get(key))) is not None}
        raw_usage = data.get('usage')
        usage = {key: int(value) for key in ('prompt_tokens', 'completion_tokens', 'total_tokens', 'cached_tokens')
                 if isinstance(raw_usage, dict) and (value := number(raw_usage.get(key))) is not None and value.is_integer() and value <= 2**53}
        if isinstance(raw_usage, dict) and isinstance(raw_usage.get('prompt_tokens_details'), dict):
            cached = number(raw_usage['prompt_tokens_details'].get('cached_tokens'))
            if cached is not None and cached.is_integer() and cached <= 2**53:
                usage['cached_tokens'] = int(cached)
        progress = llama_cpp_prompt_progress(data)
        self.counts['timings_samples'] += int(isinstance(raw_timings, dict))
        self.counts['prompt_progress_samples'] += int(progress is not None)
        self.counts['usage_samples'] += int(isinstance(raw_usage, dict))
        payload: dict[str, Any] = {
            'provider': provider, 'kind': 'protocol_chunk',
            'timings_present': isinstance(raw_timings, dict),
            'usage_present': isinstance(raw_usage, dict),
            'prompt_progress_present': isinstance(data.get('prompt_progress'), dict),
            'prompt_progress_valid': progress is not None,
            'timings': timings, 'usage': usage,
            'prompt_progress': progress or {},
        }
        if provider == 'ollama':
            message = data.get('message') if isinstance(data.get('message'), dict) else {}
            payload.update(
                keys=sorted(data), message_keys=sorted(message),
                content_chars=len(str(message.get('content') or '')),
                thinking_chars=len(str(message.get('thinking') or '')),
                tool_call_count=len(message.get('tool_calls') or []),
                done=data.get('done') is True, done_reason=data.get('done_reason'),
            )
        else:
            choices = data.get('choices') if isinstance(data.get('choices'), list) else []
            first = choices[0] if choices and isinstance(choices[0], dict) else {}
            delta = first.get('delta') if isinstance(first.get('delta'), dict) else {}
            payload.update(choice_count=len(choices), delta_keys=sorted(delta),
                content_chars=len(str(delta.get('content') or '')),
                reasoning_chars=len(str(delta.get('reasoning_content') or delta.get('reasoning') or '')),
                finish_reason=first.get('finish_reason'))
        self.event(payload)

    def snapshot(self) -> dict[str, Any]:
        return {**self.counts,
                'accepted_seconds': self.accepted_seconds,
                'first_payload_seconds': self.first_payload_seconds,
                'first_output_seconds': self.first_output_seconds,
                'last_output_seconds': self.last_output_seconds,
                'last_payload_seconds': self.last_payload_seconds,
                'elapsed_seconds': max(0.0, time.perf_counter() - self.started)}

    def log(self, *, provider: str, observation: str) -> None:
        log_event('backend', 'stream_observation', provider=provider,
                  client_request_id=self.client_request_id,
                  observation=observation, **self.snapshot())


class OpenAICompatibleClient:
    """Unified client for OpenAI-compatible, oMLX, llama.cpp, and native Ollama APIs.

    HarnessyXO keeps one model-profile format. Auto mode routes Ollama through
    /api/chat, recognizes oMLX and llama.cpp while retaining their OpenAI-compatible
    chat transport, and leaves other compatible servers on /v1/chat/completions.
    """

    def __init__(self, profile: dict[str, Any], *, model_override: str | None = None, thinking: str | None = None) -> None:
        self.profile = deepcopy(profile)
        self.base_url = str(profile.get('base_url', '')).rstrip('/')
        self.model = str(model_override or profile.get('model', '')).strip()
        self.profile['model'] = self.model  # capability/proof identity follows the actual request model
        self.api_key = str(profile.get('api_key', '')).strip()
        self.omlx_admin_api_key = str(profile.get('omlx_admin_api_key') or '').strip()
        self._omlx_admin_login_unavailable = False
        self.temperature = _optional_float(profile.get('temperature'))
        self.thinking_selection = canonical(thinking)
        self.thinking = resolve_thinking(profile, self.thinking_selection)
        self._show_metadata: dict[str, Any] | None = None
        self.api_mode = str(profile.get('api_mode') or 'auto').strip().lower()
        self._detected_backend: str | None = None
        self._detected_llamacpp: bool | None = None
        self._detected_omlx: bool | None = None
        self._last_runtime_context_window: int | None = None
        if not self.base_url:
            raise ValueError('Provider base URL is empty')
        if not self.model:
            raise ValueError('Provider model is empty')

    @property
    def endpoint(self) -> str:
        return f'{self.base_url}/chat/completions'

    @property
    def models_endpoint(self) -> str:
        return f'{self.base_url}/models'

    @property
    def ollama_root(self) -> str:
        base = self.base_url.rstrip('/')
        return base[:-3].rstrip('/') if base.endswith('/v1') else base

    @property
    def omlx_admin_login_endpoint(self) -> str:
        return f'{self.ollama_root}/admin/api/login'

    @property
    def omlx_activity_endpoint(self) -> str:
        # oMLX mounts its admin surface at the server root, while model profiles
        # normally point at the OpenAI-compatible /v1 base.
        return f'{self.ollama_root}/admin/api/activity'

    def _headers(self) -> dict[str, str]:
        headers = {'Content-Type': 'application/json'}
        if self.api_key:
            headers['Authorization'] = f'Bearer {self.api_key}'
        return headers

    @staticmethod
    def _has_image_input(messages: list[dict[str, Any]]) -> bool:
        for msg in messages:
            if msg.get('_harnessy_images'):
                return True
            content = msg.get('content')
            if isinstance(content, list) and any(
                isinstance(part, dict) and part.get('type') == 'image_url'
                for part in content
            ):
                return True
        return False

    async def _probe_ollama(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(2.0)) as client:
                response = await client.get(f'{self.ollama_root}/api/version', headers=self._headers())
                return (
                    response.status_code < 400
                    and isinstance(response.json(), dict)
                    and bool(response.json().get('version'))
                )
        except Exception:
            return False

    async def _probe_llamacpp(self) -> bool:
        """Detect llama-server without changing the selected API protocol.

        Current llama.cpp identifies OpenAI-compatible model rows with
        ``owned_by: llamacpp``.  Detection is cached per client.  Failure stays
        silent because ordinary OpenAI-compatible servers remain supported.
        """
        if self._detected_llamacpp is not None:
            return self._detected_llamacpp
        base = self.base_url.rstrip('/')
        candidates = [f'{base}/models']
        if not base.endswith('/v1'):
            candidates.append(f'{base}/v1/models')
        candidates = list(dict.fromkeys(candidates))
        detected = False
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(2.0)) as client:
                for url in candidates:
                    try:
                        response = await client.get(url, headers=self._headers())
                        if response.status_code >= 400:
                            continue
                        data = response.json()
                        if not isinstance(data, dict):
                            continue
                        rows = data.get('data') if isinstance(data.get('data'), list) else data.get('models')
                        if not isinstance(rows, list):
                            continue
                        for row in rows:
                            if not isinstance(row, dict):
                                continue
                            owner = str(row.get('owned_by') or '').strip().casefold()
                            if owner in {'llamacpp', 'llama.cpp', 'llama-cpp'}:
                                detected = True
                                break
                        if detected:
                            break
                    except Exception:
                        continue
        except Exception:
            detected = False
        self._detected_llamacpp = detected
        return detected

    async def _probe_omlx(self) -> bool:
        """Detect oMLX from its OpenAI-compatible model ownership marker."""
        if self._detected_omlx is not None:
            return self._detected_omlx
        base = self.base_url.rstrip('/')
        candidates = [f'{base}/models']
        if not base.endswith('/v1'):
            candidates.append(f'{base}/v1/models')
        candidates = list(dict.fromkeys(candidates))
        detected = False
        llama_detected = False
        saw_listing = False
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(2.0)) as client:
                for url in candidates:
                    try:
                        response = await client.get(url, headers=self._headers())
                        if response.status_code >= 400:
                            continue
                        data = response.json()
                        if not isinstance(data, dict):
                            continue
                        rows = data.get('data') if isinstance(data.get('data'), list) else data.get('models')
                        if not isinstance(rows, list):
                            continue
                        saw_listing = True
                        for row in rows:
                            if not isinstance(row, dict):
                                continue
                            owner = str(row.get('owned_by') or '').strip().casefold()
                            if owner == 'omlx':
                                detected = True
                            elif owner in {'llamacpp', 'llama.cpp', 'llama-cpp'}:
                                llama_detected = True
                        if detected or llama_detected:
                            break
                    except Exception:
                        continue
        except Exception:
            detected = False
        self._detected_omlx = detected
        # Auto detection checks oMLX before llama.cpp. Reuse the same model-list
        # response for llama.cpp instead of making a second identical probe.
        if saw_listing:
            self._detected_llamacpp = llama_detected
        return detected

    async def omlx_runtime_status(
        self, client: httpx.AsyncClient | None = None, *, request_id: str = '',
    ) -> dict[str, Any] | None:
        """Return best-effort live oMLX prefill/decode activity for this model.

        ``/admin/api/activity`` is session-authenticated by current oMLX.  Use
        the same long-lived HTTP client as the poller so a successful admin
        login cookie is retained for the rest of the model call.  The normal
        model API key is tried as the admin key by default; a separate
        ``omlx_admin_api_key`` can be supplied when the model API uses an oMLX
        sub-key (sub-keys intentionally cannot log into the admin surface).

        This is telemetry only: missing/older endpoints and authentication
        failures never fail the model request itself.
        """
        try:
            if client is not None:
                reachable, payload = await self._omlx_activity_payload(client)
                return omlx_activity_status(payload, model_id=self.model, request_id=request_id) if reachable else None
            async with httpx.AsyncClient(timeout=httpx.Timeout(2.0)) as active_client:
                reachable, payload = await self._omlx_activity_payload(active_client)
                return omlx_activity_status(payload, model_id=self.model, request_id=request_id) if reachable else None
        except Exception:
            return None

    async def _omlx_activity_payload(self, active_client: httpx.AsyncClient) -> tuple[bool, Any]:
        """Fetch one authenticated oMLX activity snapshot for telemetry/health."""
        response = await active_client.get(self.omlx_activity_endpoint, headers=self._headers())
        if response.status_code == 401 and not self._omlx_admin_login_unavailable:
            admin_key = self.omlx_admin_api_key or self.api_key
            if admin_key:
                login = await active_client.post(
                    self.omlx_admin_login_endpoint,
                    headers={'Content-Type': 'application/json'},
                    json={'api_key': admin_key, 'remember': False},
                )
                if login.status_code < 400:
                    response = await active_client.get(self.omlx_activity_endpoint, headers=self._headers())
                else:
                    self._omlx_admin_login_unavailable = True
            else:
                self._omlx_admin_login_unavailable = True
        if response.status_code >= 400:
            return False, None
        try:
            payload = response.json()
        except Exception:
            return False, None
        return isinstance(payload, dict), payload

    async def _stream_health_probe(self, backend: str, request_id: str = '') -> dict[str, Any]:
        """Read-only, best-effort stream health probe with generic fallback."""
        normalized = str(backend or 'openai').strip().lower()
        if normalized == 'omlx':
            try:
                async with httpx.AsyncClient(timeout=httpx.Timeout(3.0)) as client:
                    reachable, payload = await self._omlx_activity_payload(client)
                if not reachable:
                    return {
                        'backend_reachable': False, 'request_state': 'unknown',
                        'request_scoped': False, 'evidence': 'activity_unavailable',
                    }
                return omlx_request_health(payload, model_id=self.model, request_id=request_id)
            except Exception:
                return {
                    'backend_reachable': False, 'request_state': 'unknown',
                    'request_scoped': False, 'evidence': 'activity_probe_failed',
                }

        if normalized == 'ollama':
            try:
                runtime = await self.ollama_runtime_status()
            except Exception:
                runtime = None
            if isinstance(runtime, dict) and str(runtime.get('phase') or '') in {
                'prompt_processing', 'prefill', 'generating', 'waiting',
            }:
                return {
                    'backend_reachable': True, 'request_state': 'active',
                    'request_scoped': False, 'evidence': 'provider_runtime_activity',
                }
            probe_url = f'{self.ollama_root}/api/version'
        else:
            probe_url = self.models_endpoint

        # A reachable endpoint is useful diagnostic evidence, but generic
        # OpenAI-compatible and stock Ollama endpoints cannot prove that this
        # exact generation still exists. Never promote reachability to request
        # liveness or use it for early termination.
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(3.0)) as client:
                response = await client.get(probe_url, headers=self._headers())
            return {
                'backend_reachable': True,
                'request_state': 'unknown',
                'request_scoped': False,
                'evidence': f'health_http_{int(response.status_code)}',
            }
        except Exception:
            return {
                'backend_reachable': False,
                'request_state': 'unknown',
                'request_scoped': False,
                'evidence': 'health_probe_failed',
            }

    @staticmethod
    async def fetch_models(base_url: str, api_key: str = '') -> list[str]:
        """Fetch model ids from OpenAI-compatible or Ollama model-list APIs."""
        base = base_url.rstrip('/')
        candidates = [f'{base}/models']
        if not base.endswith('/v1'):
            candidates.append(f'{base}/v1/models')
        root = base[:-3].rstrip('/') if base.endswith('/v1') else base
        candidates.append(f'{root}/api/tags')
        candidates = list(dict.fromkeys(candidates))
        headers: dict[str, str] = {}
        if api_key.strip():
            headers['Authorization'] = f'Bearer {api_key.strip()}'
        last_error: Exception | None = None
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
            for url in candidates:
                try:
                    response = await client.get(url, headers=headers)
                    if response.status_code >= 400:
                        last_error = RuntimeError(f'HTTP {response.status_code}: {response.text[:500]}')
                        continue
                    data = response.json()
                    if isinstance(data, dict) and isinstance(data.get('models'), list):
                        items = data.get('models') or []
                    else:
                        items = data.get('data', data if isinstance(data, list) else []) if isinstance(data, dict) else data
                    models: list[str] = []
                    for item in items or []:
                        if isinstance(item, str):
                            models.append(item)
                        elif isinstance(item, dict):
                            model_id = item.get('id') or item.get('model') or item.get('name')
                            if model_id:
                                models.append(str(model_id))
                    if models:
                        return sorted(set(models), key=str.lower)
                    last_error = RuntimeError('The server returned no model IDs')
                except Exception as exc:
                    last_error = exc
        raise RuntimeError(f'Could not fetch models: {last_error or "unknown error"}')

    async def _detect_backend(self) -> str:
        if self.api_mode in {'ollama', 'ollama-native', 'native-ollama'}:
            return 'ollama'
        if self.api_mode in {'omlx', 'o-mlx'}:
            return 'omlx'
        if self.api_mode in {'llamacpp', 'llama.cpp', 'llama-cpp'}:
            return 'llamacpp'
        if self.api_mode in {'openai', 'openai-compatible'}:
            return 'openai'
        if self._detected_backend:
            return self._detected_backend
        if await self._probe_ollama():
            self._detected_backend = 'ollama'
            return 'ollama'
        if await self._probe_omlx():
            self._detected_backend = 'omlx'
            return 'omlx'
        if await self._probe_llamacpp():
            self._detected_backend = 'llamacpp'
            return 'llamacpp'
        self._detected_backend = 'openai'
        return 'openai'

    async def detect_backend(self) -> str:
        """Return the backend HarnessyXO would use for this profile."""
        return await self._detect_backend()

    @staticmethod
    def _normalize_ollama_runtime_status(data: Any) -> dict[str, Any]:
        """Normalize both HarnessyXO's enhanced Ollama status and /api/ps data.

        Stock Ollama does not expose request phase progress through /api/chat
        while a long prefill is still blocking response headers.  Some recent
        MLX-enabled builds expose ``/v1/status`` with richer live information.
        HarnessyXO intentionally treats that endpoint as optional and falls back
        to the standard process listing for the effective context length.
        """
        leaves: list[tuple[str, Any]] = []

        def walk(value: Any, path: str = '') -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    next_path = f'{path}.{key}' if path else str(key)
                    walk(child, next_path)
                return
            if isinstance(value, list):
                for index, child in enumerate(value):
                    walk(child, f'{path}[{index}]')
                return
            leaves.append((path.lower(), value))

        walk(data)

        def positive_int_for_keys(keys: set[str]) -> int | None:
            for path, value in leaves:
                key = path.rsplit('.', 1)[-1].split('[', 1)[0]
                if key not in keys:
                    continue
                try:
                    number = int(value)
                except (TypeError, ValueError):
                    continue
                if number > 0:
                    return number
            return None

        phase: str | None = None
        phase_keys = {'status', 'state', 'phase', 'request_status', 'request_state'}
        # Prefer explicit request/status fields over unrelated strings such as
        # model names or backend descriptions.
        candidate_strings: list[str] = []
        for path, value in leaves:
            key = path.rsplit('.', 1)[-1].split('[', 1)[0]
            if key in phase_keys and isinstance(value, str):
                candidate_strings.append(value.lower())
        for value in candidate_strings:
            if any(word in value for word in ('prompt processing', 'prompt_processing', 'prefill', 'processing prompt')):
                phase = 'prompt_processing'
                break
            if any(word in value for word in ('generating', 'generation', 'decoding', 'decode')):
                phase = 'generating'
                break
            if any(word in value for word in ('waiting', 'queued', 'loading')):
                phase = 'waiting'
                break
            if any(word in value for word in ('idle', 'ready')):
                phase = 'idle'
                break

        context_window = positive_int_for_keys({
            'num_ctx', 'context_length', 'context_window', 'context_limit',
            'max_context', 'max_context_length',
        })
        context_used = positive_int_for_keys({
            'context_tokens', 'context_used', 'current_context', 'prompt_tokens',
        })
        processed = positive_int_for_keys({'processed', 'processed_tokens', 'prompt_processed'})
        total = positive_int_for_keys({'total', 'total_tokens', 'prompt_total'})
        generated = positive_int_for_keys({'generated', 'generated_tokens', 'eval_count'})
        # Preserve live/average provenance; never promote a running average
        # to an instantaneous rate, and admit an explicit live rate of zero.
        flat: dict[str, Any] = {}
        for path, value in leaves:
            flat.setdefault(path.rsplit('.', 1)[-1].split('[', 1)[0], value)
        rate = generation_rate(flat)

        result: dict[str, Any] = {}
        if phase:
            result['phase'] = phase
        if context_window:
            result['context_window'] = context_window
        if context_used:
            result['context_used'] = context_used
        if processed:
            result['processed'] = processed
        if total:
            result['total'] = total
        if generated:
            result['generated'] = generated
        result.update(rate)
        return result

    def _select_runtime_status(self, data: Any) -> Any:
        if not isinstance(data, dict):
            return {}
        target = self.model.removesuffix(':latest')
        explicit_model = data.get('model')
        if isinstance(explicit_model, str) and explicit_model.removesuffix(':latest') != target:
            return {}
        for name in ('requests', 'runners', 'models'):
            rows = data.get(name)
            if not isinstance(rows, list):
                continue
            matches = [r for r in rows if isinstance(r, dict) and
                       str(r.get('model') or r.get('name') or '').removesuffix(':latest') == target]
            if len(matches) == 1:
                return matches[0]
            if len(rows) == 1 and isinstance(rows[0], dict) and not (rows[0].get('model') or rows[0].get('name')):
                return rows[0]
            return {}  # ambiguous/unrelated server snapshot is not our TPS
        return data

    async def ollama_runtime_status(self) -> dict[str, Any] | None:
        """Return optional live Ollama phase/context information.

        ``/v1/status`` is used when an Ollama build exposes it.  For ordinary
        Ollama installations, ``/api/ps`` is consulted once to discover the
        loaded runner's effective context length.  Failure is deliberately
        silent because these are telemetry helpers, not prerequisites for chat.
        """
        if await self._detect_backend() != 'ollama':
            return None

        normalized: dict[str, Any] = {}
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(1.5)) as client:
                response = await client.get(f'{self.ollama_root}/v1/status', headers=self._headers())
                if response.status_code < 400:
                    normalized.update(self._normalize_ollama_runtime_status(self._select_runtime_status(response.json())))
        except Exception:
            pass

        runtime_ctx = int(normalized.get('context_window') or self._last_runtime_context_window or 0)
        if runtime_ctx <= 0:
            try:
                async with httpx.AsyncClient(timeout=httpx.Timeout(1.5)) as client:
                    response = await client.get(f'{self.ollama_root}/api/ps', headers=self._headers())
                    if response.status_code < 400:
                        data = response.json()
                        models = data.get('models') if isinstance(data, dict) else None
                        selected: Any = None
                        if isinstance(models, list):
                            target = self.model.removesuffix(':latest')
                            selected = next((row for row in models if isinstance(row, dict) and
                                str(row.get('name') or row.get('model') or '').removesuffix(':latest') == target), None)
                        # A single loaded DIFFERENT model is not this chat's
                        # context limit. A reachable server need not have our model loaded.
                        ps_status = self._normalize_ollama_runtime_status(selected or {})
                        runtime_ctx = int(ps_status.get('context_window') or 0)
            except Exception:
                runtime_ctx = 0
        if runtime_ctx > 0:
            self._last_runtime_context_window = runtime_ctx
            normalized['context_window'] = runtime_ctx
        return normalized or None

    async def model_metadata(self, *, refresh: bool = False) -> dict[str, Any] | None:
        """Read /api/show without starting inference. Missing data stays unknown."""
        if self._show_metadata is not None and not refresh:
            return deepcopy(self._show_metadata)
        if await self._detect_backend() != 'ollama':
            return None
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(6.0)) as client:
                response = await client.post(f'{self.ollama_root}/api/show',
                    headers=self._headers(), json={'model': self.model})
                response.raise_for_status()
                data = response.json()
            if not isinstance(data, dict):
                return None
            self._show_metadata = data
            return deepcopy(data)
        except Exception:
            return None

    async def model_capabilities(self) -> set[str] | None:
        data = await self.model_metadata()
        if not data or not isinstance(data.get('capabilities'), list):
            return None
        return {str(x).strip().lower() for x in data['capabilities'] if str(x).strip()}

    @staticmethod
    def _same_model_id(left: Any, right: Any) -> bool:
        """Compare model IDs without inventing family/name heuristics."""
        a = str(left or '').strip()
        b = str(right or '').strip()
        return bool(a and b and (a == b or a.removesuffix(':latest') == b.removesuffix(':latest')))

    async def openai_model_row(self) -> dict[str, Any] | None:
        """Return this model's OpenAI-compatible listing row when available."""
        base = self.base_url.rstrip('/')
        candidates = [f'{base}/models']
        if not base.endswith('/v1'):
            candidates.append(f'{base}/v1/models')
        async with httpx.AsyncClient(timeout=httpx.Timeout(4.0)) as client:
            for url in dict.fromkeys(candidates):
                try:
                    response = await client.get(url, headers=self._headers())
                    if response.status_code >= 400:
                        continue
                    data = response.json()
                    if not isinstance(data, dict):
                        continue
                    rows = data.get('data') if isinstance(data.get('data'), list) else data.get('models')
                    if not isinstance(rows, list):
                        continue
                    for row in rows:
                        if isinstance(row, dict) and self._same_model_id(
                            row.get('id') or row.get('model') or row.get('name'), self.model
                        ):
                            return deepcopy(row)
                except Exception:
                    continue
        return None

    async def omlx_model_status(self) -> dict[str, Any] | None:
        """Read oMLX's passive per-model status/capability metadata.

        This endpoint does not run inference.  Older oMLX builds may not expose
        it; absence is deliberately treated as unknown rather than unsupported.
        """
        if await self._detect_backend() != 'omlx':
            return None
        base = self.base_url.rstrip('/')
        candidates = [f'{base}/models/status'] if base.endswith('/v1') else [
            f'{base}/v1/models/status', f'{base}/models/status'
        ]
        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
            for url in dict.fromkeys(candidates):
                try:
                    response = await client.get(url, headers=self._headers())
                    if response.status_code >= 400:
                        continue
                    data = response.json()
                    if not isinstance(data, dict) or not isinstance(data.get('models'), list):
                        continue
                    for row in data['models']:
                        if isinstance(row, dict) and self._same_model_id(
                            row.get('id') or row.get('model') or row.get('name'), self.model
                        ):
                            result = deepcopy(row)
                            result['_harnessy_endpoint'] = url
                            return result
                except Exception:
                    continue
        return None

    async def llamacpp_props(self) -> dict[str, Any] | None:
        """Read llama.cpp GET /props capability metadata without inference."""
        if await self._detect_backend() != 'llamacpp':
            return None
        root = self.base_url[:-3].rstrip('/') if self.base_url.endswith('/v1') else self.base_url.rstrip('/')
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
                response = await client.get(f'{root}/props', headers=self._headers())
                if response.status_code >= 400:
                    return None
                data = response.json()
                return deepcopy(data) if isinstance(data, dict) else None
        except Exception:
            return None

    async def _compatibility_acceptance_probe(self, extra: dict[str, Any], *,
                                              messages: list[dict[str, Any]] | None = None) -> tuple[bool | None, str]:
        """Tiny, explicit manual probe for OpenAI-compatible request fields.

        A 2xx response proves that the selected endpoint/model accepts the
        request shape.  A 4xx proves rejection.  Transport/server failures stay
        unknown.  This helper is never used by automatic background detection,
        because even a one-token completion can load a large local model.
        """
        payload: dict[str, Any] = {
            'model': self.model,
            'messages': messages or [{'role': 'user', 'content': 'Reply with one character: X'}],
            'stream': False,
            'max_tokens': 1,
            'temperature': 0,
        }
        payload.update(deepcopy(extra))
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(connect=10.0, read=90.0, write=30.0, pool=10.0)) as client:
                response = await client.post(self.endpoint, headers=self._headers(), json=payload)
                if response.status_code < 300:
                    return True, f'HTTP {response.status_code}'
                if 400 <= response.status_code < 500:
                    return False, f'HTTP {response.status_code}: {response.text[:300]}'
                return None, f'HTTP {response.status_code}: {response.text[:300]}'
        except Exception as exc:
            return None, str(exc)[:300]

    async def detect_capability_profile(self, *, active_probes: bool = False) -> dict[str, Any]:
        """Return a capability-enriched profile for Ollama/oMLX/llama.cpp/OAI APIs.

        Passive metadata is preferred and is safe for automatic detection.
        ``active_probes=True`` is reserved for the user's explicit Detect button;
        it may issue tiny one-token compatibility requests for otherwise unknown
        API-shape features.  Unknown never means unsupported and therefore never
        clears an existing manual switch.
        """
        result = deepcopy(self.profile)
        backend = await self._detect_backend()
        fields: dict[str, dict[str, Any]] = {}

        def record(name: str, value: bool | None, source: str, *, confidence: str = 'provider-reported', detail: str = '') -> None:
            state = 'unknown' if value is None else ('supported' if value else 'unsupported')
            fields[name] = {'state': state, 'source': source, 'confidence': confidence, 'detail': detail}
            if value is not None:
                result[name] = bool(value)

        # Generic model-list metadata is useful even when the server does not
        # identify itself as one of HarnessyXO's optimized backends.
        listing = await self.openai_model_row() if backend != 'ollama' else None
        if listing:
            caps_raw = listing.get('capabilities')
            if isinstance(caps_raw, list):
                caps = {str(x).strip().lower().replace('-', '_') for x in caps_raw if str(x).strip()}
            elif isinstance(caps_raw, dict):
                caps = {str(k).strip().lower().replace('-', '_') for k, v in caps_raw.items() if v is True}
            else:
                caps = set()
            modalities_raw = listing.get('modalities')
            if modalities_raw is None:
                architecture = listing.get('architecture') if isinstance(listing.get('architecture'), dict) else {}
                modalities_raw = architecture.get('input_modalities')
            if isinstance(modalities_raw, dict) and isinstance(modalities_raw.get('vision'), bool):
                record('supports_vision', bool(modalities_raw['vision']), 'OpenAI-compatible /models modalities.vision')
            elif isinstance(modalities_raw, list):
                mods = {str(x).strip().lower() for x in modalities_raw}
                record('supports_vision', bool({'image', 'vision'} & mods), 'OpenAI-compatible /models modalities')
            if caps:
                if 'supports_vision' not in fields and {'vision', 'image', 'multimodal'} & caps:
                    record('supports_vision', True, 'OpenAI-compatible /models capabilities')
                if {'thinking', 'reasoning'} & caps:
                    record('supports_thinking', True, 'OpenAI-compatible /models capabilities')
                if {'reasoning_effort', 'reasoning_levels'} & caps:
                    record('supports_reasoning_effort', True, 'OpenAI-compatible /models capabilities')
                if {'streaming_usage', 'usage_stream', 'stream_usage'} & caps:
                    record('supports_usage_stream', True, 'OpenAI-compatible /models capabilities')
                if {'developer_role', 'developer'} & caps:
                    record('supports_developer_role', True, 'OpenAI-compatible /models capabilities')
                if {'strict_tool_schema', 'strict_tools', 'strict_mode'} & caps:
                    record('supports_strict_mode', True, 'OpenAI-compatible /models capabilities')

        if backend == 'ollama':
            metadata = await self.model_metadata(refresh=True)
            if metadata and isinstance(metadata.get('capabilities'), list):
                result = detected_profile(result, metadata, version=await self.ollama_version())
                caps = {str(x).strip().lower() for x in metadata['capabilities'] if str(x).strip()}
                record('supports_vision', 'vision' in caps, 'Ollama /api/show')
                record('supports_thinking', 'thinking' in caps, 'Ollama /api/show')
                # Native Ollama streaming ends with authoritative token counters.
                record('supports_usage_stream', True, 'Ollama native /api/chat stream')
                if result.get('supports_reasoning_effort'):
                    record('supports_reasoning_effort', True, 'Ollama model-family metadata')
            else:
                fields.setdefault('supports_vision', {'state': 'unknown', 'source': 'Ollama /api/show unavailable', 'confidence': 'unknown', 'detail': ''})
                fields.setdefault('supports_thinking', {'state': 'unknown', 'source': 'Ollama /api/show unavailable', 'confidence': 'unknown', 'detail': ''})

        elif backend == 'omlx':
            status = await self.omlx_model_status()
            record('supports_usage_stream', True, 'oMLX streaming usage/timing API')
            if status:
                model_type = str(status.get('model_type') or '').strip().lower()
                engine_type = str(status.get('engine_type') or '').strip().lower()
                if model_type or engine_type:
                    is_vision = model_type in {'vlm', 'vision', 'ocr'} or engine_type == 'vlm'
                    is_text = model_type in {'llm', 'text'} and engine_type not in {'vlm'}
                    if is_vision or is_text:
                        record('supports_vision', is_vision, 'oMLX /v1/models/status',
                               detail=f'model_type={model_type or "?"}, engine_type={engine_type or "?"}')
                thinking_marker = status.get('thinking_default')
                if thinking_marker is None:
                    thinking_marker = status.get('supports_thinking')
                if thinking_marker is not None:
                    # Presence of thinking_default is capability evidence even
                    # when the configured default is false.
                    record('supports_thinking', True, 'oMLX /v1/models/status',
                           detail=f'thinking_default={status.get("thinking_default")!r}')
                    result['thinking_mode'] = 'chat_template_kwargs'
                    family = model_family(result, status)
                    result['thinking_detection'] = {
                        'source': 'oMLX /v1/models/status', 'backend': 'omlx',
                        'profile_identity': hashlib.sha256(json.dumps([
                            str(result.get(k) or '').rstrip('/') for k in ('base_url','model','api_mode')
                        ], separators=(',', ':')).encode()).hexdigest(),
                        'capabilities': ['thinking'], 'family': family,
                        'version': '', 'metadata_key': hashlib.sha256(json.dumps(status, sort_keys=True, default=str).encode()).hexdigest(),
                        'architecture': str(status.get('config_model_type') or ''),
                        'renderer': '', 'parser': '',
                    }
            else:
                fields.setdefault('supports_vision', {'state': 'unknown', 'source': 'oMLX /v1/models/status unavailable', 'confidence': 'unknown', 'detail': ''})
                fields.setdefault('supports_thinking', {'state': 'unknown', 'source': 'oMLX /v1/models/status unavailable', 'confidence': 'unknown', 'detail': ''})

        elif backend == 'llamacpp':
            props = await self.llamacpp_props()
            if props:
                modalities = props.get('modalities')
                if isinstance(modalities, dict) and isinstance(modalities.get('vision'), bool):
                    record('supports_vision', bool(modalities['vision']), 'llama.cpp GET /props modalities.vision')
                elif isinstance(modalities, list):  # tolerate older/alternate compatible shapes
                    mods = {str(x).strip().lower() for x in modalities}
                    record('supports_vision', bool({'image', 'vision'} & mods), 'llama.cpp GET /props modalities')
                caps = props.get('chat_template_caps') if isinstance(props.get('chat_template_caps'), dict) else {}
                reasoning_effort = caps.get('supports_reasoning_effort')
                thinking = caps.get('supports_thinking')
                if thinking is not None:
                    record('supports_thinking', bool(thinking), 'llama.cpp GET /props chat_template_caps')
                elif reasoning_effort is True:
                    record('supports_thinking', True, 'llama.cpp GET /props chat_template_caps')
                if reasoning_effort is not None:
                    record('supports_reasoning_effort', bool(reasoning_effort), 'llama.cpp GET /props chat_template_caps')
                    if reasoning_effort:
                        result['thinking_mode'] = 'reasoning_effort'
                # Current llama-server exposes native request timings and usage
                # for streamed chat completions; this is backend capability, not
                # a model-name guess.
                record('supports_usage_stream', True, 'llama.cpp native streaming timings/usage')
            else:
                fields.setdefault('supports_vision', {'state': 'unknown', 'source': 'llama.cpp GET /props unavailable', 'confidence': 'unknown', 'detail': ''})
                fields.setdefault('supports_thinking', {'state': 'unknown', 'source': 'llama.cpp GET /props unavailable', 'confidence': 'unknown', 'detail': ''})

        # Explicit manual detection may run tiny compatibility requests.  These
        # prove API acceptance only; they do not pretend to prove model quality.
        if active_probes and backend != 'ollama':
            if 'supports_developer_role' not in fields:
                accepted, detail = await self._compatibility_acceptance_probe({}, messages=[
                    {'role': 'developer', 'content': 'Capability probe. Follow the user message.'},
                    {'role': 'user', 'content': 'Reply with one character: X'},
                ])
                if accepted is not None:
                    record('supports_developer_role', accepted, 'one-token developer-role compatibility probe',
                           confidence='api-accepted', detail=detail)
            if 'supports_strict_mode' not in fields:
                accepted, detail = await self._compatibility_acceptance_probe({
                    'tools': [{
                        'type': 'function',
                        'function': {
                            'name': 'harnessy_capability_probe',
                            'description': 'No-op compatibility probe.',
                            'parameters': {'type': 'object', 'properties': {}, 'additionalProperties': False},
                            'strict': True,
                        },
                    }],
                    'tool_choice': 'none',
                })
                if accepted is not None:
                    record('supports_strict_mode', accepted, 'one-token strict-tool-schema compatibility probe',
                           confidence='api-accepted', detail=detail)

        known = ('supports_vision', 'supports_usage_stream', 'supports_thinking',
                 'supports_reasoning_effort', 'supports_developer_role', 'supports_strict_mode')
        for name in known:
            fields.setdefault(name, {'state': 'unknown', 'source': 'No trustworthy capability evidence',
                                     'confidence': 'unknown', 'detail': ''})
        result['capability_detection'] = {
            'schema': 1,
            'backend': backend,
            'profile_identity': hashlib.sha256(json.dumps([
                str(result.get(k) or '').rstrip('/') for k in ('base_url','model','api_mode')
            ], separators=(',', ':')).encode()).hexdigest(),
            'active_probes': bool(active_probes),
            'observed_at_unix': time.time(),
            'fields': fields,
        }
        return result

    async def ollama_version(self) -> str:
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(3.0)) as client:
                response = await client.get(f'{self.ollama_root}/api/version', headers=self._headers())
                response.raise_for_status()
                return str(response.json().get('version') or '')
        except Exception:
            return ''

    async def detect_thinking_profile(self) -> dict[str, Any] | None:
        data = await self.model_metadata()
        if not data or not isinstance(data.get('capabilities'), list):
            return None
        return detected_profile(self.profile, data, version=await self.ollama_version())

    async def verify_thinking_levels(self, *, force: bool = False, progress=None,
                                     include_default: bool = False) -> dict[str, Any]:
        return await verify_native_thinking(self, force=force, progress=progress, include_default=include_default)

    def _thinking_request_summary(self, backend: str) -> dict[str, Any]:
        return {'thinking_ui': self.thinking_selection, 'thinking_effective': self.thinking,
                'thinking_source': ('profile_preset' if self.thinking_selection == 'profile' else
                                    'model_default' if self.thinking_selection == 'default' else 'chat'),
                'thinking_display': level_label(self.profile, self.thinking_selection),
                'thinking_effective_display': level_label(self.profile, self.thinking),
                'thinking_control': control_description(self.profile)['label'],
                'thinking_wire_fields': thinking_payload(self.profile, self.thinking, backend),
                'thinking_model_default': model_default_status(self.profile, backend=backend),
                'thinking_native_verification': deepcopy(self.profile.get('thinking_native_verification') or {})}

    async def ping(self) -> bool:
        try:
            backend = await self._detect_backend()
            if backend == 'ollama':
                async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
                    response = await client.get(f'{self.ollama_root}/api/tags', headers=self._headers())
                    return response.status_code < 400
            await self.fetch_models(self.base_url, self.api_key)
            return True
        except Exception:
            return False

    def _sampling_fields(self) -> dict[str, int | float]:
        values: dict[str, int | float | None] = {
            'temperature': _optional_float(self.profile.get('temperature')),
            'top_p': _optional_float(self.profile.get('top_p')),
            'top_k': _optional_int(self.profile.get('top_k')),
            'min_p': _optional_float(self.profile.get('min_p')),
            'presence_penalty': _optional_float(self.profile.get('presence_penalty')),
            'frequency_penalty': _optional_float(self.profile.get('frequency_penalty')),
            'repeat_penalty': _optional_float(self.profile.get('repeat_penalty')),
        }
        return {k: v for k, v in values.items() if v is not None}

    def _output_token_limit(self, request_limit: int | None = None) -> int:
        """Resolve an optional per-request cap without changing the profile.

        A check or other auxiliary request may reduce the configured generation
        allowance, but must not increase it or affect another in-flight request.
        The normal backend token-limit field governs reasoning as well as answer
        output where supported; no additional thinking controls are introduced.
        """
        if request_limit is not None and (
            isinstance(request_limit, bool)
            or not isinstance(request_limit, int)
            or request_limit <= 0
        ):
            raise ValueError('max_output_tokens must be a positive integer or None')
        configured = int(self.profile.get('max_output_tokens') or 0)
        if request_limit is None:
            return configured
        return min(configured, request_limit) if configured > 0 else request_limit

    def _payload(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None,
        *, backend: str = 'openai', max_output_tokens: int | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            'model': self.model,
            'messages': self._to_openai_messages(messages),
            'stream': True,
        }
        payload.update(self._sampling_fields())
        max_output = self._output_token_limit(max_output_tokens)
        max_field = str(self.profile.get('max_tokens_field') or 'max_tokens').strip()
        if max_output > 0 and max_field:
            payload[max_field] = max_output
        if tools:
            payload['tools'] = tools
            # Some compatibility servers reject tool_choice despite otherwise
            # supporting tools, so only send it when explicitly requested.
            if self.profile.get('send_tool_choice'):
                payload['tool_choice'] = 'auto'
        if backend == 'omlx' or self.profile.get('supports_usage_stream', True):
            # Current oMLX returns its authoritative prompt/decode TPS only in
            # the final streamed usage chunk, so request it even when an older
            # generic profile has Streaming usage supported disabled.
            payload['stream_options'] = {'include_usage': True}
        if backend == 'llamacpp':
            # llama.cpp can attach request-scoped prompt/decode counters to each
            # SSE chunk. This is the authoritative live TPS source for its
            # OpenAI-compatible endpoint; generic servers never receive this
            # llama.cpp-specific request field.
            payload['timings_per_token'] = True
            payload['return_progress'] = True
        payload.update(thinking_payload(self.profile, self.thinking, 'openai'))
        return payload

    @staticmethod
    def _data_url_to_base64(value: Any) -> str | None:
        if isinstance(value, dict):
            value = value.get('url')
        if not isinstance(value, str):
            return None
        match = re.match(r'^data:image/[^;]+;base64,(.+)$', value, flags=re.S | re.I)
        if match:
            # Validate while preserving the original compact base64 string.
            try:
                base64.b64decode(match.group(1), validate=False)
            except Exception:
                return None
            return match.group(1)
        return None

    @staticmethod
    def _normalize_system_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Return one leading system message, preserving non-system order.

        Several local chat templates (including llama.cpp/Jinja templates)
        reject a second or late system role. HarnessyXO may add archive or
        continuation guidance dynamically, so consolidate all system guidance
        before transport instead of relying on a permissive backend template.
        """
        systems: list[str] = []
        rest: list[dict[str, Any]] = []
        for message in messages:
            if str(message.get('role') or '') == 'system':
                content = message.get('content')
                if isinstance(content, list):
                    text = ''.join(
                        str(part.get('text') or '')
                        for part in content if isinstance(part, dict) and part.get('type') == 'text'
                    )
                else:
                    text = str(content or '')
                if text.strip():
                    systems.append(text.strip())
            else:
                rest.append(message)
        if not systems:
            return list(messages)
        return [{'role': 'system', 'content': '\n\n'.join(systems)}] + rest

    def _to_ollama_messages(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for msg in self._normalize_system_messages(messages):
            role = str(msg.get('role') or 'user')
            content = msg.get('content')
            text_parts: list[str] = []
            images: list[str] = []

            # HarnessyXO's native image channel is intentionally independent of
            # OpenAI image_url formatting. This removes an unnecessary
            # encode->data URL->regex decode hop for Ollama vision requests.
            native_images = msg.get('_harnessy_images') or []
            for image in native_images:
                if not isinstance(image, dict):
                    continue
                encoded = image.get('data')
                if isinstance(encoded, str) and encoded:
                    try:
                        base64.b64decode(encoded, validate=False)
                    except Exception:
                        continue
                    images.append(encoded)

            if isinstance(content, list):
                for part in content:
                    if not isinstance(part, dict):
                        continue
                    if part.get('type') == 'text':
                        text_parts.append(str(part.get('text') or ''))
                    elif part.get('type') == 'image_url' and not native_images:
                        encoded = self._data_url_to_base64(part.get('image_url'))
                        if encoded:
                            images.append(encoded)
            else:
                text_parts.append(str(content or ''))

            native: dict[str, Any] = {'role': role, 'content': ''.join(text_parts)}
            if images:
                native['images'] = images
            if msg.get('name'):
                native['tool_name'] = msg['name']
            if msg.get('tool_call_id'):
                native['tool_call_id'] = msg['tool_call_id']
            if msg.get('tool_calls'):
                native_calls = []
                for call in msg.get('tool_calls') or []:
                    fn = dict(call.get('function') or {})
                    args = fn.get('arguments')
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except json.JSONDecodeError:
                            args = {'raw': args}
                    fn['arguments'] = args or {}
                    native_call = {'function': fn}
                    if call.get('id'):
                        native_call['id'] = call['id']
                    native_calls.append(native_call)
                native['tool_calls'] = native_calls
            out.append(native)
        return out

    @staticmethod
    def _to_openai_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        # Strip HarnessyXO-private transport metadata. The public OpenAI-style
        # content already contains data:image/... image_url parts.
        return [
            {k: v for k, v in msg.items() if not str(k).startswith('_harnessy_')}
            for msg in OpenAICompatibleClient._normalize_system_messages(messages)
        ]

    @staticmethod
    def _request_summary(payload: dict[str, Any], backend: str, endpoint: str) -> dict[str, Any]:
        image_count = 0
        image_bytes = 0
        text_length = 0
        message_image_counts: list[int] = []
        image_byte_counts: list[int] = []
        image_sha256_12: list[str] = []
        for message in payload.get('messages') or []:
            per_message = 0
            content = message.get('content') if isinstance(message, dict) else None
            if isinstance(content, str):
                text_length += len(content)
            elif isinstance(content, list):
                for part in content:
                    if not isinstance(part, dict):
                        continue
                    if part.get('type') == 'text':
                        text_length += len(str(part.get('text') or ''))
                    elif part.get('type') == 'image_url':
                        encoded = OpenAICompatibleClient._data_url_to_base64(part.get('image_url'))
                        if encoded:
                            try:
                                raw = base64.b64decode(encoded, validate=False)
                            except Exception:
                                raw = b''
                            if raw:
                                image_count += 1
                                per_message += 1
                                image_bytes += len(raw)
                                image_byte_counts.append(len(raw))
                                image_sha256_12.append(hashlib.sha256(raw).hexdigest()[:12])
            if isinstance(message, dict):
                for encoded in message.get('images') or []:
                    if not isinstance(encoded, str):
                        continue
                    try:
                        raw = base64.b64decode(encoded, validate=False)
                    except Exception:
                        raw = b''
                    if raw:
                        image_count += 1
                        per_message += 1
                        image_bytes += len(raw)
                        image_byte_counts.append(len(raw))
                        image_sha256_12.append(hashlib.sha256(raw).hexdigest()[:12])
            message_image_counts.append(per_message)
        thinking_parameter: Any = None
        if 'think' in payload:
            thinking_parameter = payload.get('think')
        elif 'reasoning_effort' in payload:
            thinking_parameter = payload.get('reasoning_effort')
        elif 'reasoning' in payload:
            thinking_parameter = payload.get('reasoning')
        elif 'enable_thinking' in payload:
            thinking_parameter = payload.get('enable_thinking')
        elif 'chat_template_kwargs' in payload:
            thinking_parameter = payload.get('chat_template_kwargs')
        return {
            'backend': backend,
            'endpoint': endpoint,
            'model': payload.get('model'),
            'context_window_requested': int((payload.get('options') or {}).get('num_ctx') or 0) or None,
            'thinking_parameter': thinking_parameter,
            'images_attached': image_count,
            'image_bytes': image_bytes,
            'message_image_counts': message_image_counts,
            'image_byte_counts': image_byte_counts,
            'image_sha256_12': image_sha256_12,
            'vision_transport': 'messages[].images' if backend == 'ollama' and image_count else (
                'content[].image_url' if image_count else None
            ),
            'message_text_length': text_length,
            'tool_count': len(payload.get('tools') or []),
            'server_timings_requested': bool(payload.get('timings_per_token')) if 'timings_per_token' in payload else None,
            'server_progress_requested': bool(payload.get('return_progress')) if 'return_progress' in payload else None,
            'stream_usage_requested': bool((payload.get('stream_options') or {}).get('include_usage')) if 'stream_options' in payload else None,
        }

    def _effective_ollama_context(self, runtime_context_window: int = 0) -> int:
        configured = max(0, int(self.profile.get('context_window') or 0))
        observed = max(0, int(runtime_context_window or 0))
        return min(configured, observed or 262144) if configured else observed

    def _ollama_payload(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        *,
        runtime_context_window: int | None = None,
        max_output_tokens: int | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            'model': self.model,
            'messages': self._to_ollama_messages(messages),
            'stream': True,
        }
        options = self._sampling_fields()
        context_window = int(self.profile.get('context_window') or 0)
        observed_runtime_context = int(runtime_context_window or 0)
        if context_window > 0:
            # Treat the profile value as a ceiling, never as permission to
            # silently inflate an unloaded/unknown Ollama runner. v0.2.26 could
            # fall back to the old 1M profile default when /api/ps had no runner,
            # allocating a huge KV cache even though the user had been operating
            # at 262k. Unknown runtime state therefore uses a conservative 262k
            # startup ceiling (or the smaller profile cap). Once Ollama reports a
            # concrete runner context, that observed value is authoritative.
            options['num_ctx'] = self._effective_ollama_context(observed_runtime_context)
        max_output = self._output_token_limit(max_output_tokens)
        if max_output > 0:
            options['num_predict'] = max_output
        if options:
            payload['options'] = options
        if tools:
            payload['tools'] = tools
        payload.update(thinking_payload(self.profile, self.thinking, 'ollama'))
        return payload

    async def _stream_openai(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None,
        *, backend: str = 'openai', max_output_tokens: int | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        budget = getattr(self, 'request_budget_callback', None)
        if callable(budget):
            budget(0)
        payload = self._payload(messages, tools, backend=backend, max_output_tokens=max_output_tokens)
        backend_label = 'llama.cpp' if backend == 'llamacpp' else ('oMLX' if backend == 'omlx' else 'openai')
        observation = _StreamObservation()
        request_summary = self._request_summary(payload, backend_label, self.endpoint)
        request_summary['client_request_id'] = observation.client_request_id
        request_summary.update(self._thinking_request_summary('openai'))
        log_event('backend', 'request_start', provider='openai', model=self.model, endpoint=self.endpoint, request=request_summary, client_request_id=observation.client_request_id)
        yield {'type': 'request', 'request': request_summary}
        if backend == 'omlx':
            async with aclosing(self._stream_omlx_transport(payload, observation=observation)) as stream:
                async for event in stream:
                    yield event
            return

        queue: asyncio.Queue[tuple[str, Any]] = asyncio.Queue()
        timeout = httpx.Timeout(connect=15.0, read=None, write=60.0, pool=15.0)

        native_progress: dict[str, int | float] | None = None
        native_generating = False
        native_generated_high_water = 0
        def native_status(data: Any) -> dict[str, Any] | None:
            nonlocal native_progress, native_generating, native_generated_high_water
            if backend != 'llamacpp':
                return None
            if StreamProgressWatchdog._payload_has_output(data):
                native_generating = True
            status = llama_cpp_stream_status(data)
            if not status:
                return None
            if status.get('phase') == 'generating':
                generated = int(status.get('generated') or 0)
                if generated < native_generated_high_water:
                    return None
                native_generated_high_water = generated
                native_generating = True
                return status
            if native_generating:
                return None
            progress = status.get('native_prompt_progress')
            if isinstance(progress, dict):
                if native_progress and (
                    progress['total'] != native_progress['total']
                    or progress['cache'] != native_progress['cache']
                    or progress['processed'] < native_progress['processed']
                    or progress['time_ms'] < native_progress['time_ms']
                ):
                    return None
                native_progress = progress
            return status

        async def health_probe(request_id: str) -> dict[str, Any]:
            observation.log(provider='openai', observation='health_check')
            return await self._stream_health_probe(backend, request_id)

        async def pump_response() -> None:
            try:
                async with httpx.AsyncClient(timeout=timeout) as client:
                    async with client.stream('POST', self.endpoint, headers=self._headers(), json=payload) as response:
                        if response.status_code >= 400:
                            body = (await response.aread()).decode(errors='replace')
                            log_event('backend', 'request_http_error', provider='openai', model=self.model,
                                      status=response.status_code, body_chars=len(body))
                            raise LLMServerError(response.status_code, body)
                        observation.transport(accepted=True)
                        await queue.put(('accepted', None))
                        content_type = response.headers.get('content-type', '')
                        if 'text/event-stream' not in content_type and 'application/json' in content_type:
                            body = await response.aread()
                            data = json.loads(body)
                            observation.observe(data, provider='openai')
                            await queue.put(('json', data))
                            return
                        async for raw_line in response.aiter_lines():
                            line = raw_line.strip()
                            if not line or line.startswith(':'):
                                observation.transport()
                                await queue.put(('transport', None))
                                continue
                            if line.startswith('data:'):
                                line = line[5:].strip()
                            if line == '[DONE]':
                                return
                            try:
                                data = json.loads(line)
                            except json.JSONDecodeError as exc:
                                observation.event({
                                    'provider': 'openai', 'kind': 'malformed_json',
                                    'error': str(exc), 'line_chars': len(line), 'preview': line[:1000],
                                })
                                observation.transport(malformed=True)
                                await queue.put(('transport', None))
                                continue
                            observation.observe(data, provider='openai')
                            status = native_status(data)
                            if status:
                                await queue.put(('runtime_status', status))
                            await queue.put(('data', data))
            except BaseException as exc:
                await queue.put(('error', exc))
            finally:
                await queue.put(('done', None))

        response_task = asyncio.create_task(pump_response(), name='harnessy-openai-stream')
        watchdog = StreamProgressWatchdog(backend_label, client_request_id=observation.client_request_id)
        try:
            async for kind, value in watched_queue(
                queue, watchdog, health_probe,
            ):
                if kind == 'watchdog':
                    yield {'type': 'stream_watchdog', **dict(value or {})}
                    continue
                if kind in {'accepted', 'transport'}:
                    continue
                if kind == 'runtime_status':
                    yield {'type': 'runtime_status', 'status': value}
                    continue
                if kind == 'error':
                    if isinstance(value, asyncio.CancelledError):
                        raise value
                    if isinstance(value, BaseException):
                        raise value
                    raise RuntimeError(str(value))
                if kind == 'done':
                    log_event('backend', 'request_complete', provider='openai', model=self.model,
                              finish_reason='stream_end', client_request_id=observation.client_request_id, **observation.counts)
                    break
                if kind == 'json':
                    data = value if isinstance(value, dict) else {}
                    if data.get('error'):
                        raise LLMServerError(500, json.dumps(data), provider_label=backend_label)
                    if backend == 'llamacpp':
                        status = native_status(data)
                        if status:
                            yield {'type': 'runtime_status', 'status': status}
                    if data.get('usage'):
                        yield {'type': 'usage', 'usage': data.get('usage'), 'raw': data}
                    choice = (data.get('choices') or [{}])[0]
                    message = choice.get('message', {}) if isinstance(choice, dict) else {}
                    if isinstance(message, dict) and message.get('tool_calls'):
                        raw_calls = message.get('tool_calls')
                        observation.event({'provider': 'openai', 'kind': 'tool_call_message', 'tool_calls': raw_calls})
                        log_event('tools', 'tool_stream_raw', provider='openai', semantics='message', tool_calls=raw_calls)
                    log_event('backend', 'request_complete', provider='openai', model=self.model,
                              finish_reason=choice.get('finish_reason') if isinstance(choice, dict) else None,
                              client_request_id=observation.client_request_id, **observation.counts)
                    yield {
                        'type': 'message', 'message': message,
                        'finish_reason': choice.get('finish_reason') if isinstance(choice, dict) else None,
                    }
                    break
                if kind != 'data' or not isinstance(value, dict):
                    continue
                data = value
                if data.get('error'):
                    raise LLMServerError(500, json.dumps(data), provider_label=backend_label)
                choices = data.get('choices') or []
                first_choice = choices[0] if choices else {}
                first_delta = first_choice.get('delta') or {} if isinstance(first_choice, dict) else {}
                if data.get('usage'):
                    yield {'type': 'usage', 'usage': data.get('usage'), 'raw': data}
                if not choices:
                    continue
                choice = choices[0]
                delta = choice.get('delta') or {}
                if isinstance(delta, dict) and delta.get('tool_calls'):
                    raw_calls = delta.get('tool_calls')
                    observation.event({'provider': 'openai', 'kind': 'tool_call_delta', 'tool_calls': raw_calls})
                    log_event('tools', 'tool_stream_raw', provider='openai', semantics='delta', tool_calls=raw_calls)
                yield {'type': 'delta', 'delta': delta, 'finish_reason': choice.get('finish_reason')}
        finally:
            observation.log(provider='openai', observation='transport_closed')
            if not response_task.done():
                response_task.cancel()
            try:
                await response_task
            except asyncio.CancelledError:
                pass

    async def _stream_omlx_transport(self, payload: dict[str, Any], *, observation: _StreamObservation | None = None) -> AsyncIterator[dict[str, Any]]:
        """Confirm oMLX's synthetic abort notice before treating it as output.

        oMLX can yield ``[Error: Request aborted: ...]`` as content or reasoning
        before its structured SSE error. Holding only this bounded opening
        prefix lets recovery see the error without mistaking it for generation.
        Flush every held delta unless the subsequent error confirms the same
        abort detail, allowing wrapper characters to be filtered by oMLX's
        tool/reasoning parser. Real output must still prevent replay.
        """
        observation = observation or _StreamObservation()
        capacity_phrase = 'Request aborted: process memory limit exceeded '
        notice_prefixes = tuple(
            marker + capacity_phrase for marker in ('[Error: ', 'Error: ', '')
        )
        pending: list[dict[str, Any]] = []
        notice = ''
        checking = True
        async with aclosing(self._stream_omlx_transport_raw(payload, observation=observation)) as stream:
            try:
                async for event in stream:
                    delta = event.get('delta')
                    if checking and isinstance(delta, dict):
                        texts = [delta.get(key) for key in (
                            'content', 'reasoning', 'reasoning_content', 'thinking',
                        ) if delta.get(key)]
                        if not texts and not delta.get('tool_calls') and not delta.get('function_call'):
                            if pending and len(pending) < 128:
                                pending.append(event)
                                continue
                            if pending:
                                for held in pending:
                                    yield held
                                pending.clear()
                                checking = False
                            yield event
                            continue
                        text_only = (all(isinstance(text, str) for text in texts)
                                     and not delta.get('tool_calls') and not delta.get('function_call'))
                        candidate = notice + ''.join(texts) if text_only else ''
                        stripped = candidate.lstrip()
                        if (text_only and len(candidate) <= 8192 and len(pending) < 128
                                and any(prefix.startswith(stripped) or stripped.startswith(prefix)
                                        for prefix in notice_prefixes)):
                            pending.append(event)
                            notice = candidate
                            continue
                        for held in pending:
                            yield held
                        pending.clear()
                        checking = False
                    yield event
            except Exception as exc:
                detail_prefix = 'oMLX memory guard aborted this request mid-prefill: '
                message = str(exc.error.get('message') or '') if isinstance(exc, LLMServerError) else ''
                detail = message[len(detail_prefix):] if message.startswith(detail_prefix) else ''
                visible = notice.strip()
                for marker in ('[Error: ', 'Error: '):
                    if visible.startswith(marker):
                        visible = visible[len(marker):]
                        break
                if visible.endswith(']'):
                    visible = visible[:-1]
                confirmed = (bool(pending) and isinstance(exc, LLMServerError)
                             and exc.code == 'prefill_memory_exceeded' and detail
                             and visible.strip() == detail.strip())
                if confirmed:
                    log_event('backend', 'synthetic_abort_notice_confirmed', provider='omlx',
                              model=self.model, notice_chars=len(notice), chunks=len(pending))
                else:
                    if isinstance(exc, LLMServerError) and exc.code == 'prefill_memory_exceeded':
                        log_event('backend', 'abort_notice_unmatched', provider='omlx',
                                  model=self.model, notice_chars=len(notice), chunks=len(pending),
                                  detail_chars=len(detail), notice_has_bracket=notice.strip().endswith(']'))
                    for held in pending:
                        yield held
                raise
            else:
                for held in pending:
                    yield held

    async def _stream_omlx_transport_raw(self, payload: dict[str, Any], *, observation: _StreamObservation | None = None) -> AsyncIterator[dict[str, Any]]:
        """Stream oMLX while independently polling its live activity endpoint.

        The OpenAI-compatible usage event remains the authoritative final
        accounting source.  /admin/api/activity is only used while the request
        is in flight so the UI can show real PP/TG speed instead of an estimate.
        """
        observation = observation or _StreamObservation()
        queue: asyncio.Queue[tuple[str, Any]] = asyncio.Queue()
        stop = asyncio.Event()
        timeout = httpx.Timeout(connect=15.0, read=None, write=60.0, pool=15.0)
        prefix_log = OmlxPrefixCacheLogReader(self.base_url)
        activity_lease = UnscopedTelemetryLease(self.base_url, 'omlx')

        def raise_stream_error(data: Any) -> None:
            if not isinstance(data, dict) or not data.get('error'):
                return
            body = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
            raise LLMServerError(500, body, provider_label='oMLX')

        async def health_probe(request_id: str) -> dict[str, Any]:
            observation.log(provider='openai', observation='health_check')
            return await self._stream_health_probe('omlx', request_id)

        async def pump_response() -> None:
            try:
                async with httpx.AsyncClient(timeout=timeout) as client:
                    async with client.stream('POST', self.endpoint, headers=self._headers(), json=payload) as response:
                        if response.status_code >= 400:
                            body = (await response.aread()).decode(errors='replace')
                            log_event('backend', 'request_http_error', provider='openai', model=self.model,
                                      status=response.status_code, body_chars=len(body))
                            raise LLMServerError(response.status_code, body)
                        observation.transport(accepted=True)
                        await queue.put(('accepted', None))
                        content_type = response.headers.get('content-type', '')
                        if 'text/event-stream' not in content_type and 'application/json' in content_type:
                            body = await response.aread()
                            data = json.loads(body)
                            observation.observe(data, provider='openai')
                            await queue.put(('json', data))
                            return
                        async for raw_line in response.aiter_lines():
                            line = raw_line.strip()
                            if not line or line.startswith(':'):
                                observation.transport()
                                await queue.put(('transport', None))
                                continue
                            if line.startswith('data:'):
                                line = line[5:].strip()
                            if line == '[DONE]':
                                return
                            try:
                                data = json.loads(line)
                            except json.JSONDecodeError as exc:
                                observation.event({
                                    'provider': 'openai', 'kind': 'malformed_json',
                                    'error': str(exc), 'line_chars': len(line), 'preview': line[:1000],
                                })
                                observation.transport(malformed=True)
                                await queue.put(('transport', None))
                                continue
                            observation.observe(data, provider='openai')
                            await queue.put(('data', data))
            except BaseException as exc:
                await queue.put(('error', exc))
            finally:
                await queue.put(('done', None))

        async def pump_activity() -> None:
            try:
                async with httpx.AsyncClient(timeout=httpx.Timeout(2.0)) as client:
                    last_signature: tuple[Any, ...] | None = None
                    owned_request_id = ''
                    overlap_reported = False
                    last_scoped_log_at = 0.0
                    while not stop.is_set():
                        overlapping = activity_lease.ambiguous
                        if overlapping and not overlap_reported:
                            overlap_reported = True
                            await queue.put(('activity_ambiguous', None))
                        if overlapping and not owned_request_id:
                            # Another request's sole visible row cannot prove
                            # progress for this chat. Continue watching for a
                            # completed stream without claiming its counters.
                            status = None
                        elif overlapping:
                            status = await self.omlx_runtime_status(client, request_id=owned_request_id)
                        else:
                            status = await self.omlx_runtime_status(client)
                            if activity_lease.ambiguous:
                                # Overlap started during an unscoped HTTP poll;
                                # its result cannot bind a request ID safely.
                                status = None
                            elif status and status.get('request_id'):
                                owned_request_id = str(status['request_id'])
                        if activity_lease.ambiguous and not overlap_reported:
                            overlap_reported = True
                            await queue.put(('activity_ambiguous', None))
                        if status:
                            if activity_lease.ambiguous:
                                if not owned_request_id or str(status.get('request_id') or '') != owned_request_id:
                                    status = None
                                else:
                                    status['request_scoped'] = True
                        if status:
                            if status.get('request_scoped'):
                                observed = time.perf_counter()
                                if observed - last_scoped_log_at >= 30.0:
                                    last_scoped_log_at = observed
                                    log_event(
                                        'backend', 'scoped_activity_progress', provider='omlx', model=self.model,
                                        phase=str(status.get('phase') or ''),
                                        processed=int(status.get('processed') or 0),
                                        total=int(status.get('total') or 0),
                                        generated=int(status.get('generated') or 0),
                                        request_id_seen=True,
                                    )
                            request_id = str(status.get('request_id') or '')
                            if request_id and status.get('cached_tokens') is None:
                                cache_row = prefix_log.for_request(request_id)
                                if cache_row:
                                    status['cached_tokens'] = int(cache_row['cached_tokens'])
                                    status['uncached_total'] = int(cache_row['reprefill_tokens'])
                                    status['cache_hit_rate'] = float(cache_row['cache_hit_rate'])
                                    status['cache_hit_source'] = str(cache_row['cache_hit_source'])
                                    status['prompt_total_with_cache'] = int(cache_row['total_prompt_tokens'])
                            signature = (
                                status.get('request_id'), status.get('phase'), status.get('processed'), status.get('total'),
                                status.get('generated'), status.get('tps'), status.get('prefill_tps'),
                                status.get('cached_tokens'), status.get('cache_hit_rate'),
                            )
                            # Refresh the timestamp on every successful poll so a
                            # stable cumulative rate remains visibly live. Avoid
                            # redundant queue traffic when all other values match.
                            if signature != last_signature:
                                last_signature = signature
                                await queue.put(('runtime_status', status))
                            elif str(status.get('phase') or '') == 'generating' and number(status.get('tps')):
                                await queue.put(('runtime_status', status))
                        try:
                            await asyncio.wait_for(
                                stop.wait() if activity_lease.ambiguous else activity_lease.overlap.wait(),
                                timeout=0.75,
                            )
                        except TimeoutError:
                            pass
            except asyncio.CancelledError:
                return
            except Exception:
                return

        response_task = asyncio.create_task(pump_response(), name='harnessy-omlx-stream')
        activity_task = asyncio.create_task(pump_activity(), name='harnessy-omlx-live-activity')
        watchdog = StreamProgressWatchdog('oMLX', client_request_id=observation.client_request_id)
        last_activity_phase = 'prompt_processing'
        ambiguous_reported = False
        try:
            async for kind, value in watched_queue(
                queue, watchdog, health_probe,
            ):
                if kind == 'watchdog':
                    yield {'type': 'stream_watchdog', **dict(value or {})}
                    continue
                if kind in {'accepted', 'transport'}:
                    continue
                if kind == 'activity_ambiguous' or (kind == 'runtime_status' and activity_lease.ambiguous
                                                   and not (isinstance(value, dict) and value.get('request_scoped'))):
                    if not ambiguous_reported:
                        ambiguous_reported = True
                        yield {'type': 'runtime_status', 'status': {
                            'backend': 'oMLX', 'phase': last_activity_phase,
                            'processed': 0, 'total': 0, 'generated': 0,
                            'cached_tokens': None, 'uncached_total': None, 'cache_hit_rate': None,
                            'tps': 0.0, 'prefill_tps': 0.0, 'tps_kind': 'unavailable',
                            'tps_source': 'ambiguous_concurrent_requests',
                        }}
                    continue
                if kind == 'runtime_status':
                    if isinstance(value, dict):
                        last_activity_phase = str(value.get('phase') or last_activity_phase)
                        yield {'type': 'runtime_status', 'status': value}
                    continue
                if kind == 'error':
                    if isinstance(value, asyncio.CancelledError):
                        raise value
                    if isinstance(value, BaseException):
                        raise value
                    raise RuntimeError(str(value))
                if kind == 'done':
                    log_event('backend', 'request_complete', provider='openai', model=self.model,
                              finish_reason='stream_end', client_request_id=observation.client_request_id, **observation.counts)
                    break
                if kind == 'json':
                    data = value if isinstance(value, dict) else {}
                    raise_stream_error(data)
                    status = omlx_stream_status(data)
                    if status:
                        yield {'type': 'runtime_status', 'status': status}
                    if data.get('usage'):
                        yield {'type': 'usage', 'usage': data.get('usage'), 'raw': data}
                    choice = (data.get('choices') or [{}])[0]
                    message = choice.get('message', {}) if isinstance(choice, dict) else {}
                    if isinstance(message, dict) and message.get('tool_calls'):
                        raw_calls = message.get('tool_calls')
                        observation.event({'provider': 'openai', 'kind': 'tool_call_message', 'tool_calls': raw_calls})
                        log_event('tools', 'tool_stream_raw', provider='openai', semantics='message', tool_calls=raw_calls)
                    yield {'type': 'message', 'message': message,
                           'finish_reason': choice.get('finish_reason') if isinstance(choice, dict) else None}
                    continue
                if kind != 'data' or not isinstance(value, dict):
                    continue

                data = value
                raise_stream_error(data)
                status = omlx_stream_status(data)
                if status:
                    yield {'type': 'runtime_status', 'status': status}
                choices = data.get('choices') or []
                first_choice = choices[0] if choices else {}
                first_delta = first_choice.get('delta') or {} if isinstance(first_choice, dict) else {}
                if data.get('usage'):
                    yield {'type': 'usage', 'usage': data.get('usage'), 'raw': data}
                if not choices:
                    continue
                choice = choices[0]
                delta = choice.get('delta') or {}
                if isinstance(delta, dict) and delta.get('tool_calls'):
                    raw_calls = delta.get('tool_calls')
                    observation.event({'provider': 'openai', 'kind': 'tool_call_delta', 'tool_calls': raw_calls})
                    log_event('tools', 'tool_stream_raw', provider='openai', semantics='delta', tool_calls=raw_calls)
                yield {'type': 'delta', 'delta': delta, 'finish_reason': choice.get('finish_reason')}
        finally:
            observation.log(provider='openai', observation='transport_closed')
            stop.set()
            activity_lease.close()
            if not activity_task.done():
                activity_task.cancel()
            if not response_task.done():
                response_task.cancel()
            try:
                await activity_task
            except asyncio.CancelledError:
                pass
            try:
                await response_task
            except asyncio.CancelledError:
                pass

    @staticmethod
    def _normalize_ollama_tool_calls(calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for idx, call in enumerate(calls or []):
            fn = dict(call.get('function') or {})
            args = fn.get('arguments')
            if not isinstance(args, str):
                args = json.dumps(args or {}, separators=(',', ':'))
            fn['arguments'] = args
            item = {
                'index': idx,
                'id': call.get('id') or f'call_{idx}',
                'type': call.get('type') or 'function',
                'function': fn,
            }
            out.append(item)
        return out

    @staticmethod
    def _normalize_ollama_text_channels(message: Any) -> tuple[dict[str, Any], dict[str, list[str]]]:
        """Normalize native text while retaining its original wire fields."""
        message = message if isinstance(message, dict) else {}
        delta: dict[str, Any] = {}
        sources: dict[str, list[str]] = {}
        if message.get('content'):
            delta['content'] = message.get('content')
            sources['answer'] = ['message.content']
        if message.get('thinking'):
            delta['reasoning'] = message.get('thinking')
            sources['reasoning'] = ['message.thinking']
        return delta, sources

    async def _stream_ollama(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None,
        *, max_output_tokens: int | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        # Auto metadata detection also covers the first send before a health
        # timer has run. This reads Show only, never fabricates capabilities.
        if self.profile.get('auto_detect_capabilities', True) and self._show_metadata is None:
            detected = await self.detect_thinking_profile()
            if detected is not None:
                self.profile.update(detected)
        # Only explicit variable levels require native proof. Default is omitted;
        # Off remains False. Never silently retry the user's work at another level.
        if (self.profile.get('supports_thinking') and model_family(self.profile) == 'qwen3.8'
                and self.profile.get('thinking_preset', 'auto') in {'auto', 'qwen3.8'}
                and self.thinking in {'low', 'medium', 'high'}):
            yield {'type': 'preflight_status', 'status': 'Checking native Thinking controls…'}
            report = await self.verify_thinking_levels()
            if report.get('status') != 'verified':
                raise ThinkingConfigurationError(str(report.get('reason') or 'Native Thinking verification failed.'))
        # Resolve the effective runner context before constructing the request.
        # This prevents a stale/default 1M HarnessyXO profile from accidentally
        # expanding an Ollama runner that is actually operating at (for example)
        # 262k.  Telemetry failure is non-fatal; the configured value remains the
        # fallback in that case.
        try:
            preflight_runtime = await self.ollama_runtime_status()
        except Exception:
            preflight_runtime = None
        preflight_context = int((preflight_runtime or {}).get('context_window') or 0)
        budget = getattr(self, 'request_budget_callback', None)
        if callable(budget):
            budget(self._effective_ollama_context(preflight_context),
                   'observed_runtime' if preflight_context else 'native_startup_ceiling_runtime_unobserved')
        payload = self._ollama_payload(
            messages, tools, runtime_context_window=preflight_context,
            max_output_tokens=max_output_tokens,
        )
        observation = _StreamObservation()
        request_summary = self._request_summary(payload, 'ollama', f'{self.ollama_root}/api/chat')
        request_summary['client_request_id'] = observation.client_request_id
        request_summary.update(self._thinking_request_summary('ollama'))
        request_summary['context_window_profile_cap'] = int(self.profile.get('context_window') or 0) or None
        request_summary['runtime_context_window_before_request'] = preflight_context or None
        request_summary['context_window_effective'] = int((payload.get('options') or {}).get('num_ctx') or 0) or None
        request_summary['context_window_source'] = 'runtime' if preflight_context > 0 else 'safe_fallback'
        log_event(
            'backend', 'request_start', provider='ollama', model=self.model,
            endpoint=f'{self.ollama_root}/api/chat', request=request_summary,
            client_request_id=observation.client_request_id,
        )
        log_event(
            'backend', 'phase', provider='ollama', model=self.model, phase='prompt_processing',
            context_window=request_summary.get('context_window_requested'),
        )
        yield {'type': 'request', 'request': request_summary}

        # Run the streaming POST in a background task so optional /v1/status
        # telemetry can be polled while Ollama is still blocking response
        # headers during a long prompt prefill.  Without this, the UI can only
        # say "Waiting for model" for several minutes even though the model is
        # actively processing tens of thousands of tokens.
        queue: asyncio.Queue[tuple[str, Any]] = asyncio.Queue()
        timeout = httpx.Timeout(connect=15.0, read=None, write=60.0, pool=15.0)

        async def health_probe(request_id: str) -> dict[str, Any]:
            observation.log(provider='ollama', observation='health_check')
            return await self._stream_health_probe('ollama', request_id)

        async def pump_response() -> None:
            try:
                async with httpx.AsyncClient(timeout=timeout) as client:
                    async with client.stream('POST', f'{self.ollama_root}/api/chat', headers=self._headers(), json=payload) as response:
                        if response.status_code >= 400:
                            body = (await response.aread()).decode(errors='replace')
                            log_event('backend', 'request_http_error', provider='ollama', model=self.model, status=response.status_code, body_chars=len(body))
                            raise LLMServerError(response.status_code, body, provider_label='Ollama')
                        observation.transport(accepted=True)
                        await queue.put(('accepted', None))
                        async for line in response.aiter_lines():
                            line = line.strip()
                            if not line:
                                observation.transport()
                                await queue.put(('transport', None))
                                continue
                            try:
                                data = json.loads(line)
                            except json.JSONDecodeError as exc:
                                observation.event({
                                    'provider': 'ollama', 'kind': 'malformed_json',
                                    'error': str(exc), 'line_chars': len(line), 'preview': line[:1000],
                                })
                                observation.transport(malformed=True)
                                await queue.put(('transport', None))
                                continue
                            message = data.get('message') or {} if isinstance(data, dict) else {}
                            observation.observe(data, provider='ollama')
                            await queue.put(('data', data))
            except BaseException as exc:
                await queue.put(('error', exc))
            finally:
                await queue.put(('done', None))

        # Poll optional runtime telemetry independently from the response
        # stream. Previously status was sampled only when no stream chunk had
        # arrived for 750 ms, which meant the exact period users care about
        # most -- active 20-30 tok/s decoding -- had no live speed samples.
        # The telemetry task is deliberately low-frequency and best-effort; it
        # never gates or slows the actual model stream.
        telemetry_stop = asyncio.Event()

        rates = LiveRateSelection()
        log_reader = OllamaLogReader(self.ollama_root, self.model, self.profile)

        async def pump_log_status() -> None:
            # Independent of HTTP status timeouts, and never on the NiceGUI loop.
            # Missing/rotated/permission-denied logs are optional, not chat errors.
            try:
                try:
                    await asyncio.to_thread(log_reader.prime)
                except Exception:
                    pass  # optional telemetry cannot terminate inference
                while not telemetry_stop.is_set():
                    try:
                        sample = await asyncio.to_thread(log_reader.poll)
                    except Exception:
                        sample = None
                    await queue.put(('log_status', sample or {}))
                    try:
                        await asyncio.wait_for(telemetry_stop.wait(), timeout=0.5)
                    except TimeoutError:
                        pass
            except asyncio.CancelledError:
                return

        async def pump_runtime_status() -> None:
            previous_generated: int | None = None
            previous_generated_at: float | None = None
            fields = ('phase', 'generated', 'tps', 'tps_kind')
            previous_signature = tuple((preflight_runtime or {}).get(k) for k in fields)
            while not telemetry_stop.is_set():
                try:
                    if log_reader.ambiguous:
                        await queue.put(('runtime_ambiguous', None))
                        return
                    runtime = await self.ollama_runtime_status()
                    if log_reader.ambiguous:
                        await queue.put(('runtime_ambiguous', None))
                        return
                    if runtime:
                        runtime = dict(runtime)
                        idle = str(runtime.get('phase') or '').lower() == 'idle'
                        if idle:
                            for field in ('phase', 'generated', 'tps', 'tps_kind'):
                                runtime.pop(field, None)
                        now = time.perf_counter()
                        signature = tuple(runtime.get(k) for k in fields)
                        changed = signature != previous_signature
                        previous_signature = signature
                        generated = int(runtime.get('generated') or 0)
                        direct_tps = number(runtime.get('tps'))
                        if not changed or idle:
                            runtime.pop('tps', None)
                            runtime.pop('tps_kind', None)
                        elif direct_tps is not None:
                            runtime['tps_observed_at'] = now
                        elif (generated > 0 and previous_generated is not None and
                              previous_generated_at is not None and generated >= previous_generated and now > previous_generated_at):
                            sample = float(generated - previous_generated) / (now - previous_generated_at)
                            if sample < 10_000:
                                runtime.update(tps=sample, tps_kind='delta', tps_observed_at=now)
                        if generated > 0 and changed:
                            previous_generated = generated
                            previous_generated_at = now
                        await queue.put(('runtime_status', runtime))
                except asyncio.CancelledError:
                    return
                except Exception:
                    pass  # telemetry must never make a healthy stream fail
                try:
                    await asyncio.wait_for(log_reader.overlap.wait(), timeout=0.75)
                except TimeoutError:
                    pass

        task = asyncio.create_task(pump_response(), name='harnessy-ollama-stream')
        telemetry_task = asyncio.create_task(pump_runtime_status(), name='harnessy-ollama-runtime-status')
        log_task = asyncio.create_task(pump_log_status(), name='harnessy-ollama-log-status')
        watchdog = StreamProgressWatchdog('Ollama', client_request_id=observation.client_request_id)
        runtime_state: dict[str, Any] = {}
        last_runtime: dict[str, Any] = {}
        last_phase = ''
        ambiguous_reported = False
        saw_done = False
        try:
            async for kind, value in watched_queue(
                queue, watchdog, health_probe,
            ):
                if kind == 'watchdog':
                    yield {'type': 'stream_watchdog', **dict(value or {})}
                    continue

                if kind == 'runtime_ambiguous' or (kind in {'runtime_status', 'log_status'} and log_reader.ambiguous):
                    if not ambiguous_reported:
                        ambiguous_reported = True
                        rates.samples.clear()
                        runtime_state.clear()
                        last_runtime = {
                            'phase': 'generating' if last_phase == 'generating' else 'prompt_processing',
                            'processed': 0, 'total': 0, 'generated': 0,
                            'tps': 0.0, 'prefill_tps': 0.0, 'tps_kind': 'unavailable',
                            'tps_source': 'ambiguous_concurrent_requests',
                        }
                        yield {'type': 'runtime_status', 'status': dict(last_runtime)}
                    continue
                if kind in {'runtime_status', 'log_status'}:
                    sample = dict(value) if isinstance(value, dict) else {}
                    source = 'ollama_log' if kind == 'log_status' else 'ollama_status'
                    now = time.perf_counter()
                    if source == 'ollama_log' and not sample:
                        rates.samples.pop(source, None)
                    rates.update(source, sample, now)
                    phase = str(sample.get('phase') or '').strip().lower()
                    # A delayed/idle server status must not send an already
                    # decoding response back through prefill or erase its rate.
                    if last_phase == 'generating' and phase != 'generating':
                        sample.pop('phase', None)
                        phase = ''
                    runtime_state.update({k: v for k, v in sample.items()
                                          if k in {'phase', 'context_window', 'context_used', 'processed', 'total', 'generated'}})
                    runtime_state.update(rates.current(now))
                    if phase in {'prompt_processing', 'prefill', 'generating', 'waiting'} and phase != last_phase:
                        last_phase = phase
                        log_event('backend', 'phase', provider='ollama', model=self.model, phase=phase,
                                  tps=runtime_state.get('tps'), tps_source=runtime_state.get('tps_source'))
                        yield {'type': 'phase', 'phase': phase}
                    if runtime_state != last_runtime:
                        last_runtime = dict(runtime_state)
                        yield {'type': 'runtime_status', 'status': dict(runtime_state)}
                    continue

                if kind == 'accepted':
                    # Do not infer that prefill starts here: on some Ollama/MLX
                    # builds response headers arrive only after prefill has
                    # already completed.  The runner starts at Prompt Processing
                    # immediately after submitting the request; live status, when
                    # available, refines it from there.
                    continue
                if kind == 'error':
                    log_event(
                        'backend', 'stream_error', provider='ollama', model=self.model,
                        error=f'{type(value).__name__}: {value}',
                    )
                    if isinstance(value, asyncio.CancelledError):
                        raise value
                    if isinstance(value, BaseException):
                        raise value
                    raise RuntimeError(str(value))
                if kind == 'done':
                    if not saw_done:
                        log_event('backend', 'backend_eof', provider='ollama', model=self.model, expected_done=False)
                        observation.event({'provider': 'ollama', 'kind': 'backend_eof', 'expected_done': False})
                        raise RuntimeError(
                            'Ollama stream closed before the required final done:true event. '
                            'The model response is incomplete and HarnessyXO will not treat it as a successful finish.'
                        )
                    break
                if kind != 'data' or not isinstance(value, dict):
                    continue

                data = value
                if data.get('error'):
                    raise LLMServerError(500, json.dumps(data), provider_label='Ollama')
                message = data.get('message') or {}
                # Native Ollama calls its reasoning field `thinking`; the runner
                # uses a normalized reasoning key internally. Carry the original
                # wire fields alongside the normalized text so the UI can show
                # the real route.
                delta, channel_sources = self._normalize_ollama_text_channels(message)
                if message.get('tool_calls'):
                    raw_tool_calls = message.get('tool_calls') or []
                    normalized_tool_calls = self._normalize_ollama_tool_calls(raw_tool_calls)
                    observation.event({
                        'provider': 'ollama',
                        'kind': 'tool_call_raw_snapshot',
                        'tool_calls': raw_tool_calls,
                    })
                    log_event(
                        'tools', 'tool_stream_raw', provider='ollama', semantics='snapshot',
                        tool_calls=raw_tool_calls,
                    )
                    # Native Ollama emits complete/cumulative tool-call snapshots,
                    # not OpenAI-style incremental fragments. Preserve that
                    # semantic distinction so the runner replaces by index rather
                    # than concatenating repeated names/JSON.
                    delta['tool_calls'] = normalized_tool_calls
                    observation.event({
                        'provider': 'ollama',
                        'kind': 'tool_call_snapshot',
                        'tool_calls': normalized_tool_calls,
                    })
                if delta:
                    if last_phase != 'generating':
                        last_phase = 'generating'
                        log_event('backend', 'phase', provider='ollama', model=self.model, phase='generating')
                        yield {'type': 'phase', 'phase': 'generating'}
                    yield {
                        'type': 'delta',
                        'delta': delta,
                        'channel_sources': channel_sources,
                        'tool_call_mode': 'snapshot' if delta.get('tool_calls') else 'delta',
                        'finish_reason': data.get('done_reason') if data.get('done') else None,
                    }
                if data.get('done'):
                    saw_done = True
                    prompt = int(data.get('prompt_eval_count') or 0)
                    completion = int(data.get('eval_count') or 0)
                    usage = {
                        'prompt_tokens': prompt,
                        'completion_tokens': completion,
                        'total_tokens': prompt + completion,
                    }
                    log_event(
                        'backend', 'request_complete', provider='ollama', model=self.model,
                        prompt_tokens=prompt, completion_tokens=completion, done_reason=data.get('done_reason'),
                        client_request_id=observation.client_request_id, **observation.counts,
                    )
                    yield {'type': 'usage', 'usage': usage, 'raw': data}
        finally:
            observation.log(provider='ollama', observation='transport_closed')
            telemetry_stop.set()
            log_reader.close()
            if not log_task.done():
                log_task.cancel()
            try:
                await log_task
            except asyncio.CancelledError:
                pass
            if not telemetry_task.done():
                telemetry_task.cancel()
            if not task.done():
                task.cancel()
            try:
                await telemetry_task
            except asyncio.CancelledError:
                pass
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def stream_chat(
        self, messages: list[dict[str, Any]], *, tools: list[dict[str, Any]] | None = None,
        max_output_tokens: int | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        """Stream a reply, optionally limiting only this request's generation.

        Omit ``max_output_tokens`` for the profile's ordinary allowance. A
        positive request cap never increases a smaller configured allowance.
        """
        request_options = (
            {'max_output_tokens': self._output_token_limit(max_output_tokens)}
            if max_output_tokens is not None else {}
        )
        has_images = self._has_image_input(messages)
        backend = await self._detect_backend()
        # Vision is most reliable through Ollama's canonical messages[].images
        # transport. If a profile was left in OpenAI-compatible mode but its
        # endpoint is actually Ollama, switch only image-bearing requests to
        # native /api/chat. Text-only requests still honor the selected mode.
        if has_images and backend != 'ollama' and await self._probe_ollama():
            # The existing image route uses native Ollama even for a compatible
            # profile. Thinking detection/verification must follow that actual
            # transport, without changing the profile for the next text request.
            saved_profile, saved_mode, saved_metadata = self.profile, self.api_mode, self._show_metadata
            self.profile = {**deepcopy(self.profile), 'api_mode': 'ollama'}
            self.api_mode, self._show_metadata = 'ollama', None
            try:
                async with aclosing(self._stream_ollama(messages, tools, **request_options)) as stream:
                    async for event in stream:
                        yield event
            finally:
                self.profile, self.api_mode, self._show_metadata = saved_profile, saved_mode, saved_metadata
            return
        if backend == 'ollama':
            async with aclosing(self._stream_ollama(messages, tools, **request_options)) as stream:
                async for event in stream:
                    yield event
            return
        async with aclosing(self._stream_openai(messages, tools, backend=backend, **request_options)) as stream:
            async for event in stream:
                yield event
