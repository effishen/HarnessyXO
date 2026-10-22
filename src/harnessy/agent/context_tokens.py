"""Run-local prompt accounting backed by completed provider measurements.

The rough UTF-8 estimate remains the fallback.  A measured unchanged prefix
can be reused without discounting newly appended text.  Rebased requests need
several compatible observations before any learned discount is applied.
No tokenizer/model is downloaded and no prompt text is retained in samples.
"""
from __future__ import annotations

import hashlib
import json
import math
from collections import deque
from dataclasses import dataclass
from typing import Any, Mapping


_MEASURED_SOURCES = frozenset({'backend_usage', 'backend_timings', 'native_tokenizer'})
_MAX_SAMPLES = 16
_MAX_ROWS = 4096
_SCALAR_TYPES = (str, int, float, bool, type(None))


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), default=str)


def _digest(value: Any) -> str:
    return hashlib.sha256(_json(value).encode('utf-8', errors='replace')).hexdigest()


def _text(value: Any) -> int:
    return math.ceil(len(str(value or '').encode('utf-8', errors='replace')) / 3)


def _public_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # Match the client's public OpenAI view, including its single system row.
    systems: list[str] = []
    rest: list[dict[str, Any]] = []
    for original in messages:
        row = {k: v for k, v in original.items() if not str(k).startswith('_harnessy_')}
        if row.get('role') == 'system':
            content = row.get('content')
            text = ''.join(str(p.get('text') or '') for p in content
                           if isinstance(p, dict) and p.get('type') == 'text') if isinstance(content, list) else str(content or '')
            if text.strip():
                systems.append(text.strip())
        else:
            rest.append(row)
    return ([{'role': 'system', 'content': '\n\n'.join(systems)}] if systems else []) + rest


def _message(row: dict[str, Any]) -> int:
    content = row.get('content') or ''
    if isinstance(content, list):
        body = sum(4096 if p.get('type') == 'image_url' else _text(p.get('text', ''))
                   for p in content if isinstance(p, dict))
    else:
        body = _text(content)
    extras = {k: row[k] for k in ('name', 'tool_call_id', 'tool_calls') if row.get(k)}
    return 8 + body + _text(json.dumps(extras, ensure_ascii=False, separators=(',', ':')))


def _tools(tools: list[dict[str, Any]]) -> int:
    return _text(json.dumps(tools or [], ensure_ascii=False, separators=(',', ':'))) + (8 if tools else 0)


def _has_media(messages: list[dict[str, Any]]) -> bool:
    for row in messages:
        if row.get('_harnessy_images') or row.get('images'):
            return True
        content = row.get('content')
        if isinstance(content, list) and any(isinstance(p, dict) and p.get('type') not in {'text', 'input_text'} for p in content):
            return True
    return False


def _row_features(row: dict[str, Any]) -> tuple[int, ...]:
    counts = [0, 0, 0, 0, 0, 0, 0, 0]
    role = str(row.get('role') or '')
    counts[5 if role == 'system' else 6 if role == 'tool' else 7] = _message(row)
    content = row.get('content')
    text = _json(content) if isinstance(content, list) else str(content or '')
    text += _json(row.get('tool_calls') or '')
    for char in text:
        point = ord(char)
        counts[0 if char.isspace() else 1 if point < 128 and char.isalpha()
               else 2 if point < 128 and char.isdigit() else 3 if point < 128 else 4] += 1
    return tuple(counts)


def _shape_features(features: list[tuple[int, ...]]) -> tuple[float, ...]:
    counts = [sum(row[index] for row in features) for index in range(8)]
    body = max(1, sum(counts[:5]))
    roles = max(1, sum(counts[5:]))
    return tuple(n / body for n in counts[:5]) + tuple(n / roles for n in counts[5:])


def _shape(messages: list[dict[str, Any]]) -> tuple[float, ...]:
    """A bounded composition check, never a substitute for a tokenizer."""
    return _shape_features([_row_features(row) for row in messages])


@dataclass(frozen=True)
class _Sample:
    fingerprints: tuple[str, ...]
    rough_rows: tuple[int, ...]
    tools_fingerprint: str
    rough: int
    actual: int
    source: str
    shape: tuple[float, ...]


@dataclass(frozen=True)
class _Evaluation:
    tokens: int
    rough: int
    method: str
    source: str
    ratio: float = 1.0
    uncertainty: int = 0
    samples: int = 0
    exact: bool = False


class RequestTokenCounter:
    """Immutable measurement view for one budgeting pass and its mutations."""

    def __init__(self, samples: tuple[_Sample, ...], exact: _Sample | None, tools_fingerprint: str) -> None:
        self._samples = samples
        self._exact = exact
        self._tools_fingerprint = tools_fingerprint
        self._cache: dict[tuple[tuple[str, ...], str], _Evaluation] = {}
        self._row_cache: dict[tuple[Any, ...], tuple[str, int]] = {}
        self._shape_cache: dict[str, tuple[int, ...]] = {}
        self._allocation_ratio = 1.0
        self._known_rows = {fp for sample in samples for fp in sample.fingerprints}

    def _row_facts(self, row: dict[str, Any], *, digest: bool = True) -> tuple[str, int]:
        # Long immutable strings are common in tool results. Python caches
        # their hash, so unchanged rows need not be re-encoded/re-tokenized
        # hundreds of times during one compaction. Nested mutable payloads
        # are serialized before lookup so in-place edits stay observable.
        serialized: str | None = None
        if all(type(value) in _SCALAR_TYPES for value in row.values()):
            cache_key = tuple((key, type(value), value) for key, value in sorted(row.items()))
        else:
            # Serializing nested fields on every lookup detects in-place
            # changes; expensive cost/shape work can still be reused.
            serialized = _json(row)
            cache_key = ('nested', serialized)
        found = self._row_cache.get(cache_key)
        if found is not None and (not digest or found[0]):
            return found
        fingerprint = (hashlib.sha256((serialized if serialized is not None else _json(row)).encode(
            'utf-8', errors='replace')).hexdigest() if digest else '')
        result = (fingerprint, found[1] if found is not None else _message(row))
        if len(self._row_cache) >= _MAX_ROWS * 2:
            self._row_cache.clear()
        self._row_cache[cache_key] = result
        return result

    def _request_shape(self, public: list[dict[str, Any]], fingerprints: tuple[str, ...]) -> tuple[float, ...]:
        features: list[tuple[int, ...]] = []
        for row, fingerprint in zip(public, fingerprints):
            counts = self._shape_cache.get(fingerprint)
            if counts is None:
                counts = _row_features(row)
                if len(self._shape_cache) >= _MAX_ROWS * 2:
                    self._shape_cache.clear()
                self._shape_cache[fingerprint] = counts
            features.append(counts)
        return _shape_features(features)

    def estimate_text(self, value: Any) -> int:
        return math.ceil(_text(value) * self._allocation_ratio)

    def estimate_message(self, row: dict[str, Any]) -> int:
        # Components are allocations, not independently tokenized measurements.
        return math.ceil(_message(row) * self._allocation_ratio)

    def estimate_tools(self, tools: list[dict[str, Any]]) -> int:
        return math.ceil(_tools(tools) * self._allocation_ratio)

    def _evaluate(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> _Evaluation:
        public = _public_messages(messages)
        if not self._samples and self._exact is None:
            rough = _tools(tools) + sum(self._row_facts(row, digest=False)[1] for row in public)
            self._allocation_ratio = 1.
            return _Evaluation(rough, rough, 'rough', 'utf8_estimate')
        facts = [self._row_facts(row) for row in public]
        fingerprints = tuple(row[0] for row in facts)
        tools_fp = _digest(tools or [])
        key = (fingerprints, tools_fp)
        if key in self._cache:
            result = self._cache[key]
            self._allocation_ratio = result.tokens / max(1, result.rough)
            return result
        rough_rows = tuple(row[1] for row in facts)
        schema = _tools(tools)
        rough = schema + sum(rough_rows)
        result = _Evaluation(rough, rough, 'rough', 'utf8_estimate')
        same_schema = tools_fp == self._tools_fingerprint
        if same_schema and not _has_media(messages) and len(fingerprints) <= _MAX_ROWS:
            exact = self._exact
            if exact is not None and exact.fingerprints == fingerprints:
                result = _Evaluation(exact.actual, rough, 'native_tokenizer',
                                     'native_tokenizer', exact.actual / max(1, rough),
                                     samples=1, exact=True)
            else:
                anchors = [sample for sample in self._samples
                           if len(sample.fingerprints) <= len(fingerprints)
                           and fingerprints[:len(sample.fingerprints)] == sample.fingerprints]
                if anchors:
                    anchor = max(anchors, key=lambda sample: len(sample.fingerprints))
                    added = rough_rows[len(anchor.fingerprints):]
                    uncertainty = max(128, math.ceil(anchor.actual * .02)) + 8 * len(added)
                    total = anchor.actual + sum(added) + uncertainty
                    result = _Evaluation(total, rough, 'prefix_anchor',
                                         anchor.source,
                                         total / max(1, rough), uncertainty, len(anchors))
                elif len(self._samples) >= 3 and rough >= 1024:
                    shape = self._request_shape(public, fingerprints)
                    compatible = [sample for sample in self._samples
                                  if .5 <= rough / max(1, sample.rough) <= 2
                                  and sum(abs(a - b) for a, b in zip(shape, sample.shape)) <= .18]
                    known = sum(cost for fp, cost in zip(fingerprints, rough_rows) if fp in self._known_rows)
                    if len(compatible) >= 3 and known / max(1, sum(rough_rows)) >= .85:
                        # Use the most conservative compatible observation, an
                        # extra ratio guard and an additive guard. New text is
                        # always charged at least its uncalibrated estimate.
                        ratio = min(4., max(.65, max(s.actual / max(1, s.rough) for s in compatible) + .04))
                        allocated = math.ceil((schema + known) * ratio)
                        novel = sum(rough_rows) - known
                        allocated += math.ceil(novel * max(1., ratio))
                        uncertainty = max(256, math.ceil(rough * .02))
                        sources = {sample.source for sample in compatible}
                        result = _Evaluation(allocated + uncertainty, rough, 'calibrated',
                                             next(iter(sources)) if len(sources) == 1 else 'backend_usage', ratio,
                                             uncertainty, len(compatible))
        self._allocation_ratio = result.tokens / max(1, rough)
        if len(self._cache) >= 64:
            self._cache.clear()
        self._cache[key] = result
        return result

    def estimate_request(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> int:
        return self._evaluate(messages, tools).tokens

    def metadata(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
        result = self._evaluate(messages, tools)
        return {
            'token_accounting_method': result.method,
            'token_accounting_source': result.source,
            'token_accounting_exact': result.exact,
            'token_accounting_actual_tokens': result.tokens if result.exact else None,
            'token_accounting_raw_tokens': result.rough,
            'token_accounting_samples': result.samples,
            'token_accounting_ratio': round(result.ratio, 6),
            'token_accounting_uncertainty_tokens': result.uncertainty,
            'budget_method': {
                'rough': 'UTF-8 estimate',
                'calibrated': 'Compatible backend measurements',
                'prefix_anchor': 'Measured prefix with estimated new messages',
                'native_tokenizer': 'Backend request tokenizer',
            }[result.method] + '; components remain estimated allocations',
            'usage_kind': 'exact_request_tokenizer_measurement' if result.exact else
                          'estimate_based_on_backend_usage' if result.method != 'rough' else
                          'estimate_not_tokenizer_measurement',
        }


class PromptTokenAccounting:
    """Measurements belong only to this run and exact profile/config identity."""

    def __init__(self, profile: Mapping[str, Any], *, configuration: Mapping[str, Any] | None = None) -> None:
        self._profile = profile
        self._default_configuration = dict(configuration or {})
        self._identity = ''
        self._schema = ''
        self._samples: deque[_Sample] = deque(maxlen=_MAX_SAMPLES)
        self._current_exact: _Sample | None = None

    def _ensure(self, tools: list[dict[str, Any]], configuration: Mapping[str, Any] | None, *, media: bool) -> str:
        identity = _digest((dict(self._profile), dict(self._default_configuration if configuration is None else configuration)))
        schema = _digest(tools or [])
        if identity != self._identity or schema != self._schema or media:
            self._samples.clear()
            self._current_exact = None
            self._identity, self._schema = identity, schema
        return schema

    def counter(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], *,
                configuration: Mapping[str, Any] | None = None) -> RequestTokenCounter:
        media = _has_media(messages)
        schema = self._ensure(tools, configuration, media=media)
        fingerprints = tuple(_digest(row) for row in _public_messages(messages))
        if self._current_exact is not None and fingerprints != self._current_exact.fingerprints:
            self._current_exact = None
        counter = RequestTokenCounter(tuple(self._samples), self._current_exact, schema)
        counter.estimate_request(messages, tools)
        return counter

    def observe(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], prompt_tokens: Any,
                source: str, *, complete: bool = True, estimated: bool = False,
                configuration: Mapping[str, Any] | None = None) -> bool:
        media = _has_media(messages)
        schema = self._ensure(tools, configuration, media=media)
        if (complete is not True or estimated is not False or source not in _MEASURED_SOURCES or media
                or isinstance(prompt_tokens, bool) or not isinstance(prompt_tokens, int)
                or not 0 < prompt_tokens <= 2 ** 31 - 1):
            return False
        public = _public_messages(messages)
        if not public or len(public) > _MAX_ROWS:
            return False
        rough_rows = tuple(_message(row) for row in public)
        rough = _tools(tools) + sum(rough_rows)
        if prompt_tokens > rough * 8 + 8192:
            return False
        sample = _Sample(tuple(_digest(row) for row in public), rough_rows, schema,
                         rough, prompt_tokens, source, _shape(public))
        # Repeated identical usage receipts do not fabricate several stable
        # observations. Native preflight + completion is one prompt sample.
        self._samples = deque((old for old in self._samples if old.fingerprints != sample.fingerprints), maxlen=_MAX_SAMPLES)
        self._samples.append(sample)
        self._current_exact = sample if source == 'native_tokenizer' else None
        return True
