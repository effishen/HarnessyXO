"""Numeric observations for one durable, presentation-only model request row.

This tracker performs no I/O and retains no prompt, answer, reasoning or tool
argument text. A request's wait/TTFT is deliberately never called prefill time.
"""
from __future__ import annotations

import math
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .telemetry import llama_cpp_prompt_progress, number


_RUNTIME_SOURCES = frozenset({
    'llama.cpp_stream', 'omlx_usage', 'omlx_activity', 'ollama_status', 'ollama_log',
})
_FAILURES = frozenset({'', 'error', 'cancelled', 'interrupted'})


def _count(value: Any) -> int | None:
    parsed = number(value)
    return int(parsed) if parsed is not None and parsed.is_integer() and parsed <= 2**53 else None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PromptProcessingObservation:
    """Observe a single actual transport, including its eventual usage chunk.

    ``step`` is the runner's zero-based step; the public detail is one-based.
    Inject clocks in private QA. ``finish`` freezes wall elapsed time and permits
    only a fixed failure category; the owner persists/emits the resulting row.
    """

    def __init__(
        self, request: dict[str, Any], step: int = 0, purpose: str = 'model_call',
        *, monotonic: Callable[[], float] = time.perf_counter,
        wall_clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._clock = monotonic
        self._started = float(monotonic())
        self._wall = wall_clock()
        self._finished: float | None = None
        self._first_output: float | None = None
        self._last_output: float | None = None
        self._output_samples = 0
        self._terminal_usage_seen = False
        self._completion_evidence = False
        self._prefill_snapshot: dict[str, Any] | None = None
        self._prefill_completed_at: str | None = None
        self._prefill_completion_source = ''
        self._complete_prefill_seconds: float | None = None
        self._complete_prefill_tokens: int | None = None
        self._progress_total: int | None = None
        self._output_bytes = {'answer': 0, 'reasoning': 0}
        self._tool_bytes: dict[int, dict[str, int]] = {}
        self._runtime_fields: set[str] = set()
        self._native_fields: set[str] = set()
        self._values: dict[str, Any] = {
            'request_id': str(request.get('client_request_id') or ''),
            'backend': str(request.get('backend') or ''),
            'model': str(request.get('model') or ''),
            'step': max(0, int(step)) + 1,
            'purpose': 'completion_check' if purpose == 'completion_check' else 'model_call',
            'request_started_at': self._wall.isoformat(timespec='milliseconds'),
            'phase': 'waiting',
            'first_token_at': None,
            'duration_seconds': 0.0,
            'ttft_seconds': None,
            'prefill_seconds': None,
            'prefill_tps': None,
            'prefill_estimated': False,
            'prompt_tokens': None,
            'prompt_tokens_estimated': False,
            'processed_tokens': None,
            'cached_tokens': None,
            'uncached_total': None,
            'cache_hit_rate': None,
            'cache_accounting_available': False,
            'generated_tokens': None,
            'generated_tokens_estimated': False,
            'generation_tps': None,
            'generation_tps_estimated': False,
            'generation_seconds': None,
            'generation_seconds_estimated': False,
            'failure_kind': '',
        }

    def _complete_prefill(self, source: str) -> None:
        """Record the first positive completion boundary, independently of decode.

        A backend phase name or a successful HTTP EOF is not enough. Native
        100% counters, actual output or authoritative positive decode accounting
        prove that this particular request finished its prompt work.
        """
        if self._prefill_completed_at is None:
            elapsed = max(0.0, float(self._clock()) - self._started)
            self._prefill_completed_at = (self._wall + timedelta(seconds=elapsed)).isoformat(timespec='milliseconds')
            self._prefill_completion_source = source

    def _snapshot_prefill(self) -> None:
        """Freeze known prefill facts; late final usage may fill unknown fields.

        In particular, the last partial sample's elapsed time must never become
        the duration of a completed prompt. Request wall time and TTFT are not
        substitutes for native prefill duration either.
        """
        if self._prefill_completed_at is None:
            return
        frozen = self._prefill_snapshot or {}
        compatible = self._compatible_prefill_counts(
            _count(self._values['prompt_tokens']), _count(self._values['cached_tokens']))
        if not compatible and self._prefill_snapshot is not None:
            return  # do not combine contradictory counter epochs in one receipt
        prompt = _count(frozen.get('prompt_tokens'))
        if prompt is None:
            prompt = _count(self._values['prompt_tokens'])
        cached = _count(frozen.get('cached_tokens'))
        if cached is None:
            cached = _count(self._values['cached_tokens'])
        valid_cache = cached is not None and (prompt is None or cached <= prompt)
        fresh = _count(frozen.get('processed_tokens'))
        if fresh is None:
            fresh = prompt - cached if prompt is not None and valid_cache else None
        if fresh is None:
            fresh = self._complete_prefill_tokens
        seconds = number(frozen.get('prefill_seconds'))
        if seconds is None:
            seconds = self._complete_prefill_seconds
        candidate = {
            'schema_version': 1,
            'completed_at': self._prefill_completed_at,
            'completion_source': self._prefill_completion_source,
            'prompt_tokens': prompt,
            'cached_tokens': cached if valid_cache else None,
            'cache_hit_rate': ((cached * 100.0 / prompt if prompt else None) if valid_cache else
                               number(self._values['cache_hit_rate']) if cached is None else None),
            'processed_tokens': fresh,
            'prefill_seconds': seconds,
            'prefill_tps': number(fresh / seconds) if fresh is not None and seconds and seconds > 0 else None,
            'prefill_estimated': False,
        }
        if not compatible:
            # Actual completion remains an event even when a backend's first
            # numeric tuple contradicts itself. Preserve its independent native
            # duration and timestamp, leaving the unreliable counts unavailable.
            for key in ('prompt_tokens', 'cached_tokens', 'cache_hit_rate', 'processed_tokens', 'prefill_tps'):
                candidate[key] = None
        if self._prefill_snapshot is None:
            self._prefill_snapshot = candidate
        else:
            for key, value in candidate.items():
                if self._prefill_snapshot.get(key) is None and value is not None:
                    self._prefill_snapshot[key] = value

    def _compatible_prefill_counts(self, prompt: int | None, cached: int | None) -> bool:
        frozen = self._prefill_snapshot or {}
        if not all(frozen.get(key) is None or value is None or frozen[key] == value
                   for key, value in (('prompt_tokens', prompt), ('cached_tokens', cached))):
            return False
        prompt = prompt if prompt is not None else _count(frozen.get('prompt_tokens'))
        cached = cached if cached is not None else _count(frozen.get('cached_tokens'))
        fresh = _count(frozen.get('processed_tokens'))
        if prompt is not None:
            if cached is not None and cached > prompt:
                return False
            if fresh is not None and (prompt < fresh or (cached is not None and prompt - cached != fresh)):
                return False
            hit = number(frozen.get('cache_hit_rate'))
            if prompt == 0 and hit is not None:
                return False  # a zero denominator cannot explain a saved ratio
            if prompt > 0 and cached is not None and hit is not None:
                # A backend may report a rounded percentage before its counts.
                # Preserve agreement at the whole-percent precision displayed
                # in the receipt, e.g. 1% and a measured 0.7% are compatible.
                if math.floor(hit + .5) != math.floor(cached * 100.0 / prompt + .5):
                    return False
        return True

    def _set(self, key: str, value: Any, *, runtime: bool = False, estimated: bool = False) -> None:
        parsed = _count(value) if key.endswith('_tokens') or key == 'uncached_total' else number(value)
        if key == 'cache_hit_rate' and parsed is not None and parsed > 100:
            return
        if parsed is None or (runtime and key in self._native_fields):
            return
        self._values[key] = parsed
        if key == 'generation_tps':
            self._values['generation_tps_estimated'] = estimated
        elif key == 'prefill_tps':
            self._values['prefill_estimated'] = estimated
        if runtime:
            self._runtime_fields.add(key)
        else:
            self._native_fields.add(key)
            self._runtime_fields.discard(key)

    def _output(self, payload: dict[str, Any], *, snapshot: bool, tool_snapshot: bool) -> None:
        before_bytes = sum(self._output_bytes.values()) + sum(sum(row.values()) for row in self._tool_bytes.values())
        observed = False
        for channel, fields in (
            ('answer', ('content',)),
            ('reasoning', ('reasoning', 'reasoning_content', 'thinking')),
        ):
            text = next((payload.get(key) for key in fields if isinstance(payload.get(key), str) and payload[key]), '')
            length = len(text.encode('utf-8'))
            if length:
                observed = True
                self._output_bytes[channel] = (
                    max(self._output_bytes[channel], length) if snapshot else self._output_bytes[channel] + length
                )
        calls = payload.get('tool_calls')
        if not isinstance(calls, list):
            calls = ([{'index': 0, 'function': payload['function_call']}]
                     if isinstance(payload.get('function_call'), dict) else [])
        for position, call in enumerate(calls):
            if not isinstance(call, dict):
                continue
            index = _count(call.get('index', position))
            if index is None or index > 4096:
                continue
            function = call.get('function')
            if not isinstance(function, dict):
                continue
            lengths = self._tool_bytes.setdefault(index, {'name': 0, 'arguments': 0})
            for field in ('name', 'arguments'):
                value = function.get(field)
                if isinstance(value, str):
                    length = len(value.encode('utf-8'))
                elif field == 'arguments' and isinstance(value, (dict, list)):
                    # Native Ollama tools can contain a parsed JSON snapshot.
                    # Only the serialized length survives this observation.
                    import json
                    length = len(json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8'))
                else:
                    length = 0
                if length:
                    observed = True
                    lengths[field] = max(lengths[field], length) if snapshot or tool_snapshot else lengths[field] + length
        if observed:
            after_bytes = sum(self._output_bytes.values()) + sum(sum(row.values()) for row in self._tool_bytes.values())
            if after_bytes > before_bytes:
                self._output_samples += 1
                self._last_output = float(self._clock())
            self._values['phase'] = 'generating'
            if self._first_output is None:
                self._first_output = float(self._clock())
                elapsed = max(0.0, self._first_output - self._started)
                self._values['ttft_seconds'] = elapsed
                self._values['first_token_at'] = (self._wall + timedelta(seconds=elapsed)).isoformat(timespec='milliseconds')
                self._complete_prefill('output')

    def _usage(self, usage: dict[str, Any], raw: dict[str, Any]) -> None:
        for source, target in (('prompt_tokens', 'prompt_tokens'), ('completion_tokens', 'generated_tokens'),
                               ('cached_tokens', 'cached_tokens')):
            self._set(target, usage.get(source))
        details = usage.get('prompt_tokens_details')
        if isinstance(details, dict):
            self._set('cached_tokens', details.get('cached_tokens'))
        for source, target in (('prompt_tokens_per_second', 'prefill_tps'),
                               ('generation_tokens_per_second', 'generation_tps'),
                               ('prompt_eval_duration', 'prefill_seconds'),
                               ('generation_duration', 'generation_seconds')):
            self._set(target, usage.get(source))
        if self._values['generated_tokens'] is not None and self._values['generated_tokens'] > 0:
            self._values['phase'] = 'generating'
        for source, target in (('prompt_eval_count', 'prompt_tokens'), ('eval_count', 'generated_tokens')):
            self._set(target, raw.get(source))
        # Ollama's count is the logical whole prompt. Its eval duration covers
        # only uncached work; absent cache accounting cannot be treated as zero.
        self._set('cached_tokens', raw.get('prompt_eval_cached_count'))
        for source, target in (('prompt_eval_duration', 'prefill_seconds'), ('eval_duration', 'generation_seconds')):
            value = number(raw.get(source))
            if value is not None:
                self._set(target, value / 1_000_000_000)
        complete_usage = self._completion_evidence and (
            (_count(usage.get('prompt_tokens')) is not None and _count(usage.get('completion_tokens')) is not None)
            or (_count(raw.get('prompt_eval_count')) is not None and _count(raw.get('eval_count')) is not None))
        if complete_usage or (_count(usage.get('completion_tokens')) or 0) > 0 or (_count(raw.get('eval_count')) or 0) > 0:
            self._complete_prefill('usage')
        if (self._prefill_completed_at is not None and self._complete_prefill_seconds is None
                and (self._prefill_snapshot is None or self._compatible_prefill_counts(
                    _count(self._values['prompt_tokens']), _count(self._values['cached_tokens'])))):
            seconds = number(usage.get('prompt_eval_duration'))
            raw_ns = number(raw.get('prompt_eval_duration'))
            if seconds is not None or raw_ns is not None:
                self._complete_prefill_seconds = seconds if seconds is not None else raw_ns / 1_000_000_000

    def _timings(self, timings: dict[str, Any]) -> None:
        self._set('cached_tokens', timings.get('cache_n'))
        processed, cached = _count(timings.get('prompt_n')), _count(timings.get('cache_n'))
        generating = ((_count(timings.get('predicted_n')) or 0) > 0 or self._first_output is not None
                      or self._completion_evidence)
        expected_fresh = _count((self._prefill_snapshot or {}).get('processed_tokens'))
        if expected_fresh is None and self._progress_total is not None:
            known_cache = _count(self._values['cached_tokens'])
            if known_cache is not None and known_cache <= self._progress_total:
                expected_fresh = self._progress_total - known_cache
        full_timing = (generating and (expected_fresh is None or processed == expected_fresh)
                       and self._compatible_prefill_counts(
                           processed + cached if processed is not None and cached is not None else None, cached))
        if full_timing and processed is not None and self._complete_prefill_tokens is None:
            self._complete_prefill_tokens = processed
        if processed is not None:
            if self._progress_total is None or generating:
                self._set('processed_tokens', processed)
            # Early timing counters can describe the work done so far. Native
            # prompt_progress carries the full denominator independently.
            if cached is not None and full_timing:
                self._set('prompt_tokens', processed + cached)
                self._set('uncached_total', processed)
        self._set('generated_tokens', timings.get('predicted_n'))
        if (_count(timings.get('predicted_n')) or 0) > 0:
            self._values['phase'] = 'generating'
            self._complete_prefill('backend_timing')
        elif full_timing and self._completion_evidence:
            self._complete_prefill('backend_timing')
        self._set('prefill_tps', timings.get('prompt_per_second'))
        # Prefill timings often contain predicted_ms/per_second=0 placeholders.
        # They are not a decode measurement that should suppress an eventual
        # stream estimate when this backend omits its final timing sample.
        if (_count(timings.get('predicted_n')) or 0) > 0:
            self._set('generation_tps', timings.get('predicted_per_second'))
        for source, target in (('prompt_ms', 'prefill_seconds'), ('predicted_ms', 'generation_seconds')):
            value = number(timings.get(source))
            if value is not None and (target != 'generation_seconds' or value > 0 or (_count(timings.get('predicted_n')) or 0) > 0):
                self._set(target, value / 1000.0)
                if target == 'prefill_seconds' and full_timing and self._complete_prefill_seconds is None:
                    self._complete_prefill_seconds = value / 1000.0

    def _progress(self, progress: dict[str, Any]) -> None:
        validated = llama_cpp_prompt_progress({'prompt_progress': progress})
        if validated is None:
            return
        complete = int(validated['total']) > 0 and int(validated['processed']) == int(validated['total'])
        if self._values['phase'] == 'generating':
            # A delayed 100% native counter can supply previously unknown
            # prefill facts. Delayed partials cannot rewind decode or turn their
            # elapsed time into the final duration.
            if complete:
                frozen = self._prefill_snapshot or {}
                if (frozen.get('prompt_tokens') in {None, int(validated['total'])}
                        and frozen.get('cached_tokens') in {None, int(validated['cache'])}):
                    for key, value in (('prompt_tokens', validated['total']), ('cached_tokens', validated['cache'])):
                        if self._values[key] is None:
                            self._set(key, value)
                    self._complete_prefill('native_progress')
                    if self._complete_prefill_seconds is None:
                        self._complete_prefill_seconds = float(validated['time_ms']) / 1000.0
                    if self._complete_prefill_tokens is None:
                        self._complete_prefill_tokens = int(validated['total']) - int(validated['cache'])
            return
        self._set('prompt_tokens', validated['total'])
        self._progress_total = int(validated['total'])
        self._set('cached_tokens', validated['cache'])
        self._set('uncached_total', int(validated['total']) - int(validated['cache']))
        processed = int(validated['processed']) - int(validated['cache'])
        self._set('processed_tokens', processed)
        elapsed = float(validated['time_ms']) / 1000.0
        self._set('prefill_seconds', elapsed)
        if elapsed > 0:
            self._set('prefill_tps', processed / elapsed)
        if complete:
            self._complete_prefill('native_progress')
            if self._complete_prefill_seconds is None:
                self._complete_prefill_seconds = elapsed
            if self._complete_prefill_tokens is None:
                self._complete_prefill_tokens = processed

    def observe(self, event: dict[str, Any]) -> None:
        if self._finished is not None or not isinstance(event, dict):
            return
        kind = str(event.get('type') or '')
        raw = event.get('raw') if isinstance(event.get('raw'), dict) else {}
        finish_reason = event.get('finish_reason') or raw.get('finish_reason') or raw.get('done_reason')
        choices = raw.get('choices')
        if not finish_reason and isinstance(choices, list) and choices and isinstance(choices[0], dict):
            finish_reason = choices[0].get('finish_reason')
        if raw.get('done') is True or finish_reason in {
            'stop', 'tool_calls', 'function_call', 'completed', 'complete', 'length',
            'max_tokens', 'max_output_tokens', 'token_limit', 'max_completion_tokens', 'output_limit',
        }:
            self._completion_evidence = True
        if kind in {'delta', 'message'}:
            payload = event.get(kind)
            if isinstance(payload, dict):
                self._output(payload, snapshot=kind == 'message', tool_snapshot=event.get('tool_call_mode') == 'snapshot')
        if kind == 'phase':
            phase = str(event.get('phase') or '')
            if self._values['phase'] != 'generating' and phase in {'waiting', 'prompt_processing', 'prefill', 'generating'}:
                self._values['phase'] = 'prompt_processing' if phase == 'prefill' else phase
        if kind == 'runtime_status':
            status = event.get('status')
            if isinstance(status, dict):
                source = str(status.get('tps_source') or '')
                if source == 'ambiguous_concurrent_requests':
                    for key in self._runtime_fields:
                        self._values[key] = None
                        if key == 'generation_tps':
                            self._values['generation_tps_estimated'] = False
                        elif key == 'prefill_tps':
                            self._values['prefill_estimated'] = False
                    self._runtime_fields.clear()
                elif source in _RUNTIME_SOURCES or status.get('request_scoped') is True:
                    phase = str(status.get('phase') or '')
                    if self._values['phase'] != 'generating' and phase in {'prompt_processing', 'prefill', 'generating', 'waiting'}:
                        self._values['phase'] = 'prompt_processing' if phase == 'prefill' else phase
                    # Generating activity rows can omit total. Context-used is
                    # prompt plus output, so it cannot stand in for prompt size.
                    for source_key, target in (('total', 'prompt_tokens'), ('processed', 'processed_tokens'),
                                               ('cached_tokens', 'cached_tokens'), ('generated', 'generated_tokens'),
                                               ('uncached_total', 'uncached_total'), ('cache_hit_rate', 'cache_hit_rate')):
                        if source == 'omlx_usage' and source_key == 'processed':
                            continue  # the normalizer defaults unknown cache to zero
                        if (source == 'llama.cpp_stream' and source_key == 'total'
                                and phase in {'prompt_processing', 'prefill'}
                                and not isinstance(status.get('native_prompt_progress'), dict)):
                            continue
                        self._set(target, status.get(source_key), runtime=True)
                    self._set('prefill_tps', status.get('prefill_tps'), runtime=True,
                              estimated=status.get('prefill_tps_estimated') is True)
                    if status.get('tps_kind') not in {None, '', 'unavailable'}:
                        self._set('generation_tps', status.get('tps'), runtime=True,
                                  estimated=status.get('tps_kind') == 'estimated' or status.get('tps_estimated') is True)
                    progress = status.get('native_prompt_progress')
                    if isinstance(progress, dict):
                        self._progress(progress)
                    timings = status.get('backend_timings')
                    if isinstance(timings, dict):
                        self._timings(timings)
                    if (_count(status.get('generated')) or 0) > 0:
                        self._complete_prefill('usage')
                    elif phase in {'prompt_processing', 'prefill'}:
                        total, cached = _count(status.get('total')), _count(status.get('cached_tokens'))
                        fresh, processed = _count(status.get('uncached_total')), _count(status.get('processed'))
                        if (total is not None and total > 0 and cached is not None and cached <= total
                                and fresh == total - cached and processed == fresh):
                            self._complete_prefill('runtime_progress')
                            if self._complete_prefill_tokens is None:
                                self._complete_prefill_tokens = fresh
        usage = event.get('usage') if isinstance(event.get('usage'), dict) else {}
        if isinstance(raw.get('usage'), dict):
            self._usage(raw['usage'], {})
        if kind == 'usage' or usage:
            self._usage(usage, raw)
            # A terminal usage event is generated from the response's usage
            # chunk, independently of client-side text estimates. Positive
            # completion accounting is itself evidence that prefill finished.
            if kind == 'usage' and _count(usage.get('prompt_tokens')) is not None and _count(usage.get('completion_tokens')) is not None:
                self._terminal_usage_seen = True
                if (_count(usage.get('completion_tokens')) or 0) > 0:
                    self._completion_evidence = True
        timings = raw.get('timings')
        if isinstance(timings, dict):
            self._timings(timings)
        progress = raw.get('prompt_progress')
        if isinstance(progress, dict):
            self._progress(progress)
        if self._terminal_usage_seen and self._completion_evidence:
            self._complete_prefill('usage')
        self._snapshot_prefill()

    def finish(self, failure_kind: str = '') -> None:
        if self._finished is None:
            self._finished = float(self._clock())
            self._values['failure_kind'] = failure_kind if failure_kind in _FAILURES else 'error'

    def details(self) -> dict[str, Any]:
        result = dict(self._values)
        result['prefill_complete'] = self._prefill_snapshot is not None
        result['prefill_completed_at'] = self._prefill_completed_at
        # Do not expose the owned dictionary to UI/storage callers. An update
        # made by a receiver must not change later snapshots of this request.
        result['prefill_snapshot'] = dict(self._prefill_snapshot) if self._prefill_snapshot is not None else None
        now = self._finished if self._finished is not None else float(self._clock())
        result['duration_seconds'] = max(0.0, now - self._started)
        output_bytes = sum(self._output_bytes.values()) + sum(sum(row.values()) for row in self._tool_bytes.values())
        if output_bytes and not result['generated_tokens']:
            # A prefill sample's initial generated=0 must not mask later output
            # on backends which do not send another numeric sample.
            result['generated_tokens'] = math.ceil(output_bytes / 3)
            result['generated_tokens_estimated'] = True
        if result['generation_seconds'] is None and self._first_output is not None:
            # A stream-observed decode duration is separate from native backend
            # duration; its derived speed is explicitly an estimate.
            result['generation_seconds'] = max(0.0, now - self._first_output)
            result['generation_seconds_estimated'] = True
        if result['generation_tps'] is None and result['generated_tokens'] is not None:
            elapsed = number(result['generation_seconds'])
            # A buffered one-shot response tells us nothing about decode speed.
            # It must not become millions of tok/s merely because EOF followed
            # its only output chunk by a fraction of a millisecond. Repeated
            # identical snapshots are likewise not evidence of live streaming.
            sample_span = (self._last_output - self._first_output
                           if self._last_output is not None and self._first_output is not None else 0.0)
            meaningful_stream = self._output_samples >= 2 and sample_span >= .1
            if elapsed and elapsed > 0 and ('generation_seconds' in self._native_fields or meaningful_stream):
                result['generation_tps'] = number(result['generated_tokens'] / elapsed)
                result['generation_tps_estimated'] = 'generation_seconds' not in self._native_fields or result['generated_tokens_estimated']
        prompt, cached = _count(result['prompt_tokens']), _count(result['cached_tokens'])
        valid_cache = cached is not None and (prompt is None or cached <= prompt)
        result['cache_accounting_available'] = valid_cache or result['cache_hit_rate'] is not None
        if prompt is not None and cached is not None:
            if valid_cache:
                result['uncached_total'] = prompt - cached
                result['cache_hit_rate'] = cached * 100.0 / prompt if prompt > 0 else None
            else:
                # Asynchronous or malformed counters must not become 100% cache
                # hits, negative remaining work, or a false completed progress.
                result['uncached_total'] = None
                result['cache_hit_rate'] = None
                result['cache_accounting_available'] = False
        completed_usage = (self._finished is not None and not result['failure_kind']
                           and self._terminal_usage_seen and self._completion_evidence)
        # Actual output from this transport proves that its prompt has finished
        # processing. A phase label alone is insufficient evidence. A later
        # generation error does not undo prefill work that already completed.
        if (completed_usage or self._first_output is not None) and result['uncached_total'] is not None:
            result['processed_tokens'] = result['uncached_total']
        if (result['processed_tokens'] is not None and result['uncached_total'] is not None
                and result['processed_tokens'] > result['uncached_total']):
            result['processed_tokens'] = None
        if result['prefill_tps'] is None and result['processed_tokens'] is not None:
            elapsed = number(result['prefill_seconds'])
            if elapsed and elapsed > 0:
                result['prefill_tps'] = number(result['processed_tokens'] / elapsed)
        return result
