"""Bounded request-view tuning; no backend settings or durable state writes."""
from __future__ import annotations

from dataclasses import dataclass, field
import math

PREFILL_MEMORY_TUNING_STEP_TOKENS = 1_024
PREFILL_MEMORY_TUNING_MIN_TOKENS = 4_096
PREFILL_MEMORY_TUNING_MAX_RETRIES = 24
PREFILL_MEMORY_TUNING_HEADROOM_RATIO = 0.005
CONTEXT_TUNING_STEP_RATIO = 0.02
AUTO_CONTEXT_MAX_UPWARD_PROBES = 64
AUTO_CONTEXT_STABLE_REQUESTS = 4
AUTO_CONTEXT_MAX_PROBE_COOLDOWN = 64
# Model admission can race cleanup after an aborted prefill. These retries do
# not consume prompt-reduction attempts or supply prompt-capacity samples.
MODEL_MEMORY_RETRY_DELAYS = (2, 5, 10, 20, 30)


async def wait_for_model_memory(seconds: float) -> None:
    import asyncio
    await asyncio.sleep(seconds)


def _floor_tokens(value: float) -> int:
    return max(0, int(value) // PREFILL_MEMORY_TUNING_STEP_TOKENS * PREFILL_MEMORY_TUNING_STEP_TOKENS)


@dataclass
class RetryContextTuner:
    """Measurements from one model request's rejected prefill attempts only."""

    samples: list[tuple[int, int, int, int]] = field(default_factory=list)
    method: str = ''
    base_history: int = 0
    decrement: int = 0
    suggested_decrement: int = 0
    attempt: int = 0
    reduction_was_bounded: bool = False

    def next_target(
        self, *, current_target: int, assembled: int = 0, fixed: int = 0,
        estimated_bytes: int = 0, limit_bytes: int = 0, attempt: int = 1,
        known_good: int = 0, prompt_tokens: int = 0, context_tokens: int = 0,
        output_reserve: int = 0,
    ) -> int:
        step = PREFILL_MEMORY_TUNING_STEP_TOKENS
        minimum = PREFILL_MEMORY_TUNING_MIN_TOKENS
        normal = max(minimum, current_target)
        active = max(0, assembled - fixed)
        base = max(minimum, min(normal, active) if active else normal)

        if prompt_tokens > 0 and context_tokens > 0:
            allowed = max(0, context_tokens - output_reserve - math.ceil(context_tokens * 0.10))
            drop = max(step, math.ceil(assembled * (1 - allowed / prompt_tokens)))
            self.method = 'reported_context'
        elif estimated_bytes > limit_bytes > 0:
            desired = int(limit_bytes * (1.0 - PREFILL_MEMORY_TUNING_HEADROOM_RATIO))
            # A single total-memory estimate does not expose the fixed model
            # allocation. Use the overage conservatively until two comparable
            # rejected requests can estimate the variable bytes/token slope.
            drop = math.ceil(base * (estimated_bytes - desired) * 1.5 / estimated_bytes)
            self.method = 'memory_ratio'
            for old_tokens, old_peak, old_limit, old_fixed in reversed(self.samples):
                if old_limit != limit_bytes or old_fixed != fixed:
                    continue
                delta_tokens = old_tokens - assembled
                delta_bytes = old_peak - estimated_bytes
                if delta_tokens < step or delta_bytes <= 0:
                    continue
                slope = delta_bytes / delta_tokens
                intercept = estimated_bytes - slope * assembled
                # Reject impossible fixed allocations; cache/concurrency may
                # have changed between observations. This is an estimate, not
                # a guaranteed hardware limit or a tokenizer measurement.
                if intercept < 0:
                    continue
                predicted_input = (desired - intercept) / slope
                drop = max(step, math.ceil(assembled - predicted_input))
                self.method = 'memory_slope'
                break
            self.samples.append((assembled, estimated_bytes, limit_bytes, fixed))
            self.samples = self.samples[-PREFILL_MEMORY_TUNING_MAX_RETRIES:]
        else:
            # A limit alone cannot predict memory at a different prompt size.
            # Missing, non-positive, or contradicted peak estimates use search.
            drop = math.ceil(base * CONTEXT_TUNING_STEP_RATIO)
            self.method = 'fallback_step'

        # Memory pressure can change between two observations. A large slope
        # recommendation or a historic accepted target is not permission to
        # discard a large part of the current request in one attempt. Explore
        # downward in small steps, even when feedback predicts a much lower
        # eventual size. Exact reported model limits are enforced separately
        # by the runner's full-input budget.
        self.base_history = base
        self.suggested_decrement = max(step, math.ceil(drop))
        self.attempt = attempt
        slow_step = max(step, math.ceil(base * CONTEXT_TUNING_STEP_RATIO))
        decrement = min(slow_step, max(step, math.ceil(drop)))
        target = max(minimum, _floor_tokens(base - decrement))
        if target >= normal and normal > minimum:
            target = max(minimum, _floor_tokens(normal - step))
        self.decrement = max(0, base - target)
        self.reduction_was_bounded = self.suggested_decrement > decrement
        return target

    def snapshot(self) -> dict[str, int | str | bool]:
        """Compact telemetry without prompt text or model-specific token mixing."""
        return {
            'tuning_method': self.method,
            'base_history_tokens_estimated': self.base_history,
            'decrement_tokens_estimated': self.decrement,
            'suggested_decrement_tokens_estimated': self.suggested_decrement,
            'reduction_was_bounded': self.reduction_was_bounded,
            'retry_number': self.attempt,
            'max_retries': PREFILL_MEMORY_TUNING_MAX_RETRIES,
        }


@dataclass
class AutoContextTuner:
    """Slowly reassess current capacity on natural requests during one job.

    Upward probes use natural subsequent requests. A ceiling is never treated
    as an accepted size when compaction sent substantially less history. Old
    rejections are retained as evidence, not an irrevocable capacity ceiling.
    """

    target: int | None = None
    good: int = 0
    bad: int = 0
    limit_bytes: int = 0
    pending_probe: int | None = None
    probes: int = 0
    stable_successes: int = 0
    cooldown_successes: int = AUTO_CONTEXT_STABLE_REQUESTS
    failed_probes: int = 0
    probe_reason: str = ''
    _probe_in_flight: bool = False

    def failure(self, history: int, *, limit_bytes: int = 0) -> None:
        if limit_bytes and self.limit_bytes and limit_bytes != self.limit_bytes:
            self.good = self.bad = 0
        if limit_bytes:
            self.limit_bytes = limit_bytes
        self.pending_probe = None
        self.stable_successes = 0
        if self._probe_in_flight:
            self.failed_probes += 1
            # Repeated probes into unchanged pressure become increasingly
            # infrequent. Count only accepted natural requests, never waits,
            # retry attempts, or new LLM calls issued solely for checking.
            self.cooldown_successes = min(
                AUTO_CONTEXT_MAX_PROBE_COOLDOWN,
                AUTO_CONTEXT_STABLE_REQUESTS * 2 ** min(self.failed_probes, 4),
            )
        self._probe_in_flight = False
        if history <= self.good:
            # Previously successful context no longer fits current pressure.
            self.good = 0
        self.bad = min(self.bad or history, history)

    def success(self, history: int, *, target: int, request_headroom: int = 0) -> None:
        self.good = max(self.good, _floor_tokens(history))
        if self.bad and history >= self.bad:
            self.bad = 0  # evidence superseded, e.g. another model was unloaded
        if not self.bad and self.target is None:
            return
        self.target = target
        self.pending_probe = None
        self._probe_in_flight = False
        self.stable_successes += 1
        # Epoch rebuilding intentionally leaves a bounded append runway. That
        # reserve may qualify a request for a small next-base increase, but it
        # is never added to the actually accepted history measurement above.
        headroom = min(max(0, request_headroom), 32_000,
                       max(0, target - PREFILL_MEMORY_TUNING_MIN_TOKENS))
        packing_tolerance = max(PREFILL_MEMORY_TUNING_STEP_TOKENS,
                                math.ceil(target * CONTEXT_TUNING_STEP_RATIO))
        utilized = history + headroom >= target - packing_tolerance
        if (self.probes < AUTO_CONTEXT_MAX_UPWARD_PROBES
                and self.stable_successes >= self.cooldown_successes and utilized):
            increase = max(PREFILL_MEMORY_TUNING_STEP_TOKENS,
                           _floor_tokens(target * CONTEXT_TUNING_STEP_RATIO))
            self.pending_probe = target + increase
            self.probe_reason = ('capacity_reassessment'
                                 if self.bad and self.pending_probe >= self.bad else 'gradual_growth')

    def activate_probe(self, ceiling: int) -> int | None:
        candidate = min(self.pending_probe or 0, ceiling)
        self.pending_probe = None
        if (self.target is None or candidate <= self.target
                or self.probes >= AUTO_CONTEXT_MAX_UPWARD_PROBES):
            return None
        self.target = candidate
        self.probes += 1
        self.stable_successes = 0
        self._probe_in_flight = True
        return candidate

    def snapshot(self) -> dict[str, int | str | None]:
        return {
            'history_target_tokens_estimated': self.target,
            'accepted_history_tokens_estimated': self.good,
            'rejected_history_tokens_estimated': self.bad,
            'stable_successes': self.stable_successes,
            'cooldown_successes': self.cooldown_successes,
            'upward_probes': self.probes,
            'failed_upward_probes': self.failed_probes,
            'max_upward_probes': AUTO_CONTEXT_MAX_UPWARD_PROBES,
            'pending_probe_tokens_estimated': self.pending_probe,
            'probe_reason': self.probe_reason,
        }
