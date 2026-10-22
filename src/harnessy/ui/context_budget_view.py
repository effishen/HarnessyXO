"""Plain-language, recorded context-budget facts for the performance dialog."""
from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any, Mapping


@dataclass(frozen=True)
class ContextBudgetView:
    rows: tuple[tuple[str, str], ...]
    explanation: str


def _count(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        numeric = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(numeric) or not numeric.is_integer() or not 0 <= numeric <= 2 ** 53:
        return None
    return int(numeric)


def _tokens(value: int | None, *, estimated: bool = False) -> str:
    return ('~' if estimated else '') + f'{value:,} tok' if value is not None else '—'


def context_budget_view(
    strategy: Mapping[str, Any] | None, *, backend_prompt_tokens: Any = None,
) -> ContextBudgetView:
    """Keep saved budget estimates distinct from this call's backend usage.

    ``backend_prompt_tokens`` must be supplied only when the caller knows the
    generation metric contains a backend count rather than an estimate.  The
    strategy's explicitly sourced native usage takes precedence.  Missing old
    metadata never becomes a zero or a measurement of the next request.
    """
    strategy = strategy if isinstance(strategy, Mapping) else {}
    total = _count(strategy.get('effective_context_window'))
    output = _count(strategy.get('reserved_output_tokens'))
    safety = _count(strategy.get('safety_margin_tokens'))
    input_budget = _count(strategy.get('input_budget_tokens'))
    fixed = _count(strategy.get('fixed_input_tokens_estimated'))
    controller = _count(strategy.get('controller_metadata_tokens_estimated'))
    # The budgeter's fixed cost is system messages and tools.  Controller notes
    # are a separate input component; subtract them once, not from fixed again.
    history = max(0, input_budget - fixed - (controller or 0)) if input_budget is not None and fixed is not None else None
    assembled = _count(strategy.get('assembled_input_tokens_estimated'))
    method = str(strategy.get('token_accounting_method') or strategy.get('token_count_method') or 'rough')
    native = (
        _count(strategy.get('token_accounting_actual_tokens'))
        if strategy.get('token_accounting_exact') is True and method == 'native_tokenizer'
        else _count(strategy.get('native_input_tokens')) if method == 'native_exact' else None
    )
    labels = {
        'rough': 'Rough UTF-8 estimate',
        'calibrated': 'Calibrated estimate from backend usage',
        'measured_prefix': 'Measured prefix + estimated additions',
        'prefix_anchor': 'Measured prefix + estimated additions',
        'native_exact': 'Backend tokenizer count' if native is not None else 'Estimate; tokenizer count unavailable',
        'native_tokenizer': 'Backend tokenizer count' if native is not None else 'Estimate; tokenizer count unavailable',
    }
    method_label = labels.get(method, 'Estimate')
    actual = None
    if strategy.get('current_request_actual_prompt_tokens_source') in {'backend_usage', 'backend_timings'}:
        actual = _count(strategy.get('current_request_actual_prompt_tokens'))
    if actual is None:
        actual = _count(backend_prompt_tokens)

    if input_budget is None:
        return ContextBudgetView(
            rows=(('Backend input for this completed call', _tokens(actual)),),
            explanation='No context-budget breakdown was saved for this older request. Missing values are shown as —.',
        )

    rows = [
        ('Total context window', _tokens(total)),
        ('Reserved for model output', _tokens(output)),
        ('Safety margin', _tokens(safety)),
        ('Available input budget', _tokens(input_budget)),
        ('System instructions and tools', _tokens(fixed, estimated=True)),
        ('Controller-note overhead', _tokens(controller, estimated=True)),
        ('Conversation allowance' if controller is not None else 'Conversation and controller allowance', _tokens(history, estimated=True)),
        ('Input used for budgeting', _tokens(native if native is not None else assembled, estimated=native is None)),
        ('Budget count method', method_label),
        ('Backend input for this completed call', _tokens(actual)),
    ]
    source = strategy.get('token_accounting_source') or strategy.get('token_count_source')
    if isinstance(source, str) and source.strip():
        rows.append(('Budget count source', source.strip()[:240]))
    raw = _count(strategy.get('token_accounting_raw_tokens', strategy.get('raw_input_tokens_estimated')))
    if raw is not None:
        rows.append(('Uncalibrated UTF-8 estimate', _tokens(raw, estimated=True)))
    samples = _count(strategy.get('token_accounting_samples', strategy.get('token_count_calibration_samples')))
    if samples is not None:
        rows.append(('Compatible token-count samples', f'{samples:,}'))
    try:
        factor = float(strategy.get('token_accounting_ratio', strategy.get('token_count_calibration_factor')))
    except (TypeError, ValueError, OverflowError):
        factor = math.nan
    if math.isfinite(factor) and factor > 0:
        rows.append(('Calibration factor', f'{factor:.3f}×'))
    uncertainty = _count(strategy.get('token_accounting_uncertainty_tokens'))
    if uncertainty is not None:
        rows.append(('Estimator uncertainty (already included)', _tokens(uncertainty, estimated=True)))
    notices = _count(strategy.get('controller_notice_count'))
    if notices is not None:
        rows.append(('Controller archive notes in this prompt', f'{notices:,}'))
    return ContextBudgetView(
        rows=tuple(rows),
        explanation=(
            'Output and safety space share the total context window. System instructions, tools and controller notes '
            'use part of the input budget; the rest is available for conversation. ~ marks an estimate. '
            'These are the last recorded request’s values. Backend input is its completed-call usage, not the next request’s size.'
        ),
    )
