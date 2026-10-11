"""Evidence-triggered, non-mutating local-model tuning reminders."""
from __future__ import annotations

import re
from typing import Any

from .context_budget import estimate_text


def _normalized_text(value: Any, *, limit: int = 120_000) -> str:
    text = re.sub(r'\s+', ' ', str(value or '').casefold()).strip()
    return text[:limit]


def answer_replays_reasoning(reasoning_text: str, answer_text: str) -> bool:
    """Detect a substantial exact replay without semantic guessing."""
    reasoning = _normalized_text(reasoning_text)
    answer = _normalized_text(answer_text)
    if len(reasoning) < 512 or len(answer) < 256:
        return False
    # Check both the beginning of the answer (the common spill pattern) and a
    # bounded tail of Thinking. This is deterministic and avoids logging or
    # embedding the private generated text in diagnostics.
    answer_head = answer[:512]
    reasoning_tail = reasoning[-512:]
    return answer_head in reasoning or reasoning_tail in answer


def recommended_reasoning_budget(max_output_tokens: int) -> int:
    """Reserve roughly half of a model turn for the final answer."""
    maximum = max(0, int(max_output_tokens or 0))
    if maximum == 0:
        return 0
    if maximum <= 2048:
        return max(1, maximum // 2)
    recommendation = (maximum // 2 // 1024) * 1024
    return max(1024, min(recommendation, maximum - 1024))


def output_tuning_advice(
    *,
    profile: dict[str, Any],
    backend: str,
    reasoning_text: str,
    answer_text: str,
) -> dict[str, Any] | None:
    """Return one structured reminder only when this turn supplies evidence."""
    reasoning_tokens = estimate_text(reasoning_text)
    answer_tokens = estimate_text(answer_text)
    max_output = max(0, int(profile.get('max_output_tokens') or 0))
    replay = answer_replays_reasoning(reasoning_text, answer_text)
    headroom_pressure = bool(
        max_output > 0
        and reasoning_tokens >= max(4096, int(max_output * 0.70))
        and answer_tokens > 0
    )
    if not replay and not headroom_pressure:
        return None

    normalized_backend = str(backend or '').strip().lower()
    display_backend = (
        'oMLX' if normalized_backend == 'omlx'
        else 'Ollama' if normalized_backend == 'ollama'
        else 'llama.cpp' if normalized_backend == 'llamacpp'
        else str(backend or 'this backend')
    )
    issue = 'answer_replayed_reasoning' if replay else 'reasoning_used_most_output_headroom'
    recommended = recommended_reasoning_budget(max_output) if max_output else 0
    profile_key = str(profile.get('id') or profile.get('model') or 'profile')
    advice_key = f'{issue}:{normalized_backend or "generic"}:{profile_key}:{max_output}'

    if normalized_backend == 'omlx' and recommended:
        summary = (
            f'This turn suggests the reasoning budget left too little answer headroom. '
            f'With Maximum output tokens set to {max_output:,}, try oMLX Thinking Budget {recommended:,} '
            'if the selected model exposes that control.'
        )
        provider_note = (
            'Apply model-setting changes only while idle: saving oMLX model settings can unload the active model '
            'and cannot resume an in-flight request.'
        )
        setting_name = 'oMLX Thinking Budget'
    else:
        summary = (
            'This turn suggests reasoning used most of the model output allowance. If this backend/model exposes '
            'a separate reasoning or thinking budget, lower it enough to leave final-answer headroom.'
        )
        provider_note = (
            f'{display_backend} capabilities vary by model and transport. HarnessyXO has not changed any backend setting.'
        )
        setting_name = 'Backend reasoning / thinking budget (if supported)'

    return {
        'advice_key': advice_key,
        'issue': issue,
        'title': 'Thinking budget reminder',
        'summary': summary,
        'tone': 'cyan',
        'details': {
            'advice_key': advice_key,
            'issue': issue,
            'backend': display_backend,
            'setting_name': setting_name,
            'max_output_tokens': max_output or None,
            'recommended_tokens': recommended or None,
            'estimated_reasoning_tokens': reasoning_tokens,
            'estimated_answer_tokens': answer_tokens,
            'provider_note': provider_note,
            'automatic_change': False,
        },
    }
