"""Small, truthful presentation helpers for health and per-chat telemetry.

No I/O, timers or NiceGUI elements. UI owns polling/lifecycles; values here never
claim model readiness or a live rate based on a previous completed generation.
"""
from __future__ import annotations

import json
import math
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from harnessy.agent.telemetry import RATE_TTL


def positive_number(value: Any) -> float:
    try:
        result = float(value or 0)
        return result if math.isfinite(result) and result > 0 else 0.0
    except (TypeError, ValueError):
        return 0.0


def compact_count(value: Any) -> str:
    n = int(positive_number(value))
    if n >= 1_000_000:
        return f'{n / 1_000_000:.2f}'.rstrip('0').rstrip('.') + 'M'
    if n >= 1000:
        return f'{n / 1000:.1f}'.rstrip('0').rstrip('.') + 'k'
    return str(n)


def elapsed_text(seconds: Any) -> str:
    seconds = int(positive_number(seconds))
    hours, rem = divmod(seconds, 3600)
    minutes, seconds = divmod(rem, 60)
    return f'{hours}:{minutes:02}:{seconds:02}' if hours else f'{minutes:02}:{seconds:02}'


def request_elapsed_seconds(live: dict[str, Any], now: float) -> float | None:
    """A current request's monotonic age, with a legacy phase-clock fallback."""
    started = positive_number(live.get('request_started_perf')) or positive_number(live.get('phase_started'))
    return max(0.0, now - started) if started and started <= now else None


def previous_call_presentation(latest: dict[str, Any]) -> tuple[str, str]:
    """Completed-call measurements stay separate from all live request rates."""
    parts = []
    tps = positive_number(latest.get('tps'))
    if tps:
        parts.append(f'decode {tps:.1f} tok/s')
    ttft = positive_number(latest.get('ttft_seconds'))
    if ttft:
        parts.append(f'TTFT {ttft:.1f}s')
    prefill = positive_number(latest.get('prefill_tps'))
    if prefill:
        parts.append(f'PP {prefill:.1f} tok/s')
    text = 'Previous call · ' + ' · '.join(parts) if parts else ''
    return text, ('Last completed model call. These are not this request’s live speeds. '
                  'TTFT is time to first token; PP is prompt processing. Open Stats for full measurements.')


def stream_wait_detail(live: dict[str, Any], now: float) -> str:
    """Tick the observed quiet interval without turning reachability into progress."""
    watch = live.get('stream_watchdog')
    if not isinstance(watch, dict) or watch.get('status') not in {'suspected', 'waiting'}:
        return ''
    quiet = positive_number(watch.get('quiet_seconds'))
    observed = positive_number(watch.get('observed_perf'))
    if observed and now >= observed:
        quiet += now - observed
    health = watch.get('health') if isinstance(watch.get('health'), dict) else {}
    if health.get('backend_reachable') is False:
        detail = 'Backend unreachable at last check'
    elif health.get('backend_reachable') is True:
        detail = ('Backend reports request active' if health.get('request_scoped')
                  and health.get('request_state') in {'pending', 'active', 'running', 'prefill', 'generating'}
                  else 'Backend reachable; inference progress unconfirmed')
    else:
        detail = 'Inference progress unconfirmed'
    return f'Quiet {quiet:.0f}s · {detail}'


def live_tool_duration_text(
    name: str, arguments: dict[str, Any] | None, started_perf: float,
    *, now_perf: float, default_timeout_seconds: int = 180,
) -> str:
    """Present a live Tool age without pretending buffered output is streaming."""
    elapsed = max(0.0, float(now_perf) - float(started_perf or now_perf))

    def span(seconds: float) -> str:
        if seconds < 60:
            return f'{seconds:.1f}s'
        whole = max(0, int(seconds))
        minutes, secs = divmod(whole, 60)
        if minutes < 60:
            return f'{minutes}m {secs:02d}s'
        hours, minutes = divmod(minutes, 60)
        return f'{hours}h {minutes:02d}m {secs:02d}s'

    label = span(elapsed)
    if str(name or '') != 'run_command' or elapsed < 10:
        return label
    args = arguments if isinstance(arguments, dict) else {}
    try:
        timeout = int(args.get('timeout_seconds') or default_timeout_seconds or 180)
    except (TypeError, ValueError):
        timeout = int(default_timeout_seconds or 180)
    timeout = max(1, min(timeout, 7200))
    if elapsed < timeout:
        return f'{label} / {span(float(timeout))} timeout · no live output'
    return f'{label} · timeout reached · no live output'


def endpoint_display(profile: dict[str, Any]) -> str:
    """Display a URL without embedded credentials, query tokens or fragments."""
    try:
        url = urlsplit(str(profile.get('base_url') or ''))
        if not url.hostname:
            return 'Not configured'
        host = f'[{url.hostname}]' if ':' in url.hostname else url.hostname
        if url.port:
            host += f':{url.port}'
        return urlunsplit((url.scheme, host, url.path, '', ''))
    except ValueError:
        return 'Invalid endpoint'


def metric_metadata(latest: dict[str, Any]) -> dict[str, Any]:
    try:
        raw = json.loads(str(latest.get('raw_json') or '{}'))
        value = raw.get('harnessy', {}) if isinstance(raw, dict) else {}
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


def metric_matches_profile(latest: dict[str, Any], profile: dict[str, Any]) -> bool:
    return (not latest.get('model_profile_id') or str(latest['model_profile_id']) == str(profile.get('id') or '')) and (
        not latest.get('model_name') or str(latest['model_name']) == str(profile.get('model') or ''))


def context_presentation(latest: dict[str, Any], profile: dict[str, Any], *, estimated_tokens: int = 0,
                         observed_context: int = 0) -> tuple[str, str]:
    same = metric_matches_profile(latest, profile)
    latest = latest if same else {}
    meta = metric_metadata(latest)
    request = meta.get('request') if isinstance(meta.get('request'), dict) else {}
    configured = int(positive_number(profile.get('context_window')))
    observed = int(positive_number(observed_context))
    recorded = int(positive_number(request.get('runtime_context_window') or latest.get('context_window')))
    runtime = observed or recorded
    maximum = min(runtime, configured) if runtime and configured else runtime or configured
    tokens = int(positive_number(latest.get('prompt_tokens'))) if latest else max(0, estimated_tokens)
    estimated = not latest or bool(meta.get('prompt_usage_estimated', meta.get('usage_estimated', False)))
    text = f'Context {"~" if estimated else ""}{compact_count(tokens)} / {compact_count(maximum) if maximum else "—"}'
    source = ('Rough saved-text estimate; full assembled request not yet measured.' if not latest else
              'Last recorded request: prompt usage is estimated.' if estimated else
              'Last recorded request: prompt usage is backend-measured.')
    detail = f'{source}\nNot a live count of the next request or remaining output space.\n'
    detail += f'Profile cap: {configured:,} tokens.' if configured else 'Profile cap: not configured.'
    detail += (f'\n{"Observed runtime" if observed else "Last recorded runtime"}: {runtime:,} tokens.'
               if runtime else '\nRuntime context not observed yet.')
    return text, detail


def auto_context_presentation(
    live: dict[str, Any] | None, latest: dict[str, Any], profile: dict[str, Any],
) -> tuple[str, str]:
    """Show the actual request target, without carrying it into a new job."""
    live = live or {}
    running = bool(live.get('active') and not live.get('finished'))
    snapshot = live.get('context_budget')
    snapshot = snapshot if isinstance(snapshot, dict) else {}
    identity = {'model_profile_id': snapshot.get('model_profile_id'),
                'model_name': snapshot.get('model')}
    matches = bool(snapshot) and metric_matches_profile(identity, profile)
    if matches:
        strategy = snapshot.get('context_strategy') or {}
        source = 'Current run, latest request.' if running else 'Last run, latest attempted request.'
    elif running:
        # A freshly queued/preparing run must not inherit the old job's cap.
        return 'Auto cap pending', 'The automatic retained-history cap appears when this run prepares its model request.'
    else:
        request = metric_metadata(latest).get('request') if metric_matches_profile(latest, profile) else {}
        strategy = request.get('context_strategy') if isinstance(request, dict) else {}
        source = 'Last recorded request.'
    strategy = strategy if isinstance(strategy, dict) else {}
    target = int(positive_number(strategy.get('hot_token_target')))
    if not target:
        return 'Auto cap —', 'No automatic retained-history cap has been recorded for this model yet.'
    prefix = 'Auto cap' if running else 'Last auto cap'
    ceiling = int(positive_number(strategy.get('active_context_ceiling_tokens')))
    # Older requests record the selected ceiling but not its runtime clamp.
    if not ceiling:
        requested = int(positive_number(strategy.get('active_context_requested_tokens')))
        runtime = int(positive_number(strategy.get('effective_context_window')))
        ceiling = min(requested, runtime) if requested and runtime else requested or runtime
    target = min(target, ceiling) if ceiling else target
    detail = f'{source}\nAutomatic retained-history cap: {target:,} tokens.'
    detail += f'\nSelected ceiling for that request: {ceiling:,} tokens.' if ceiling else '\nSelected ceiling was not recorded.'
    if strategy.get('auto_context_probe'):
        detail += '\nTesting a larger cap; acceptance is not yet established by this display.'
    detail += (
        '\nThis is the history target, not current token usage or the full model context window. '
        'Instructions, tools and output space can leave less room for history.'
    )
    if not running:
        detail += '\nA new run starts from its configured ceiling and tunes afresh.'
    return f'{prefix} {compact_count(target)}', detail


def run_presentation(live: dict[str, Any] | None, latest: dict[str, Any], now: float) -> dict[str, str]:
    live = live or {}
    previous, previous_detail = previous_call_presentation(latest)
    if not live.get('active') or live.get('finished'):
        outcome = str(live.get('outcome') or '')
        phase = {'stopped': 'Stopped', 'error': 'Error'}.get(outcome, 'Ready')
        duration = positive_number(latest.get('duration_seconds'))
        return {'phase': phase, 'rate': '', 'previous': previous, 'previous_detail': previous_detail,
                'elapsed': 'Last ' + elapsed_text(duration) if duration else '',
                'detail': 'Last completed model generation; not live throughput. Open Stats for full timings.'}
    phase = str(live.get('phase') or '')
    status = str(live.get('status') or '')
    status_lower = status.casefold()
    tool = live.get('current_tool') if isinstance(live.get('current_tool'), dict) else {}
    if live.get('awaiting_approval'):
        label = 'Waiting for approval'
    elif live.get('stopping'):
        label = 'Stopping'
    elif live.get('completion_wait_reason'):
        label = str(live['completion_wait_reason'])
    elif 'queued' in status_lower and not 'delivered' in status_lower:
        label = 'Queued'
    elif 'waiting' in status_lower and ('writer' in status_lower or 'workspace' in status_lower):
        label = 'Waiting for workspace'
    elif tool:
        label = 'Running tool'
    elif live.get('tool_building'):
        label = 'Generating tool'
    elif phase in {'prefill', 'prompt_processing'}:
        label = 'Prompt Processing'
    elif phase == 'generating':
        label = 'Generating'
    elif status_lower.startswith(('building', 'preparing')):
        label = 'Preparing'
    elif phase == 'waiting':
        label = 'Waiting for model · progress unavailable'
    else:
        label = 'Working'
    rate = ''
    try:
        tps = float(live.get('tps'))
        if not math.isfinite(tps) or tps < 0:
            tps = None
    except (TypeError, ValueError):
        tps = None
    at = positive_number(live.get('tps_observed_at'))
    kind = str(live.get('tps_kind') or 'unavailable')
    if label in {'Generating', 'Generating tool'} and tps is not None and at and 0 <= now - at <= RATE_TTL and kind != 'unavailable':
        rate = f'{tps:.1f} tok/s' + (' avg' if kind == 'average' else '')
    elif label == 'Prompt Processing' and at and 0 <= now - at <= RATE_TTL:
        prefill = positive_number(live.get('prefill_tps'))
        if prefill:
            rate = f'{prefill:.1f} tok/s PP'
    request_age = request_elapsed_seconds(live, now)
    start = positive_number(live.get('run_started'))
    elapsed = ('Request ' + elapsed_text(request_age) if request_age is not None
               and label in {'Waiting for model · progress unavailable', 'Prompt Processing'} else
               'Run ' + elapsed_text(max(0, now - start)) if start else '')
    detail = f'{label}: {tool.get("name") or status or phase}. '
    detail += ('Elapsed is this model request.' if elapsed.startswith('Request ')
               else 'Elapsed is the whole current run.')
    if label in {'Generating', 'Generating tool'} and not rate:
        detail += ' Live speed is not available yet or is stale.'
    wait_detail = stream_wait_detail(live, now)
    if wait_detail:
        detail += '\n' + wait_detail
    return {'phase': label, 'rate': rate, 'elapsed': elapsed, 'detail': detail,
            'previous': previous, 'previous_detail': previous_detail}
