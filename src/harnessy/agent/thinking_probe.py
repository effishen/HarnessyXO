"""Bounded installed-Ollama renderer verification, never a guessed native mapping.

Only static probe requests are sent. Default verification OMITs think entirely;
think=True, null and explicit High are not substitutes for the backend default.
Reports contain hashes/configuration, never prompts, credentials or reasoning.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from collections import OrderedDict
from copy import deepcopy
from typing import Any

import httpx

from harnessy.core.thinking import (detected_profile, profile_identity, model_family,
                                    default_proof_identity, DETECTION_FIELDS)

_CACHE: OrderedDict[str, tuple[float, dict[str, Any]]] = OrderedDict()
_OMITTED = object()


def _render_observation(data: Any) -> dict[str, Any] | None:
    if not isinstance(data, dict):
        return None
    # Ollama's ChatResponse JSON tag is _debug_info (api/types.go).
    # The pre-0.2.42 tests copied our misspelling instead of that public shape.
    # Keep the unprefixed name for compatible forks, but never let it mask a
    # malformed/conflicting official envelope when both are present.
    field = '_debug_info' if '_debug_info' in data else 'debug_info'
    debug = data.get(field)
    if not isinstance(debug, dict):
        return None
    if '_debug_info' in data and 'debug_info' in data:
        legacy = data['debug_info']
        if not isinstance(legacy, dict) or legacy.get('rendered_template') != debug.get('rendered_template'):
            return None
    rendered = debug.get('rendered_template')
    if not isinstance(rendered, str) or not rendered or len(rendered) > 524288:
        return None
    if '<|im_start|>assistant' not in rendered:
        return None
    # Do not interpret an effort phrase quoted by a user as a system directive.
    systems = re.findall(r'<\|im_start\|>system\s*\n(.*?)<\|im_end\|>', rendered, re.S)
    markers = re.findall(r'(?:^|\n)Reasoning effort is set to\s+(\w+)\b', '\n'.join(systems), re.I)
    efforts = {x.lower() for x in markers}
    ambiguous = len(efforts) > 1 or any(x not in {'low', 'medium', 'xhigh'} for x in efforts)
    effort = next(iter(efforts)) if len(efforts) == 1 and not ambiguous else None
    suffix = rendered.rsplit('<|im_start|>assistant', 1)[-1].strip()
    return {'debug_field': field, 'render_sha256': hashlib.sha256(rendered.encode()).hexdigest(),
            'effort': effort, 'effort_ambiguous': ambiguous,
            'thinking_open': suffix.endswith('<think>'),
            'thinking_closed': bool(re.search(r'<think>\s*</think>\s*$', suffix)),
            'render_chars': len(rendered)}


def _default_report(profile: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    """Reduce an omitted-parameter observation to a conservative display record."""
    sample = next((s for s in report['samples'] if s.get('think_omitted') is True), {})
    result = {k: report[k] for k in ('profile_identity', 'metadata_key', 'version', 'model', 'method', 'checked_at')}
    result.update(schema=1, status='unverified', backend='ollama',
                  proof_identity=default_proof_identity(profile), request_fields={},
                  level=None, effort=None, sample=deepcopy(sample),
                  reason='The omitted-parameter probe did not establish a default level. No level was guessed.')
    # Persisting a proof without a server version would disguise a server upgrade.
    if not report.get('version'):
        result['reason'] = 'Server version unavailable; the default could not be safely verified for this endpoint.'
        return result
    if sample.get('result') != 'rendered' or sample.get('effort_ambiguous'):
        return result
    if sample.get('thinking_closed') and not sample.get('thinking_open'):
        result.update(status='verified', level='off', evidence='closed_thinking_prefix')
    elif sample.get('thinking_open') and not sample.get('thinking_closed'):
        effort = sample.get('effort')
        if effort in {'low', 'medium', 'xhigh'}:
            result.update(status='verified', level={'low': 'low', 'medium': 'medium', 'xhigh': 'high'}[effort],
                          effort=effort, evidence='explicit_effort_marker')
        elif effort is None and report.get('status') == 'verified':
            medium = next((s for s in report['samples'] if s.get('think') == 'medium'), {})
            if medium.get('render_sha256') == sample.get('render_sha256'):
                result.update(status='verified', level='medium', effort='medium',
                              evidence='verified_medium_comparison',
                              comparison={'status': 'verified', 'level': 'medium',
                                          'render_sha256': medium['render_sha256']})
    if result['status'] == 'verified':
        result['level_label'] = 'xhigh' if result['effort'] == 'xhigh' else str(result['level']).title()
        result['reason'] = ('Backend default observed with all Thinking fields omitted. '
                            'Static renderer evidence, not measured generation or model-internal effort.')
    return result


async def verify_native_thinking(client: Any, *, force: bool = False, progress=None,
                                 include_default: bool = False) -> dict[str, Any]:
    """Verify levels; optionally observe the omitted-parameter model default too.

    Manual UI checks include Default. Ordinary Default/Off sends and metadata
    discovery do not start inference probes. The caller owns scheduling/consent.
    HTTP success alone is NOT proof. Older endpoints may ignore the debug flag;
    num_predict=1 bounds that fallback, and missing debug proof stops the check.
    """
    if include_default:
        # A failed recheck must not silently retain a previous success in this client.
        client.profile['thinking_default_verification'] = None
    if await client.detect_backend() != 'ollama':
        raise ValueError('Native Thinking verification requires an Ollama-native profile.')
    metadata = await client.model_metadata(refresh=True)
    if not metadata or 'thinking' not in (metadata.get('capabilities') or []):
        raise ValueError('The selected model did not report thinking capability; detection could not verify it.')
    version = await client.ollama_version()
    detected = detected_profile(client.profile, metadata, version=version)
    if model_family(detected) != 'qwen3.8':
        raise ValueError('Automatic renderer verification currently targets Qwen3.8. Other models keep an unverified default; use an explicit compatibility preset for their levels.')
    detection = detected['thinking_detection']
    signature = json.dumps(['native-render-v3', profile_identity(detected), detection['metadata_key'], version,
                            default_proof_identity(detected)])
    cached = _CACHE.get(signature)
    if force:
        _CACHE.pop(signature, None)
    elif (cached and time.monotonic() - cached[0] < 900
          and (not include_default or 'default_verification' in cached[1])):
        _CACHE.move_to_end(signature)
        result = deepcopy(cached[1])
        for k in DETECTION_FIELDS:
            if k in detected:
                client.profile[k] = deepcopy(detected[k])
        client.profile['thinking_native_verification'] = deepcopy(result)
        if 'default_verification' in result:
            client.profile['thinking_default_verification'] = deepcopy(result['default_verification'])
        return result
    report: dict[str, Any] = {'status': 'unverified', 'method': 'Ollama /api/chat _debug_render_only',
        'profile_identity': profile_identity(detected), 'metadata_key': detection['metadata_key'],
        'version': version, 'model': client.model, 'samples': [], 'wire_values': {},
        'checked_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'model_levels': ['low', 'medium', 'xhigh'],
        'level_labels': {'off': 'Off', 'low': 'Low', 'medium': 'Medium', 'high': 'xhigh'}}
    if version == '0.0.0':
        report['version_note'] = ('0.0.0 does not identify a specific server build. '
                                  'It does not establish server age; recheck after replacing the server.')
    runtime = await client.ollama_runtime_status()
    context = client._effective_ollama_context(int((runtime or {}).get('context_window') or 0))
    options = {'num_predict': 1}
    if context:
        options['num_ctx'] = context

    async def run_probes() -> None:
        wires = ((_OMITTED,) if include_default else ()) + (False, 'low', 'medium', 'high', 'max')
        async with httpx.AsyncClient(timeout=httpx.Timeout(connect=5.0, read=90.0, write=10.0, pool=5.0)) as http:
            for wire in wires:
                omitted = wire is _OMITTED
                if progress:
                    progress('Checking model default (no override)…' if omitted else f'Checking native Thinking {wire!r}…')
                sample: dict[str, Any] = {'think_omitted': True} if omitted else {'think': wire}
                report['samples'].append(sample)
                payload = {'model': client.model, 'messages': [{'role': 'user', 'content': 'Reply with OK.'}],
                           'stream': False, '_debug_render_only': True, 'options': options}
                if not omitted:
                    payload['think'] = wire
                try:
                    response = await http.post(f'{client.ollama_root}/api/chat', headers=client._headers(), json=payload)
                    sample['http_status'] = response.status_code
                    if response.status_code >= 400:
                        sample['result'] = 'rejected'
                        try:
                            error_text = str(response.json().get('error') or '')[:2000].lower()
                        except (ValueError, AttributeError):
                            error_text = ''
                        level_rejection = (any(w in error_text for w in ('think', 'reasoning effort'))
                                           and any(w in error_text for w in ('invalid', 'unsupported', 'unexpected', 'not support')))
                        if omitted or wire is False or (response.status_code not in {400, 422} and not level_rejection):
                            report['reason'] = f'Installed endpoint rejected renderer check (HTTP {response.status_code}).'
                            return
                        continue
                    observation = _render_observation(response.json())
                    if observation is None:
                        sample['result'] = 'no_render_proof'
                        report['reason'] = ('No usable rendered_template was found in _debug_info (or legacy debug_info). '
                                            'This does not establish the server age or whether the model supports levels. '
                                            'Verification stopped; if renderer-only mode was ignored, the request was limited to one token.')
                        return
                    sample.update(observation, result='rendered')
                except asyncio.CancelledError:
                    raise
                except (httpx.HTTPError, ValueError, TypeError):
                    sample['result'] = 'request_failed'
                    report['reason'] = 'Renderer verification request failed or timed out. No level mapping was assumed.'
                    return
    try:
        await asyncio.wait_for(run_probes(), timeout=180.0)
    except asyncio.TimeoutError:
        report['reason'] = 'Renderer verification timed out. No level mapping was assumed.'
    samples = report['samples']

    def find(wire):
        return next((s for s in samples if 'think' in s and type(s['think']) is type(wire) and s['think'] == wire), {})

    off, low, medium = find(False), find('low'), find('medium')
    high = next((find(w) for w in ('high', 'max') if find(w).get('effort') == 'xhigh' and find(w).get('thinking_open')), {})
    verified = (off.get('thinking_closed') and low.get('effort') == 'low' and low.get('thinking_open')
                and medium.get('thinking_open') and medium.get('effort') in {None, 'medium'}
                and not any(s.get('effort_ambiguous') for s in (off, low, medium, high))
                and bool(high) and len({s.get('render_sha256') for s in (off, low, medium, high)}) == 4)
    if verified:
        report.update(status='verified', wire_values={'off': False, 'low': 'low', 'medium': 'medium', 'high': high['think']},
                      reason='Distinct Off / Low / Medium / xhigh renderings confirmed. Generated behaviour is not measured by this check.')
    elif 'reason' not in report:
        report['reason'] = ('The installed renderer did not demonstrate distinct Qwen3.8 Off / Low / Medium / highest prompts. '
                            'Use Model default or Off; the model may need an appropriate Ollama renderer. No mapping was guessed.')
    if include_default:
        report['default_verification'] = _default_report(detected, report)
    if verified:
        _CACHE[signature] = (time.monotonic(), deepcopy(report))
        while len(_CACHE) > 32:
            _CACHE.popitem(last=False)
    for k in DETECTION_FIELDS:
        if k in detected:
            client.profile[k] = deepcopy(detected[k])
    client.profile['thinking_native_verification'] = deepcopy(report)
    if include_default:
        client.profile['thinking_default_verification'] = deepcopy(report['default_verification'])
    return report
