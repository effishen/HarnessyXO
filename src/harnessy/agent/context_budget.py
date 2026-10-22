"""Prompt-view budgeting only. Persisted transcript and memory are never edited.

Counts are conservative UTF-8/3 estimates, NOT tokenizer measurements. A margin
is reserved for provider chat templates and unknown image/tokenizer overhead.
"""
from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from typing import Any, Callable


class ContextBudgetError(ValueError):
    """Legacy public exception; estimates no longer reject model requests."""


def estimate_text(text: Any) -> int:
    return math.ceil(len(str(text or '').encode('utf-8')) / 3)


def estimate_message(message: dict[str, Any]) -> int:
    content = message.get('content') or ''
    if isinstance(content, list):
        # Image cost depends on the backend/processor. Never count base64 as text
        # or count the private native-image transport copy a second time.
        count = sum(4096 if part.get('type') == 'image_url' else estimate_text(part.get('text', ''))
                    for part in content if isinstance(part, dict))
    else:
        count = estimate_text(content)
    return 8 + count + estimate_text(json.dumps({k: message[k] for k in ('name', 'tool_call_id', 'tool_calls')
                                                 if message.get(k)}, ensure_ascii=False, separators=(',', ':')))


def effective_context(profile: dict[str, Any], runtime: int = 0) -> tuple[int, str]:
    configured = max(0, int(profile.get('context_window') or 0))
    runtime = max(0, int(runtime or 0))
    if runtime:
        return (min(configured, runtime) if configured else runtime), 'observed_runtime'
    if configured:
        # Match the native Ollama startup ceiling. The client performs its own
        # runtime probe immediately before sending and rechecks the final view.
        backend = str(profile.get('backend') or profile.get('provider') or '').lower()
        native = backend == 'ollama' or '11434' in str(profile.get('base_url') or '')
        return min(configured, 262144) if native else configured, 'profile_cap_runtime_unobserved'
    return 0, 'unknown_runtime_and_profile'


def bounded_memory(text: str, max_tokens: int) -> str:
    if estimate_text(text) <= max_tokens:
        return text
    note = ('\n\n[Workspace memory prompt excerpt; SQLite remains authoritative. '
            'Use read_project_memory with start_char/max_chars for omitted generated-memory sections.]\n\n')
    # Character slicing must also handle multi-byte text. Choose actual encoded
    # size conservatively, then decode at character boundaries.
    available = max(0, max_tokens * 3 - len(note.encode('utf-8')))
    raw = text.encode('utf-8')
    head = raw[:available // 2].decode('utf-8', errors='ignore')
    tail = raw[-(available - available // 2):].decode('utf-8', errors='ignore') if available else ''
    return head + note + tail


_PASTE = re.compile(r'(<pasted_text>\n)(.*?)(\n</pasted_text>)', re.S)
_LEGACY_ARCHIVE_PREFIX = (
    '[HarnessyXO generated archive marker — not assistant reasoning and not evidence of current environment state. '
    'Completed transcript steps archived from this prompt only; saved originals are unchanged. '
)
_CONTEXT_NOTICE_PREFIX = '[HarnessyXO context notice — controller metadata]'
_SOURCE_ID = re.compile(r'[A-Za-z0-9_.:-]{1,128}\Z')


def _notice_source_ids(values: Any) -> list[str]:
    if not isinstance(values, (list, tuple)):
        return []
    result: list[str] = []
    bounded = values if len(values) <= 24 else [*values[:12], *values[-12:]]
    for value in bounded:
        if isinstance(value, str) and _SOURCE_ID.fullmatch(value) and value not in result:
            result.append(value)
    return result


def _context_notice_ids(message: dict[str, Any]) -> list[str]:
    """Read bounded retrieval pointers, never historical message bodies."""
    if message.get('_harnessy_context_notice') is True:
        return _notice_source_ids(message.get('_harnessy_notice_source_ids'))
    text = str(message.get('content') or '')[:4096]
    match = re.search(r'First message IDs: (.*?)\. Most recent message IDs: (.*?)\. Use search_chat_history', text)
    if match:
        return _notice_source_ids([part.strip() for group in match.groups() for part in group.split(',')])
    return []


def _is_context_notice(message: dict[str, Any], source_for: Callable[[dict[str, Any]], Any]) -> bool:
    # Literal user/model text stored in the transcript is always preserved,
    # even when it quotes a former controller marker verbatim.
    if source_for(message) is not None or message.get('role') not in {'user', 'assistant', 'system'}:
        return False
    if message.get('tool_calls') or message.get('tool_call_id'):
        return False
    if message.get('_harnessy_context_notice') is True:
        return True
    content = message.get('content')
    return isinstance(content, str) and content.startswith(_LEGACY_ARCHIVE_PREFIX)


def _set_context_notice(message: dict[str, Any], source_ids: list[str]) -> None:
    ids = _notice_source_ids(source_ids)
    ids = list(dict.fromkeys([*ids[:3], *ids[-3:]]))
    message.update({
        'role': 'user',
        '_harnessy_context_notice': True,
        '_harnessy_region': 'context_notice',
        '_harnessy_notice_source_ids': ids,
        'content': (
            _CONTEXT_NOTICE_PREFIX + '\n'
            'Some earlier saved messages are outside this request. Their originals remain in chat history. '
            'Use search_chat_history or read_chat_message only when an exact earlier detail is needed. '
            + ('Original message IDs (earliest/recent): ' + ', '.join(ids) + '. ' if ids else '')
            + 'Continue the task without announcing routine context housekeeping. '
            'This controller note is not an assistant reply or evidence of current environment state.'
        ),
    })


def _notice_insertion_index(messages: list[dict[str, Any]], index: int) -> int:
    """Keep a controller row outside an assistant/tool-result protocol block."""
    index = min(max(0, index), len(messages))
    if index < len(messages) and messages[index].get('role') == 'tool':
        while index > 0 and messages[index - 1].get('role') == 'tool':
            index -= 1
        if index > 0 and messages[index - 1].get('role') == 'assistant' and messages[index - 1].get('tool_calls'):
            index -= 1
    return index


def _normalize_context_notices(
    messages: list[dict[str, Any]], source_for: Callable[[dict[str, Any]], Any],
) -> tuple[dict[str, Any] | None, int]:
    """Collapse old request-only controller artifacts before any budgeting."""
    prior: list[dict[str, Any]] = []
    source_ids: list[str] = []
    first_index = 0
    for index, message in enumerate(messages):
        if not _is_context_notice(message, source_for):
            continue
        if not prior:
            first_index = index
        prior.append(message)
        source_ids.extend(_context_notice_ids(message))
        # Retain first/recent pointers without growing a second history buffer.
        source_ids = list(dict.fromkeys([*source_ids[:3], *source_ids[-3:]]))
    if not prior:
        return None, 0
    removed = {id(message) for message in prior}
    messages[:] = [message for message in messages if id(message) not in removed]
    note: dict[str, Any] = {}
    _set_context_notice(note, source_ids)
    messages.insert(_notice_insertion_index(messages, first_index), note)
    return note, len(prior)


def _completed_tool_blocks(messages: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Pair by protocol adjacency, not globally: a backend may reuse call IDs."""
    blocks = []
    index = 0
    while index < len(messages):
        first = messages[index]
        calls = first.get('tool_calls') or []
        if first.get('role') != 'assistant' or not calls:
            index += 1
            continue
        ids = {str(call.get('id') or '') for call in calls}
        end = index + 1
        while end < len(messages) and messages[end].get('role') == 'tool':
            end += 1
        results = messages[index + 1:end]
        if '' not in ids and len(ids) == len(calls) == len(results) and ids == {str(m.get('tool_call_id') or '') for m in results}:
            blocks.append([first, *results])
        index = end
    return blocks


def budget_request(
    messages: list[dict[str, Any]], tools: list[dict[str, Any]], *,
    profile: dict[str, Any], runtime: int, hot_target: int,
    system_components: dict[str, str], source_for: Callable[[dict[str, Any]], Any],
    compact_tool: Callable[[Any], str],
    protected_source_ids: set[str] | None = None,
    protected_eviction_order: list[str] | None = None,
    token_counter: Any = None,
) -> dict[str, Any]:
    """Mutate the assembled request view in place; preserve complete tool pairs.

    Large completed results are reduced first (oldest first). Entire completed
    call/result blocks can be archived next, including within the current user
    turn. The latest user instruction is never silently truncated. Archive
    notices retain original message IDs for explicit bounded retrieval.
    """
    archive_marker, prior_notice_count = _normalize_context_notices(messages, source_for)
    count_text = token_counter.estimate_text if token_counter is not None else estimate_text
    count_message = token_counter.estimate_message if token_counter is not None else estimate_message
    context, context_source = effective_context(profile, runtime)
    # Unknown is not misrepresented as a backend capacity. A local planning
    # ceiling still bounds growth until an actual context can be observed.
    planning_ceiling = context or 48000
    reserve = int(profile.get('max_output_tokens') or 0)
    reserve = reserve if reserve > 0 else min(8192, max(1024, planning_ceiling // 4))
    safety = max(512, math.ceil(planning_ceiling * 0.10))
    input_limit = planning_ceiling - reserve - safety
    schema_tokens = system_tokens = fixed = request_limit = 0

    def recount() -> int:
        nonlocal schema_tokens, system_tokens, fixed, request_limit
        total = token_counter.estimate_request(messages, tools) if token_counter is not None else None
        # Whole-request evaluation can invalidate a native/prefix anchor and
        # change the allocation ratio. Refresh fixed costs afterward, before
        # deciding how much history fits or reporting component allocations.
        schema_tokens = (token_counter.estimate_tools(tools) if token_counter is not None else
                         count_text(json.dumps(tools or [], ensure_ascii=False, separators=(',', ':'))) + (8 if tools else 0))
        system_tokens = sum(count_message(message) for message in messages if message.get('role') == 'system')
        fixed = schema_tokens + system_tokens
        # Estimates guide trimming of retrievable history. Mandatory input
        # remains preserved for actual backend admission feedback.
        request_limit = min(input_limit, fixed + max(0, hot_target))
        if token_counter is not None:
            return total
        return schema_tokens + sum(count_message(message) for message in messages)

    before = recount()
    count = before

    def changed_request(delta: int) -> None:
        nonlocal count
        # A native count/prefix anchor describes one exact request. Mutating
        # its covered rows can invalidate it, so a row delta is not sufficient.
        count = recount() if token_counter is not None else count + delta
    compacted = 0
    compacted_ids: list[str] = []
    steps_archived = 0
    attachments_deferred = 0
    archived_ids: list[str] = []
    protected_ids = {str(x) for x in (protected_source_ids or set()) if str(x)}
    protected_order = [str(x) for x in (protected_eviction_order or []) if str(x) in protected_ids]
    protected_rank = {source_id: index for index, source_id in enumerate(protected_order)}
    protected_evicted: list[str] = []
    adaptive_capsules_evicted: list[str] = []

    def source_id_for(message: dict[str, Any]) -> str:
        source = source_for(message)
        return str(getattr(source, 'id', '') or '') if source is not None else ''

    def compact_result(message: dict[str, Any], *, protected: bool = False) -> bool:
        nonlocal count, compacted
        source = source_for(message)
        if source is None:
            return False
        replacement = compact_tool(source)
        old = count_message(message)
        if count_text(replacement) >= count_text(message.get('content')):
            return False
        message['content'] = replacement
        changed_request(count_message(message) - old)
        compacted += 1
        sid = str(getattr(source, 'id', '') or '')
        if sid and sid not in compacted_ids:
            compacted_ids.append(sid)
        if protected:
            if sid and sid not in protected_evicted:
                protected_evicted.append(sid)
        return True

    # Only actual paired/completed tool results can be compacted. Unknown or
    # incomplete records are preserved and cause an explicit error if necessary.
    completed_blocks = _completed_tool_blocks(messages)
    paired_results = {id(m) for block in completed_blocks for m in block[1:]}
    for m in messages:
        if count <= request_limit:
            break
        if id(m) not in paired_results:
            continue
        if source_id_for(m) in protected_ids:
            continue
        compact_result(m)

    # Pasted attachments have independent persisted IDs. Defer payload, not the
    # user's message text, and make retrieval explicit in the same attachment.
    for m in messages:
        if count <= request_limit:
            break
        # Runner-control rows can quote arbitrary candidate text, including
        # attachment-like tags. They are not actual attachment payloads, and
        # rewriting them would change the evidence used by the final check.
        if m.get('role') != 'user' or m.get('_harnessy_ephemeral'):
            continue
        contents = [m] if isinstance(m.get('content'), str) else [p for p in m.get('content') or [] if p.get('type') == 'text']
        for holder in contents:
            key = 'content' if holder is m else 'text'
            text = str(holder.get(key) or '')
            if '<pasted_text>' not in text:
                continue
            old = count_message(m)
            text, n = _PASTE.subn(
                '[Pasted-text payload deferred to fit the request. The private attachment is unchanged. '
                'Use a narrow search_attachment query and one bounded read_attachment range with the '
                'attachment_id above; do not reconstruct the whole attachment through sequential reads.]',
                text,
            )
            holder[key] = text
            attachments_deferred += n
            changed_request(count_message(m) - old)

    latest_user = next((m for m in reversed(messages) if m.get('role') == 'user' and source_for(m) is not None), None)
    # Atomic blocks: assistant/tool-call record plus every paired result. A
    # completed block is removable without changing any remaining arguments.
    blocks = completed_blocks
    claimed = {id(m) for block in blocks for m in block}
    # Keep chronological order, and remove only persisted content with a
    # retrievable source. Standalone old user/assistant text is independently safe.
    block_by_first = {id(b[0]): b for b in blocks}
    candidates = []
    for m in messages:
        if id(m) in block_by_first:
            candidates.append(block_by_first[id(m)])
        elif id(m) not in claimed and m is not latest_user and m.get('role') in {'user', 'assistant'}:
            if not m.get('tool_calls'):
                candidates.append([m])
    def archive_block(block: list[dict[str, Any]]) -> list[str]:
        nonlocal archive_marker, count, steps_archived
        ids = [str(source_for(message).id) for message in block]
        old = sum(count_message(message) for message in block)
        prior_marker_tokens = count_message(archive_marker) if archive_marker is not None else 0
        pointer_ids = _context_notice_ids(archive_marker) if archive_marker is not None else []
        if archive_marker is None:
            index = next(i for i, message in enumerate(messages) if message is block[0])
            archive_marker = {}
            messages.insert(_notice_insertion_index(messages, index), archive_marker)
        remove = {id(message) for message in block}
        messages[:] = [message for message in messages if id(message) not in remove]
        archived_ids.extend(ids)
        steps_archived += 1
        _set_context_notice(archive_marker, [*pointer_ids, *ids])
        changed_request(count_message(archive_marker) - prior_marker_tokens - old)
        return ids

    for block in candidates:
        if count <= request_limit:
            break
        if not all(source_for(m) is not None for m in block):
            continue
        if any(source_id_for(m) in protected_ids for m in block):
            continue
        archive_block(block)

    # Request-only adaptive-retention capsules are deliberately late and
    # disposable under hard budget pressure. They preserve evidence without
    # forcing the hot-history start boundary backwards, but must never make a
    # request impossible to fit. Dropping one releases the corresponding
    # run-local retention state via the normal eviction report.
    if count > request_limit:
        for message in list(messages):
            if count <= request_limit:
                break
            if not bool(message.get('_harnessy_adaptive_retention')):
                continue
            old = count_message(message)
            source_id = str(message.get('_harnessy_source_id') or '')
            messages.remove(message)
            changed_request(-old)
            if source_id and source_id not in adaptive_capsules_evicted:
                adaptive_capsules_evicted.append(source_id)
                if source_id not in protected_evicted:
                    protected_evicted.append(source_id)

    # Adaptive-retention entries are a priority, not an absolute pin. If all
    # ordinary compaction/archive candidates were exhausted and the request is
    # still above its target, release protected retrievals in deterministic
    # least-recently-refreshed order. This prevents a set of retained chunks
    # from making the prompt impossible to budget.
    if count > request_limit and protected_ids:
        protected_results: list[dict[str, Any]] = []
        for block in completed_blocks:
            for message in block[1:]:
                sid = source_id_for(message)
                if sid in protected_ids and message in messages:
                    protected_results.append(message)
        message_positions = {id(message): index for index, message in enumerate(messages)}
        protected_results.sort(
            key=lambda message: (
                protected_rank.get(source_id_for(message), len(protected_rank) + 1),
                message_positions.get(id(message), 10**9),
            )
        )
        for message in protected_results:
            if count <= request_limit:
                break
            compact_result(message, protected=True)

    if count > request_limit and protected_ids:
        protected_blocks = []
        for block in candidates:
            if not all(source_for(m) is not None for m in block):
                continue
            block_ids = [source_id_for(m) for m in block]
            if not any(source_id in protected_ids for source_id in block_ids):
                continue
            ranks = [protected_rank.get(source_id, len(protected_rank) + 1)
                     for source_id in block_ids if source_id in protected_ids]
            protected_blocks.append((min(ranks) if ranks else len(protected_rank) + 1, block))
        protected_blocks.sort(key=lambda row: row[0])
        for _rank, block in protected_blocks:
            if count <= request_limit:
                break
            if not all(message in messages for message in block):
                continue
            ids = archive_block(block)
            for sid in ids:
                if sid in protected_ids and sid not in protected_evicted:
                    protected_evicted.append(sid)

    count = recount()

    components: dict[str, int] = defaultdict(int)
    for key, value in system_components.items():
        components[key] += count_text(value)
    # Include wrappers/separators/chat-template estimate rather than pretend the
    # component sums exactly match a tokenizer measurement.
    known_system = sum(components.values())
    components['request_overhead'] += max(0, system_tokens - known_system)
    components['tool_schemas'] = schema_tokens
    for m in messages:
        if m.get('role') == 'system':
            continue
        tokens = count_message(m)
        if m.get('_harnessy_context_notice') is True and source_for(m) is None:
            components['controller_metadata'] += tokens
            continue
        source = source_for(m)
        content = m.get('content')
        plain = content if isinstance(content, str) else '\n'.join(str(p.get('text') or '') for p in content or [] if isinstance(p, dict))
        key = 'conversation'
        if m.get('role') == 'tool' and m.get('name') in {'read_attachment', 'search_attachment', 'read_chat_message', 'search_chat_history', 'read_project_memory', 'web_search', 'web_open', 'web_find'}:
            key = 'retrieved_material'
        if source is None and ('warm-context excerpts' in plain or bool(m.get('_harnessy_adaptive_retention'))):
            key = 'retrieved_material'
        if source is not None and m.get('role') == 'user':
            base = min(tokens, count_text(source.content))
            components['conversation'] += base
            components['expanded_attachments'] += tokens - base
        else:
            components[key] += tokens
    for key in ('core', 'global_instructions', 'workspace_instructions', 'project_chat_instructions', 'task_state', 'skill', 'memory', 'archive_policy',
                'conversation', 'expanded_attachments', 'retrieved_material', 'tool_schemas', 'controller_metadata'):
        components.setdefault(key, 0)
    report = {
        'budget_method': 'estimated UTF-8 bytes / 3 + message overhead; images assumed 4096 tokens each',
        'usage_kind': 'estimate_not_tokenizer_measurement', 'component_tokens_estimated': dict(components),
        'effective_context_window': context or None, 'context_source': context_source,
        'unknown_context_planning_ceiling': planning_ceiling if not context else None,
        'input_budget_tokens': input_limit, 'reserved_output_tokens': reserve,
        'request_limit_tokens': request_limit, 'fixed_input_tokens_estimated': fixed,
        'safety_margin_tokens': safety, 'assembled_tokens_before': before,
        'assembled_input_tokens_estimated': count, 'assembled_with_output_reserve_estimated': count + reserve,
        'estimate_over_budget': count > input_limit,
        'estimated_excess_tokens': max(0, count - input_limit),
        'active_tool_results_compacted': compacted, 'completed_steps_archived': steps_archived,
        'controller_metadata_tokens_estimated': components['controller_metadata'],
        'controller_notice_count': int(archive_marker is not None),
        'context_notices_collapsed': max(0, prior_notice_count - 1),
        'compacted_tool_message_ids': compacted_ids[-24:],
        'attachment_payloads_deferred': attachments_deferred, 'budget_archived_message_ids': archived_ids[-24:],
        'adaptive_retention_evicted_message_ids': protected_evicted,
        'adaptive_retention_capsules_evicted': len(adaptive_capsules_evicted),
        'memory_excerpted': '[Workspace memory prompt excerpt;' in system_components.get('memory', ''),
    }
    if token_counter is not None:
        report.update(token_counter.metadata(messages, tools))
    return report
