"""Read-only, disk-backed chat snapshots and Markdown exports.

No renderer/DOM dependency. Inference never holds a source SQLite transaction.
Only optional artifact registration by the caller writes workspace metadata.
"""
from __future__ import annotations

import asyncio
import json
import re
import os
import stat
import shutil
import sqlite3
import threading
import time
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, TextIO

from ..diagnostics.sqlite import connect_database
from .transcript import assistant_stream_groups

LEVELS = {
    1: 'Full Transcript',
    2: 'All Responses + Activity Summaries',
    3: 'Main Responses + Activity Summaries',
    4: 'Main Responses + Activity Counts',
    5: 'Summary / Handover',
}

EXPORT_TYPES = {
    'transcript': 'Selected transcript contents',
    'handover': 'Generated project handover',
}

CONTENT_DETAIL = {
    'full': 'Original text',
    'summary': 'AI summary',
    'counts': 'Counts only',
}

_CONTENT_DETAIL_VALUES = {'exclude', *CONTENT_DETAIL}


@dataclass(frozen=True, slots=True)
class ExportOptions:
    # ``level`` remains as a compatibility bridge for saved callers and older
    # tests. The v0.6.5 UI writes the explicit fields below instead.
    level: int | None = None
    first_record: int = 1
    last_record: int | None = None
    timestamps: bool = True
    model_info: bool = True
    raw_metadata: bool = False
    length: str = 'standard'
    include_attachment_references: bool = True
    bundle_attachments: bool = False

    export_type: str = 'transcript'
    include_user_messages: bool = True
    include_main_responses: bool = True
    intermediate_detail: str = 'summary'
    thinking_detail: str = 'summary'
    tools_detail: str = 'summary'

    def __post_init__(self) -> None:
        if self.level is None:
            return
        if self.level not in LEVELS:
            raise ValueError('Select a legacy export detail level from 1 to 5.')
        mappings = {
            1: ('transcript', 'full', 'full', 'full'),
            2: ('transcript', 'full', 'summary', 'summary'),
            3: ('transcript', 'summary', 'summary', 'summary'),
            4: ('transcript', 'counts', 'counts', 'counts'),
            5: ('handover', 'summary', 'summary', 'summary'),
        }
        export_type, intermediate, thinking, tools = mappings[self.level]
        object.__setattr__(self, 'export_type', export_type)
        object.__setattr__(self, 'include_user_messages', True)
        object.__setattr__(self, 'include_main_responses', True)
        object.__setattr__(self, 'intermediate_detail', intermediate)
        object.__setattr__(self, 'thinking_detail', thinking)
        object.__setattr__(self, 'tools_detail', tools)

    @property
    def requires_model(self) -> bool:
        return self.export_type == 'handover' or 'summary' in {
            self.intermediate_detail, self.thinking_detail, self.tools_detail,
        }

    @property
    def is_full_transcript(self) -> bool:
        return (
            self.export_type == 'transcript'
            and self.include_user_messages
            and self.include_main_responses
            and self.intermediate_detail == 'full'
            and self.thinking_detail == 'full'
            and self.tools_detail == 'full'
        )

    @property
    def artifact_tag(self) -> str:
        if self.level is not None:
            return f'L{self.level}'
        return 'Handover' if self.export_type == 'handover' else 'Transcript'

    def validate(self) -> None:
        if self.level is not None and self.level not in LEVELS:
            raise ValueError('Select a legacy export detail level from 1 to 5.')
        if self.export_type not in EXPORT_TYPES:
            raise ValueError('Select either a transcript export or generated handover.')
        for label, value in (
            ('Intermediate responses', self.intermediate_detail),
            ('Thinking', self.thinking_detail),
            ('Tool activity', self.tools_detail),
        ):
            if value not in _CONTENT_DETAIL_VALUES:
                raise ValueError(f'Select a valid detail option for {label}.')
        if (
            self.export_type == 'transcript'
            and not self.include_user_messages
            and not self.include_main_responses
            and self.intermediate_detail == 'exclude'
            and self.thinking_detail == 'exclude'
            and self.tools_detail == 'exclude'
        ):
            raise ValueError('Select at least one transcript content item to export.')
        if self.raw_metadata and not self.is_full_transcript:
            raise ValueError('Raw saved metadata requires every transcript content item in Original text mode.')
        if self.bundle_attachments and not self.include_attachment_references:
            raise ValueError('Select referenced attachments before enabling the ZIP attachment bundle.')
        if self.first_record < 1 or (self.last_record is not None and self.last_record < self.first_record):
            raise ValueError('Record range must start at 1 or later, with the last record at or after the first.')
        if self.length not in {'brief', 'standard', 'detailed'}:
            raise ValueError('Select Brief, Standard or Detailed.')


def _json(text: str | None, fallback):
    try:
        value = json.loads(text) if text else fallback
        return value if isinstance(value, type(fallback)) else fallback
    except (ValueError, TypeError):
        return fallback


def fenced(text: str, language: str = '') -> str:
    fence = '`' * max(3, 1 + max((len(m.group()) for m in re.finditer(r'`+', text)), default=0))
    return fence + language + '\n' + text + ('\n' if not text.endswith('\n') else '') + fence + '\n\n'


def literal(text: Any) -> str:
    """One-line metadata label, not Markdown supplied by a file/model."""
    return re.sub(r'([\\`*_{}\[\]<>#|])', r'\\\1', str(text).replace('\n', ' ').replace('\r', ' '))


@dataclass(slots=True)
class Record:
    seq: int
    row: dict[str, Any]

    @property
    def role(self) -> str: return str(self.row.get('role') or '')
    @property
    def text(self) -> str: return str(self.row.get('content') or '')
    @property
    def meta(self) -> dict: return _json(self.row.get('metadata_json'), {})
    @property
    def calls(self) -> list: return _json(self.row.get('tool_calls_json'), [])
    @property
    def groups(self) -> list[dict[str, str]]:
        return assistant_stream_groups(self.meta, self.text, str(self.meta.get('reasoning') or ''), str(self.row.get('created_at') or ''))
    @property
    def classification(self) -> str:
        if self.role != 'assistant': return self.role
        if self.meta.get('terminal_stop_reason'): return 'main'
        if self.meta.get('continuation_reason') == 'output_limit': return 'continuation'
        if self.calls or self.meta.get('continuation_reason'): return 'intermediate'
        # Historical records without completion metadata must not lose answers.
        return 'unclassified'


@dataclass(slots=True)
class ChatSnapshot:
    database: Path
    workspace_root: Path
    workspace_name: str
    chat_id: str
    title: str
    captured_at: str
    total_records: int
    active: bool = False

    @classmethod
    def capture(cls, workspace, chat_id: str, directory: Path, *, active: bool = False,
                cancel: threading.Event | None = None) -> 'ChatSnapshot':
        """SQLite's incremental backup yields a coherent snapshot, including WAL.

        pages bounds each backup step and lets a live writer run between steps.
        The source is opened mode=ro. Temporary space is needed for the workspace
        database (not its attachment binaries); it is removed after export.
        """
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / 'snapshot.sqlite'
        deadline = time.monotonic() + 120
        def progress(_status, _remaining, _total):
            if cancel is not None and cancel.is_set():
                raise RuntimeError('Export cancelled while snapshotting.')
            if time.monotonic() > deadline:
                raise TimeoutError('Chat snapshot exceeded two minutes; the running agent was not stopped.')
        source = workspace._connect(readonly=True, timeout=2)
        dest = None
        try:
            dest = connect_database(target, role='other')
            source.backup(dest, pages=128, progress=progress, sleep=.01)
            dest.row_factory = sqlite3.Row
            chat = dest.execute('SELECT title FROM chats WHERE id=?', (chat_id,)).fetchone()
            if chat is None:
                raise ValueError('Chat no longer exists; nothing was exported.')
            count = dest.execute(
                "SELECT COUNT(*) FROM messages WHERE chat_id=? AND role IN ('user','assistant','tool')",
                (chat_id,),
            ).fetchone()[0]
            return cls(target, workspace.root, workspace.name, chat_id, str(chat['title']),
                       datetime.now(timezone.utc).isoformat(timespec='seconds'), count, active)
        finally:
            try:
                source.close()
            finally:
                if dest is not None:
                    dest.close()

    def records(self, options: ExportOptions) -> Iterator[Record]:
        options.validate()
        con = connect_database(self.database.as_uri() + '?mode=ro', role='other', uri=True)
        con.row_factory = sqlite3.Row
        try:
            cur = con.execute("SELECT * FROM messages WHERE chat_id=? AND role IN ('user','assistant','tool') ORDER BY created_at ASC, rowid ASC LIMIT ? OFFSET ?",
                (self.chat_id, (options.last_record - options.first_record + 1) if options.last_record is not None else -1, options.first_record - 1))
            seq = options.first_record
            while rows := cur.fetchmany(64):
                for row in rows:
                    yield Record(seq, dict(row)); seq += 1
        finally:
            con.close()

    def attachments(self) -> dict[str, dict]:
        con = connect_database(self.database.as_uri() + '?mode=ro', role='other', uri=True)
        con.row_factory = sqlite3.Row
        try:
            return {r['id']:dict(r) for r in con.execute('SELECT * FROM attachments WHERE chat_id=?', (self.chat_id,))}
        finally: con.close()


@dataclass
class Activity:
    thinking: int = 0
    tools: int = 0
    intermediate: int = 0
    names: Counter = field(default_factory=Counter)
    outcomes: Counter = field(default_factory=Counter)
    pending: dict = field(default_factory=lambda: defaultdict(list))

    def observe(
        self,
        record: Record,
        *,
        thinking: bool = True,
        tools: bool = True,
        intermediate: bool = True,
    ) -> None:
        if record.role == 'assistant':
            if thinking:
                self.thinking += sum(bool(g['reasoning']) for g in record.groups)
            if intermediate:
                self.intermediate += bool(record.text and record.classification == 'intermediate')
            if tools:
                for call in record.calls:
                    if not isinstance(call, dict): continue
                    name = str((call.get('function') or {}).get('name') or 'unknown')
                    self.tools += 1; self.names[name] += 1
                    self.pending[str(call.get('id') or '')].append(name)
        elif record.role == 'tool' and tools:
            key = str(record.row.get('tool_call_id') or '')
            if self.pending.get(key):
                self.pending[key].pop(0)
                if not self.pending[key]: del self.pending[key]
            else:
                # A range/legacy chat can begin at a result without the call row.
                self.tools += 1
                self.names[str(record.row.get('name') or 'unknown')] += 1
            status = str(record.meta.get('execution_status') or '').lower()
            ok = record.meta.get('ok')
            result_flags = _json(record.text, {}) if not status else {}
            if 'cancel' in status or result_flags.get('cancelled') is True: self.outcomes['cancelled'] += 1
            elif ok is False or status in {'failed', 'error', 'denied'}: self.outcomes['failed'] += 1
            elif ok is True: self.outcomes['succeeded'] += 1
            else: self.outcomes['unknown'] += 1

    def text(
        self,
        *,
        thinking: bool = True,
        tools: bool = True,
        intermediate: bool = True,
    ) -> str:
        if not (self.thinking or self.tools or self.intermediate): return ''
        parts: list[str] = []
        if thinking:
            parts.append(f'{self.thinking} Thinking blocks')
        if tools:
            parts.append(f'{self.tools} tool calls')
        if intermediate:
            parts.append(f'{self.intermediate} intermediate replies')
        out = '> Activity: ' + ' · '.join(parts) + '\n'
        if tools and self.names:
            out += '> Tools: ' + ', '.join(f'{literal(k)} ×{v}' for k,v in self.names.items()) + '\n'
            outcomes = dict(self.outcomes)
            outcomes['pending / no recorded outcome'] = max(0, self.tools - sum(outcomes.values()))
            out += '> Outcomes: ' + ', '.join(f'{v} {k}' for k,v in outcomes.items() if v) + '\n'
        return out + '\n'


def write_record(out: TextIO, record: Record, options: ExportOptions, *, full: bool = False) -> None:
    role = {'user':'You', 'assistant':'HarnessyXO', 'tool':'Tool'}.get(record.role, record.role or 'Unknown')
    extra = ' — answer continuation' if record.classification == 'continuation' else ''
    if record.role == 'assistant' and record.classification == 'unclassified' and options.level in {3,4}:
        extra = ' — completion classification unavailable; retained'
    out.write(f'## {role}{extra} · Record {record.seq}\n\n')
    labels = ['ID: ' + literal(record.row.get('id'))]
    if options.timestamps: labels.append(literal(record.row.get('created_at', '')))
    if options.model_info and record.meta.get('model'): labels.append('Model: ' + literal(record.meta['model']))
    if record.meta.get('queued_followup'): labels.append('Delivered queued follow-up')
    out.write('> ' + ' · '.join(labels) + '\n\n')
    if full and record.role == 'assistant':
        for group in record.groups:
            if group['reasoning']:
                out.write('### Thinking (saved model-provided text)\n\n' + group['reasoning'] + '\n\n')
            if group['answer']:
                out.write('### Response\n\n' + group['answer'] + '\n\n')
        # Preserve the authoritative saved fields if old stream segments disagree.
        if ''.join(g['answer'] for g in record.groups) != record.text:
            out.write('### Saved response field (differs from stream segments)\n\n' + record.text + '\n\n')
        saved_reasoning = str(record.meta.get('reasoning') or '')
        if saved_reasoning and ''.join(g['reasoning'] for g in record.groups) != saved_reasoning:
            out.write('### Saved Thinking field (differs from stream segments)\n\n' + saved_reasoning + '\n\n')
        if record.calls:
            out.write('### Tool calls and arguments\n\n' + fenced(json.dumps(record.calls, ensure_ascii=False, indent=2), 'json'))
    elif record.role == 'tool':
        if record.row.get('tool_call_id'):
            out.write('Call ID: ' + literal(record.row['tool_call_id']) + '\n\n')
        if record.meta.get('execution_status'):
            out.write('Recorded status: ' + literal(record.meta['execution_status']) + '\n\n')
        if isinstance(record.meta.get('ok'), bool):
            out.write('Recorded result OK: ' + str(record.meta['ok']).lower() + '\n\n')
        out.write('Tool: ' + literal(record.row.get('name') or 'unknown') + '\n\n')
        if 'arguments' in record.meta:
            out.write('Arguments:\n\n' + fenced(json.dumps(record.meta['arguments'], ensure_ascii=False, indent=2),'json'))
        out.write(fenced(record.text, 'text'))
    else:
        out.write(record.text + '\n\n')
    if options.raw_metadata and record.row.get('metadata_json'):
        out.write('<details><summary>Saved metadata</summary>\n\n' + fenced(str(record.row['metadata_json']), 'json') + '</details>\n\n')
    out.write('---\n\n')


def write_selected_record(
    out: TextIO,
    record: Record,
    options: ExportOptions,
    *,
    include_answer: bool = False,
    include_thinking: bool = False,
    include_tool_activity: bool = False,
) -> bool:
    """Write only explicitly selected original fields from one saved record."""
    if record.role == 'user':
        if not options.include_user_messages:
            return False
    elif record.role == 'assistant':
        has_thinking = include_thinking and any(group['reasoning'] for group in record.groups)
        has_answer = include_answer and bool(record.text or any(group['answer'] for group in record.groups))
        has_calls = include_tool_activity and bool(record.calls)
        if not (has_thinking or has_answer or has_calls):
            return False
    elif record.role == 'tool':
        if not include_tool_activity:
            return False
    else:
        return False

    role = {'user': 'You', 'assistant': 'HarnessyXO', 'tool': 'Tool'}.get(
        record.role, record.role or 'Unknown',
    )
    extra = ' — answer continuation' if include_answer and record.classification == 'continuation' else ''
    if (
        include_answer
        and record.role == 'assistant'
        and record.classification == 'unclassified'
        and options.intermediate_detail != 'full'
    ):
        extra = ' — completion classification unavailable; retained'
    out.write(f'## {role}{extra} · Record {record.seq}\n\n')
    labels = ['ID: ' + literal(record.row.get('id'))]
    if options.timestamps:
        labels.append(literal(record.row.get('created_at', '')))
    if options.model_info and record.meta.get('model'):
        labels.append('Model: ' + literal(record.meta['model']))
    if record.meta.get('queued_followup'):
        labels.append('Delivered queued follow-up')
    out.write('> ' + ' · '.join(labels) + '\n\n')

    if record.role == 'user':
        out.write(record.text + '\n\n')
    elif record.role == 'assistant':
        if include_thinking:
            for group in record.groups:
                if group['reasoning']:
                    out.write('### Thinking (saved model-provided text)\n\n' + group['reasoning'] + '\n\n')
            saved_reasoning = str(record.meta.get('reasoning') or '')
            joined_reasoning = ''.join(group['reasoning'] for group in record.groups)
            if saved_reasoning and joined_reasoning != saved_reasoning:
                out.write(
                    '### Saved Thinking field (differs from stream segments)\n\n'
                    + saved_reasoning + '\n\n'
                )
        if include_answer:
            for group in record.groups:
                if group['answer']:
                    out.write('### Response\n\n' + group['answer'] + '\n\n')
            if ''.join(group['answer'] for group in record.groups) != record.text:
                out.write(
                    '### Saved response field (differs from stream segments)\n\n'
                    + record.text + '\n\n'
                )
        if include_tool_activity and record.calls:
            out.write(
                '### Tool calls and arguments\n\n'
                + fenced(json.dumps(record.calls, ensure_ascii=False, indent=2), 'json')
            )
    else:
        if record.row.get('tool_call_id'):
            out.write('Call ID: ' + literal(record.row['tool_call_id']) + '\n\n')
        if record.meta.get('execution_status'):
            out.write('Recorded status: ' + literal(record.meta['execution_status']) + '\n\n')
        if isinstance(record.meta.get('ok'), bool):
            out.write('Recorded result OK: ' + str(record.meta['ok']).lower() + '\n\n')
        out.write('Tool: ' + literal(record.row.get('name') or 'unknown') + '\n\n')
        if 'arguments' in record.meta:
            out.write(
                'Arguments:\n\n'
                + fenced(json.dumps(record.meta['arguments'], ensure_ascii=False, indent=2), 'json')
            )
        out.write(fenced(record.text, 'text'))

    if options.raw_metadata and record.row.get('metadata_json'):
        out.write(
            '<details><summary>Saved metadata</summary>\n\n'
            + fenced(str(record.row['metadata_json']), 'json')
            + '</details>\n\n'
        )
    out.write('---\n\n')
    return True


def write_selected_summary_source(
    activity: TextIO,
    record: Record,
    options: ExportOptions,
) -> bool:
    """Spool only fields whose selected representation is an AI summary."""
    sections: list[str] = []
    if record.role == 'assistant':
        if options.thinking_detail == 'summary':
            reasoning = [group['reasoning'] for group in record.groups if group['reasoning']]
            if reasoning:
                sections.append('Thinking:\n' + '\n'.join(reasoning))
        if (
            options.intermediate_detail == 'summary'
            and record.classification == 'intermediate'
            and record.text
        ):
            sections.append('Intermediate response:\n' + record.text)
        if options.tools_detail == 'summary' and record.calls:
            sections.append(
                'Tool calls and arguments:\n'
                + json.dumps(record.calls, ensure_ascii=False, indent=2)
            )
    elif record.role == 'tool' and options.tools_detail == 'summary':
        sections.append(
            'Tool result: '
            + str(record.row.get('name') or 'unknown')
            + '\nArguments: '
            + json.dumps(record.meta.get('arguments'), ensure_ascii=False)
            + '\nResult: '
            + record.text
        )
    if not sections:
        return False
    activity.write(
        f'\n[Record {record.seq}; {record.row.get("id")}; {record.role}]\n'
        + '\n\n'.join(sections)
        + '\n'
    )
    return True


async def render_selected_markdown(
    snapshot: ChatSnapshot,
    options: ExportOptions,
    target: Path,
    *,
    summarizer=None,
    progress: Callable[[str], None] | None = None,
    cancel: threading.Event | None = None,
) -> set[str]:
    """Render the v0.6.5 explicit content-selection export contract."""
    attachments: set[str] = set()
    activity_path = target.parent / ('activity-' + target.stem + '.txt')
    counts = Activity()
    last_kind = ''
    counted_thinking = options.thinking_detail in {'summary', 'counts'}
    counted_tools = options.tools_detail in {'summary', 'counts'}
    counted_intermediate = options.intermediate_detail in {'summary', 'counts'}

    with target.open('w', encoding='utf-8', newline='\n') as out, activity_path.open(
        'w+', encoding='utf-8',
    ) as activity:
        out.write('# ' + literal(snapshot.title) + '\n\n')
        out.write(
            f'Export type: **{EXPORT_TYPES[options.export_type]}**  \n'
            f'Workspace: {literal(snapshot.workspace_name)}  \n'
            f'Snapshot: {snapshot.captured_at}  \n'
        )
        end = min(options.last_record or snapshot.total_records, snapshot.total_records)
        out.write(f'Saved record range: {options.first_record}–{end} of {snapshot.total_records}\n\n')
        out.write(
            'This export uses saved records, not the browser window. Currently streaming, '
            'unsaved text is not included.\n\n'
        )
        if snapshot.active:
            out.write(
                '**The agent was active when this snapshot was requested; the conversation may '
                'continue after this export.**\n\n'
            )

        if options.export_type == 'transcript':
            def detail(value: str) -> str:
                return 'Excluded' if value == 'exclude' else CONTENT_DETAIL[value]

            out.write('## Included content\n\n')
            out.write(
                f'- User prompts: {"Original text" if options.include_user_messages else "Excluded"}\n'
                f'- Main responses: {"Original text" if options.include_main_responses else "Excluded"}\n'
                f'- Intermediate responses: {detail(options.intermediate_detail)}\n'
                f'- Thinking: {detail(options.thinking_detail)}\n'
                f'- Tool calls and results: {detail(options.tools_detail)}\n\n'
            )
            if options.requires_model:
                out.write(
                    '**Generated summaries are interpretations, not verbatim evidence.** Original '
                    'text retained by the selections above is labelled separately.\n\n'
                )
        else:
            out.write(
                '**This handover is a generated interpretation, not a verbatim transcript.** It '
                'uses the complete saved record range as source material.\n\n'
            )

        if not snapshot.total_records:
            out.write('No saved messages.\n\n')

        async def flush_activity() -> None:
            nonlocal counts
            summary_counts = counts.text(
                thinking=counted_thinking,
                tools=counted_tools,
                intermediate=counted_intermediate,
            )
            if summary_counts:
                out.write(summary_counts)
            activity.flush()
            if activity.tell():
                if summarizer is None:
                    raise ValueError('The selected AI summary options require a model.')
                summary = await summarizer.summarize_file(
                    activity_path,
                    'Summarize only this selected activity sequence. Preserve failures, uncertainty, '
                    'file paths and source record IDs. Do not recreate excluded fields or repeat original '
                    'main answers.',
                    'brief',
                )
                out.write('### Selected activity summary — generated\n\n' + summary + '\n\n')
            counts = Activity()
            activity.seek(0)
            activity.truncate()

        try:
            for record in snapshot.records(options):
                if cancel is not None and cancel.is_set():
                    raise asyncio.CancelledError()
                if options.include_attachment_references:
                    attachments.update(
                        str(value)
                        for value in record.meta.get('attachment_ids', [])
                        if isinstance(value, str)
                    )
                if progress and record.seq % 24 == 0:
                    progress(f'Exporting saved record {record.seq} of {end}…')

                if options.export_type == 'handover':
                    write_record(activity, record, options, full=True)
                    last_kind = record.classification
                    if record.seq % 24 == 0:
                        await asyncio.sleep(0)
                    continue

                if record.role == 'user':
                    await flush_activity()
                    write_selected_record(out, record, options)
                elif record.role == 'assistant':
                    is_intermediate = record.classification == 'intermediate'
                    answer_mode = (
                        options.intermediate_detail
                        if is_intermediate
                        else ('full' if options.include_main_responses else 'exclude')
                    )
                    full_thinking = options.thinking_detail == 'full'
                    full_tools = options.tools_detail == 'full'
                    full_answer = answer_mode == 'full'
                    if is_intermediate:
                        counts.observe(
                            record,
                            thinking=counted_thinking,
                            tools=counted_tools,
                            intermediate=counted_intermediate,
                        )
                        write_selected_summary_source(activity, record, options)
                        write_selected_record(
                            out,
                            record,
                            options,
                            include_answer=full_answer,
                            include_thinking=full_thinking,
                            include_tool_activity=full_tools,
                        )
                    else:
                        has_any_compact_activity = (
                            options.intermediate_detail in {'summary', 'counts'}
                            or options.thinking_detail in {'summary', 'counts'}
                            or options.tools_detail in {'summary', 'counts'}
                        )
                        if has_any_compact_activity:
                            # Original fields on this response must follow any
                            # compacted activity from earlier records. When the
                            # current response has no original activity field,
                            # one combined summary may cover the preceding
                            # sequence plus its selected Thinking/tool fields.
                            if full_thinking or full_tools:
                                await flush_activity()
                            counts.observe(
                                record,
                                thinking=counted_thinking,
                                tools=counted_tools,
                                intermediate=False,
                            )
                            write_selected_summary_source(activity, record, options)
                            write_selected_record(
                                out,
                                record,
                                options,
                                include_thinking=full_thinking,
                                include_tool_activity=full_tools,
                            )
                            # Thinking/tool activity belonging to the main
                            # response precedes the response text itself.
                            await flush_activity()
                            write_selected_record(
                                out,
                                record,
                                options,
                                include_answer=full_answer,
                            )
                        else:
                            write_selected_record(
                                out,
                                record,
                                options,
                                include_answer=full_answer,
                                include_thinking=full_thinking,
                                include_tool_activity=full_tools,
                            )
                elif record.role == 'tool':
                    counts.observe(
                        record,
                        thinking=False,
                        tools=counted_tools,
                        intermediate=False,
                    )
                    write_selected_summary_source(activity, record, options)
                    write_selected_record(
                        out,
                        record,
                        options,
                        include_tool_activity=options.tools_detail == 'full',
                    )
                last_kind = record.classification
                if record.seq % 24 == 0:
                    await asyncio.sleep(0)

            if options.export_type == 'handover':
                activity.flush()
                if snapshot.total_records:
                    if summarizer is None:
                        raise ValueError('A generated handover requires a model.')
                    summary = await summarizer.summarize_file(
                        activity_path,
                        'Write a project handover: objective and constraints, current state, findings '
                        'with evidence, decisions/corrections, files changed, tests/results, unresolved '
                        'questions, and next steps. Distinguish suggestions from tool observations and '
                        'verified results. Cite source record IDs. Do not turn superseded guesses into facts.',
                        options.length,
                    )
                    out.write('## Generated handover\n\n' + summary + '\n\n')
            else:
                await flush_activity()
                if options.include_main_responses and last_kind in {
                    'user', 'tool', 'intermediate', 'continuation',
                }:
                    out.write(
                        '> No concluding answer is recorded at the end of the selected range. This '
                        'sequence may be in progress, interrupted, or outside the selected range.\n\n'
                    )
        finally:
            pass
    activity_path.unlink(missing_ok=True)
    return attachments


async def render_markdown(snapshot: ChatSnapshot, options: ExportOptions, target: Path, *, summarizer=None,
                          progress: Callable[[str], None] | None = None, cancel: threading.Event | None = None) -> set[str]:
    """Stream records to disk. Activity text is disk-spooled, not held as a chat list."""
    options.validate()
    if options.first_record > snapshot.total_records and snapshot.total_records:
        raise ValueError('The first record is past the end of this chat.')
    if options.level is None:
        if options.requires_model and summarizer is None:
            raise ValueError('The selected export options require a summary model.')
        return await render_selected_markdown(
            snapshot,
            options,
            target,
            summarizer=summarizer,
            progress=progress,
            cancel=cancel,
        )
    if options.level in {2,3,5} and summarizer is None:
        raise ValueError('This level requires a model. Levels 1 and 4 work without inference.')
    attachments: set[str] = set()
    activity_path = target.parent / ('activity-' + target.stem + '.txt')
    counts = Activity()
    last_kind = ''
    with target.open('w', encoding='utf-8', newline='\n') as out, activity_path.open('w+', encoding='utf-8') as activity:
        out.write('# ' + literal(snapshot.title) + '\n\n')
        out.write(f'Export: **{LEVELS[options.level]}**  \nWorkspace: {literal(snapshot.workspace_name)}  \nSnapshot: {snapshot.captured_at}  \n')
        end = min(options.last_record or snapshot.total_records, snapshot.total_records)
        out.write(f'Saved record range: {options.first_record}–{end} of {snapshot.total_records}\n\n')
        out.write('This export uses saved records, not the browser window. Currently streaming, unsaved text is not included.\n\n')
        if snapshot.active: out.write('**The agent was active when this snapshot was requested; the conversation may continue after this export.**\n\n')
        if options.level in {2,3,5}:
            out.write('**Generated summaries are interpretations, not verbatim evidence.** Original text retained at this detail level is labelled separately.\n\n')
        if not snapshot.total_records:
            out.write('No saved messages.\n\n')
        if options.level in {3,4}:
            out.write('Answers with uncertain historical completion metadata are retained, not silently discarded. Thinking counts refer to saved Thinking blocks, not internal thoughts.\n\n')
        async def flush() -> None:
            nonlocal counts
            summary_counts = counts.text()
            if summary_counts:
                out.write(summary_counts)
                if options.level in {2,3}:
                    activity.flush()
                    if activity.tell():
                        summary = await summarizer.summarize_file(activity_path, 'Summarize this activity sequence. Preserve failures, uncertainty, file paths and source record IDs. Do not repeat original main answers.', 'brief')
                        out.write('### Activity summary — generated\n\n' + summary + '\n\n')
            counts = Activity()
            activity.seek(0); activity.truncate()
        try:
            for record in snapshot.records(options):
                if cancel is not None and cancel.is_set(): raise asyncio.CancelledError()
                if options.include_attachment_references:
                    attachments.update(
                        str(x) for x in record.meta.get('attachment_ids', []) if isinstance(x, str)
                    )
                if progress and record.seq % 24 == 0: progress(f'Exporting saved record {record.seq} of {end}…')
                if options.level == 1:
                    write_record(out, record, options, full=True)
                elif options.level == 5:
                    write_record(activity, record, options, full=True)
                else:
                    if record.role == 'user':
                        await flush(); write_record(out, record, options)
                    elif options.level == 4 and record.role in {'assistant', 'tool'}:
                        counts.observe(record)
                        if record.role == 'assistant' and record.classification != 'intermediate':
                            await flush()
                            if record.text: write_record(out, record, options)
                    elif record.role in {'assistant','tool'}:
                        counts.observe(record)
                        activity.write(f'\n[Record {record.seq}; {record.row.get("id")}; {record.role}]\n')
                        if record.role == 'tool':
                            activity.write('Tool: ' + str(record.row.get('name') or '') + '\nArguments: ' + json.dumps(record.meta.get('arguments'), ensure_ascii=False) + '\nResult: ' + record.text + '\n')
                        else:
                            for group in record.groups:
                                if group['reasoning']: activity.write('Thinking: ' + group['reasoning'] + '\n')
                            if record.calls: activity.write('Tool calls: ' + json.dumps(record.calls, ensure_ascii=False) + '\n')
                            if record.classification == 'intermediate':
                                activity.write('Intermediate reply: ' + record.text + '\n')
                                if options.level == 2 and record.text: write_record(out, record, options)
                            else:
                                await flush()
                                if record.text: write_record(out, record, options)
                    else:
                        await flush(); write_record(out, record, options)
                last_kind = record.classification
                # Yield between disk batches even for inference-free exports.
                if record.seq % 24 == 0: await asyncio.sleep(0)
            if options.level == 5:
                activity.flush()
                if snapshot.total_records:
                    summary = await summarizer.summarize_file(activity_path,
                        'Write a project handover: objective and constraints, current state, findings with evidence, decisions/corrections, files changed, tests/results, unresolved questions, next steps. Distinguish suggestions from tool observations and verified results. Cite source record IDs. Do not turn superseded guesses into facts.', options.length)
                    out.write('## Generated handover\n\n' + summary + '\n\n')
                else: out.write('No saved messages.\n')
            elif options.level != 1:
                await flush()
                if last_kind in {'user','tool','intermediate','continuation'}:
                    out.write('> No concluding answer is recorded at the end of the selected range. This sequence may be in progress, interrupted, or outside the selected range.\n\n')
        finally:
            # The caller owns the whole private temporary directory as well.
            pass
    activity_path.unlink(missing_ok=True)
    return attachments


def append_attachments(snapshot: ChatSnapshot, options: ExportOptions, markdown: Path, ids: set[str], *, cancel: threading.Event | None = None) -> Path:
    """Bundle only referenced regular files inside this workspace, no symlink escape."""
    records = snapshot.attachments()
    bundle = markdown.with_suffix('.zip') if options.bundle_attachments else None
    archive = zipfile.ZipFile(bundle, 'w', compression=zipfile.ZIP_DEFLATED) if bundle else None
    try:
        with markdown.open('a', encoding='utf-8') as out:
            if ids:
                out.write('## Attachments\n\n')
                if not bundle: out.write('References only; attachment bytes are not embedded in this Markdown file.\n\n')
                else: out.write('Attachment metadata comes from the chat snapshot; bundled bytes are the currently available files at export time, not historical versions.\n\n')
            for aid in sorted(ids):
                if cancel is not None and cancel.is_set(): raise RuntimeError('Export cancelled.')
                row = records.get(aid)
                if not row:
                    out.write('- Unavailable attachment record: ' + literal(aid) + '\n'); continue
                name = Path(str(row['name'])).name
                if name in {'', '.', '..'}: name = 'attachment.bin'
                path = (snapshot.workspace_root / str(row['path'])).resolve()
                inside = path.is_relative_to(snapshot.workspace_root.resolve())
                if not inside or not path.is_file():
                    out.write('- ' + literal(name) + ' — file unavailable or outside workspace; not bundled.\n'); continue
                if archive:
                    safe_id = re.sub(r'[^A-Za-z0-9_-]', '_', aid) or 'attachment'
                    name = name.replace('\\', '_')
                    arcname = 'attachments/' + safe_id + '/' + name
                    # 1 MiB chunks keep binary attachment bundling cancellable.
                    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0))
                    with os.fdopen(fd, 'rb') as source, archive.open(arcname, 'w', force_zip64=True) as target:
                        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                            raise ValueError('Attachment changed into a non-regular file; no incomplete bundle was published.')
                        while chunk := source.read(1024*1024):
                            if cancel is not None and cancel.is_set(): raise RuntimeError('Export cancelled.')
                            target.write(chunk)
                    from urllib.parse import quote
                    out.write('- [' + literal(name) + '](' + quote(arcname) + ')\n')
                else:
                    out.write('- ' + literal(name) + f' — {row["size"]} bytes; ' + literal(row['path']) + '\n')
        if archive: archive.write(markdown, markdown.name)
    finally:
        if archive: archive.close()
    return bundle or markdown
