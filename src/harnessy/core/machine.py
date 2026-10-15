from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
import threading
import uuid
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..diagnostics.sqlite import connect_database
from .sqlite_store import StoreConnection, backup_legacy_store_database, enable_store_wal
from .paths import settings_dir
from .instructions import DEFAULT_GLOBAL_INSTRUCTIONS
from .chat_templates import DEFAULT_CHAT_TEMPLATES, append_new_templates
from .notifications import DEFAULT_NTFY_SETTINGS, normalize_ntfy_settings
from .thinking import model_family

GLOBAL_INSTRUCTIONS_NAME = 'GLOBAL_INSTRUCTIONS.md'

# Pages and background workers may use separate stores for the same machine.
# Keep their read/modify/write settings updates in one critical section.
_SETTINGS_LOCKS: dict[str, Any] = {}
_SETTINGS_LOCKS_GUARD = threading.Lock()


def completion_hold_label(state: str) -> str:
    """Describe the owner's current work without confusing a hold with a check."""
    return {
        'checking': 'Completion Check',
        'continuing': 'Continuing work',
        'running': 'Resuming work',
        'unconfirmed': 'Completion not confirmed',
        'interrupted': 'Run interrupted',
        'unconfirmed_released': 'Completion unconfirmed',
    }.get(str(state), 'Completion not confirmed')


def completion_wait_reason(hold: dict[str, Any]) -> str:
    state = str(hold.get('state') or '')
    owner = str(hold.get('project_label') or hold.get('chat_id') or 'another project')
    if state in {'checking', 'continuing', 'running'}:
        return f'Waiting for {owner} · {completion_hold_label(state)}'
    return f'Queue paused · {completion_hold_label(state).lower()} · {owner}'


def completion_blocking_hold(
    holds: list[dict[str, Any]], workspace_id: str, chat_id: str,
) -> dict[str, Any] | None:
    """The same owner exemption used by durable admission, also for display."""
    holds = [row for row in holds if row.get('state') not in {'generating', 'unconfirmed_released'}]
    if any(row['workspace_id'] == workspace_id and row['chat_id'] == chat_id for row in holds):
        return None
    return holds[0] if holds else None

DEFAULT_MODEL_PROFILE: dict[str, Any] = {
    'id': 'local-openai',
    'name': 'Local OpenAI-compatible',
    'base_url': 'http://127.0.0.1:8080/v1',
    'model': 'qwen',
    'api_key': '',
    'omlx_admin_api_key': '',
    'api_mode': 'auto',
    'send_tool_choice': False,
    'temperature': None,
    'top_p': None,
    'top_k': None,
    'min_p': None,
    'presence_penalty': None,
    'frequency_penalty': None,
    'repeat_penalty': None,
    'context_window': 262_144,
    # Physical/API request capacity for this endpoint. This is an advanced
    # backend guard, separate from the user-facing Global Agent Slots ceiling.
    'provider_concurrency': 1,
    # How much conversational/tool history HarnessyXO may keep live before
    # request-view compaction begins. 'auto' preserves the historical balanced
    # behavior; 'maximum' lets the runtime context budget decide the ceiling.
    'active_context_mode': 'auto',
    'active_context_tokens': 0,
    'max_output_tokens': 32_768,
    'max_tokens_field': 'max_tokens',
    'supports_usage_stream': False,
    'supports_vision': False,
    'supports_thinking': False,
    'thinking_mode': 'reasoning_effort',
    'default_thinking': 'default',
    'thinking_format': 'qwen-chat-template',
    'thinking_preset': 'auto',
    'thinking_off_mode': 'auto',
    'thinking_wire_values': {},
    'thinking_ollama_values': {},
    'auto_detect_capabilities': True,
    'supports_developer_role': False,
    'supports_reasoning_effort': False,
    'supports_strict_mode': False,
    'pricing_input_per_million': 0.0,
    'pricing_output_per_million': 0.0,
}


DEFAULT_TOOL_PERMISSIONS: dict[str, str] = {
    'filesystem_read': 'on',
    'filesystem_write': 'on',
    'attachments': 'on',
    'memory': 'on',
    'shell': 'off',
    'processes': 'ask',
    'git_read': 'on',
    'git_write': 'ask',
    'browser': 'ask',
    'web': 'ask',
    'code_intelligence': 'on',
    'diagnostics': 'on',
    'external_targets': 'ask',
}

DEFAULT_TEMPLATES = DEFAULT_CHAT_TEMPLATES

DEFAULT_PROMPT_NAVIGATOR_OPTIONS: dict[str, bool | str] = {
    'layout': 'individual',
    'bookmarks': True,
    'error': False,
    'context': False,
    'attention': False,
    'stopped': False,
    'recovery': False,
    'approval': False,
    'completion_check': False,
}


def normalize_prompt_navigator_options(value: Any) -> dict[str, bool | str]:
    """Keep navigator display choices separate from saved history/status data."""
    options = value if isinstance(value, dict) else {}
    normalized: dict[str, bool | str] = {
        key: options[key] if isinstance(options.get(key), bool) else default
        for key, default in DEFAULT_PROMPT_NAVIGATOR_OPTIONS.items()
        if isinstance(default, bool)
    }
    layout = options.get('layout')
    normalized['layout'] = layout if isinstance(layout, str) and layout in {'individual', 'grouped'} else 'individual'
    return normalized


DEFAULT_SETTINGS: dict[str, Any] = {
    'settings_version': 14,
    'general': {
        'enter_to_send': True,
        'dark': False,
        'prompt_navigator': True,
        'prompt_navigator_options': dict(DEFAULT_PROMPT_NAVIGATOR_OPTIONS),
        'login_session_timeout_minutes': 0,
    },
    'server': {
        'host': '0.0.0.0',
        'port': 6767,
    },
    'models': {
        'active_profile_id': DEFAULT_MODEL_PROFILE['id'],
        'default_profile_id': None,
        'profiles': [deepcopy(DEFAULT_MODEL_PROFILE)],
    },
    'agent': {
        'completion_check_enabled': True,
        # Long-running agents are unlimited by default. Users can opt into a
        # finite step guardrail explicitly in Settings.
        'step_limit_enabled': False,
        'max_steps': 200,
        # Kept for rollback compatibility with pre-v5 builds. v5 uses tool_permissions.
        'shell_enabled': False,
        'shell_timeout_seconds': 180,
        'auto_memory': True,
        # One shared ceiling for active chat coordinators and temporary
        # subagents. Provider-side inference capacity remains an independent
        # backend concern; HarnessyXO never exceeds this agent ceiling.
        'global_agent_slots': 1,
        'tool_permissions': deepcopy(DEFAULT_TOOL_PERMISSIONS),
    },
    'chat': {
        'templates': deepcopy(DEFAULT_TEMPLATES),
    },
    'notifications': {
        'ntfy': deepcopy(DEFAULT_NTFY_SETTINGS),
    },
    'last_workspace_id': None,
}


@dataclass(slots=True)
class WorkspaceRegistration:
    id: str
    name: str
    path: Path
    last_opened: str | None = None
    pinned: bool = False


class MachineStore:
    def __init__(self, root: Path | None = None) -> None:
        # Preserve the final component so startup authentication can reject a
        # symlinked settings root instead of receiving its resolved target.
        self.root = Path(root or settings_dir()).expanduser().absolute()
        self.root.mkdir(parents=True, exist_ok=True)
        self.settings_path = self.root / 'settings.json'
        with _SETTINGS_LOCKS_GUARD:
            self._settings_lock = _SETTINGS_LOCKS.setdefault(
                str(self.settings_path.resolve()), threading.RLock(),
            )
        self.global_instructions_path = self.root / GLOBAL_INSTRUCTIONS_NAME
        self.db_path = self.root / 'machine.db'
        self.skills_dir = self.root / 'skills'
        self.skills_dir.mkdir(parents=True, exist_ok=True)
        self._maybe_import_legacy_machine_state()
        self._init_db()
        # Exclusive creation preserves authored AND deliberately empty files.
        try:
            with self.global_instructions_path.open('x', encoding='utf-8') as stream:
                stream.write(DEFAULT_GLOBAL_INSTRUCTIONS)
        except FileExistsError:
            pass
        if not self.settings_path.exists():
            self.save_settings(deepcopy(DEFAULT_SETTINGS))

    def read_global_instructions(self) -> str:
        if not self.global_instructions_path.is_file():
            return ''
        return self.global_instructions_path.read_text('utf-8', errors='replace')

    def write_global_instructions(self, content: str) -> None:
        text = str(content or '')
        # Empty is an explicit setting, not "use the default next startup".
        value = text.rstrip() + '\n' if text.strip() else ''
        if self.global_instructions_path.is_file() and self.read_global_instructions() == value:
            return
        import os
        import tempfile
        fd, name = tempfile.mkstemp(prefix='.global-instructions-', dir=self.root)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.global_instructions_path)
        finally:
            if os.path.exists(name):
                os.unlink(name)


    def _maybe_import_legacy_machine_state(self) -> None:
        """Import ~/.harnessy once when the new .settings folder is empty.

        This keeps upgrades painless while making all future machine state live
        beside the HarnessyXO application as requested.
        """
        if self.settings_path.exists() or self.db_path.exists():
            return
        legacy = Path.home() / '.harnessy'
        if legacy.resolve() == self.root:
            return
        legacy_settings = legacy / 'settings.json'
        legacy_db = legacy / 'machine.db'
        if legacy_db.is_file():
            try:
                backup_legacy_store_database(legacy_db, self.db_path)
            except (OSError, sqlite3.Error) as exc:
                raise RuntimeError(
                    'Cannot import the legacy Harnessy machine database. Its '
                    'data was left intact and a blank replacement was not '
                    'created. Close the older Harnessy instance and retry.'
                ) from exc
        try:
            if legacy_settings.is_file():
                shutil.copy2(legacy_settings, self.settings_path)
        except OSError:
            # Retain the existing best-effort settings-file import behavior.
            pass

    def _connect(self) -> sqlite3.Connection:
        con = connect_database(self.db_path, role='machine', factory=StoreConnection)
        con.row_factory = sqlite3.Row
        return con

    def _init_db(self) -> None:
        with self._connect() as con:
            enable_store_wal(con)
            con.execute('''
                CREATE TABLE IF NOT EXISTS workspaces (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    path TEXT NOT NULL UNIQUE,
                    last_opened TEXT,
                    position INTEGER,
                    pinned INTEGER NOT NULL DEFAULT 0
                )
            ''')
            columns = {r['name'] for r in con.execute('PRAGMA table_info(workspaces)').fetchall()}
            if 'position' not in columns:
                con.execute('ALTER TABLE workspaces ADD COLUMN position INTEGER')
            if 'pinned' not in columns:
                con.execute('ALTER TABLE workspaces ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0')
            rows = con.execute('SELECT id FROM workspaces ORDER BY rowid ASC').fetchall()
            for index, row in enumerate(rows):
                con.execute('UPDATE workspaces SET position=COALESCE(position, ?) WHERE id=?', (index, row['id']))
            # Whole-agent jobs live in machine state rather than a workspace's
            # LLM-visible Files tree.  A queued prompt can therefore survive a
            # browser refresh/restart without becoming editable project data.
            con.execute('''
                CREATE TABLE IF NOT EXISTS run_queue_jobs (
                    id TEXT PRIMARY KEY,
                    workspace_id TEXT NOT NULL,
                    chat_id TEXT NOT NULL,
                    lane INTEGER NOT NULL,
                    preferred_slot INTEGER NOT NULL DEFAULT 0,
                    prompt TEXT NOT NULL DEFAULT '',
                    attachment_ids_json TEXT NOT NULL DEFAULT '[]',
                    profile_id TEXT NOT NULL DEFAULT '',
                    thinking TEXT NOT NULL DEFAULT 'default',
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    outcome TEXT NOT NULL DEFAULT '',
                    error TEXT NOT NULL DEFAULT ''
                )
            ''')
            queue_columns = {r['name'] for r in con.execute('PRAGMA table_info(run_queue_jobs)').fetchall()}
            if 'preferred_slot' not in queue_columns:
                # Earlier lane=1 records were automatic global-queue jobs, not
                # explicit user requests for Slot 1.
                con.execute('ALTER TABLE run_queue_jobs ADD COLUMN preferred_slot INTEGER NOT NULL DEFAULT 0')
            if 'retry_of_job_id' not in queue_columns:
                con.execute('ALTER TABLE run_queue_jobs ADD COLUMN retry_of_job_id TEXT')
            con.execute(
                'CREATE UNIQUE INDEX IF NOT EXISTS idx_run_queue_retry_source '
                'ON run_queue_jobs(retry_of_job_id) WHERE retry_of_job_id IS NOT NULL'
            )
            con.execute(
                'CREATE INDEX IF NOT EXISTS idx_run_queue_lane_status_created '
                'ON run_queue_jobs(lane,status,created_at)'
            )
            con.execute(
                'CREATE INDEX IF NOT EXISTS idx_run_queue_chat_status '
                'ON run_queue_jobs(workspace_id,chat_id,status,created_at)'
            )
            # Independent owners prevent concurrent backend failures from
            # clearing one another's queue hold after one request recovers.
            con.execute('''
                CREATE TABLE IF NOT EXISTS backend_recoveries (
                    run_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    workspace_id TEXT NOT NULL DEFAULT '',
                    chat_id TEXT NOT NULL DEFAULT '',
                    project_label TEXT NOT NULL DEFAULT '',
                    model TEXT NOT NULL DEFAULT '',
                    attempt INTEGER NOT NULL DEFAULT 1,
                    reason TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL
                )
            ''')
            con.execute('''
                CREATE TABLE IF NOT EXISTS completion_holds (
                    workspace_id TEXT NOT NULL, chat_id TEXT NOT NULL,
                    run_id TEXT NOT NULL, state TEXT NOT NULL,
                    project_label TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '',
                    reason TEXT NOT NULL DEFAULT '', details_json TEXT NOT NULL DEFAULT '{}',
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(workspace_id,chat_id)
                )
            ''')
            con.commit()

    def list_completion_holds(
        self, *, include_generating: bool = False, include_released: bool = False,
    ) -> list[dict[str, Any]]:
        excluded = ([] if include_generating else ['generating']) + ([] if include_released else ['unconfirmed_released'])
        where = 'WHERE state NOT IN (' + ','.join('?' for _ in excluded) + ') ' if excluded else ''
        with self._connect() as con:
            return [dict(row) for row in con.execute(
                'SELECT * FROM completion_holds ' + where + 'ORDER BY updated_at,workspace_id,chat_id', excluded,
            ).fetchall()]

    @staticmethod
    def _begin_completion_run(con: sqlite3.Connection, details: dict[str, Any]) -> None:
        run_id, workspace_id, chat_id = str(details['run_id']), str(details['workspace_id']), str(details['chat_id'])
        prior = con.execute('SELECT run_id,state FROM completion_holds WHERE workspace_id=? AND chat_id=?',
                            (workspace_id, chat_id)).fetchone()
        state = ('generating' if prior is None or prior['state'] == 'unconfirmed_released' or
                 (prior['run_id'] == run_id and prior['state'] == 'generating') else 'running')
        con.execute(
            "INSERT INTO completion_holds VALUES(?,?,?,?,?,?,?,?,strftime('%Y-%m-%dT%H:%M:%fZ','now')) "
            "ON CONFLICT(workspace_id,chat_id) DO UPDATE SET run_id=excluded.run_id,state=excluded.state,"
            "project_label=excluded.project_label,model=excluded.model,reason=excluded.reason,"
            "details_json=excluded.details_json,updated_at=excluded.updated_at",
            (workspace_id, chat_id, run_id, state, str(details.get('project_label') or chat_id),
             str(details.get('model') or ''), 'Resuming the project before admitting other queued work.'
             if state == 'running' else 'Run in progress; completion has not yet been checked.', json.dumps(details)),
        )

    def begin_completion_run(self, details: dict[str, Any]) -> None:
        """Track crashes and transfer only this project's prior completion hold."""
        with self._connect() as con:
            con.execute('BEGIN IMMEDIATE')
            self._begin_completion_run(con, details)
            con.commit()

    def record_completion_gate(self, state: str, details: dict[str, Any]) -> bool:
        """Persist a verdict boundary; stale runs cannot clear a resumed owner's hold."""
        if state not in {'checking', 'continuing', 'unconfirmed', 'interrupted',
                         'complete', 'needs_input', 'stopped'}:
            raise ValueError('Invalid completion gate state.')
        run_id = str(details.get('run_id') or '')
        workspace_id, chat_id = str(details.get('workspace_id') or ''), str(details.get('chat_id') or '')
        if not run_id or not workspace_id or not chat_id:
            raise ValueError('Completion gate needs run, workspace and chat IDs.')
        with self._connect() as con:
            con.execute('BEGIN IMMEDIATE')
            prior = con.execute('SELECT run_id,state FROM completion_holds WHERE workspace_id=? AND chat_id=?',
                                (workspace_id, chat_id)).fetchone()
            if prior is not None and (prior['run_id'] != run_id or prior['state'] == 'unconfirmed_released'):
                return False
            if state in {'complete', 'needs_input', 'stopped'}:
                con.execute('DELETE FROM completion_holds WHERE workspace_id=? AND chat_id=? AND run_id=?',
                            (workspace_id, chat_id, run_id))
            else:
                reason = str(details.get('reason') or {
                    'checking': 'Checking whether the reply is final.',
                    'continuing': 'The model reports unfinished work; the same run is continuing.',
                    'unconfirmed': 'Completion was not confirmed. Continue this project or explicitly resume the queue.',
                    'interrupted': 'The run was interrupted before completion was confirmed.',
                }[state])
                con.execute(
                    "INSERT INTO completion_holds VALUES(?,?,?,?,?,?,?,?,strftime('%Y-%m-%dT%H:%M:%fZ','now')) "
                    "ON CONFLICT(workspace_id,chat_id) DO UPDATE SET state=excluded.state,"
                    "project_label=excluded.project_label,model=excluded.model,reason=excluded.reason,"
                    "details_json=excluded.details_json,updated_at=excluded.updated_at",
                    (workspace_id, chat_id, run_id, state, str(details.get('project_label') or chat_id),
                     str(details.get('model') or ''), reason[:4000], json.dumps(details)),
                )
            con.commit()
        return True

    def release_completion_attempts(self, details: dict[str, Any]) -> bool:
        """Retain a failed-check notice while handing off only its settled run.

        Call after the runner has unwound. A stale verdict cannot release a
        newer run, another project, or any backend retry still in progress.
        """
        run_id = str(details.get('run_id') or '')
        workspace_id, chat_id = str(details.get('workspace_id') or ''), str(details.get('chat_id') or '')
        if not run_id or not workspace_id or not chat_id:
            raise ValueError('Completion handoff needs run, workspace and chat IDs.')
        with self._connect() as con:
            con.execute('BEGIN IMMEDIATE')
            prior = con.execute('SELECT * FROM completion_holds WHERE workspace_id=? AND chat_id=?',
                                (workspace_id, chat_id)).fetchone()
            if prior is None or prior['run_id'] != run_id:
                return False
            if prior['state'] == 'unconfirmed_released':
                return True
            previous_details = json.loads(prior['details_json'] or '{}')
            merged = {**previous_details, **details, 'queue_released': True}
            con.execute(
                "UPDATE completion_holds SET state='unconfirmed_released',reason=?,details_json=?,"
                "updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE workspace_id=? AND chat_id=? AND run_id=?",
                ('Verification attempts finished without confirming completion. The queue may continue; '
                 'you can retry this project from its saved conversation.', json.dumps(merged),
                 workspace_id, chat_id, run_id),
            )
            if merged.get('completion_backend_recovery_exhausted') is True:
                con.execute(
                    "DELETE FROM backend_recoveries WHERE run_id=? AND workspace_id=? AND chat_id=? AND state IN ('failed','cancelled')",
                    (run_id, workspace_id, chat_id),
                )
            con.commit()
        return True

    @staticmethod
    def _completion_admission_reason(con: sqlite3.Connection, workspace_id: str, chat_id: str) -> str:
        holds = con.execute("SELECT * FROM completion_holds WHERE state NOT IN ('generating','unconfirmed_released') "
                            "ORDER BY updated_at").fetchall()
        # A held owner must be able to recover even when several independent
        # projects failed. Its completion never clears the other owners.
        owner = completion_blocking_hold([dict(row) for row in holds], workspace_id, chat_id)
        return completion_wait_reason(owner) if owner else ''

    def run_admission_reason(self, workspace_id: str, chat_id: str, *, include_backend: bool = False) -> str:
        with self._connect() as con:
            if include_backend and con.execute('SELECT 1 FROM backend_recoveries LIMIT 1').fetchone():
                return 'Queue paused · backend needs attention'
            return self._completion_admission_reason(con, str(workspace_id), str(chat_id))

    def recover_interrupted_completion_holds(self) -> int:
        with self._connect() as con:
            changed = con.execute(
                "UPDATE completion_holds SET state='interrupted',"
                "reason='HarnessyXO restarted before completion was confirmed. Continue this project or explicitly resume the queue.',"
                "updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE state IN ('generating','checking','continuing','running')"
            ).rowcount
            con.commit()
        return int(changed or 0)

    def record_backend_recovery(self, state: str, details: dict[str, Any]) -> None:
        """Persist a run's global queue hold before retrying any inference."""
        if state not in {'retrying', 'failed', 'cancelled', 'succeeded'}:
            raise ValueError('Invalid backend recovery state.')
        run_id = str(details.get('run_id') or '').strip()
        if not run_id:
            raise ValueError('Backend recovery needs a run ID.')
        with self._connect() as con:
            con.execute('BEGIN IMMEDIATE')
            if state == 'succeeded':
                con.execute('DELETE FROM backend_recoveries WHERE run_id=?', (run_id,))
            else:
                con.execute(
                    "INSERT INTO backend_recoveries(run_id,state,workspace_id,chat_id,project_label,model,attempt,reason,updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?,strftime('%Y-%m-%dT%H:%M:%fZ','now')) "
                    "ON CONFLICT(run_id) DO UPDATE SET state=excluded.state,workspace_id=excluded.workspace_id,"
                    "chat_id=excluded.chat_id,project_label=excluded.project_label,model=excluded.model,"
                    "attempt=excluded.attempt,reason=excluded.reason,updated_at=excluded.updated_at",
                    (run_id, state, str(details.get('workspace_id') or ''), str(details.get('chat_id') or ''),
                     str(details.get('project_label') or ''), str(details.get('model') or ''),
                     max(0, int(details.get('attempt', 1))), str(details.get('reason') or 'GPU backend failure')[:4000]),
                )
            con.commit()

    def list_backend_recoveries(self) -> list[dict[str, Any]]:
        with self._connect() as con:
            return [dict(row) for row in con.execute(
                'SELECT * FROM backend_recoveries ORDER BY updated_at,run_id'
            ).fetchall()]

    def clear_rewound_chat_holds(self, workspace_id: str, chat_id: str) -> None:
        """Retire this chat's runtime notices after a committed deletion.

        The caller owns the timeline admission gate and has joined every old
        run/retry. Other projects' completion and backend holds stay intact.
        """
        with self._connect() as con:
            con.execute('BEGIN IMMEDIATE')
            for table in ('completion_holds', 'backend_recoveries'):
                con.execute(f'DELETE FROM {table} WHERE workspace_id=? AND chat_id=?',
                            (str(workspace_id), str(chat_id)))
            con.commit()

    def run_queue_paused(self) -> bool:
        with self._connect() as con:
            return (con.execute('SELECT 1 FROM backend_recoveries LIMIT 1').fetchone() is not None
                    or con.execute("SELECT 1 FROM completion_holds WHERE state NOT IN ('generating','unconfirmed_released') LIMIT 1").fetchone() is not None)

    def recover_interrupted_backend_recoveries(self) -> int:
        """A restart cannot prove that a GPU recovered; preserve its hold."""
        with self._connect() as con:
            changed = con.execute(
                "UPDATE backend_recoveries SET state='failed',"
                "reason='HarnessyXO restarted during the GPU retry. Check the backend, then resume the queue.',"
                "updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE state='retrying'"
            ).rowcount
            con.commit()
        return int(changed or 0)

    def resume_run_queue(self) -> bool:
        """Explicit acknowledgement only after every automatic retry settles."""
        with self._connect() as con:
            con.execute('BEGIN IMMEDIATE')
            if con.execute("SELECT 1 FROM backend_recoveries WHERE state='retrying' LIMIT 1").fetchone():
                return False
            if con.execute("SELECT 1 FROM completion_holds WHERE state IN ('checking','continuing','running') LIMIT 1").fetchone():
                return False
            con.execute('DELETE FROM backend_recoveries')
            con.execute("DELETE FROM completion_holds WHERE state IN ('unconfirmed','interrupted')")
            con.commit()
        return True

    @staticmethod
    def _run_queue_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        item = dict(row)
        try:
            raw_ids = json.loads(str(item.pop('attachment_ids_json', '[]') or '[]'))
        except json.JSONDecodeError:
            raw_ids = []
        item['attachment_ids'] = [str(value) for value in raw_ids if str(value)] if isinstance(raw_ids, list) else []
        item['lane'] = max(1, int(item.get('lane') or 1))
        item['preferred_slot'] = max(0, int(item.get('preferred_slot') or 0))
        return item

    def enqueue_run_job(
        self,
        *,
        workspace_id: str,
        chat_id: str,
        lane: int,
        prompt: str,
        preferred_slot: int = 0,
        attachment_ids: list[str] | None = None,
        profile_id: str = '',
        thinking: str = 'default',
        job_id: str = '',
    ) -> dict[str, Any]:
        job_id = str(job_id or uuid.uuid4().hex)
        clean_ids = list(dict.fromkeys(str(value) for value in (attachment_ids or []) if str(value)))
        with self._connect() as con:
            con.execute(
                '''INSERT INTO run_queue_jobs(
                       id,workspace_id,chat_id,lane,preferred_slot,prompt,attachment_ids_json,
                       profile_id,thinking,status,created_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,\'pending\',strftime(\'%Y-%m-%dT%H:%M:%fZ\',\'now\'))''',
                (
                    job_id, str(workspace_id), str(chat_id), max(1, int(lane)),
                    max(0, int(preferred_slot)), str(prompt or ''),
                    json.dumps(clean_ids), str(profile_id or ''), str(thinking or 'default'),
                ),
            )
            con.commit()
        job = self.get_run_job(job_id)
        if job is None:  # pragma: no cover - SQLite committed but failed to read back
            raise RuntimeError('Queued run was not saved.')
        return job

    def get_run_job(self, job_id: str) -> dict[str, Any] | None:
        with self._connect() as con:
            row = con.execute('SELECT * FROM run_queue_jobs WHERE id=?', (str(job_id),)).fetchone()
        return self._run_queue_row(row)

    def list_run_jobs(
        self,
        *,
        active_only: bool = True,
        workspace_id: str | None = None,
        chat_id: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if active_only:
            clauses.append("status IN ('pending','running')")
        if workspace_id is not None:
            clauses.append('workspace_id=?')
            params.append(str(workspace_id))
        if chat_id is not None:
            clauses.append('chat_id=?')
            params.append(str(chat_id))
        sql = 'SELECT * FROM run_queue_jobs'
        if clauses:
            sql += ' WHERE ' + ' AND '.join(clauses)
        sql += ' ORDER BY CASE status WHEN \'running\' THEN 0 ELSE 1 END, created_at ASC, rowid ASC LIMIT ?'
        params.append(max(1, min(int(limit), 5000)))
        with self._connect() as con:
            rows = con.execute(sql, params).fetchall()
        return [item for row in rows if (item := self._run_queue_row(row)) is not None]

    def recent_terminal_run_jobs(self, workspace_id: str, chat_id: str, *, limit: int = 10) -> list[dict[str, Any]]:
        """Recent incomplete attempts for inline retry notices."""
        return self.recent_retryable_run_jobs(
            workspace_id=workspace_id, chat_id=chat_id, limit=limit, include_cancelled=False,
        )

    def recent_retryable_run_jobs(
        self, *, workspace_id: str | None = None, chat_id: str | None = None,
        limit: int = 20, include_cancelled: bool = True,
    ) -> list[dict[str, Any]]:
        """Recent unsuccessful attempts which have not already been retried."""
        statuses = "'failed','interrupted','stopped','cancelled'" if include_cancelled else "'failed','interrupted','stopped'"
        clauses = [
            f'job.status IN ({statuses})', "job.outcome<>'archived'",
            'NOT EXISTS (SELECT 1 FROM run_queue_jobs retry WHERE retry.retry_of_job_id=job.id)',
        ]
        params: list[Any] = []
        for name, value in (('workspace_id', workspace_id), ('chat_id', chat_id)):
            if value is not None:
                clauses.append(f'job.{name}=?')
                params.append(str(value))
        params.append(max(1, min(int(limit), 100)))
        with self._connect() as con:
            rows = con.execute(
                'SELECT job.* FROM run_queue_jobs job WHERE ' + ' AND '.join(clauses)
                + ' ORDER BY job.created_at DESC,job.rowid DESC LIMIT ?', params,
            ).fetchall()
        return [item for row in reversed(rows) if (item := self._run_queue_row(row)) is not None]

    def get_run_job_retry(self, job_id: str) -> dict[str, Any] | None:
        with self._connect() as con:
            row = con.execute('SELECT * FROM run_queue_jobs WHERE retry_of_job_id=?', (str(job_id),)).fetchone()
        return self._run_queue_row(row)

    def retry_run_job(
        self, job_id: str, *, attachment_ids: list[str], slot_limit: int, prompt: str | None = None,
    ) -> tuple[dict[str, Any], bool]:
        """Append one new attempt; repeated clicks return the same saved retry."""
        with self._connect() as con:
            con.execute('BEGIN IMMEDIATE')
            existing = self._run_queue_row(con.execute(
                'SELECT * FROM run_queue_jobs WHERE retry_of_job_id=?', (str(job_id),),
            ).fetchone())
            if existing is not None:
                return existing, False
            source = self._run_queue_row(con.execute(
                'SELECT * FROM run_queue_jobs WHERE id=?', (str(job_id),),
            ).fetchone())
            if (source is None or source['status'] not in {'stopped', 'cancelled', 'failed', 'interrupted'}
                    or source.get('outcome') == 'archived'):
                raise ValueError('Only stopped, cancelled, failed or interrupted runs can be retried.')
            retry_id = uuid.uuid4().hex
            slot = int(source.get('preferred_slot') or 0)
            if slot > max(1, int(slot_limit)):
                slot = 0
            con.execute(
                "INSERT INTO run_queue_jobs(id,workspace_id,chat_id,lane,preferred_slot,prompt,"
                "attachment_ids_json,profile_id,thinking,status,created_at,retry_of_job_id) "
                "VALUES(?,?,?,1,?,?,?,?,?,'pending',strftime('%Y-%m-%dT%H:%M:%fZ','now'),?)",
                (retry_id, source['workspace_id'], source['chat_id'], slot,
                 source['prompt'] if prompt is None else str(prompt),
                 json.dumps(attachment_ids), source['profile_id'], source['thinking'], str(job_id)),
            )
            retry = self._run_queue_row(con.execute('SELECT * FROM run_queue_jobs WHERE id=?', (retry_id,)).fetchone())
            con.commit()
        assert retry is not None
        return retry, True

    def claim_next_run_job(self, lane: int | None = None) -> dict[str, Any] | None:
        """Atomically claim the oldest pending job in the global queue."""
        pending = self.peek_next_run_job(lane)
        return self.start_run_job(str(pending['id'])) if pending is not None else None

    def peek_next_run_job(self, lane: int | None = None) -> dict[str, Any] | None:
        del lane  # compatibility with pre-v0.6 callers
        with self._connect() as con:
            row = con.execute(
                "SELECT * FROM run_queue_jobs WHERE status='pending' "
                'ORDER BY created_at ASC,rowid ASC LIMIT 1',
            ).fetchone()
        return self._run_queue_row(row)

    def start_run_job(self, job_id: str) -> dict[str, Any] | None:
        """Mark one still-pending job running after its full-run lane is held."""
        with self._connect() as con:
            con.execute('BEGIN IMMEDIATE')
            if con.execute('SELECT 1 FROM backend_recoveries LIMIT 1').fetchone():
                # Share the pause check and claim transaction: a released
                # scheduler lease alone does not authorize the next request.
                return None
            row = con.execute(
                "SELECT * FROM run_queue_jobs WHERE id=? AND status='pending'",
                (str(job_id),),
            ).fetchone()
            if row is None:
                con.commit()
                return None
            if self._completion_admission_reason(con, str(row['workspace_id']), str(row['chat_id'])):
                return None
            changed = con.execute(
                "UPDATE run_queue_jobs SET status='running',started_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'),error='' "
                "WHERE id=? AND status='pending'",
                (row['id'],),
            ).rowcount
            if changed:
                # The persisted claim and crash marker are one transaction;
                # a process exit before headless runner setup cannot open B.
                self._begin_completion_run(con, {
                    'run_id': 'queue-' + str(row['id']), 'workspace_id': row['workspace_id'],
                    'chat_id': row['chat_id'], 'model_profile_id': row['profile_id'],
                    'thinking': row['thinking'],
                })
            con.commit()
        return self.get_run_job(str(row['id'])) if changed else None

    def finish_run_job(self, job_id: str, *, status: str, outcome: str = '', error: str = '') -> bool:
        terminal = str(status or '').strip().lower()
        if terminal not in {'completed', 'failed', 'stopped', 'cancelled', 'interrupted'}:
            raise ValueError('Invalid terminal queued-run status.')
        with self._connect() as con:
            changed = con.execute(
                "UPDATE run_queue_jobs SET status=?,outcome=?,error=?,"
                "finished_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=? AND status IN ('pending','running')",
                (terminal, str(outcome or ''), str(error or '')[:4000], str(job_id)),
            ).rowcount
            con.commit()
        return bool(changed)

    def cancel_run_job(self, job_id: str) -> dict[str, Any] | None:
        """Cancel a job which has not started; a running job uses the normal Stop control."""
        before = self.get_run_job(job_id)
        if before is None or before.get('status') != 'pending':
            return None
        if not self.finish_run_job(job_id, status='cancelled', outcome='cancelled'):
            return None
        return before

    def recover_interrupted_run_jobs(self) -> int:
        """Never replay an indeterminate prompt after an application restart.

        AgentRunner checkpoints the user prompt before model work.  Replaying a
        formerly-running record could therefore duplicate a partially completed
        turn.  Mark it interrupted and safely continue untouched pending jobs.
        """
        with self._connect() as con:
            changed = con.execute(
                "UPDATE run_queue_jobs SET status='interrupted',outcome='interrupted',"
                "error='HarnessyXO restarted while this queued run was active; it was not replayed automatically.',"
                "finished_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE status='running'"
            ).rowcount
            con.commit()
        return int(changed or 0)

    def rebalance_run_queue_lanes(self, limit: int) -> int:
        """Keep legacy lanes global; release unavailable slot preferences."""
        capacity = max(1, min(int(limit or 1), 32))
        with self._connect() as con:
            changed = con.execute(
                "UPDATE run_queue_jobs SET lane=1 WHERE status='pending' AND lane<>1"
            ).rowcount
            changed += con.execute(
                "UPDATE run_queue_jobs SET preferred_slot=0 WHERE status='pending' AND preferred_slot>?",
                (capacity,),
            ).rowcount
            con.commit()
        return int(changed or 0)

    def archive_pending_run_jobs(
        self, *, workspace_id: str, chat_ids: list[str],
    ) -> dict[str, list[dict[str, Any]]]:
        """Cancel pending family jobs and return their exact archive metadata."""
        clean_ids = list(dict.fromkeys(str(value) for value in chat_ids if str(value)))
        result: dict[str, list[dict[str, Any]]] = {value: [] for value in clean_ids}
        if not clean_ids:
            return result
        marks = ','.join('?' for _ in clean_ids)
        with self._connect() as con:
            running = con.execute(
                f"SELECT id FROM run_queue_jobs WHERE workspace_id=? AND chat_id IN ({marks}) "
                "AND status='running' LIMIT 1", (str(workspace_id), *clean_ids),
            ).fetchone()
            if running is not None:
                raise RuntimeError('Wait for every running family job to finish before archiving.')
            rows = con.execute(
                f"SELECT * FROM run_queue_jobs WHERE workspace_id=? AND chat_id IN ({marks}) "
                "AND status='pending' ORDER BY created_at,rowid", (str(workspace_id), *clean_ids),
            ).fetchall()
            for row in rows:
                item = self._run_queue_row(row)
                if item is not None:
                    result.setdefault(str(item['chat_id']), []).append(item)
            if rows:
                con.executemany(
                    "UPDATE run_queue_jobs SET status='cancelled',outcome='archived',"
                    "finished_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=? AND status='pending'",
                    [(str(row['id']),) for row in rows],
                )
            con.commit()
        return result

    def load_settings(self) -> dict[str, Any]:
        with self._settings_lock:
            try:
                data = json.loads(self.settings_path.read_text('utf-8'))
            except (FileNotFoundError, json.JSONDecodeError):
                data = {}
            migrated, changed = _migrate_settings(data)
            merged = _deep_merge(deepcopy(DEFAULT_SETTINGS), migrated)
            merged = _normalize_settings(merged)
            merged.setdefault('agent', {})['completion_check_enabled'] = True
            if changed or merged != data:
                self.save_settings(merged)
            return merged

    def save_settings(self, data: dict[str, Any]) -> None:
        with self._settings_lock:
            migrated, _ = _migrate_settings(data)
            merged = _normalize_settings(_deep_merge(deepcopy(DEFAULT_SETTINGS), migrated))
            merged.setdefault('agent', {})['completion_check_enabled'] = True
            with tempfile.NamedTemporaryFile(
                mode='w', encoding='utf-8', prefix='.settings-', suffix='.tmp',
                dir=self.root, delete=False,
            ) as stream:
                tmp = Path(stream.name)
                json.dump(merged, stream, indent=2)
            try:
                tmp.replace(self.settings_path)
            finally:
                tmp.unlink(missing_ok=True)

    def load_tool_permission_settings(self) -> dict[str, Any]:
        """Read live grants strictly; missing/corrupt policy never restores defaults.

        Unlike the preferences editor's migration path, this read must neither
        repair the file nor synthesize an On grant for an executing tool.
        """
        with self._settings_lock:
            data = json.loads(self.settings_path.read_text('utf-8'))
            agent = data.get('agent') if isinstance(data, dict) else None
            permissions = agent.get('tool_permissions') if isinstance(agent, dict) else None
            if not isinstance(permissions, dict) or any(
                permissions.get(key) not in {'off', 'ask', 'on'}
                for key in DEFAULT_TOOL_PERMISSIONS
            ):
                raise ValueError('Saved tool permission policy is unavailable.')
            return data

    def update_settings(
        self, changes: dict[str, Any], *, replace_sections: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        """Apply only the caller-owned fields to the latest saved preferences."""
        with self._settings_lock:
            current = self.load_settings()
            if changes:
                updated = _deep_merge(current, changes)
                for key in replace_sections:
                    if key in changes:
                        updated[key] = deepcopy(changes[key])
                self.save_settings(updated)
                current = self.load_settings()
            return current

    def save_settings_changes(
        self, original: dict[str, Any], updated: dict[str, Any],
    ) -> dict[str, Any]:
        """Save edited draft fields without reverting another page's changes."""
        return self.update_settings(_settings_changes(original, updated))

    def login_session_timeout_seconds(self) -> int:
        """Live authentication preference without reparsing settings per frame."""
        info = self.settings_path.stat()
        signature = (info.st_mtime_ns, info.st_size, info.st_ino)
        cached = getattr(self, '_login_session_timeout_cache', None)
        if cached is not None and cached[0] == signature:
            return cached[1]
        data = json.loads(self.settings_path.read_text('utf-8'))
        if not isinstance(data, dict) or not isinstance(data.get('general', {}), dict):
            raise ValueError('Invalid login timeout settings.')
        minutes = _normalized_login_timeout_minutes(
            data.get('general', {}).get('login_session_timeout_minutes', 0), strict=True,
        )
        seconds = int(minutes) * 60
        self._login_session_timeout_cache = (signature, seconds)
        return seconds

    def list_model_profiles(self, settings: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        cfg = settings or self.load_settings()
        return [deepcopy(p) for p in cfg.get('models', {}).get('profiles', [])]

    def get_model_profile(self, profile_id: str | None, settings: dict[str, Any] | None = None) -> dict[str, Any]:
        cfg = settings or self.load_settings()
        profiles = cfg.get('models', {}).get('profiles', [])
        target = profile_id or cfg.get('models', {}).get('default_profile_id') or cfg.get('models', {}).get('active_profile_id')
        for profile in profiles:
            if profile.get('id') == target:
                return deepcopy(profile)
        if profiles:
            return deepcopy(profiles[0])
        return deepcopy(DEFAULT_MODEL_PROFILE)

    def list_workspaces(self) -> list[WorkspaceRegistration]:
        with self._connect() as con:
            rows = con.execute(
                'SELECT id, name, path, last_opened, pinned FROM workspaces '
                'ORDER BY position ASC, rowid ASC'
            ).fetchall()
        return [
            WorkspaceRegistration(r['id'], r['name'], Path(r['path']), r['last_opened'], bool(r['pinned']))
            for r in rows
        ]

    def get_workspace(self, workspace_id: str) -> WorkspaceRegistration | None:
        with self._connect() as con:
            row = con.execute(
                'SELECT id, name, path, last_opened, pinned FROM workspaces WHERE id=?', (workspace_id,)
            ).fetchone()
        if not row:
            return None
        return WorkspaceRegistration(
            row['id'], row['name'], Path(row['path']), row['last_opened'], bool(row['pinned']),
        )

    def register_workspace(self, path: str | Path, name: str | None = None, workspace_id: str | None = None) -> WorkspaceRegistration:
        resolved = Path(path).expanduser().resolve()
        if not resolved.exists() or not resolved.is_dir():
            raise ValueError(f'Workspace directory does not exist: {resolved}')
        workspace_id = workspace_id or str(uuid.uuid4())
        display_name = (name or resolved.name or str(resolved) or 'Workspace').strip()
        with self._connect() as con:
            existing = con.execute('SELECT id FROM workspaces WHERE path=?', (str(resolved),)).fetchone()
            if existing:
                con.execute('UPDATE workspaces SET name=? WHERE id=?', (display_name, existing['id']))
                workspace_id = existing['id']
            else:
                next_position = int(con.execute('SELECT COALESCE(MAX(position), -1) + 1 AS n FROM workspaces').fetchone()['n'])
                con.execute(
                    'INSERT INTO workspaces(id, name, path, position) VALUES(?,?,?,?)',
                    (workspace_id, display_name, str(resolved), next_position),
                )
            con.commit()
        return self.get_workspace(workspace_id) or WorkspaceRegistration(workspace_id, display_name, resolved)

    def rename_workspace(self, workspace_id: str, name: str) -> WorkspaceRegistration:
        display_name = str(name or '').strip()
        if not display_name:
            raise ValueError('Workspace name cannot be empty.')
        if len(display_name) > 160:
            raise ValueError('Workspace name is too long.')
        with self._connect() as con:
            row = con.execute(
                'SELECT id, path, last_opened, pinned FROM workspaces WHERE id=?', (workspace_id,)
            ).fetchone()
            if not row:
                raise ValueError('Workspace is no longer registered.')
            con.execute('UPDATE workspaces SET name=? WHERE id=?', (display_name, workspace_id))
            con.commit()
        return WorkspaceRegistration(
            str(row['id']), display_name, Path(row['path']), row['last_opened'], bool(row['pinned']),
        )

    def set_workspace_pinned(self, workspace_id: str, pinned: bool) -> WorkspaceRegistration:
        with self._connect() as con:
            row = con.execute('SELECT id FROM workspaces WHERE id=?', (workspace_id,)).fetchone()
            if row is None:
                raise ValueError('Workspace is no longer registered.')
            con.execute('UPDATE workspaces SET pinned=? WHERE id=?', (1 if pinned else 0, workspace_id))
            con.commit()
        registration = self.get_workspace(workspace_id)
        if registration is None:
            raise ValueError('Workspace is no longer registered.')
        return registration

    def unregister_workspace(self, workspace_id: str) -> None:
        with self._connect() as con:
            con.execute('DELETE FROM workspaces WHERE id=?', (workspace_id,))
            con.commit()

    def touch_workspace(self, workspace_id: str) -> None:
        with self._connect() as con:
            con.execute("UPDATE workspaces SET last_opened=datetime('now') WHERE id=?", (workspace_id,))
            con.commit()

    def reorder_workspaces(self, workspace_ids: list[str]) -> None:
        ordered = list(dict.fromkeys(str(wid) for wid in workspace_ids if str(wid).strip()))
        if not ordered:
            return
        with self._connect() as con:
            rows = con.execute(
                'SELECT id,pinned FROM workspaces ORDER BY position ASC,rowid ASC'
            ).fetchall()
            existing = [str(r['id']) for r in rows]
            ordered = [wid for wid in ordered if wid in existing]
            remainder = [wid for wid in existing if wid not in ordered]
            final = ordered + remainder
            for index, row in enumerate(rows):
                workspace_id = str(row['id'])
                if bool(row['pinned']) and final.index(workspace_id) != index:
                    raise ValueError('Pinned workspaces must stay in their exact sidebar position.')
            con.executemany('UPDATE workspaces SET position=? WHERE id=?', list(enumerate(final)))
            con.commit()


def _settings_changes(original: dict[str, Any], updated: dict[str, Any]) -> dict[str, Any]:
    changes: dict[str, Any] = {}
    for key, value in updated.items():
        if isinstance(value, dict) and isinstance(original.get(key), dict):
            nested = _settings_changes(original[key], value)
            if nested:
                changes[key] = nested
        elif key not in original or original[key] != value:
            changes[key] = deepcopy(value)
    return changes


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in base.items():
        if isinstance(value, dict):
            result[key] = _deep_merge(value, override.get(key, {}) if isinstance(override.get(key), dict) else {})
        else:
            result[key] = deepcopy(override.get(key, value))
    for key, value in override.items():
        if key not in result:
            result[key] = deepcopy(value)
    return result


def _normalized_login_timeout_minutes(value: Any, *, strict: bool = False) -> int:
    # Missing preferences are supplied as zero (Never) by callers. Malformed
    # explicit values retain the former 12-hour limit instead of disabling it.
    if isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= 6:
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 576_000:
        if strict:
            raise ValueError('Invalid login session timeout.')
        return 720
    return value


def _normalize_settings(data: dict[str, Any]) -> dict[str, Any]:
    # Browser launching was removed, including previously saved preferences.
    if isinstance(data.get('general'), dict):
        data['general'].pop('open_browser', None)
        data['general']['login_session_timeout_minutes'] = _normalized_login_timeout_minutes(
            data['general'].get('login_session_timeout_minutes', 0),
        )
        data['general']['prompt_navigator_options'] = normalize_prompt_navigator_options(
            data['general'].get('prompt_navigator_options'),
        )
    models = data.setdefault('models', {})
    profiles = models.get('profiles')
    if not isinstance(profiles, list) or not profiles:
        profiles = [deepcopy(DEFAULT_MODEL_PROFILE)]
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in profiles:
        if not isinstance(raw, dict):
            continue
        p = _deep_merge(deepcopy(DEFAULT_MODEL_PROFILE), raw)
        if ('thinking_preset' not in raw and raw.get('supports_thinking')
                and raw.get('thinking_mode', 'reasoning_effort') in {'reasoning_effort', 'reasoning'}
                and not model_family(raw)):
            p['thinking_preset'] = 'legacy'  # preserve old explicitly enabled compatibility controls
        pid = str(p.get('id') or uuid.uuid4()).strip()
        while pid in seen:
            pid = str(uuid.uuid4())
        p['id'] = pid
        p['name'] = str(p.get('name') or p.get('model') or 'Model profile').strip()
        p['base_url'] = str(p.get('base_url') or '').rstrip('/')
        p['model'] = str(p.get('model') or '').strip()
        try:
            p['provider_concurrency'] = max(1, min(int(p.get('provider_concurrency', 1) or 1), 32))
        except (TypeError, ValueError):
            p['provider_concurrency'] = 1
        seen.add(pid)
        normalized.append(p)
    if not normalized:
        normalized = [deepcopy(DEFAULT_MODEL_PROFILE)]
    models['profiles'] = normalized
    active = str(models.get('active_profile_id') or '')
    if active not in {p['id'] for p in normalized}:
        models['active_profile_id'] = normalized[0]['id']
    # Browsing/editing a profile must not silently change the new-chat default.
    if models.get('default_profile_id') not in {p['id'] for p in normalized}:
        models['default_profile_id'] = models['active_profile_id']
    agent = data.setdefault('agent', {})
    permissions = agent.get('tool_permissions') if isinstance(agent.get('tool_permissions'), dict) else {}
    normalized_permissions: dict[str, str] = {}
    for key, default in DEFAULT_TOOL_PERMISSIONS.items():
        value = str(permissions.get(key, default) or default).strip().lower()
        normalized_permissions[key] = value if value in {'off', 'ask', 'on'} else default
    # Keep inactive legacy REA preferences for rollback; they grant no tool access.
    if 'rea' in permissions:
        normalized_permissions['rea'] = deepcopy(permissions['rea'])
    agent['tool_permissions'] = normalized_permissions
    agent['step_limit_enabled'] = bool(agent.get('step_limit_enabled', False))
    agent['completion_check_enabled'] = bool(agent.get('completion_check_enabled', True))
    try:
        agent['global_agent_slots'] = max(1, min(int(
            agent.get('global_agent_slots', agent.get('model_concurrency', 1)) or 1
        ), 32))
    except (TypeError, ValueError):
        agent['global_agent_slots'] = 1
    agent.pop('model_concurrency', None)
    try:
        agent['max_steps'] = max(1, int(agent.get('max_steps', 200) or 200))
    except (TypeError, ValueError):
        agent['max_steps'] = 200
    # Keep the old boolean in sync so a rollback to an older HarnessyXO build is predictable.
    agent['shell_enabled'] = normalized_permissions['shell'] == 'on'
    notifications = data.setdefault('notifications', {})
    if not isinstance(notifications, dict):
        notifications = {}
        data['notifications'] = notifications
    notifications['ntfy'] = normalize_ntfy_settings(notifications.get('ntfy'))
    data['settings_version'] = 14
    return data


def _migrate_settings(data: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Migrate v0.1.x settings into the v0.2 settings structure."""
    if not isinstance(data, dict):
        return {}, True
    version = int(data.get('settings_version', 1) or 1)
    changed = False
    out = deepcopy(data)

    # Old UI layout: provider / ui / agent at top level.
    if version < 3 or 'models' not in out:
        provider = out.pop('provider', {}) if isinstance(out.get('provider'), dict) else {}
        old_ui = out.pop('ui', {}) if isinstance(out.get('ui'), dict) else {}
        if provider:
            profile = _deep_merge(deepcopy(DEFAULT_MODEL_PROFILE), {
                'id': 'local-openai',
                'name': provider.get('name') or 'Local OpenAI-compatible',
                'base_url': provider.get('base_url', DEFAULT_MODEL_PROFILE['base_url']),
                'model': provider.get('model', DEFAULT_MODEL_PROFILE['model']),
                'api_key': provider.get('api_key', ''),
                'temperature': provider.get('temperature'),
            })
            out['models'] = {'active_profile_id': profile['id'], 'profiles': [profile]}
        out.setdefault('general', {})
        out['general'].setdefault('dark', old_ui.get('dark', False))
        out['general'].setdefault('enter_to_send', True)
        out.setdefault('server', {})
        old_host = str(old_ui.get('host', '127.0.0.1'))
        try:
            old_port = int(old_ui.get('port', 6767))
        except (TypeError, ValueError):
            old_port = 6767
        if old_host == '127.0.0.1' and old_port == 7860:
            old_host, old_port = '127.0.0.1', 6767
        out['server'].setdefault('host', old_host)
        out['server'].setdefault('port', old_port)
        out.setdefault('chat', {'templates': deepcopy(DEFAULT_TEMPLATES)})
        out['settings_version'] = 3
        changed = True

    # v0.2.0-v0.2.2 silently defaulted temperature to 0.2. From v0.2.3,
    # sampling settings are opt-in overrides. Treat the old implicit 0.2 as
    # model-default during migration; preserve any non-default value because it
    # was likely chosen intentionally.
    if version < 4:
        profiles = out.get('models', {}).get('profiles', []) if isinstance(out.get('models'), dict) else []
        for profile in profiles if isinstance(profiles, list) else []:
            if not isinstance(profile, dict):
                continue
            old_temperature = profile.get('temperature')
            try:
                was_implicit_default = old_temperature is not None and abs(float(old_temperature) - 0.2) < 1e-12
            except (TypeError, ValueError):
                was_implicit_default = False
            if old_temperature is None or was_implicit_default:
                profile['temperature'] = None
            for key in ('top_p', 'top_k', 'min_p', 'presence_penalty', 'frequency_penalty', 'repeat_penalty'):
                profile.setdefault(key, None)
        out['settings_version'] = 4
        changed = True

    if version < 5:
        agent = out.setdefault('agent', {})
        existing = agent.get('tool_permissions') if isinstance(agent.get('tool_permissions'), dict) else {}
        permissions = dict(DEFAULT_TOOL_PERMISSIONS)
        permissions.update({k: str(v).lower() for k, v in existing.items() if k in permissions and str(v).lower() in {'off', 'ask', 'on'}})
        # Preserve the old shell_enabled behavior exactly during migration.
        permissions['shell'] = 'on' if bool(agent.get('shell_enabled', False)) else 'off'
        agent['tool_permissions'] = permissions
        out['settings_version'] = 5
        changed = True

    if version < 6:
        agent = out.setdefault('agent', {})
        # v5 always had a finite step cap and shipped with 20 as the implicit
        # default. Treat an untouched legacy 20 as the old default and migrate
        # it to the new unlimited behavior. Preserve any other value as an
        # explicit user-selected limit.
        try:
            legacy_max_steps = int(agent.get('max_steps', 20) or 20)
        except (TypeError, ValueError):
            legacy_max_steps = 20
        if 'step_limit_enabled' not in agent:
            agent['step_limit_enabled'] = legacy_max_steps != 20
        agent['max_steps'] = max(1, legacy_max_steps) if legacy_max_steps != 20 else 200
        out['settings_version'] = 6
        changed = True

    if version < 7:
        agent = out.setdefault('agent', {})
        agent.setdefault('model_concurrency', 1)
        out['settings_version'] = 7
        changed = True

    if version < 8:
        # 1,048,576 was HarnessyXO's factory profile default, not an explicit
        # declaration that the user wanted every unloaded Ollama model to start
        # with a 1M KV cache. Migrate that legacy default to the safer 262k
        # baseline. Anyone deliberately using >262k can raise the cap again after
        # upgrade; an already observed larger runtime is still respected up to
        # the profile cap.
        models = out.get('models') if isinstance(out.get('models'), dict) else {}
        profiles = models.get('profiles') if isinstance(models.get('profiles'), list) else []
        for profile in profiles:
            if not isinstance(profile, dict):
                continue
            try:
                legacy_context = int(profile.get('context_window') or 0)
            except (TypeError, ValueError):
                legacy_context = 0
            if legacy_context == 1_048_576:
                profile['context_window'] = 262_144
        out['settings_version'] = 8
        changed = True

    if version < 9:
        chat = out.setdefault('chat', {})
        if 'templates' not in chat:
            chat['templates'] = deepcopy(DEFAULT_TEMPLATES)
        elif isinstance(chat['templates'], list):
            chat['templates'] = append_new_templates(chat['templates'])
        # This migration runs once. Later Save/load never restores deletions.
        out['settings_version'] = 9
        changed = True

    if version < 10:
        # v0.3.23 and earlier exposed an undocumented global
        # agent.context_hot_tokens override. Preserve an intentional legacy
        # override by promoting it into each model profile's new per-model
        # Active Context setting. Otherwise keep the historical balanced
        # behavior as 'auto'. Leave the legacy field intact for rollback.
        agent = out.get('agent') if isinstance(out.get('agent'), dict) else {}
        try:
            legacy_hot = int(agent.get('context_hot_tokens') or 0)
        except (TypeError, ValueError):
            legacy_hot = 0
        models = out.get('models') if isinstance(out.get('models'), dict) else {}
        profiles = models.get('profiles') if isinstance(models.get('profiles'), list) else []
        for profile in profiles:
            if not isinstance(profile, dict):
                continue
            if 'active_context_mode' not in profile:
                profile['active_context_mode'] = 'custom' if legacy_hot > 0 else 'auto'
            if 'active_context_tokens' not in profile:
                profile['active_context_tokens'] = legacy_hot if legacy_hot > 0 else 0
        out['settings_version'] = 10
        changed = True

    if version < 11:
        notifications = out.setdefault('notifications', {})
        if not isinstance(notifications, dict):
            notifications = {}
            out['notifications'] = notifications
        notifications.setdefault('ntfy', deepcopy(DEFAULT_NTFY_SETTINGS))
        out['settings_version'] = 11
        changed = True

    if version < 12:
        notifications = out.setdefault('notifications', {})
        if not isinstance(notifications, dict):
            notifications = {}
            out['notifications'] = notifications
        ntfy = notifications.setdefault('ntfy', {})
        if not isinstance(ntfy, dict):
            ntfy = {}
            notifications['ntfy'] = ntfy
        # Receiving phone-authored prompts is intentionally opt-in for every
        # existing installation: possession of the topic becomes remote input
        # authority once this feature is enabled.
        ntfy.setdefault('receive_replies', False)
        ntfy.setdefault('reply_window_minutes', 1_440)
        out['settings_version'] = 12
        changed = True

    if version < 13:
        agent = out.setdefault('agent', {})
        agent.setdefault('global_agent_slots', agent.get('model_concurrency', 1))
        agent.pop('model_concurrency', None)
        out['settings_version'] = 13
        changed = True

    if version < 14:
        server = out.get('server') if isinstance(out.get('server'), dict) else {}
        out['server'] = server
        host = str(server.get('host') or DEFAULT_SETTINGS['server']['host']).strip()
        try:
            port = int(server.get('port', DEFAULT_SETTINGS['server']['port']) or DEFAULT_SETTINGS['server']['port'])
        except (TypeError, ValueError):
            port = int(DEFAULT_SETTINGS['server']['port'])
        # Move only the exact former factory endpoint. A customized address or
        # port is preserved, and a user who deliberately selects localhost in
        # schema 14 keeps it on every later load.
        if host == '127.0.0.1' and port == 6767:
            server['host'] = '0.0.0.0'
        server.setdefault('host', DEFAULT_SETTINGS['server']['host'])
        server.setdefault('port', DEFAULT_SETTINGS['server']['port'])
        out['settings_version'] = 14
        changed = True

    return out, changed
