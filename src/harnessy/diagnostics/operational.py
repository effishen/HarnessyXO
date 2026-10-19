"""Reviewed operational labels and an explicit bounded source-export ledger."""
from __future__ import annotations

import ast
import builtins
from collections import Counter
from functools import lru_cache
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
import stat
from typing import Any

LABEL_FIELDS = frozenset({'terminal_stop_reason', 'terminal_reason', 'backend_done_reason',
    'completion_state', 'last_error_code', 'source', 'state', 'component', 'missing_dependency', 'terminal_mode'})
_LABEL = re.compile(r'[A-Za-z0-9_.:/-]{0,128}\Z')
_EXTRA_LABELS = {
    'terminal_mode': {'guest_console', 'project_files'},
    'terminal_stop_reason': {'workspace_infrastructure_failure', 'backend_stream_stalled',
        'completion_unconfirmed', 'backend_failure', 'missing_final_answer', 'user_cancelled', 'error', 'stopped'},
    'terminal_reason': {'workspace_infrastructure_failure', 'backend_stream_stalled',
        'completion_unconfirmed', 'backend_failure', 'missing_final_answer', 'user_cancelled', 'error', 'stopped'},
    'backend_done_reason': {'stop', 'tool_calls', 'function_call', 'length', 'max_tokens',
        'max_output_tokens', 'token_limit', 'max_completion_tokens', 'output_limit',
        'stream_stalled', 'unspecified', 'eos', 'end_turn'},
    'source': {'ui', 'tool', 'run_queue', 'headless', 'ntfy', 'schedule', 'recovery',
        'saved_settings', 'global', 'target', 'api', 'manual', 'startup'},
    'state': {'waiting', 'requested', 'recovering', 'recovered', 'retrying', 'retry', 'failed',
        'blocked', 'paused', 'completed', 'running', 'stopped', 'unknown', 'unavailable', 'idle'},
}


@lru_cache(maxsize=1)
def _installed_labels() -> tuple[dict[str, set[str]], set[str]]:
    """Only short literal application labels/classes; never evaluate source."""
    labels = {key: set(_EXTRA_LABELS.get(key, ())) | {''} for key in LABEL_FIELDS}
    classes = {key for module in (builtins, sqlite3) for key, value in vars(module).items()
               if isinstance(value, type) and issubclass(value, BaseException)}
    classes.update({'ConnectError', 'ReadError', 'WriteError', 'ConnectTimeout', 'ReadTimeout',
        'WriteTimeout', 'PoolTimeout', 'HTTPStatusError', 'RemoteProtocolError', 'LocalProtocolError',
        'TimeoutExpired', 'CalledProcessError', 'SSLError', 'SSLCertVerificationError',
        'JSONDecodeError', 'CancelledError', 'gaierror', 'herror'})
    root = Path(__file__).resolve().parents[1]
    for path in sorted(root.rglob('*.py'))[:512]:
        try:
            if path.is_symlink() or path.stat().st_size > 2 * 1024 * 1024:
                continue
            tree = ast.parse(path.read_text(encoding='utf-8'))
        except (OSError, UnicodeError, SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                classes.add(node.name)
            pairs = ([(node.arg, node.value)] if isinstance(node, ast.keyword) else
                     zip(node.keys, node.values) if isinstance(node, ast.Dict) else ())
            for key, value in pairs:
                key = key.value if isinstance(key, ast.Constant) else key
                if (key in labels and isinstance(value, ast.Constant)
                        and isinstance(value.value, str) and _LABEL.fullmatch(value.value)):
                    labels[key].add(value.value)
    return labels, classes


def operational_label(value: Any, key: str) -> str | None:
    labels, classes = _installed_labels()
    permitted = classes if key in {'error_type', 'exception_class', 'exception_type'} else labels.get(key, set())
    if isinstance(value, str) and value in permitted:
        return value
    if isinstance(value, str) and len(value) < 240:
        match = re.fullmatch(r'<redacted ' + re.escape(key) + r'; chars=(\d{1,4}); sha256_12=([0-9a-f]{12})>', value)
        if match:
            return next((item for item in permitted if len(item) == int(match[1])
                and hashlib.sha256(item.encode()).hexdigest()[:12] == match[2]), None)
    return None


APP_FILE_TAIL_BYTES = 16 * 1024 * 1024
APP_TOTAL_READ_BYTES = 128 * 1024 * 1024
APP_MAX_FILES = 512


class ExportCoverage:
    """Every attempted log source has an outcome, including failed opens."""
    def __init__(self):
        self.sources: list[dict[str, Any]] = []
        self.read_bytes = 0
        self.sources_omitted_after_file_limit = 0

    def read(self, source: Path, member: str, reader, tail_bytes: int | None):
        row: dict[str, Any] = {'archive_member': member, 'status': 'pending',
            'source_id': hashlib.sha256(str(source.absolute()).encode()).hexdigest(),
            'original_bytes': None, 'read_bytes': 0, 'exported_bytes': 0,
            'source_lines_read': 0, 'exported_lines': 0,
            'tail_truncated': False, 'content_projection': 'unrecorded',
            'original_size_observed_before_open': True}
        if len(self.sources) >= APP_MAX_FILES:
            self.sources_omitted_after_file_limit += 1
            return None, None
        self.sources.append(row)
        try:
            info = source.lstat()
            if not stat.S_ISREG(info.st_mode) or source.is_symlink():
                row['status'] = 'unsafe'
                return None, row
            row['original_bytes'] = info.st_size
        except FileNotFoundError:
            row['status'] = 'missing'
            return None, row
        except OSError:
            row['status'] = 'unreadable'
            return None, row
        cap = min(APP_FILE_TAIL_BYTES, APP_TOTAL_READ_BYTES - self.read_bytes)
        if tail_bytes is not None:
            cap = min(cap, max(0, tail_bytes))
        if cap <= 0:
            row['status'] = 'limited'
            row['tail_truncated'] = bool(info.st_size)
            return None, row
        payload = reader(source, tail_bytes=cap)
        if payload is None:
            row['status'] = 'unsafe_or_unreadable'
            return None, row
        self.read_bytes += len(payload)
        row.update(status='read', read_bytes=len(payload),
                   source_lines_read=len(payload.splitlines()), tail_truncated=info.st_size > len(payload))
        return payload, row

    @staticmethod
    def written(row, payload: bytes, projection: str):
        if row is None:
            return
        row.update(status='included', exported_bytes=len(payload),
                   exported_lines=len(payload.splitlines()), content_projection=projection)
        row['content_redaction_markers'] = payload.count(b'<redacted') + payload.count(b'"redacted":true')
        row['source_lines_not_exported'] = max(0, row['source_lines_read'] - row['exported_lines'])

    def report(self):
        return {'schema_version': 1, 'scope': 'application_log_sources_attempted_by_exporter',
            'limits': {'file_tail_bytes': APP_FILE_TAIL_BYTES, 'read_bytes_total': APP_TOTAL_READ_BYTES,
                       'files': APP_MAX_FILES},
            'sources': self.sources, 'summary': dict(Counter(row['status'] for row in self.sources)),
            'read_bytes_total': self.read_bytes,
            'exported_bytes_total': sum(row['exported_bytes'] for row in self.sources),
            'file_limit_reached': len(self.sources) >= APP_MAX_FILES,
            'sources_omitted_after_file_limit': self.sources_omitted_after_file_limit,
            'counts_are_bounded_source_observations': True,
            'separate_collectors': ['VM_LOGS.json', 'TARGET_LOGS.json', 'HOST_STATE.json', 'CONTEXT_TUNING_RETENTION.json'],
            'discovery_bounds': {'latest_entries': 2048, 'session_directory_entries': 256,
                                 'session_directories': 20, 'entries_per_session': 2048, 'crashes': 20},
            'retention': {'session_directories_kept': 20, 'session_storage_cap_bytes': 750 * 1024 * 1024,
                          'context_history_has_separate_bounds': True},
        }
