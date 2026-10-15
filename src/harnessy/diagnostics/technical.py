"""Bounded technical evidence from explicitly trusted control-plane channels.

This is not a sanitizer for arbitrary model, tool, guest-console or file text.
Those channels must never be passed as trusted controller output. Runtime
stderr keeps unfamiliar diagnostic wording; paths, credentials and command /
guest-output records are removed before persistence and again before export.
"""
from __future__ import annotations

import errno as errno_module
import ipaddress
import json
import math
import re
import signal as signal_module
from typing import Any

MAX_TECHNICAL_CHARS = 16000
MAX_TECHNICAL_LINES = 80
MAX_INPUT_CHARS = 256 * 1024
TECHNICAL_SOURCES = frozenset({'exception', 'controller_stderr', 'controller_stdout',
                              'hostagent', 'qemu', 'serial'})
_TRUSTED = TECHNICAL_SOURCES - {'exception', 'serial'}
_ANSI = re.compile(r'\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))')
_SECRET = re.compile(
    r'(?i)\b[\w-]*(?:authorization|proxy-authorization|password|passwd|passphrase|'
    r'access[_-]?token|refresh[_-]?token|api[_-]?key|secret|cookie|set-cookie|'
    r'credential|client[_-]?secret|token|access[_-]?key)[\w-]*\b\s*[=:]\s*'
    r'(?:bearer\s+|basic\s+)?(?:"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[^\r\n,;]+)')
_IDENTITY = re.compile(
    r'(?i)\b(?:username|user|hostname|host_name|machine_id|instance_name|'
    r'uuid|serial(?:_number)?|mac(?:addr|address)?|label)\s*[=:]\s*'
    r'(?:"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[^\s,;]+)')
_GUEST = re.compile(
    r'(?i)(?:\b(?:stdout|stderr)\s*=|executing (?:ssh for )?script|'
    r'executing ssh|\b(?:qCmd|vhostCmd|swtpmCmd)(?:\[\d+\])?\.Args\s*:|'
    r'\b(?:command|argv|cmdline|environment|environ)\s*[=:]|'
    r'\b(?:cloud[- ]init|provision(?:ing)?)\b.*\b(?:output|script|user[-_ ]data|content)\b|'
    r'\b(?:prompt|messages|tool_calls|file_content|file_body|system_prompt)\s*[=:]|'
    r'(?:^|\s)(?:/bin/)?(?:ba)?sh\s+-(?:[a-z]*c|s)\b|'
    r'^\s*(?:\+ |#!|(?:export|echo|printf|cat|curl|wget)\s)|'
    r'-----BEGIN [A-Z ]*(?:PRIVATE KEY|CERTIFICATE)-----)')
_URL = re.compile(r'(?i)\b(?:https?|ssh|sftp|ftp|wss?|file)://[^\s<>"\']+')
_EMAIL = re.compile(r'\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b')
_QUOTED_PATH = re.compile(r'(["\'])(?:[A-Za-z]:[\\/]|/|~[/\\])[^"\'\r\n]*\1')
_QUOTED_RESOURCE = re.compile(r'(?i)(\b(?:open|stat|access|create|read|write|load|file|directory|path|image|disk|firmware)\b[^"\'\r\n]{0,48})(["\'])([^"\'\r\n]+)\2')
_RESOURCE_NAME = re.compile(r'(?<![\w<>:])[-A-Za-z0-9_+.]+\.(?:qcow2|img|raw|pem|key|sock|db|iso|json|ya?ml|txt|fd)(?![\w>])', re.I)
_PRIVATE_PATH = re.compile(r'(?:/(?:home|Users|Volumes|workspace|private/var/folders)/|~[/\\])[^\r\n"\'<>]*?(?=:\s|["\'<>]|$)')
_PATH = re.compile(r'(?<![\w:])(?:[A-Za-z]:[\\/]|/|\.\./|\./)[^\s,;()\[\]{}<>"\']+')
_UUID = re.compile(r'\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b')
_MAC = re.compile(r'(?i)\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b')
_IP = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')
_IPV6 = re.compile(r'\[[0-9A-Fa-f:.]+(?:%[A-Za-z0-9_.-]+)?\]|(?<![A-Za-z0-9])(?:[A-Fa-f0-9]{0,4}:){2,}[A-Fa-f0-9:.]+(?:%[A-Za-z0-9_.-]+)?')
_OPAQUE = re.compile(r'\b(?=[A-Za-z0-9_+/-]{40,}\b)(?=[A-Za-z0-9_+/-]*\d)[A-Za-z0-9_+/-]{40,}={0,2}')
_PEM = re.compile(r'-----BEGIN [^-\r\n]+-----.*?(?:-----END [^-\r\n]+-----|$)', re.S)
_SAFE_PATHS = {'/dev/kvm', '/dev/net/tun', '/dev/vhost-net', '/dev/vhost-vsock',
               '/dev/null', '/proc/cpuinfo', '/proc/meminfo', '/proc/self/maps'}
_PUBLIC_FILES = {'AAVMF_CODE.fd', 'AAVMF_VARS.fd', 'OVMF_CODE.fd', 'OVMF_VARS.fd',
                 'edk2-aarch64-code.fd', 'edk2-x86_64-code.fd', 'qemu-efi-code.fd',
                 'ha.stderr.log', 'ha.stdout.log', 'serial.log', 'serialp.log', 'serialv.log',
                 'qmp.sock', 'ha.sock', 'diffdisk', 'basedisk', 'cidata.iso', 'lima.yaml'}
_FAMILIES = {
    'permission': ('permission denied', 'operation not permitted', 'access denied', 'eacces', 'eperm'),
    'storage': ('no space left', 'read-only file system', 'input/output error', 'i/o error',
                'disk', 'qcow', 'pflash', 'block device'),
    'resource': ('cannot allocate memory', 'out of memory', 'cannot set up guest memory',
                 'resource temporarily unavailable', 'too many open files'),
    'virtualization': ('kvm', 'hvf', 'hypervisor', 'accelerator', 'virtualization', 'qemu'),
    'firmware': ('firmware', 'aavmf', 'ovmf', 'pflash', 'efi'),
    'device': ('device', 'property', 'unsupported cpu', 'invalid cpu', 'machine type'),
    'dependency': ('not found', 'no such file', 'shared librar', 'exec format', 'executable'),
    'network': ('connection refused', 'connection reset', 'unreachable', 'no route', 'dns', 'broken pipe'),
    'socket': ('socket', 'qmp', 'address already in use', 'bind:'),
    'timeout': ('timed out', 'timeout', 'deadline exceeded'),
    'tls': ('tls', 'certificate', 'ssl', 'x509'),
    'archive': ('archive', 'checksum', 'sha256 mismatch', 'tar:', 'zip'),
    'process': ('exit status', 'exited', 'signal:', 'terminated', 'killed'),
}
REASON_CODES = frozenset(_FAMILIES)


def _path_label(match: re.Match[str]) -> str:
    value = match.group(0).strip('"\'')
    suffix = ':' if value.endswith(':') else ''
    value = value[:-1] if suffix else value
    if value in _SAFE_PATHS:
        return value + suffix
    basename = re.split(r'[/\\]', value)[-1].rstrip(':')
    if basename in _PUBLIC_FILES:
        return '<path:' + basename + '>' + suffix
    if re.fullmatch(r'(?:qemu-system-[a-z0-9_+-]+|limactl|virtiofsd|swtpm)(?:\.exe)?', basename):
        return '<executable:' + basename + '>' + suffix
    return '<path>' + suffix


def _ipv6_label(match: re.Match[str]) -> str:
    value = match.group(0).strip('[]')
    try:
        ipaddress.IPv6Address(value.split('%', 1)[0])
    except ValueError:
        return match.group(0)
    return '<ipv6-address>'


def _resource_label(match: re.Match[str]) -> str:
    value = match.group(0)
    return value if value in _PUBLIC_FILES else '<file>'


def _message(line: str) -> str:
    """Accept Lima JSON/logfmt messages, never arbitrary JSON extra fields."""
    if line.lstrip().startswith('{'):
        try:
            record = json.loads(line)
        except (ValueError, RecursionError):
            return '[unparseable control-plane record omitted]'
        if not isinstance(record, dict):
            return '[non-message control-plane record omitted]'
        parts = []
        value = record.get('level')
        if isinstance(value, str) and value in {'trace', 'debug', 'info', 'warning', 'error', 'fatal', 'panic'}:
            parts.append('level=' + value)
        value = record.get('time')
        if isinstance(value, str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})', value):
            parts.append('time=' + value)
        for key in ('msg', 'error'):
            value = record.get(key)
            if isinstance(value, str):
                parts.append(value)
        # Hostagent stdout is a fixed lifecycle event, not a guest output feed.
        status = record.get('status')
        if isinstance(status, dict):
            for key in ('running', 'degraded', 'exiting'):
                if isinstance(status.get(key), bool):
                    parts.append(key + '=' + str(status[key]).lower())
            for error in status.get('errors', [])[:8] if isinstance(status.get('errors'), list) else []:
                if isinstance(error, str):
                    parts.append(error)
        return ' | '.join(parts) if parts else '[non-message control-plane record omitted]'
    fields = re.findall(r'(?:^|\s)(msg|error)=("(?:\\.|[^"\\])*"|[^\s]+)', line)
    if fields:
        parts = []
        for key, value in fields:
            try:
                text = json.loads(value) if value.startswith('"') else value
            except ValueError:
                text = '[unparseable control-plane field omitted]'
            parts.append((key + ': ' if key == 'error' else '') + text)
        return ' | '.join(parts)
    return line


def _sanitize(value: Any, max_lines: int, max_chars: int) -> tuple[str, bool, bool]:
    if not isinstance(value, (str, bytes)):
        return '', False, False
    text = value.decode('utf-8', errors='replace') if isinstance(value, bytes) else value
    truncated = len(text) > MAX_INPUT_CHARS
    # Remove complete credential blocks before tail bounding, so taking a tail
    # cannot detach a retained private-key body from its BEGIN marker.
    scrubbed = _PEM.sub('[credential block omitted]', text)
    credential_block_omitted = scrubbed != text
    text = scrubbed[-MAX_INPUT_CHARS:]
    text = _ANSI.sub('', text)
    # Newline/tab are the only permitted controls. Escaped newlines are handled
    # after JSON extraction, so a quoted guest payload cannot become new records.
    text = ''.join(char for char in text if char in '\n\t' or (ord(char) >= 32 and ord(char) != 127))
    lines = text.splitlines()
    cap_lines = max(1, min(MAX_TECHNICAL_LINES, max_lines))
    cap_chars = max(1, min(MAX_TECHNICAL_CHARS, max_chars))
    truncated |= len(lines) > cap_lines
    kept = []
    omitted = credential_block_omitted
    secret_continuation = False
    secret_indented = False
    for line in lines[-cap_lines:]:
        if (secret_continuation or (secret_indented and line[:1].isspace())) and line.strip():
            kept.append('[credential continuation omitted]')
            omitted = True
            secret_continuation = False
            continue
        secret_indented = False
        secret_continuation = bool(re.search(r'(?i)\b(?:password|passwd|secret|token|api[_-]?key|authorization|cookie)\s*[=:]\s*$', line))
        if secret_continuation:
            kept.append('[credential redacted]')
            omitted = True
            continue
        line = _message(line)
        line = _ANSI.sub('', line)
        line = ''.join(char for char in line if char in '\n\t' or (ord(char) >= 32 and ord(char) != 127))
        if _GUEST.search(line):
            kept.append('[command or guest payload omitted]')
            omitted = True
            continue
        # A message field may itself contain a multiline diagnostic. Apply the
        # same gate to every continuation before retaining it.
        if any(_GUEST.search(part) for part in line.splitlines()):
            kept.append('[command or guest payload omitted]')
            omitted = True
            continue
        original = line
        if re.fullmatch(r'[A-Za-z0-9+/=]{48,}', line.strip()):
            kept.append('[encoded payload omitted]')
            omitted = True
            continue
        line = _SECRET.sub('[credential redacted]', line)
        secret_indented = line != original
        line = _URL.sub('<url>', line)
        line = _EMAIL.sub('<email>', line)
        line = _QUOTED_PATH.sub(_path_label, line)
        line = _QUOTED_RESOURCE.sub(lambda match: match.group(1) + '<file>', line)
        line = _PRIVATE_PATH.sub(_path_label, line)
        line = _PATH.sub(_path_label, line)
        line = _RESOURCE_NAME.sub(_resource_label, line)
        line = _IDENTITY.sub('[identity redacted]', line)
        line = _UUID.sub('<identifier>', line)
        line = _MAC.sub('<address>', line)
        line = _IP.sub(lambda match: match.group(0) if match.group(0) in {'127.0.0.1', '0.0.0.0'} else '<address>', line)
        line = _IPV6.sub(_ipv6_label, line)
        line = _OPAQUE.sub('<identifier>', line)
        # Bare credential tokens do not necessarily have a key/value prefix.
        line = re.sub(r'(?i)\b(?:bearer|basic)\s+[A-Za-z0-9+/_.=-]+', '[credential redacted]', line)
        line = re.sub(r'\b(?:gh[pousr]_|github_pat_|sk-)[A-Za-z0-9_-]{8,}', '[credential redacted]', line)
        omitted |= line != original
        line = line.replace('\r', '').replace('\n', ' | ')
        if len(line) > 2048:
            truncated = True
            line = line[:768] + ' [technical line truncated] ' + line[-1250:]
        kept.append(line)
    result = '\n'.join(kept)
    truncated |= len(result) > cap_chars
    if len(result) > cap_chars:
        marker = '\n[technical excerpt truncated]\n'
        side = max(0, (cap_chars - len(marker)) // 2)
        front = result[:side]
        tail = result[-side:] if side else ''
        if '\n' in front:
            front = front.rpartition('\n')[0]
        if '\n' in tail:
            tail = tail.partition('\n')[2]
        result = (front + marker + tail)[:cap_chars]
    return result, omitted, truncated


def sanitize_control_plane_text(value: Any, *, max_lines: int = MAX_TECHNICAL_LINES,
                                max_chars: int = MAX_TECHNICAL_CHARS) -> str:
    return _sanitize(value, max_lines, max_chars)[0]


def technical_error_evidence(value: Any, *, source: str = 'exception') -> dict[str, Any]:
    """Retain structured facts; prose requires an explicit trusted source."""
    source = source if isinstance(source, str) and source in TECHNICAL_SOURCES else 'exception'
    result: dict[str, Any] = {'schema_version': 1, 'source': source,
                              'omitted_content': source not in _TRUSTED, 'truncated': False}
    actual_error = isinstance(value, BaseException)
    if actual_error:
        from .faults import exception_evidence
        facts = exception_evidence(value)
        result['exception_type'] = facts.get('exception_type', 'Exception')
        for key in ('errno', 'errno_name', 'timeout_seconds'):
            if key in facts:
                result[key] = facts[key]
        for key, target in (('returncode', 'exit_code'), ('termination_signal', 'signal'), ('http_status_code', 'status_code')):
            if key in facts:
                result[target] = facts[key]
    # Arbitrary exception __str__ / properties can evaluate user-controlled data.
    # Typed exception facts have their own capture path and need no formatting.
    text = '' if actual_error else value
    if isinstance(text, bytes):
        text = text.decode('utf-8', errors='replace')
    if not isinstance(text, str):
        text = ''
    # Classification is safe for arbitrary errors: only fixed enums escape.
    lower = text[:MAX_INPUT_CHARS].lower()
    result['reason_codes'] = [code for code, tokens in _FAMILIES.items() if any(token in lower for token in tokens)]
    if source in _TRUSTED:
        diagnostic, omitted, truncated = _sanitize(text, MAX_TECHNICAL_LINES, MAX_TECHNICAL_CHARS)
        if diagnostic:
            result['diagnostic_text'] = diagnostic
        result['omitted_content'] = omitted
        result['truncated'] = truncated
        status = re.search(r'\b(?:exit status|exit code|returncode)[ =:]*(-?\d{1,3})\b', diagnostic)
        if status and -255 <= int(status.group(1)) <= 255:
            result['exit_code'] = int(status.group(1))
        sig = re.search(r'\bSIG(?:ABRT|BUS|FPE|HUP|ILL|INT|KILL|PIPE|QUIT|SEGV|TERM|TRAP|XCPU|XFSZ)\b', diagnostic)
        if sig:
            result['signal'] = sig.group(0)
        for name in re.findall(r'\bE[A-Z0-9]{2,20}\b', diagnostic):
            if name in errno_module.errorcode.values():
                result.setdefault('errno_name', name)
                break
    return validate_technical_evidence(result, trusted_source=source)


def validate_technical_evidence(value: Any, *, trusted_source: str | None = None) -> dict[str, Any]:
    """Revalidate persisted evidence instead of trusting a saved JSON object."""
    value = value if isinstance(value, dict) else {}
    source = value.get('source')
    source = source if isinstance(source, str) and source in TECHNICAL_SOURCES else 'exception'
    result: dict[str, Any] = {'schema_version': 1, 'source': source,
                             'omitted_content': value.get('omitted_content') is True,
                             'truncated': value.get('truncated') is True}
    from .operational import operational_label
    name = operational_label(value.get('exception_type'), 'exception_type')
    if name is not None:
        result['exception_type'] = name
    for key, low, high in (('errno', 0, 4095), ('exit_code', -255, 255), ('status_code', 100, 599)):
        number = value.get(key)
        if isinstance(number, int) and not isinstance(number, bool) and low <= number <= high:
            result[key] = number
    timeout = value.get('timeout_seconds')
    if isinstance(timeout, (int, float)) and not isinstance(timeout, bool) and 0 <= timeout <= 86400 and math.isfinite(timeout):
        result['timeout_seconds'] = timeout
    name = value.get('errno_name')
    if isinstance(name, str) and name in errno_module.errorcode.values():
        result['errno_name'] = name
    name = value.get('signal')
    if isinstance(name, str) and name.startswith('SIG') and name in signal_module.Signals.__members__:
        result['signal'] = name
    codes = value.get('reason_codes')
    result['reason_codes'] = sorted({code for code in codes if isinstance(code, str) and code in REASON_CODES}) if isinstance(codes, list) else []
    if source in _TRUSTED and source == trusted_source and isinstance(value.get('diagnostic_text'), str):
        text, omitted, truncated = _sanitize(value['diagnostic_text'], MAX_TECHNICAL_LINES, MAX_TECHNICAL_CHARS)
        if text:
            result['diagnostic_text'] = text
        result['omitted_content'] |= omitted
        result['truncated'] |= truncated
    else:
        result['omitted_content'] = True
    return result
