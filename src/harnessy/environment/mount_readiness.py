"""Content-free observations of the guest's three fixed workspace exports."""
from __future__ import annotations

import json


MOUNT_POINTS = {
    'files': '/mnt/harnessyxo-files',
    'worktrees': '/mnt/harnessyxo-worktrees',
    'references': '/mnt/harnessyxo-reference-source',
}
FILESYSTEMS = frozenset({'9p', 'virtiofs', 'fuse.sshfs', 'other', 'unknown'})
PROBE_ERRORS = frozenset({'', 'timeout', 'transport_unavailable', 'invalid_output',
                          'mount_missing', 'source_mismatch', 'permission_denied', 'probe_failed'})


class WorkspaceMountReadinessError(RuntimeError):
    error_code = 'WORKSPACE_BACKING_MOUNTS_UNAVAILABLE'

    def __init__(self, snapshot: dict, *, transport: str = '') -> None:
        self.snapshot = snapshot
        self.missing_roles = tuple(snapshot.get('missing_roles') or ())
        names = {'files': 'Files', 'worktrees': 'project worktrees', 'references': 'References'}
        missing = ', '.join(names[role] for role in self.missing_roles if role in names)
        message = ('Workspace file mounts are unavailable'
                   + (f': {missing}.' if missing else '.'))
        if transport == '9p' and snapshot.get('kernel_9p_supported') is False:
            message += ' This guest kernel does not support 9p file sharing.'
        message += ' The VM disk and project files were preserved. Start the VM again to reconcile its file sharing.'
        super().__init__(message)


def unavailable_mount_snapshot(error: str, *, require_references: bool = True) -> dict:
    return {
        'schema_version': 1, 'state': 'error',
        'probe_error': error if error in PROBE_ERRORS else 'probe_failed',
        'mounts': [{'role': role, 'directory_exists': None, 'is_mount': None,
                    'read_only': None, 'filesystem': 'unknown', 'source_verified': None}
                   for role in MOUNT_POINTS],
        'kernel_9p_supported': None, 'references_required': bool(require_references),
        'missing_roles': ['files', 'worktrees', *(['references'] if require_references else [])],
    }


def parse_mount_probe(stdout: str, *, require_references: bool = True,
                      expected_transport: str | None = None) -> dict:
    """Strictly project the tiny guest response; never retain paths or text."""
    if not isinstance(stdout, str) or len(stdout) > 16384:
        raise ValueError('invalid_output')
    value = json.loads(stdout)
    if (not isinstance(value, dict) or type(value.get('schema_version')) is not int
            or value.get('schema_version') != 1):
        raise ValueError('invalid_output')
    rows = value.get('mounts')
    if not isinstance(rows, list) or len(rows) != 3:
        raise ValueError('invalid_output')
    projected = {}
    for row in rows:
        if (not isinstance(row, dict) or not isinstance(row.get('role'), str)
                or row.get('role') not in MOUNT_POINTS or row['role'] in projected):
            raise ValueError('invalid_output')
        clean = {'role': row['role'], 'source_verified': None}
        for name in ('directory_exists', 'is_mount', 'read_only'):
            item = row.get(name)
            if item is not None and type(item) is not bool:
                raise ValueError('invalid_output')
            clean[name] = item
        filesystem = row.get('filesystem')
        if not isinstance(filesystem, str):
            raise ValueError('invalid_output')
        clean['filesystem'] = filesystem if filesystem in FILESYSTEMS else 'unknown'
        projected[row['role']] = clean
    kernel = value.get('kernel_9p_supported')
    if kernel is not None and type(kernel) is not bool:
        raise ValueError('invalid_output')
    error = value.get('probe_error', '')
    if not isinstance(error, str) or error not in PROBE_ERRORS:
        raise ValueError('invalid_output')
    required = ('files', 'worktrees', 'references') if require_references else ('files', 'worktrees')
    missing = [role for role in required if projected[role]['directory_exists'] is not True
               or projected[role]['is_mount'] is not True]
    expected_filesystem = {'9p': '9p', 'virtiofs': 'virtiofs', 'reverse-sshfs': 'fuse.sshfs'}
    mismatched = []
    if expected_transport is not None:
        if not isinstance(expected_transport, str) or expected_transport not in expected_filesystem:
            raise ValueError('invalid_output')
        mismatched = [role for role in required if role not in missing
                      and projected[role]['filesystem'] != expected_filesystem[expected_transport]]
        missing = [role for role in required if role in missing or role in mismatched]
    return {'schema_version': 1, 'state': 'error' if error else 'unavailable' if missing else 'ready',
            'probe_error': error or ('source_mismatch' if mismatched else 'mount_missing' if missing else ''),
            'mounts': [projected[role] for role in MOUNT_POINTS],
            'kernel_9p_supported': kernel, 'missing_roles': missing,
            'references_required': bool(require_references)}


def build_guest_mount_probe_script(*, fixture_paths: dict | None = None) -> str:
    """Generate one bounded Python probe. Fixture paths are used only by private QA."""
    config = {'mount_points': MOUNT_POINTS, 'mountinfo': '/proc/self/mountinfo',
              'filesystems': '/proc/filesystems', 'config_gz': '/proc/config.gz',
              'boot_config': None, 'modules_root': '/lib/modules'}
    if fixture_paths is not None:
        unknown = set(fixture_paths) - set(config)
        if unknown:
            raise ValueError('Unknown mount probe fixture')
        config.update(fixture_paths)
    return 'CONFIG = ' + repr(config) + '\n' + r'''
import gzip, json, os, re

def read_bounded(path, cap, compressed=False):
    with (gzip.open(path, 'rb') if compressed else open(path, 'rb')) as stream:
        value = stream.read(cap + 1)
    if len(value) > cap:
        raise ValueError('limit')
    return value.decode('utf-8', errors='replace')

def unescape(value):
    return re.sub(r'\\(040|011|012|134)', lambda match: chr(int(match[1], 8)), value)

mounts = {}
error = ''
try:
    content = read_bounded(CONFIG['mountinfo'], 1024 * 1024)
    for line in content.splitlines():
        fields = line.split()
        separator = fields.index('-')
        if separator < 6 or len(fields) < separator + 4:
            raise ValueError('mountinfo')
        target = unescape(fields[4])
        if target in CONFIG['mount_points'].values():
            fstype = fields[separator + 1]
            mounts[target] = {'is_mount': True,
                'read_only': 'ro' in fields[5].split(',') or 'ro' in fields[separator + 3].split(','),
                'filesystem': fstype if fstype in ('9p', 'virtiofs', 'fuse.sshfs') else 'other'}
except PermissionError:
    error = 'permission_denied'
except (OSError, ValueError, UnicodeError):
    error = 'probe_failed'

rows = []
for role, target in CONFIG['mount_points'].items():
    try:
        exists = os.path.isdir(target)
    except OSError:
        exists = None
    found = mounts.get(target) if not error else None
    rows.append({'role': role, 'directory_exists': exists,
        'is_mount': found['is_mount'] if found else (None if error else False),
        'read_only': found['read_only'] if found else None,
        'filesystem': found['filesystem'] if found else 'unknown'})

kernel = None
try:
    if any(line.split()[-1:] == ['9p'] for line in read_bounded(CONFIG['filesystems'], 65536).splitlines()):
        kernel = True
except (OSError, ValueError):
    pass
release = os.uname().release
if kernel is None:
    for path, compressed in ((CONFIG['config_gz'], True),
            (CONFIG['boot_config'] or '/boot/config-' + release, False)):
        try:
            text = read_bounded(path, 1024 * 1024, compressed)
            values = {}
            for name in ('CONFIG_NET_9P', 'CONFIG_NET_9P_VIRTIO', 'CONFIG_9P_FS'):
                if re.search(r'^# ' + name + r' is not set$', text, re.M):
                    values[name] = False
                elif re.search(r'^' + name + r'=[ym]$', text, re.M):
                    values[name] = True
            if False in values.values():
                kernel = False
                break
            if len(values) == 3 and all(values.values()):
                kernel = True
                break
        except (OSError, ValueError, EOFError):
            pass
if kernel is None:
    metadata = ''
    for name in ('modules.dep', 'modules.builtin'):
        try:
            metadata += read_bounded(os.path.join(CONFIG['modules_root'], release, name), 1024 * 1024)
        except (OSError, ValueError):
            pass
    if '/9p.ko' in metadata and '/9pnet_virtio.ko' in metadata:
        kernel = True
print(json.dumps({'schema_version': 1, 'mounts': rows,
    'kernel_9p_supported': kernel, 'probe_error': error}, separators=(',', ':')))
'''
