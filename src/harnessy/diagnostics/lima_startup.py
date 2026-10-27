"""Bounded, read-only observations of one selected Lima startup.

Only process IDs anchored to the verified instance (or their verified children)
are inspected. Command lines are used for ownership checks, never retained.
Export reads saved receipts; it does not contact a VM or inspect live processes.
"""
from __future__ import annotations

import asyncio
from collections import OrderedDict
from concurrent.futures import Future
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys
import threading
import time
import uuid

_PROC_ROOT = Path('/proc')
_IO_SECONDS = 1.5
_QMP_SECONDS = .6
_MAX_RECEIPTS = 8
_MAX_ENVIRONMENTS = 32
_MAX_CHILDREN = 24
_MAX_TASKS = 128
_MAX_BYTES = 128 * 1024
_FILENAME = 'lima-startup.jsonl'
_ID = re.compile(r'[0-9a-f]{32}')
_STATES = frozenset({'available', 'missing', 'unsafe', 'unavailable', 'unsupported',
    'identity_mismatch', 'timeout', 'capacity', 'not_verified', 'failed', 'limited', 'cancelled'})
_REASONS = frozenset({'quiet_startup', 'controller_error', 'controller_timeout',
    'controller_cancelled', 'controller_spawn_error', 'before_stop'})
_ROLES = frozenset({'controller', 'hostagent', 'qemu_vm', 'qemu_capability_probe',
    'qemu_version_probe', 'other_owned_child'})
_QEMU = frozenset({'qemu-system-aarch64', 'qemu-system-x86_64'})
_WAITS = frozenset({'do_wait', 'wait_woken', 'futex_wait_queue', 'futex_wait',
    'pipe_read', 'do_select', 'ep_poll', 'hrtimer_nanosleep', 'poll_schedule_timeout',
    'unix_stream_read_generic', 'io_schedule', 'do_sys_poll', '0'})
_PROCESS_NUMBERS = ('pid', 'ppid', 'start_ticks', 'cpu_user_ticks', 'cpu_system_ticks',
                    'rss_bytes', 'threads', 'minor_faults', 'major_faults')
_MEMORY: OrderedDict = OrderedDict()
_MEMORY_LOCK = threading.Lock()
_IO_LOCK = threading.Lock()
_IO_JOBS: set[Future] = set()
_PERSIST_LOCK = threading.Lock()


def _number(value, maximum=2**63 - 1):
    if (type(value) not in (int, float) or not 0 <= value <= maximum
            or (type(value) is float and not math.isfinite(value))):
        return None
    return value


def _state(value):
    return value if isinstance(value, str) and value in _STATES else 'unsafe'


def _fixed(value, choices):
    return isinstance(value, str) and value in choices


def _process_safe(value):
    value = value if isinstance(value, dict) else {}
    verified = (value.get('identity_verified') is True and value.get('state') == 'available'
        and _fixed(value.get('role'), _ROLES) and type(_number(value.get('pid'), 2**31 - 1)) is int
        and value['pid'] > 1 and type(_number(value.get('start_ticks'))) is int)
    out = {'state': _state(value.get('state')), 'identity_verified': verified}
    if not out['identity_verified']:
        return out
    if _fixed(value.get('role'), _ROLES):
        out['role'] = value['role']
    for key in _PROCESS_NUMBERS:
        number = _number(value.get(key))
        if type(number) is int:
            out[key] = number
    if _fixed(value.get('process_state'), set('RSDTtZXIWPN')):
        out['process_state'] = value['process_state']
    if _fixed(value.get('wait_channel'), _WAITS | {'other'}):
        out['wait_channel'] = value['wait_channel']
    if _fixed(value.get('probe'), {'accelerators', 'network_backends', 'machines', 'cpus', 'version'}):
        out['probe'] = value['probe']
    if _fixed(value.get('executable'), _QEMU | {'limactl'}):
        out['executable'] = value['executable']
    overrides = value.get('qemu_overrides')
    if isinstance(overrides, dict) and value.get('role') == 'controller':
        out['qemu_overrides'] = {key: overrides[key] for key in ('QEMU_SYSTEM_AARCH64', 'QEMU_SYSTEM_X86_64')
                                 if type(overrides.get(key)) is bool}
    return out


def validate_lima_startup_receipt(value):
    """Project only reviewed labels and numeric facts, including on disk reads."""
    if (not isinstance(value, dict) or value.get('schema_version') != 1
            or value.get('event') != 'lima_startup_capture'
            or not _ID.fullmatch(str(value.get('capture_id', '')))
            or not _ID.fullmatch(str(value.get('environment_id', '')))
            or not _fixed(value.get('reason'), _REASONS)):
        return None
    out = {key: value[key] for key in ('schema_version', 'event', 'capture_id', 'environment_id', 'reason')}
    stamp = value.get('captured_at')
    if isinstance(stamp, str) and len(stamp) <= 40:
        try:
            if datetime.fromisoformat(stamp.replace('Z', '+00:00')).tzinfo is not None:
                out['captured_at'] = stamp
        except ValueError:
            pass
    for key in ('command_id', 'operation_id'):
        if _ID.fullmatch(str(value.get(key, ''))):
            out[key] = value[key]
    if _fixed(value.get('controller_action'), {'start', 'create', 'stop', 'delete'}):
        out['controller_action'] = value['controller_action']
    for key in ('command_started_at_epoch', 'elapsed_seconds', 'last_output_age_seconds', 'collection_seconds'):
        number = _number(value.get(key))
        if number is not None:
            out[key] = number
    raw = value.get('home') if isinstance(value.get('home'), dict) else {}
    home = {'state': _state(raw.get('state')), 'identity_verified': (
        raw.get('identity_verified') is True and raw.get('state') == 'available'
        and type(_number(raw.get('device'))) is int and type(_number(raw.get('inode'))) is int)}
    if home['identity_verified']:
        for key in ('device', 'inode', 'instance_device', 'instance_inode'):
            if type(_number(raw.get(key))) is int:
                home[key] = raw[key]
        home['relocated'] = raw.get('relocated') is True
        if _fixed(raw.get('instance_state'), {'available', 'missing'}):
            home['instance_state'] = raw['instance_state']
    out['home'] = home
    for key in ('controller', 'hostagent', 'qemu'):
        out[key] = _process_safe(value.get(key))
    children = value.get('children') if isinstance(value.get('children'), list) else []
    out['children'] = [_process_safe(row) for row in children[:_MAX_CHILDREN]]
    out['children_limited'] = value.get('children_limited') is True
    raw = value.get('sockets') if isinstance(value.get('sockets'), dict) else {}
    out['sockets'] = {key: {'state': _state((raw.get(key) or {}).get('state'))}
                      for key in ('hostagent', 'qmp') if isinstance(raw.get(key), dict)}
    out['serial'] = []
    for row in value.get('serial', [])[:3] if isinstance(value.get('serial'), list) else []:
        if not isinstance(row, dict) or not _fixed(row.get('filename'), {'serial.log', 'serialp.log', 'serialv.log'}):
            continue
        item = {'filename': row['filename'], 'state': _state(row.get('state'))}
        for key in ('bytes', 'mtime_unix'):
            number = _number(row.get(key))
            if number is not None:
                item[key] = number
        codes = row.get('signals') if isinstance(row.get('signals'), list) else []
        item['signals'] = [code for code in codes[:32]
            if _fixed(code, {'kernel_boot', 'userspace_started', 'ssh_daemon_started',
                        'kernel_panic', 'guest_out_of_memory', 'guestagent_ready'})]
        out['serial'].append(item)
    raw = value.get('qmp') if isinstance(value.get('qmp'), dict) else {}
    out['qmp'] = {'state': _state(raw.get('state'))}
    if type(raw.get('running')) is bool:
        out['qmp']['running'] = raw['running']
    if _fixed(raw.get('vm_state'), {'running', 'paused', 'prelaunch', 'shutdown', 'suspended',
                              'inmigrate', 'postmigrate', 'finish-migrate', 'internal-error',
                              'io-error', 'watchdog', 'guest-panicked', 'save-vm', 'restore-vm'}):
        out['qmp']['vm_state'] = raw['vm_state']
    out['collector_state'] = _state(value.get('collector_state', 'available'))
    return out


def _read(path, cap=8192, *, private=False):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_size > cap
                or (private and (info.st_uid != os.geteuid() or info.st_nlink != 1
                                 or stat.S_IMODE(info.st_mode) & 0o077))):
            raise ValueError('unsafe')
        data = os.read(descriptor, cap + 1)
        if len(data) > cap:
            raise ValueError('limited')
        return data
    finally:
        os.close(descriptor)


def _directory(path):
    info = Path(path).lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o022 or Path(path).resolve() != Path(path)):
        raise ValueError('unsafe')
    return info.st_dev, info.st_ino


def _home(runtime_root, selected_home, instance_name, *, allow_missing_instance=False):
    from harnessy.environment.lima_runtime import bound_lima_home
    if instance_name != 'harnessy':
        raise ValueError('unsafe')
    root, selected = Path(runtime_root).absolute(), Path(selected_home).absolute()
    expected = bound_lima_home(root)
    if selected != expected:
        raise ValueError('identity_mismatch')
    identity = _directory(selected)
    instance = selected / instance_name
    try:
        instance_identity = _directory(instance)
    except FileNotFoundError:
        if not allow_missing_instance:
            raise
        instance_identity = (None, None)
    return instance, (*identity, *instance_identity)


def _pidfile(path):
    data = _read(path, 32).strip()
    info = path.lstat()
    if info.st_uid != os.geteuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o022:
        raise ValueError('unsafe')
    if not re.fullmatch(rb'[1-9][0-9]{0,9}', data) or not 1 < int(data) <= 2**31 - 1:
        raise ValueError('unsafe')
    return int(data)


def _stat(pid):
    words = _read(_PROC_ROOT / str(pid) / 'stat').decode('ascii').rpartition(') ')[2].split()
    if len(words) < 22 or words[0] not in set('RSDTtZXIWPN'):
        raise ValueError('unsafe')
    return {'pid': pid, 'process_state': words[0], 'ppid': int(words[1]),
        'minor_faults': int(words[7]), 'major_faults': int(words[9]),
        'cpu_user_ticks': int(words[11]), 'cpu_system_ticks': int(words[12]),
        'threads': int(words[17]), 'start_ticks': int(words[19]),
        'rss_bytes': int(words[21]) * os.sysconf('SC_PAGE_SIZE')}


def _argument(arguments, name):
    try:
        index = arguments.index(name)
        return arguments[index + 1]
    except (ValueError, IndexError):
        return None


def _controller_arguments(arguments, action, instance_name, template=None):
    """Recognize app-owned command shapes without depending on flag order."""
    tail = list(arguments[1:])
    while tail and tail[0] in {'--tty=false', '--debug'}:
        tail.pop(0)
    if not tail or tail.pop(0) != action:
        return False
    positions, name, timeout_seen = [], None, False
    while tail:
        item = tail.pop(0)
        if action == 'start' and (item == '--timeout' or item.startswith('--timeout=')):
            if timeout_seen:
                return False
            timeout_seen = True
            if item == '--timeout':
                if not tail:
                    return False
                timeout = tail.pop(0)
            else:
                timeout = item.partition('=')[2]
            if not re.fullmatch(r'[0-9]{1,6}(?:\.[0-9]{1,3})?s', timeout):
                return False
        elif action == 'create' and (item == '--name' or item.startswith('--name=')):
            if name is not None:
                return False
            if item == '--name':
                if not tail:
                    return False
                name = tail.pop(0)
            else:
                name = item.partition('=')[2]
        elif item.startswith('-'):
            return False
        else:
            positions.append(item)
    if action == 'start':
        return positions == [instance_name]
    return action == 'create' and name == instance_name and positions == [str(template)]


def _qmp_arguments(arguments, instance):
    direct = _argument(arguments, '-qmp')
    if direct == 'chardev:char-qmp':
        expected = f'socket,id=char-qmp,path={instance / "qmp.sock"},server=on,wait=off'
        return any(arguments[i] == '-chardev' and i + 1 < len(arguments)
                   and arguments[i + 1] == expected for i in range(len(arguments)))
    return direct == f'unix:{instance / "qmp.sock"},server=on,wait=off'


def _process(pid, role, instance, *, parent=None, expected_start=None,
             controller_action='start', runtime_root=None):
    """Return a safe observation and private argv only after identity checks."""
    if not sys.platform.startswith('linux'):
        return {'state': 'unsupported', 'identity_verified': False}, None
    try:
        first = _stat(pid)
        base = _PROC_ROOT / str(pid)
        uid = next(line for line in _read(base / 'status').decode('ascii').splitlines() if line.startswith('Uid:'))
        ids = uid.split()[1:]
        if len(ids) != 4 or any(int(number) != os.geteuid() for number in ids):
            raise ValueError('identity_mismatch')
        arguments = [os.fsdecode(arg) for arg in _read(base / 'cmdline', 65536).split(b'\0') if arg]
        executable = Path(os.readlink(base / 'exe'))
        exe_info = executable.stat()
        if (not arguments or executable.name != Path(arguments[0]).name
                or not stat.S_ISREG(exe_info.st_mode) or exe_info.st_uid not in {0, os.geteuid()}
                or stat.S_IMODE(exe_info.st_mode) & 0o022):
            raise ValueError('identity_mismatch')
        if expected_start is not None and first['start_ticks'] != expected_start:
            raise ValueError('identity_mismatch')
        if parent is not None and (first['ppid'] != parent['pid'] or first['start_ticks'] < parent['start_ticks']):
            raise ValueError('identity_mismatch')
        overrides = None
        if role == 'hostagent':
            owned = (executable.name == 'limactl' and 'hostagent' in arguments[1:]
                and arguments[-1] == instance.name
                and _argument(arguments, '--pidfile') == str(instance / 'ha.pid')
                and _argument(arguments, '--socket') == str(instance / 'ha.sock'))
        elif role == 'controller':
            environment = _read(base / 'environ', 65536).split(b'\0')
            overrides = {name: any(item.partition(b'=')[0] == name.encode('ascii') for item in environment)
                         for name in ('QEMU_SYSTEM_AARCH64', 'QEMU_SYSTEM_X86_64')}
            owned = executable.name == 'limactl' and b'LIMA_HOME=' + os.fsencode(instance.parent) in environment
            if controller_action == 'create' and runtime_root is not None:
                template = Path(runtime_root) / 'templates' / 'lima.yaml'
                from .vm_logs import _open_regular
                descriptor = _open_regular(template)
                try:
                    metadata = os.fstat(descriptor)
                    template_owned = metadata.st_uid == os.geteuid() and metadata.st_nlink == 1
                finally:
                    os.close(descriptor)
                owned = (owned and template_owned
                    and _controller_arguments(arguments, 'create', instance.name, template))
            else:
                owned = (owned and controller_action == 'start'
                    and _controller_arguments(arguments, 'start', instance.name))
        elif role == 'qemu_vm':
            owned = (executable.name in _QEMU and _argument(arguments, '-name') == 'lima-' + instance.name
                and _argument(arguments, '-pidfile') == str(instance / 'qemu.pid') and _qmp_arguments(arguments, instance))
        else:
            owned = parent is not None
        if not owned:
            raise ValueError('identity_mismatch')
        actual_role, probe = role, None
        if parent is not None and executable.name in _QEMU:
            tails = {('-M', 'none', '-accel', 'help'): 'accelerators',
                ('-M', 'none', '-netdev', 'help'): 'network_backends',
                ('-machine', 'help'): 'machines', ('-cpu', 'help', '-machine', 'virt'): 'cpus',
                ('-cpu', 'help', '-machine', 'q35'): 'cpus', ('--version',): 'version'}
            probe = tails.get(tuple(arguments[1:]))
            if probe:
                actual_role = 'qemu_version_probe' if probe == 'version' else 'qemu_capability_probe'
            elif (_argument(arguments, '-name') == 'lima-' + instance.name
                    and _argument(arguments, '-pidfile') == str(instance / 'qemu.pid') and _qmp_arguments(arguments, instance)):
                actual_role = 'qemu_vm'
        try:
            channel = _read(base / 'wchan', 128).decode('ascii').strip()
        except (OSError, ValueError):
            channel = None
        last = _stat(pid)
        if (last['start_ticks'], last['ppid']) != (first['start_ticks'], first['ppid']):
            raise ValueError('identity_mismatch')
        result = {'state': 'available', 'identity_verified': True, 'role': actual_role, **last}
        if executable.name in _QEMU | {'limactl'}:
            result['executable'] = executable.name
        if overrides is not None:
            result['qemu_overrides'] = overrides
        if channel is not None:
            result['wait_channel'] = channel if channel in _WAITS else 'other'
        if probe:
            result['probe'] = probe
        return _process_safe(result), arguments
    except FileNotFoundError:
        return {'state': 'missing', 'identity_verified': False}, None
    except OSError:
        return {'state': 'unavailable', 'identity_verified': False}, None
    except (ValueError, IndexError, StopIteration):
        return {'state': 'identity_mismatch', 'identity_verified': False}, None


def _socket(path):
    try:
        info = path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid():
            return {'state': 'unsafe'}
        return {'state': 'available', '_identity': (info.st_dev, info.st_ino)}
    except FileNotFoundError:
        return {'state': 'missing'}
    except OSError:
        return {'state': 'unavailable'}


def _children(parent):
    # Linux reports children per OS thread. Go may launch QEMU from any thread.
    task_root = _PROC_ROOT / str(parent['pid']) / 'task'
    children, limited, scanned = [], False, 0
    with os.scandir(task_root) as entries:
        for entry in entries:
            if scanned >= _MAX_TASKS:
                limited = True
                break
            if not entry.name.isdigit() or not entry.is_dir(follow_symlinks=False):
                continue
            scanned += 1
            try:
                ids = _read(task_root / entry.name / 'children', 4096).split()
            except (OSError, ValueError):
                continue
            for raw in ids:
                if raw.isdigit() and 1 < int(raw) <= 2**31 - 1 and int(raw) not in children:
                    if len(children) >= _MAX_CHILDREN:
                        limited = True
                        break
                    children.append(int(raw))
    return children, limited


def _snapshot(runtime_root, selected_home, instance_name, controller_pid, controller_action='start'):
    result = {'home': {'state': 'unavailable', 'identity_verified': False}, 'children': [],
              'hostagent': {'state': 'not_verified'}, 'qemu': {'state': 'not_verified'},
              'controller': {'state': 'not_verified'}, 'serial': [], 'sockets': {}}
    try:
        instance, identity = _home(runtime_root, selected_home, instance_name,
                                   allow_missing_instance=controller_action == 'create')
        result['home'] = {'state': 'available', 'identity_verified': True, 'device': identity[0],
            'inode': identity[1], 'instance_device': identity[2], 'instance_inode': identity[3],
            'relocated': Path(selected_home) != Path(runtime_root) / 'vm' / 'lima',
            'instance_state': 'available' if identity[2] is not None else 'missing'}
        if controller_pid is not None:
            if type(controller_pid) is int and 1 < controller_pid <= 2**31 - 1:
                result['controller'], _ = _process(controller_pid, 'controller', instance,
                    controller_action=controller_action, runtime_root=runtime_root)
            else:
                result['controller'] = {'state': 'unsafe', 'identity_verified': False}
        if identity[2] is None:
            result.update(hostagent={'state': 'missing'}, qemu={'state': 'missing'},
                sockets={key: {'state': 'missing'} for key in ('hostagent', 'qmp')},
                serial=[{'filename': name, 'state': 'missing', 'signals': []}
                        for name in ('serial.log', 'serialp.log', 'serialv.log')])
            if _home(runtime_root, selected_home, instance_name, allow_missing_instance=True)[1] != identity:
                raise ValueError('identity_mismatch')
            return result
        for key, filename in (('hostagent', 'ha.pid'), ('qemu', 'qemu.pid')):
            try:
                pid = _pidfile(instance / filename)
                result[key], _ = _process(pid, 'hostagent' if key == 'hostagent' else 'qemu_vm', instance)
            except FileNotFoundError:
                result[key] = {'state': 'missing', 'identity_verified': False}
            except (OSError, ValueError):
                result[key] = {'state': 'unsafe', 'identity_verified': False}
        parents = [result['hostagent']] if result['hostagent'].get('identity_verified') else []
        ancestry = {}
        seen = set()
        while parents and len(seen) < _MAX_CHILDREN:
            parent = parents.pop(0)
            current, _ = _process(parent['pid'], parent['role'], instance,
                parent=ancestry.get(parent['pid']), expected_start=parent['start_ticks'])
            if not current.get('identity_verified'):
                if parent['pid'] == result['hostagent'].get('pid'):
                    result['hostagent'] = current
                result['children_limited'] = True
                continue
            try:
                ids, limited = _children(parent)
                result['children_limited'] = result.get('children_limited', False) or limited
            except (OSError, ValueError):
                continue
            for pid in ids:
                if len(seen) >= _MAX_CHILDREN:
                    result['children_limited'] = True
                    break
                if pid in seen:
                    continue
                seen.add(pid)
                child, _ = _process(pid, 'other_owned_child', instance, parent=parent)
                # Revalidate parent start identity: never combine a reused PID's child list.
                current, _ = _process(parent['pid'], parent['role'], instance,
                    parent=ancestry.get(parent['pid']), expected_start=parent['start_ticks'])
                if not current.get('identity_verified'):
                    child = {'state': 'identity_mismatch', 'identity_verified': False}
                result['children'].append(child)
                if child.get('identity_verified'):
                    ancestry[pid] = parent
                    parents.append(child)
        for key, filename in (('hostagent', 'ha.sock'), ('qmp', 'qmp.sock')):
            result['sockets'][key] = _socket(instance / filename)
        from .vm_logs import _read_tail, _signals
        for filename in ('serial.log', 'serialp.log', 'serialv.log'):
            item = {'filename': filename, 'state': 'missing', 'signals': []}
            try:
                info = (instance / filename).lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                    raise ValueError('unsafe')
                tail = _read_tail(instance / filename, 32768)
                if tail['status'] != 'included':
                    raise ValueError('unsafe')
                item.update(state='available', bytes=info.st_size, mtime_unix=info.st_mtime,
                    signals=[row['code'] for index, line in enumerate(tail['data'].decode('utf-8', errors='replace').splitlines()[-512:])
                             for row in _signals(line, 'serial', index)])
            except FileNotFoundError:
                pass
            except (OSError, ValueError):
                item['state'] = 'unsafe'
            result['serial'].append(item)
        if _home(runtime_root, selected_home, instance_name,
                 allow_missing_instance=controller_action == 'create')[1] != identity:
            raise ValueError('identity_mismatch')
        result['_instance'] = instance
        result['_home_identity'] = identity
    except FileNotFoundError:
        result['home'] = {'state': 'missing', 'identity_verified': False}
    except (OSError, RuntimeError, ValueError):
        result = {'home': {'state': 'identity_mismatch', 'identity_verified': False}}
    return result


async def _io(function, *args):
    """Bound daemon workers; cancellation never frees a still-blocked I/O slot."""
    with _IO_LOCK:
        _IO_JOBS.difference_update(job for job in tuple(_IO_JOBS) if job.done())
        if len(_IO_JOBS) >= 2:
            raise BlockingIOError('capacity')
        future = Future()
        _IO_JOBS.add(future)
        def run():
            if future.set_running_or_notify_cancel():
                try:
                    future.set_result(function(*args))
                except BaseException as exc:
                    future.set_exception(exc)
        try:
            threading.Thread(target=run, name='harnessy-lima-observation', daemon=True).start()
        except BaseException:
            future.cancel()
            _IO_JOBS.discard(future)
            raise
    wrapped = asyncio.wrap_future(future)
    wrapped.add_done_callback(lambda result: result.exception() if not result.cancelled() else None)
    return await asyncio.wait_for(asyncio.shield(wrapped), _IO_SECONDS)


def _recheck(runtime_root, selected_home, instance_name, snapshot):
    instance, identity = _home(runtime_root, selected_home, instance_name)
    if identity != snapshot.get('_home_identity'):
        return False
    process = snapshot['qemu']
    current, _ = _process(process['pid'], 'qemu_vm', instance, expected_start=process['start_ticks'])
    return (current.get('identity_verified') and _socket(instance / 'qmp.sock').get('_identity')
            == snapshot['sockets']['qmp'].get('_identity'))


async def _query_qmp(runtime_root, selected_home, instance_name, snapshot):
    if not snapshot.get('qemu', {}).get('identity_verified'):
        return {'state': 'not_verified'}
    if snapshot.get('sockets', {}).get('qmp', {}).get('state') != 'available':
        return {'state': snapshot.get('sockets', {}).get('qmp', {}).get('state', 'not_verified')}
    writer = None
    try:
        if not await _io(_recheck, runtime_root, selected_home, instance_name, snapshot):
            return {'state': 'identity_mismatch'}
        async def query():
            nonlocal writer
            reader, writer = await asyncio.open_unix_connection(str(snapshot['_instance'] / 'qmp.sock'), limit=65536)
            if not hasattr(socket, 'SO_PEERCRED'):
                return {'state': 'unsupported'}
            credentials = writer.get_extra_info('socket').getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            peer_pid, peer_uid, _ = struct.unpack('3i', credentials)
            if peer_pid != snapshot['qemu']['pid'] or peer_uid != os.geteuid():
                return {'state': 'identity_mismatch'}
            greeting = json.loads(await reader.readline())
            if not isinstance(greeting, dict) or not isinstance(greeting.get('QMP'), dict):
                return {'state': 'failed'}
            for command in ('qmp_capabilities', 'query-status'):
                writer.write((json.dumps({'execute': command, 'id': command}) + '\r\n').encode('ascii'))
                await writer.drain()
                response = None
                for _ in range(8):
                    row = json.loads(await reader.readline())
                    if isinstance(row, dict) and row.get('id') == command:
                        response = row
                        break
                if not isinstance(response, dict) or 'return' not in response:
                    return {'state': 'failed'}
            status = response['return']
            if not isinstance(status, dict):
                return {'state': 'failed'}
            return {'state': 'available', 'running': status.get('running'), 'vm_state': status.get('status')}
        result = await asyncio.wait_for(query(), _QMP_SECONDS)
        if not await _io(_recheck, runtime_root, selected_home, instance_name, snapshot):
            return {'state': 'identity_mismatch'}
        return result
    except asyncio.TimeoutError:
        return {'state': 'timeout'}
    except (OSError, ValueError, KeyError, RuntimeError, RecursionError):
        return {'state': 'failed'}
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), .1)
            except (OSError, asyncio.TimeoutError):
                pass


def _read_rows(runtime_root):
    path = Path(runtime_root) / 'guest-diagnostics' / _FILENAME
    try:
        from .vm_logs import _open_regular
        descriptor = _open_regular(path)
        try:
            info = os.fstat(descriptor)
            if (info.st_uid != os.geteuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o077):
                return [], 'unsafe', 0
            if info.st_size > _MAX_BYTES:
                return [], 'limited', 0
            payload = os.read(descriptor, _MAX_BYTES + 1)
        finally:
            os.close(descriptor)
        rows, invalid = [], 0
        for line in payload.splitlines()[-_MAX_RECEIPTS:]:
            try:
                row = validate_lima_startup_receipt(json.loads(line))
            except (ValueError, RecursionError):
                row = None
            if row is None:
                invalid += 1
            else:
                rows.append(row)
        return rows, 'available', invalid
    except FileNotFoundError:
        return [], 'missing', 0
    except (OSError, ValueError):
        return [], 'unsafe', 0


def _retain(rows, environment_id):
    """Keep first and final evidence for the latest two controller commands."""
    unique = OrderedDict()
    for value in rows:
        safe = validate_lima_startup_receipt(value)
        if safe and safe['environment_id'] == environment_id:
            unique[safe['capture_id']] = safe
    values = list(unique.values())
    values.sort(key=lambda row: row.get('captured_at', ''))
    commands = list(dict.fromkeys(row.get('command_id', '') for row in values))[-2:]
    anchors = set()
    for command in commands:
        matching = [row for row in values if row.get('command_id', '') == command]
        anchors.add(matching[0]['capture_id'])
        failures = [row for row in matching if row['reason'] != 'quiet_startup']
        if failures:
            anchors.add(failures[-1]['capture_id'])
    chosen = set(anchors)
    for row in reversed(values):
        if len(chosen) >= _MAX_RECEIPTS:
            break
        chosen.add(row['capture_id'])
    return [row for row in values if row['capture_id'] in chosen]


def _persist(runtime_root, receipt):
    from .guest_logs import _open_capture_directory
    parent = descriptor = None
    temporary = '.lima-startup-' + uuid.uuid4().hex
    try:
        if not _PERSIST_LOCK.acquire(blocking=False):
            return False
        try:
            parent = _open_capture_directory(Path(runtime_root))
            try:
                info = os.stat(_FILENAME, dir_fd=parent, follow_symlinks=False)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                        or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o077):
                    return False
            except FileNotFoundError:
                pass
            rows, _, _ = _read_rows(runtime_root)
            rows = _retain([*rows, receipt], receipt['environment_id'])
            payload = b''.join((json.dumps(row, separators=(',', ':'), allow_nan=False) + '\n').encode() for row in rows)
            if len(payload) > _MAX_BYTES:
                return False
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600, dir_fd=parent)
            with os.fdopen(descriptor, 'wb') as stream:
                descriptor = None
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, _FILENAME, src_dir_fd=parent, dst_dir_fd=parent)
            with _MEMORY_LOCK:
                for key, current in list(_MEMORY.items()):
                    if key[1:] == (str(Path(runtime_root).absolute()), receipt['environment_id']):
                        _MEMORY[key] = _retain([*rows, *current], receipt['environment_id'])
            return True
        finally:
            _PERSIST_LOCK.release()
    except (OSError, ValueError):
        return False
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent is not None:
            try:
                os.unlink(temporary, dir_fd=parent)
            except OSError:
                pass
            os.close(parent)


async def capture_lima_startup(workspace_root, *, environment_id, runtime_root, selected_home,
        instance_name='harnessy', controller_pid=None, command_id='', operation_id='', reason,
        controller_action='start', command_started_at_epoch=None, elapsed_seconds=0.0,
        last_output_age_seconds=None):
    """Observe one exact selected instance without SSH or lifecycle commands."""
    from .vm_logs import _runtime_root, _workspace_path
    if not _ID.fullmatch(str(environment_id)) or not _fixed(reason, _REASONS):
        raise ValueError('Invalid Lima startup observation identity')
    workspace_root = _workspace_path(workspace_root)
    if workspace_root is None:
        raise ValueError('Invalid workspace runtime identity')
    runtime_root = _runtime_root(workspace_root, environment_id, runtime_root)
    started = time.monotonic()
    receipt = {'schema_version': 1, 'event': 'lima_startup_capture', 'capture_id': uuid.uuid4().hex,
        'environment_id': environment_id, 'reason': reason, 'command_id': command_id,
        'operation_id': operation_id, 'controller_action': controller_action,
        'captured_at': datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
        'command_started_at_epoch': command_started_at_epoch, 'elapsed_seconds': elapsed_seconds,
        'last_output_age_seconds': last_output_age_seconds, 'qmp': {'state': 'not_verified'}}
    receipt.update(home={'state': 'unavailable', 'identity_verified': False},
        controller={'state': 'not_verified'}, hostagent={'state': 'not_verified'}, qemu={'state': 'not_verified'})
    cancelled = False
    try:
        snapshot = await _io(_snapshot, Path(runtime_root), Path(selected_home), instance_name, controller_pid, controller_action)
        receipt.update(snapshot)
        receipt['qmp'] = await _query_qmp(runtime_root, selected_home, instance_name, snapshot)
    except asyncio.CancelledError:
        receipt['collector_state'] = 'cancelled'
        cancelled = True
    except asyncio.TimeoutError:
        receipt['collector_state'] = 'timeout'
    except BlockingIOError:
        receipt['collector_state'] = 'capacity'
    except (OSError, ValueError, RuntimeError, RecursionError):
        receipt['collector_state'] = 'failed'
    receipt['collection_seconds'] = time.monotonic() - started
    safe = validate_lima_startup_receipt(receipt)
    key = (str(Path(workspace_root).absolute()), str(Path(runtime_root).absolute()), environment_id)
    with _MEMORY_LOCK:
        rows = _MEMORY.pop(key, [])
        _MEMORY[key] = _retain([*rows, safe], environment_id)
        while len(_MEMORY) > _MAX_ENVIRONMENTS:
            _MEMORY.popitem(last=False)
    if cancelled:
        raise asyncio.CancelledError
    try:
        await _io(_persist, Path(runtime_root), safe)
    except (OSError, ValueError, RuntimeError, asyncio.TimeoutError):
        pass
    return safe


def validate_lima_startup_report(value):
    value = value if isinstance(value, dict) else {}
    out = {'schema_version': 1, 'status': 'collected', 'environments': [],
           'limited': value.get('limited') is True, 'scope': 'saved_owned_lima_startup_observations'}
    for item in value.get('environments', [])[:_MAX_ENVIRONMENTS] if isinstance(value.get('environments'), list) else []:
        if (not isinstance(item, dict) or not re.fullmatch(r'[0-9a-f]{64}', str(item.get('workspace_id', '')))
                or not _ID.fullmatch(str(item.get('environment_id', '')))):
            continue
        row = {key: item[key] for key in ('workspace_id', 'environment_id')}
        row['receipt_status'] = _state(item.get('receipt_status'))
        row['retention'] = 'in_process' if item.get('retention') == 'in_process' else 'disk'
        for key in ('captures_retained', 'invalid_receipts'):
            row[key] = int(_number(item.get(key), _MAX_RECEIPTS) or 0)
        member = f'lima-startup/{row["workspace_id"]}/{row["environment_id"]}/lima-startup.technical.jsonl'
        if item.get('archive_member') == member:
            row['archive_member'] = member
        latest = validate_lima_startup_receipt(item.get('latest_capture'))
        if latest and latest['environment_id'] == row['environment_id']:
            row['latest_capture'] = latest
        out['environments'].append(row)
    return out


def collect_lima_startup_diagnostics(latest):
    """Export retained, revalidated observations only; never probe live state."""
    from .vm_logs import _discover_workspaces, _runtime_environments
    deadline = time.monotonic() + 3
    roots, _ = _discover_workspaces(Path(latest).absolute(), deadline)
    with _MEMORY_LOCK:
        cached = dict(_MEMORY)
    for root, _runtime, _eid in cached:
        if all(str(row[0]) != root for row in roots):
            roots.append((Path(root), 'in_process_startup_capture'))
    report = {'schema_version': 1, 'status': 'collected', 'environments': [],
              'limited': False, 'scope': 'saved_owned_lima_startup_observations'}
    members, total = {}, 0
    for root, _origin in roots:
        environments, limited = _runtime_environments(root)
        report['limited'] |= limited
        for memory_root, memory_runtime, eid in cached:
            if memory_root == str(root) and (eid, Path(memory_runtime)) not in environments:
                environments.append((eid, Path(memory_runtime)))
        for eid, runtime in environments:
            if not eid:
                continue
            if len(report['environments']) >= _MAX_ENVIRONMENTS or time.monotonic() >= deadline:
                report['limited'] = True
                break
            rows = cached.get((str(root), str(runtime), eid))
            retention = 'in_process' if rows else 'disk'
            if rows:
                state, invalid = 'available', 0
            else:
                rows, state, invalid = _read_rows(runtime)
            rows = [safe for row in rows if (safe := validate_lima_startup_receipt(row)) and safe['environment_id'] == eid]
            item = {'workspace_id': hashlib.sha256(str(root).encode()).hexdigest(), 'environment_id': eid,
                    'receipt_status': state, 'captures_retained': len(rows), 'invalid_receipts': invalid, 'retention': retention}
            payload = b''.join((json.dumps(row, separators=(',', ':'), allow_nan=False) + '\n').encode() for row in rows)
            if rows and total + len(payload) <= 2 * 1024 * 1024:
                member = f'lima-startup/{item["workspace_id"]}/{eid}/lima-startup.technical.jsonl'
                item.update(archive_member=member, latest_capture=rows[-1])
                members[member] = payload
                total += len(payload)
            report['environments'].append(item)
    return {'report': validate_lima_startup_report(report), 'members': members}


def summary_lines(report):
    report = validate_lima_startup_report(report)
    lines = ['\nLima startup observations: LIMA_STARTUP.json and lima-startup/ preserve selected-instance process and monitor state.']
    for row in report.get('environments', [])[:_MAX_ENVIRONMENTS]:
        capture = validate_lima_startup_receipt(row.get('latest_capture'))
        if capture:
            probes = [child.get('probe') for child in capture['children'] if child.get('probe')]
            lines.append(f"  VM {capture['environment_id'][:12]} at {capture.get('captured_at', 'unknown')}: "
                f"home={capture['home']['state']}, hostagent={capture['hostagent']['state']}, "
                f"QEMU={capture['qemu']['state']}, monitor={capture['qmp']['state']}, probes={','.join(probes) or 'none observed'}.")
        else:
            lines.append(f"  VM {str(row.get('environment_id', ''))[:12]}: startup observations missing.")
    lines.append('  Owned processes and monitor replies are observations; running does not establish guest SSH readiness.')
    return '\n'.join(lines) + '\n'
