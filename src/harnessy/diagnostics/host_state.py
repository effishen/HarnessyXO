"""Content-free, bounded host evidence for support exports.

Only fixed OS interfaces and fixed tool version operations are inspected. There
are no network requests, VM operations, process listings, environment exports,
workspace file reads, command lines, account names, or arbitrary command inputs.
A failed probe is evidence too: every section carries an explicit status.
"""
from __future__ import annotations

import errno
import importlib.metadata
import math
import os
import platform
import re
import signal
import sqlite3
import stat
import struct
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Sequence

SCHEMA_VERSION = 1
MAX_OS_FILE_BYTES = 128 * 1024
MAX_TOOL_OUTPUT_BYTES = 16 * 1024
MAX_WORKSPACES = 8
COLLECTION_SECONDS = 8.0
TOOL_TIMEOUT_SECONDS = 0.75
_TOOLS = {
    'limactl': ('--version',),
    'qemu-system-aarch64': ('--version',),
    'qemu-system-x86_64': ('--version',),
    'qemu-img': ('--version',),
    'ssh': ('-V',),
    'mke2fs': ('-V',),
}
_BIN_DIRS = ('/opt/homebrew/bin', '/usr/local/bin', '/usr/bin', '/usr/sbin', '/bin', '/sbin',
             '/home/linuxbrew/.linuxbrew/bin', '/opt/local/bin')
_FIRMWARE = {
    'aavmf_code': '/usr/share/AAVMF/AAVMF_CODE.fd',
    'aavmf_vars': '/usr/share/AAVMF/AAVMF_VARS.fd',
    'edk2_aarch64_code': '/usr/share/qemu-efi-aarch64/QEMU_EFI.fd',
    'edk2_aarch64_code_alt': '/usr/share/edk2/aarch64/QEMU_EFI.fd',
    'ovmf_code': '/usr/share/OVMF/OVMF_CODE.fd',
    'ovmf_code_4m': '/usr/share/OVMF/OVMF_CODE_4M.fd',
    'ovmf_vars': '/usr/share/OVMF/OVMF_VARS.fd',
    'edk2_x86_code': '/usr/share/edk2/ovmf/OVMF_CODE.fd',
}
_FEATURES = frozenset('''fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36
clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl
xtopology nonstop_tsc cpuid aperfmperf tsc_known_freq pni pclmulqdq vmx smx est tm2 ssse3
fma cx16 sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand
hypervisor lahf_lm abm svm cr8_legacy extapic 3dnowprefetch osvw ibs skinit wdt tce
topoext perfctr_core perfctr_nb bpext perfctr_llc mwaitx cpb cat_l3 cdp_l3 invpcid_single
ibrs ibpb stibp ibrs_enhanced tpr_shadow vnmi flexpriority ept vpid ept_ad fsgsbase
tsc_adjust bmi1 avx2 smep bmi2 erms invpcid rtm mpx avx512f avx512dq rdseed adx smap
clflushopt clwb intel_pt avx512cd avx512bw avx512vl xsaveopt xsavec xgetbv1 xsaves
cqm cqm_llc cqm_occup_llc cqm_mbm_total cqm_mbm_local md_clear flush_l1d arch_capabilities
avx_vnni avx512_vnni avx512_bf16 avx512_fp16 amx_tile amx_int8 amx_bf16 amx_fp16
vaes vpclmulqdq sha_ni gfni serialize rdpid umip pku ospke waitpkg movdiri movdir64b
neon vfp vfpv3 vfpv4 tls thumb idiva idivt lpae evtstrm fp asimd aes pmull sha1 sha2 crc32
atomics fphp asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp sha512
sve asimdfhm dit uscat ilrcpc flagm ssbs sb paca pacg dcpodp sve2 sveaes svepmull svebitperm
svesha3 svesm4 flagm2 frint svei8mm svef32mm svef64mm svebf16 i8mm bf16 dgh rng bti mte
mte3 afp rpres mte4 sme sme2 wfxt ecbhb cssc hbc lse128 sve2p1 asimdfp16 fma4 xop tbm
ssse3 sse4.1 sse4.2 avx1.0 avx2.0 aesni pclmulqdq vmm avx512_ifma avx512_vbmi
avx512_vbmi2 avx512_bitalg avx512_vpopcntdq user_shstk ibt'''.split())
_DISTROS = frozenset('ubuntu debian fedora rhel centos rocky almalinux alpine arch manjaro opensuse-tumbleweed opensuse-leap sles nixos gentoo raspbian kali amzn ol linuxmint pop'.split())
_ARCHES = {'x86_64': 'x86_64', 'amd64': 'x86_64', 'arm64': 'aarch64', 'aarch64': 'aarch64',
           'i386': 'x86', 'i686': 'x86', 'armv7l': 'armv7', 'riscv64': 'riscv64',
           'ppc64le': 'ppc64le', 's390x': 's390x'}
_DEPENDENCIES = ('nicegui', 'httpx', 'segno', 'playwright', 'fastapi', 'starlette',
                 'uvicorn', 'anyio', 'pydantic', 'aiohttp', 'python-socketio', 'PyYAML')
_MEM_KEYS = ('MemTotal', 'MemFree', 'MemAvailable', 'Buffers', 'Cached', 'SwapTotal',
             'SwapFree', 'SwapCached', 'Shmem', 'Slab', 'SReclaimable', 'PageTables',
             'CommitLimit', 'Committed_AS', 'HugePages_Total', 'HugePages_Free', 'Hugepagesize')
_CGROUP_FILES = {
    2: ('memory.max', 'memory.current', 'memory.peak', 'memory.swap.max', 'memory.swap.current',
        'memory.high', 'memory.events', 'cpu.max', 'cpu.stat', 'cpuset.cpus.effective',
        'pids.max', 'pids.current', 'pids.events'),
    1: ('memory.limit_in_bytes', 'memory.usage_in_bytes', 'memory.max_usage_in_bytes',
        'memory.memsw.limit_in_bytes', 'memory.failcnt', 'cpu.cfs_quota_us',
        'cpu.cfs_period_us', 'cpu.stat', 'cpuset.cpus', 'pids.max', 'pids.current'),
}
_CGROUP_COUNTERS = frozenset('low high max oom oom_kill oom_group_kill nr_periods nr_throttled throttled_usec throttled_time usage_usec user_usec system_usec nr_bursts burst_usec'.split())


class _ProbeError(Exception):
    def __init__(self, status: str):
        self.status = status
        super().__init__(status)


def _error(exc: BaseException) -> dict[str, Any]:
    if isinstance(exc, _ProbeError):
        return {'status': exc.status}
    if isinstance(exc, FileNotFoundError):
        return {'status': 'missing'}
    if isinstance(exc, PermissionError):
        return {'status': 'permission_denied'}
    if isinstance(exc, OSError):
        return {'status': 'unavailable', 'errno': exc.errno}
    return {'status': 'unavailable', 'reason': 'probe_failed'}


def _path_status(path: Path, *, final_type: str = 'file') -> os.stat_result:
    """Reject symlink redirects, including ancestors; never return their target."""
    if not path.is_absolute() or '..' in path.parts or len(str(path)) > 4096:
        raise _ProbeError('unsafe_path')
    for ancestor in reversed(path.parents):
        info = ancestor.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise _ProbeError('symlink_redirect')
        if not stat.S_ISDIR(info.st_mode):
            raise _ProbeError('wrong_type')
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise _ProbeError('symlink_redirect')
    if final_type == 'file' and not stat.S_ISREG(info.st_mode):
        raise _ProbeError('wrong_type')
    if final_type == 'directory' and not stat.S_ISDIR(info.st_mode):
        raise _ProbeError('wrong_type')
    return info


def _open_checked(path: Path, *, directory: bool = False) -> int:
    """Anchor every POSIX path component; refuse links before opening a target."""
    if not path.is_absolute() or '..' in path.parts or len(str(path)) > 4096:
        raise _ProbeError('unsafe_path')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    flags |= getattr(os, 'O_CLOEXEC', 0)
    if os.open in os.supports_dir_fd and hasattr(os, 'O_NOFOLLOW'):
        parent = os.open(path.anchor, flags | getattr(os, 'O_DIRECTORY', 0))
        try:
            for component in path.parts[1:-1]:
                child = os.open(component, flags | getattr(os, 'O_DIRECTORY', 0), dir_fd=parent)
                os.close(parent)
                parent = child
            if len(path.parts) == 1:
                fd = os.dup(parent)
            else:
                fd = os.open(path.name, flags | (getattr(os, 'O_DIRECTORY', 0) if directory else 0), dir_fd=parent)
        except OSError as exc:
            # ELOOP/ENOTDIR can both denote a redirected ancestor.
            if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                raise _ProbeError('symlink_redirect') from None
            raise
        finally:
            os.close(parent)
    else:
        # The fallback records every ancestor identity before/after opening.
        checked = [(p, p.lstat()) for p in (*reversed(path.parents), path)]
        if any(stat.S_ISLNK(info.st_mode) for _p, info in checked):
            raise _ProbeError('symlink_redirect')
        fd = os.open(path, flags)
        try:
            for item, before in checked:
                after = item.lstat()
                if (before.st_dev, before.st_ino, before.st_mode) != (after.st_dev, after.st_ino, after.st_mode):
                    raise _ProbeError('changed_during_read')
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (checked[-1][1].st_dev, checked[-1][1].st_ino):
                raise _ProbeError('changed_during_read')
        except BaseException:
            os.close(fd)
            raise
    info = os.fstat(fd)
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        os.close(fd)
        raise _ProbeError('wrong_type')
    return fd


def _read_os_file(path: Path, limit: int = MAX_OS_FILE_BYTES, *, prefix_ok: bool = False) -> str:
    """Bound procfs reads even with zero stat size; never follow a path redirect."""
    fd = _open_checked(path)
    try:
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(16384, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > limit and not prefix_ok:
            raise _ProbeError('truncated')
        return bytes(data[:limit]).decode('utf-8', errors='replace')
    finally:
        os.close(fd)


def _version(text: str) -> str | None:
    match = re.search(r'(?<![\w.])(\d{1,6}(?:\.\d{1,6}){1,4})(?![\d.])', text[:MAX_TOOL_OUTPUT_BYTES])
    return match.group(1) if match else None


def _feature_list(text: str) -> list[str]:
    return sorted({token.lower() for token in text.split()[:4096] if token.lower() in _FEATURES})


def _os_state() -> dict[str, Any]:
    system = platform.system()
    out: dict[str, Any] = {'status': 'ok', 'system': system if system in ('Linux', 'Darwin', 'Windows', 'FreeBSD') else 'other',
                           'architecture': _ARCHES.get(platform.machine().lower(), 'other'),
                           'pointer_bits': struct.calcsize('P') * 8}
    release = _version(platform.release())
    if release:
        out['kernel_version'] = release
    # Known variants carry diagnostic value without exposing arbitrary build labels.
    kernel = platform.release().lower()
    out['kernel_variants'] = [label for label in ('nvidia', 'generic', 'azure', 'aws', 'microsoft', 'wsl', 'raspi', 'lowlatency') if label in kernel]
    if system == 'Darwin':
        out['os_version'] = _version(platform.mac_ver()[0])
    if system == 'Linux':
        distro: dict[str, Any] = {'status': 'missing'}
        for path in (Path('/etc/os-release'), Path('/usr/lib/os-release')):
            try:
                values = dict(re.findall(r'^([A-Z_]+)=["\']?([^\n"\']*)', _read_os_file(path, 16384), re.M))
                distro = {'status': 'ok', 'id': values.get('ID') if values.get('ID') in _DISTROS else 'other'}
                version = values.get('VERSION_ID', '')
                if re.fullmatch(r'\d{1,6}(?:\.\d{1,6}){0,3}', version):
                    distro['version'] = version
                break
            except (OSError, _ProbeError) as exc:
                distro = _error(exc)
        out['distribution'] = distro
    return out


def _linux_cpu() -> dict[str, Any]:
    out: dict[str, Any] = {'status': 'ok', 'logical_cpu_count': os.cpu_count()}
    try:
        text = _read_os_file(Path('/proc/cpuinfo'), prefix_ok=True)
        out['source_scope'] = 'bounded_cpuinfo_prefix'
        out['socket_count_status'] = 'not_collected_prefix_could_be_incomplete'
        keys: dict[str, list[str]] = {}
        for line in text.splitlines():
            key, sep, value = line.partition(':')
            if sep:
                keys.setdefault(key.strip().lower(), []).append(value.strip())
        flags = keys.get('flags', []) + keys.get('features', [])
        out['features'] = _feature_list(' '.join(flags[:2]))
        vendors = ' '.join(keys.get('vendor_id', [])[:1] + keys.get('cpu implementer', [])[:1]).lower()
        out['vendor'] = next((label for match, label in (('genuineintel', 'intel'), ('authenticamd', 'amd'), ('0x41', 'arm'), ('0x4e', 'nvidia'), ('0x61', 'apple')) if match in vendors), 'other')
        for key in ('cpu family', 'model', 'stepping', 'cpu architecture', 'cpu variant', 'cpu part', 'cpu revision'):
            value = (keys.get(key) or [''])[0]
            if re.fullmatch(r'(?:\d{1,8}|0x[0-9a-fA-F]{1,8})', value):
                out[key.replace(' ', '_')] = int(value, 16 if value.startswith('0x') else 10)
    except (OSError, _ProbeError) as exc:
        out.update(_error(exc))
    if hasattr(os, 'sched_getaffinity'):
        try:
            out['process_affinity_cpu_count'] = len(os.sched_getaffinity(0))
        except OSError:
            out['affinity_status'] = 'unavailable'
    return out


def _linux_memory() -> dict[str, Any]:
    try:
        text = _read_os_file(Path('/proc/meminfo'), 32768)
        out: dict[str, Any] = {'status': 'ok'}
        for key, value, unit in re.findall(r'^([A-Za-z_()]+):\s*(\d+)\s*(kB)?\s*$', text, re.M):
            if key in _MEM_KEYS:
                out[key] = int(value) * (1024 if unit else 1)
        return out if len(out) > 1 else {'status': 'unparseable'}
    except (OSError, _ProbeError) as exc:
        return _error(exc)


def _proc_self_root() -> Path:
    # A container may expose procfs from a different PID namespace. The kernel's
    # fixed /proc/self link identifies this process in that procfs, whereas
    # /proc/<os.getpid()> can accidentally identify an unrelated process.
    target = os.readlink('/proc/self')
    if not re.fullmatch(r'[1-9][0-9]{0,19}', target):
        raise _ProbeError('unsafe_proc_self_reference')
    return Path('/proc') / target


def _pressure() -> dict[str, Any]:
    result: dict[str, Any] = {}
    for kind in ('cpu', 'memory', 'io'):
        try:
            text = _read_os_file(Path('/proc/pressure') / kind, 4096)
            rows = {}
            for line in text.splitlines()[:8]:
                fields = line.split()
                if not fields or fields[0] not in ('some', 'full'):
                    continue
                counters = {}
                for field in fields[1:]:
                    name, _sep, value = field.partition('=')
                    if name in ('avg10', 'avg60', 'avg300') and re.fullmatch(r'\d{1,6}(?:\.\d{1,6})?', value):
                        counters[name] = float(value)
                    elif name == 'total' and re.fullmatch(r'\d{1,20}', value):
                        counters['total_stall_microseconds'] = int(value)
                rows[fields[0]] = counters
            result[kind] = {'status': 'ok', **rows} if rows else {'status': 'unparseable'}
        except (OSError, _ProbeError) as exc:
            result[kind] = _error(exc)
    return result


def _load_average() -> dict[str, Any]:
    try:
        values = os.getloadavg()
        return {'status': 'ok', **{name: round(value, 3) for name, value in zip(('one_minute', 'five_minutes', 'fifteen_minutes'), values)}}
    except (AttributeError, OSError):
        return {'status': 'unavailable'}


def _process_state(system: str) -> dict[str, Any]:
    out: dict[str, Any] = {'status': 'ok', 'scope': 'harnessy_process_only', 'pid': os.getpid()}
    for name in ('getuid', 'geteuid', 'getgid', 'getegid'):
        if hasattr(os, name):
            out[name[3:]] = getattr(os, name)()
    if hasattr(os, 'getgroups'):
        try:
            out['supplementary_group_ids'] = sorted(os.getgroups())[:256]
        except OSError:
            out['groups_status'] = 'unavailable'
    if system == 'Linux':
        try:
            text = _read_os_file(_proc_self_root() / 'status', 32768)
            allowed = {'VmPeak', 'VmSize', 'VmRSS', 'RssAnon', 'RssFile', 'RssShmem', 'VmSwap', 'VmData', 'VmStk', 'VmExe', 'VmLib', 'VmPTE', 'VmHWM', 'Threads', 'FDSize', 'voluntary_ctxt_switches', 'nonvoluntary_ctxt_switches', 'NoNewPrivs', 'Seccomp'}
            for key, value, unit in re.findall(r'^(\w+):\s*(\d+)\s*(kB)?\s*$', text, re.M):
                if key in allowed:
                    out[key] = int(value) * (1024 if unit else 1)
            fd_path = _proc_self_root() / 'fd'
            _path_status(fd_path, final_type='directory')
            with os.scandir(fd_path) as entries:
                count = sum(1 for _, _entry in zip(range(65537), entries))
            out['open_fd_count'] = min(count, 65536)
            out['open_fd_count_capped'] = count > 65536
        except (OSError, _ProbeError) as exc:
            out['proc_status'] = _error(exc)
    try:
        import resource
        usage = resource.getrusage(resource.RUSAGE_SELF)
        out['cpu_user_seconds'] = usage.ru_utime
        out['cpu_system_seconds'] = usage.ru_stime
        out['max_rss_bytes'] = usage.ru_maxrss * (1 if system == 'Darwin' else 1024)
        out['major_faults'] = usage.ru_majflt
        out['minor_faults'] = usage.ru_minflt
        out['limits'] = {}
        for label in ('NOFILE', 'NPROC', 'AS', 'DATA', 'STACK', 'MEMLOCK', 'CORE', 'CPU', 'FSIZE'):
            if hasattr(resource, 'RLIMIT_' + label):
                soft, hard = resource.getrlimit(getattr(resource, 'RLIMIT_' + label))
                out['limits'][label.lower()] = {'soft': 'unlimited' if soft == resource.RLIM_INFINITY else soft,
                                                'hard': 'unlimited' if hard == resource.RLIM_INFINITY else hard}
    except (ImportError, OSError, ValueError):
        out['resource_status'] = 'unavailable'
    return out


def _cgroup_values(path: Path, version: int) -> dict[str, Any]:
    out: dict[str, Any] = {'version': version, 'status': 'ok', 'files': {}}
    for name in _CGROUP_FILES[version]:
        try:
            text = _read_os_file(path / name, 4096).strip()
            item: dict[str, Any] = {'status': 'ok'}
            if text == 'max':
                item['value'] = 'unlimited'
            elif name == 'cpu.cfs_quota_us' and text == '-1':
                item['value'] = 'unlimited'
            elif re.fullmatch(r'\d{1,20}', text):
                item['value'] = int(text)
            elif name == 'cpu.max' and re.fullmatch(r'(?:max|\d{1,20}) \d{1,20}', text):
                quota, period = text.split()
                item.update(quota_us='unlimited' if quota == 'max' else int(quota), period_us=int(period))
            elif name.startswith('cpuset.') and re.fullmatch(r'[0-9,-]{0,1024}', text):
                # Preserve ranges only; paths and arbitrary controller messages never escape.
                item['cpu_ranges'] = text
            elif name in ('memory.events', 'cpu.stat', 'pids.events'):
                item['counters'] = {key: int(value) for key, value in re.findall(r'^(\w+) (\d{1,20})$', text, re.M) if key in _CGROUP_COUNTERS}
            else:
                item = {'status': 'unparseable'}
            out['files'][name] = item
        except (OSError, _ProbeError) as exc:
            out['files'][name] = _error(exc)
    return out


def _linux_cgroup() -> dict[str, Any]:
    try:
        text = _read_os_file(_proc_self_root() / 'cgroup', 16384)
        rows = []
        for line in text.splitlines()[:64]:
            parts = line.split(':', 2)
            if len(parts) != 3:
                continue
            _ident, controllers, member = parts
            relative = Path(member.lstrip('/'))
            if '..' in relative.parts or not member.startswith('/'):
                continue
            if controllers == '' and _ident == '0':
                # Some container namespaces report a host-relative membership
                # which does not exist under their mounted cgroup root.
                roots = [Path('/sys/fs/cgroup') / relative, Path('/sys/fs/cgroup')]
                for index, root in enumerate(dict.fromkeys(roots)):
                    try:
                        _path_status(root, final_type='directory')
                        result = _cgroup_values(root, 2)
                        result['scope'] = 'process_membership' if index == 0 else 'mounted_root_fallback'
                        rows.append(result)
                        break
                    except (OSError, _ProbeError):
                        pass
            elif controllers:
                for controller in controllers.split(','):
                    if controller not in ('memory', 'cpu', 'cpuacct', 'cpuset', 'pids'):
                        continue
                    root = Path('/sys/fs/cgroup') / controller / relative
                    try:
                        _path_status(root, final_type='directory')
                        result = _cgroup_values(root, 1)
                        result['controller'] = controller
                        rows.append(result)
                    except (OSError, _ProbeError) as exc:
                        rows.append({'version': 1, 'controller': controller, **_error(exc)})
        return {'status': 'ok' if rows else 'unavailable', 'groups': rows, 'paths_omitted': True}
    except (OSError, _ProbeError) as exc:
        return _error(exc)


def _file_metadata(path: Path, *, device: bool = False) -> dict[str, Any]:
    try:
        info = _path_status(path, final_type='any' if device else 'file')
        if device and not stat.S_ISCHR(info.st_mode):
            return {'status': 'wrong_type'}
        return {'status': 'ok', 'bytes': info.st_size, 'mode': format(stat.S_IMODE(info.st_mode), '04o'),
                'uid': info.st_uid, 'gid': info.st_gid, 'readable': os.access(path, os.R_OK),
                'writable': os.access(path, os.W_OK), 'modified_at_epoch': int(info.st_mtime)}
    except (OSError, _ProbeError) as exc:
        return _error(exc)


def _filesystem(path: Path, role: str) -> dict[str, Any]:
    out: dict[str, Any] = {'role': role}
    try:
        fd = _open_checked(path, directory=True)
        try:
            fs = os.fstatvfs(fd)
        finally:
            os.close(fd)
        out.update(status='ok', total_bytes=fs.f_blocks * fs.f_frsize,
                   available_bytes=fs.f_bavail * fs.f_frsize, free_bytes=fs.f_bfree * fs.f_frsize,
                   inode_total=fs.f_files, inode_available=fs.f_favail, inode_free=fs.f_ffree,
                   block_size=fs.f_frsize, read_only=bool(fs.f_flag & getattr(os, 'ST_RDONLY', 1)))
    except (OSError, ValueError, AttributeError, _ProbeError) as exc:
        out.update(_error(exc))
    return out


def _find_tool(name: str) -> Path | None:
    # No settings-provided commands, empty/relative PATH entries, aliases, shell,
    # or PATH values in the report. Discovery itself never changes the host PATH.
    directories = [Path(item) for item in os.environ.get('PATH', '').split(os.pathsep) if item and Path(item).is_absolute()]
    directories.extend(Path(item) for item in _BIN_DIRS)
    directories.append(Path.home() / '.local/bin')
    present_but_unusable = None
    for directory in dict.fromkeys(directories):
        candidate = directory / name
        try:
            candidate.lstat()
            if present_but_unusable is None:
                present_but_unusable = candidate
            info = candidate.stat()
            if stat.S_ISREG(info.st_mode) and os.access(candidate, os.X_OK):
                return candidate
        except (OSError, ValueError):
            pass
    return present_but_unusable


def _verified_executable(path: Path) -> tuple[Path, dict[str, Any]]:
    """Permit conventional package symlinks, refuse writable/unowned redirection."""
    try:
        lexical = path.lstat()
        resolved = path.resolve(strict=True)
        info = resolved.stat()
        meta: dict[str, Any] = {'discovery': 'fixed_name_search',
                               'symlink': stat.S_ISLNK(lexical.st_mode) or resolved != path,
                               'executable': os.access(resolved, os.X_OK)}
        if not stat.S_ISREG(info.st_mode):
            return resolved, {**meta, 'status': 'wrong_type'}
        if not meta['executable']:
            return resolved, {**meta, 'status': 'permission_denied'}
        if os.name == 'posix':
            owners = {0, os.geteuid()}
            for item in (resolved, *resolved.parents):
                current = item.stat()
                if current.st_uid not in owners or current.st_mode & 0o022:
                    return resolved, {**meta, 'status': 'unsafe_executable_permissions'}
        return resolved, {**meta, 'status': 'ok'}
    except (OSError, RuntimeError, ValueError) as exc:
        return path, _error(exc)


def _run_fixed(argv: tuple[str, ...], timeout: float) -> tuple[str, int | None, str]:
    """Only internal fixed argv reach here. Bound time, retained bytes and cleanup.

    A regular output descriptor prevents inherited pipe writers from delaying
    return. No raw output is ever returned in the public inventory.
    """
    proc = None
    try:
        with tempfile.TemporaryFile() as output:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output,
                                    stderr=subprocess.STDOUT, start_new_session=(os.name == 'posix'))
            deadline = time.monotonic() + max(0.01, timeout)
            status = 'ok'
            while proc.poll() is None:
                if output.tell() > MAX_TOOL_OUTPUT_BYTES:
                    status = 'output_limit'
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    status = 'timeout'
                    break
                try:
                    proc.wait(timeout=min(0.03, remaining))
                except subprocess.TimeoutExpired:
                    pass
            if proc.poll() is None:
                try:
                    if os.name == 'posix':
                        os.killpg(proc.pid, signal.SIGKILL)
                    else:
                        proc.kill()
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=0.25)
                except subprocess.TimeoutExpired:
                    status = 'cleanup_timeout'
            output.seek(0)
            data = output.read(MAX_TOOL_OUTPUT_BYTES + 1)
            if len(data) > MAX_TOOL_OUTPUT_BYTES:
                status = 'output_limit'
            return status, proc.returncode, data[:MAX_TOOL_OUTPUT_BYTES].decode('utf-8', errors='replace')
    except (OSError, ValueError):
        return 'unavailable', None, ''


def _tool_version(name: str, output: str) -> dict[str, Any]:
    # Tool-specific markers avoid accidentally reporting OpenSSL's version as
    # OpenSSH's (or a copyright year as a tool version).
    if name == 'ssh':
        match = re.search(r'\bOpenSSH[_ ](\d{1,6}\.\d{1,6})(?:p(\d{1,6}))?', output)
        return {'version': match.group(1), **({'patchlevel': int(match.group(2))} if match.group(2) else {})} if match else {}
    markers = {
        'limactl': r'(?:limactl|lima)(?: version)?',
        'qemu-system-aarch64': r'QEMU emulator version',
        'qemu-system-x86_64': r'QEMU emulator version',
        'qemu-img': r'qemu-img version',
        'mke2fs': r'mke2fs',
    }
    marker = markers.get(name)
    if marker is None:
        return {}
    match = re.search(marker + r'\s+v?(\d{1,6}(?:\.\d{1,6}){1,4})', output, re.I)
    return {'version': match.group(1)} if match else {}


def _tools(deadline: float) -> dict[str, Any]:
    out = {}
    for name, args in _TOOLS.items():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            out[name] = {'status': 'budget_exhausted'}
            continue
        path = _find_tool(name)
        if path is None:
            out[name] = {'status': 'missing'}
            continue
        try:
            resolved, metadata = _verified_executable(path)
            if metadata.get('status') != 'ok':
                out[name] = metadata
                continue
            status, code, output = _run_fixed((str(resolved), *args), min(TOOL_TIMEOUT_SECONDS, remaining))
            metadata.update(status=status, exit_code=code)
            version = _tool_version(name, output)
            if version:
                metadata.update(version)
            elif status == 'ok' and code == 0:
                metadata['status'] = 'version_unparseable'
            if status == 'ok' and code:
                metadata['status'] = 'command_failed'
            out[name] = metadata
        except OSError as exc:
            out[name] = _error(exc)
    return out


def _darwin_probe(key: str, deadline: float) -> dict[str, Any]:
    # All keys passed by this module are literals, never caller-provided values.
    if time.monotonic() >= deadline:
        return {'status': 'budget_exhausted'}
    status, code, text = _run_fixed(('/usr/sbin/sysctl', '-n', key), min(0.25, deadline - time.monotonic()))
    if status != 'ok' or code:
        return {'status': status if status != 'ok' else 'unavailable'}
    text = text.strip()
    if text.isdigit() and len(text) <= 20:
        return {'status': 'ok', 'value': int(text)}
    if key == 'vm.swapusage':
        values = {label + '_bytes': int(float(value) * 1024 * 1024) for label, value in re.findall(r'\b(total|used|free) = (\d{1,12}(?:\.\d{1,6})?)M', text)}
        return {'status': 'ok', **values} if values else {'status': 'unparseable'}
    if key == 'kern.boottime':
        match = re.search(r'\bsec = (\d{1,20})', text)
        if match:
            return {'status': 'ok', 'epoch_seconds': int(match.group(1))}
    if key in ('machdep.cpu.features', 'machdep.cpu.leaf7_features', 'machdep.cpu.extfeatures'):
        return {'status': 'ok', 'features': _feature_list(text)}
    return {'status': 'unparseable'}


def collect_host_diagnostics(workspace_roots: Sequence[Path | str] = (), *,
                             include_tool_versions: bool = True) -> dict[str, Any]:
    """Return JSON-safe technical inventory without touching workspace contents.

    At most eight supplied roots are stat'ed and identified only as workspace_1,
    etc. Call from a worker thread; fixed version commands have a 750 ms deadline
    each and the collection has an eight-second command budget. Set
    include_tool_versions=False for an immediate snapshot with no subprocesses.
    Missing access,
    symlinks, unsupported interfaces and exhausted budgets remain explicit.
    """
    started = time.monotonic()
    deadline = started + COLLECTION_SECONDS
    system = platform.system()
    report: dict[str, Any] = {'schema_version': SCHEMA_VERSION, 'status': 'ok',
        'captured_at_epoch': round(time.time(), 3),
        'limits': {'os_file_bytes': MAX_OS_FILE_BYTES, 'tool_output_bytes': MAX_TOOL_OUTPUT_BYTES,
                   'tool_timeout_seconds': TOOL_TIMEOUT_SECONDS, 'command_budget_seconds': COLLECTION_SECONDS,
                   'workspace_roots': MAX_WORKSPACES},
        'content_policy': 'technical_values_only_no_content_paths_accounts_argv_environment',
        'os': _os_state(), 'process': _process_state(system), 'load_average': _load_average(),
        'runtime': {'python_version': _version(platform.python_version()),
                    'python_implementation': platform.python_implementation() if platform.python_implementation() in ('CPython', 'PyPy', 'GraalVM', 'Jython', 'IronPython') else 'other',
                    'sqlite_version': _version(sqlite3.sqlite_version)},
        'filesystems': [_filesystem(Path('/'), 'system_root')],
        'dependencies': {},
    }
    try:
        report['filesystems'].append(_filesystem(Path.cwd(), 'application_current_directory'))
    except OSError as exc:
        report['filesystems'].append({'role': 'application_current_directory', **_error(exc)})
    if isinstance(workspace_roots, (list, tuple)):
        for index, root in enumerate(workspace_roots[:MAX_WORKSPACES], 1):
            role = 'workspace_' + str(index)
            if not isinstance(root, (str, Path)):
                report['filesystems'].append({'role': role, 'status': 'unsafe_path'})
            else:
                report['filesystems'].append(_filesystem(Path(root), role))
        report['workspace_roots_omitted'] = max(0, len(workspace_roots) - MAX_WORKSPACES)
    for name in _DEPENDENCIES:
        try:
            version = _version(importlib.metadata.version(name))
            report['dependencies'][name] = {'status': 'ok', 'version': version} if version else {'status': 'version_unparseable'}
        except importlib.metadata.PackageNotFoundError:
            report['dependencies'][name] = {'status': 'missing'}
        except (OSError, ValueError):
            report['dependencies'][name] = {'status': 'unavailable'}
    if system == 'Linux':
        report.update(cpu=_linux_cpu(), memory=_linux_memory(), cgroup=_linux_cgroup(), pressure=_pressure(),
                      kvm=_file_metadata(Path('/dev/kvm'), device=True),
                      firmware={name: _file_metadata(Path(path)) for name, path in _FIRMWARE.items()})
        try:
            uptime = _read_os_file(Path('/proc/uptime'), 256).split()[0]
            report['uptime'] = {'status': 'ok', 'seconds': float(uptime)} if re.fullmatch(r'\d{1,15}(?:\.\d{1,6})?', uptime) else {'status': 'unparseable'}
        except (OSError, _ProbeError, IndexError, ValueError) as exc:
            report['uptime'] = _error(exc)
    elif system == 'Darwin' and include_tool_versions:
        report['cpu'] = {key.replace('.', '_'): _darwin_probe(key, deadline) for key in ('hw.logicalcpu', 'hw.physicalcpu', 'machdep.cpu.features', 'machdep.cpu.leaf7_features', 'machdep.cpu.extfeatures')}
        report['memory'] = {'status': 'ok', 'total_bytes': _darwin_probe('hw.memsize', deadline), 'swap': _darwin_probe('vm.swapusage', deadline)}
        report['hypervisor'] = _darwin_probe('kern.hv_support', deadline)
        report['boot_time'] = _darwin_probe('kern.boottime', deadline)
        report['cgroup'] = {'status': 'not_applicable'}
        report['kvm'] = {'status': 'not_applicable'}
        report['firmware'] = {'status': 'system_managed'}
    else:
        for key in ('cpu', 'memory', 'cgroup', 'kvm', 'firmware', 'uptime'):
            report[key] = {'status': 'not_collected' if system == 'Darwin' else 'unsupported_platform'}
    report['tools'] = _tools(deadline) if include_tool_versions else {name: {'status': 'not_collected', 'reason': 'snapshot'} for name in _TOOLS}
    report['collection_duration_seconds'] = round(time.monotonic() - started, 3)
    report['command_budget_exhausted'] = time.monotonic() > deadline
    return report


def collect_resource_snapshot(workspace_roots: Sequence[Path | str] = ()) -> dict[str, Any]:
    """Capture operation-time resource evidence without any child processes.

    This is separate from the export-time inventory: an export taken hours later
    cannot prove the resource conditions when a VM operation failed. Only fixed
    numeric OS interfaces and filesystem capacity metadata are inspected here.
    """
    started = time.monotonic()
    system = platform.system()
    report: dict[str, Any] = {
        'schema_version': SCHEMA_VERSION, 'status': 'ok', 'capture_scope': 'current_host_resources',
        'captured_at_epoch': round(time.time(), 3),
        'platform': system if system in ('Linux', 'Darwin', 'Windows', 'FreeBSD') else 'other',
        'process': _process_state(system), 'load_average': _load_average(),
        'pressure': _pressure() if system == 'Linux' else {'status': 'not_applicable'},
        'memory': _linux_memory() if system == 'Linux' else {'status': 'not_collected'},
        'cgroup': _linux_cgroup() if system == 'Linux' else {'status': 'not_applicable'},
        'filesystems': [_filesystem(Path('/'), 'system_root')],
    }
    if isinstance(workspace_roots, (tuple, list)):
        for index, root in enumerate(workspace_roots[:MAX_WORKSPACES], 1):
            role = 'workspace_' + str(index)
            report['filesystems'].append(_filesystem(Path(root), role) if isinstance(root, (str, Path)) else {'role': role, 'status': 'unsafe_path'})
    report['collection_duration_seconds'] = round(time.monotonic() - started, 3)
    return report

# Typed projections are also used for receipts loaded from disk. A log event is
# untrusted input: callers must not bypass their privacy boundary merely because
# the live collector itself emits content-free values.
_STATUSES = frozenset({'ok', 'missing', 'permission_denied', 'unavailable', 'unsafe_path',
    'symlink_redirect', 'wrong_type', 'changed_during_read', 'truncated', 'unparseable',
    'budget_exhausted', 'timeout', 'output_limit', 'cleanup_timeout', 'version_unparseable',
    'command_failed', 'not_collected', 'not_applicable', 'unsupported_platform',
    'system_managed', 'unsafe_proc_self_reference', 'unsafe_executable_permissions'})
_PROCESS_NUMBERS = frozenset({'pid', 'uid', 'euid', 'gid', 'egid', 'VmPeak', 'VmSize',
    'VmRSS', 'RssAnon', 'RssFile', 'RssShmem', 'VmSwap', 'VmData', 'VmStk', 'VmExe',
    'VmLib', 'VmPTE', 'VmHWM', 'Threads', 'FDSize', 'voluntary_ctxt_switches',
    'nonvoluntary_ctxt_switches', 'NoNewPrivs', 'Seccomp', 'open_fd_count',
    'cpu_user_seconds', 'cpu_system_seconds', 'max_rss_bytes', 'major_faults', 'minor_faults'})
_FS_NUMBERS = frozenset({'total_bytes', 'available_bytes', 'free_bytes', 'inode_total',
    'inode_available', 'inode_free', 'block_size'})
_CPU_NUMBERS = frozenset({'logical_cpu_count', 'cpu_family', 'model', 'stepping',
    'cpu_architecture', 'cpu_variant', 'cpu_part', 'cpu_revision', 'process_affinity_cpu_count'})


def _valid_number(value: Any) -> bool:
    return type(value) in (int, float) and abs(value) <= 2**63 - 1 and math.isfinite(value)


def _project(value: Any, numbers: Sequence[str] | frozenset[str] = (), *, booleans: Sequence[str] = ()) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {'status': 'unavailable'}
    result: dict[str, Any] = {}
    if isinstance(value.get('status'), str) and value['status'] in _STATUSES:
        result['status'] = value['status']
    if type(value.get('errno')) is int and 0 <= value['errno'] <= 4096:
        result['errno'] = value['errno']
    for key in numbers:
        if _valid_number(value.get(key)):
            result[key] = value[key]
    for key in booleans:
        if type(value.get(key)) is bool:
            result[key] = value[key]
    return result


def _project_process(value: Any) -> dict[str, Any]:
    result = _project(value, _PROCESS_NUMBERS, booleans=('open_fd_count_capped',))
    if not isinstance(value, dict):
        return result
    if value.get('scope') == 'harnessy_process_only':
        result['scope'] = 'harnessy_process_only'
    if isinstance(value.get('supplementary_group_ids'), list):
        result['supplementary_group_ids'] = [item for item in value['supplementary_group_ids'][:256] if type(item) is int and 0 <= item <= 2**32 - 1]
    for key in ('proc_status',):
        if isinstance(value.get(key), dict):
            result[key] = _project(value[key])
    for key in ('groups_status', 'resource_status'):
        if value.get(key) == 'unavailable':
            result[key] = 'unavailable'
    if isinstance(value.get('limits'), dict):
        result['limits'] = {}
        for key in ('nofile', 'nproc', 'as', 'data', 'stack', 'memlock', 'core', 'cpu', 'fsize'):
            item = value['limits'].get(key)
            if isinstance(item, dict):
                result['limits'][key] = {label: item[label] for label in ('soft', 'hard') if _valid_number(item.get(label)) or item.get(label) == 'unlimited'}
    return result


def _project_memory(value: Any) -> dict[str, Any]:
    result = _project(value, _MEM_KEYS)
    if isinstance(value, dict):
        if isinstance(value.get('total_bytes'), dict):
            result['total_bytes'] = _project(value['total_bytes'], ('value',))
        if isinstance(value.get('swap'), dict):
            result['swap'] = _project(value['swap'], ('total_bytes', 'used_bytes', 'free_bytes'))
    return result


def _project_filesystems(value: Any) -> list[dict[str, Any]]:
    result = []
    if not isinstance(value, list):
        return result
    for item in value[:MAX_WORKSPACES + 2]:
        if not isinstance(item, dict):
            continue
        role = item.get('role')
        if role not in ('system_root', 'application_current_directory') and not (isinstance(role, str) and re.fullmatch(r'workspace_[1-8]', role)):
            continue
        result.append({'role': role, **_project(item, _FS_NUMBERS, booleans=('read_only',))})
    return result


def _project_cgroup(value: Any) -> dict[str, Any]:
    result = _project(value, booleans=('paths_omitted',))
    if not isinstance(value, dict) or not isinstance(value.get('groups'), list):
        return result
    result['groups'] = []
    for group in value['groups'][:64]:
        if not isinstance(group, dict) or type(group.get('version')) is not int or group['version'] not in (1, 2):
            continue
        out: dict[str, Any] = {'version': group['version'], **_project(group)}
        if group.get('scope') in ('process_membership', 'mounted_root_fallback'):
            out['scope'] = group['scope']
        if group.get('controller') in ('memory', 'cpu', 'cpuacct', 'cpuset', 'pids'):
            out['controller'] = group['controller']
        if isinstance(group.get('files'), dict):
            out['files'] = {}
            for name in _CGROUP_FILES[group['version']]:
                item = group['files'].get(name)
                if not isinstance(item, dict):
                    continue
                entry = _project(item, ('value', 'quota_us', 'period_us'))
                for key in ('value', 'quota_us'):
                    if item.get(key) == 'unlimited':
                        entry[key] = 'unlimited'
                ranges = item.get('cpu_ranges')
                if isinstance(ranges, str) and re.fullmatch(r'[0-9,-]{0,1024}', ranges):
                    entry['cpu_ranges'] = ranges
                if isinstance(item.get('counters'), dict):
                    entry['counters'] = _project(item['counters'], _CGROUP_COUNTERS)
                out['files'][name] = entry
        result['groups'].append(out)
    return result


def _project_pressure(value: Any) -> dict[str, Any]:
    result = _project(value)
    if not isinstance(value, dict):
        return result
    for key in ('cpu', 'memory', 'io'):
        item = value.get(key)
        if not isinstance(item, dict):
            continue
        out = _project(item)
        for kind in ('some', 'full'):
            if isinstance(item.get(kind), dict):
                out[kind] = _project(item[kind], ('avg10', 'avg60', 'avg300', 'total_stall_microseconds'))
        result[key] = out
    return result


def validate_resource_snapshot(value: Any) -> dict[str, Any]:
    """Strict content-free projection for persisted operation-time receipts."""
    if not isinstance(value, dict) or value.get('capture_scope') != 'current_host_resources':
        return {'schema_version': SCHEMA_VERSION, 'status': 'unavailable'}
    result = _project(value, ('captured_at_epoch', 'collection_duration_seconds'))
    result.update(schema_version=SCHEMA_VERSION, capture_scope='current_host_resources')
    if isinstance(value.get('collection_error'), dict):
        from .technical import validate_technical_evidence
        result['collection_error'] = validate_technical_evidence(value['collection_error'])
    if value.get('platform') in ('Linux', 'Darwin', 'Windows', 'FreeBSD', 'other'):
        result['platform'] = value['platform']
    result.update(process=_project_process(value.get('process')), memory=_project_memory(value.get('memory')),
                  cgroup=_project_cgroup(value.get('cgroup')), pressure=_project_pressure(value.get('pressure')),
                  load_average=_project(value.get('load_average'), ('one_minute', 'five_minutes', 'fifteen_minutes')),
                  filesystems=_project_filesystems(value.get('filesystems')))
    return result


def validate_host_diagnostics(value: Any) -> dict[str, Any]:
    """Validate both fresh and persisted full inventory; never pass raw strings."""
    if not isinstance(value, dict):
        return {'schema_version': SCHEMA_VERSION, 'status': 'unavailable'}
    result = _project(value, ('captured_at_epoch', 'collection_duration_seconds', 'workspace_roots_omitted'), booleans=('command_budget_exhausted',))
    result['schema_version'] = SCHEMA_VERSION
    result['content_policy'] = 'technical_values_only_no_content_paths_accounts_argv_environment'
    result.update(process=_project_process(value.get('process')), memory=_project_memory(value.get('memory')),
                  cgroup=_project_cgroup(value.get('cgroup')), pressure=_project_pressure(value.get('pressure')),
                  load_average=_project(value.get('load_average'), ('one_minute', 'five_minutes', 'fifteen_minutes')),
                  filesystems=_project_filesystems(value.get('filesystems')))
    if isinstance(value.get('limits'), dict):
        result['limits'] = _project(value['limits'], ('os_file_bytes', 'tool_output_bytes', 'tool_timeout_seconds', 'command_budget_seconds', 'workspace_roots'))
    original_os = value.get('os')
    if isinstance(original_os, dict):
        out = _project(original_os, ('pointer_bits',))
        for key, allowed in (('system', ('Linux', 'Darwin', 'Windows', 'FreeBSD', 'other')), ('architecture', (*set(_ARCHES.values()), 'other'))):
            if original_os.get(key) in allowed:
                out[key] = original_os[key]
        for key in ('kernel_version', 'os_version'):
            version = original_os.get(key)
            if isinstance(version, str) and re.fullmatch(r'\d{1,6}(?:\.\d{1,6}){1,4}', version):
                out[key] = version
        variants = original_os.get('kernel_variants')
        if isinstance(variants, list):
            out['kernel_variants'] = [item for item in variants[:8] if item in ('nvidia', 'generic', 'azure', 'aws', 'microsoft', 'wsl', 'raspi', 'lowlatency')]
        distro = original_os.get('distribution')
        if isinstance(distro, dict):
            out['distribution'] = _project(distro)
            if distro.get('id') in (*_DISTROS, 'other'):
                out['distribution']['id'] = distro['id']
            version = distro.get('version')
            if isinstance(version, str) and re.fullmatch(r'\d{1,6}(?:\.\d{1,6}){0,3}', version):
                out['distribution']['version'] = version
        result['os'] = out
    original_cpu = value.get('cpu')
    if isinstance(original_cpu, dict):
        cpu = _project(original_cpu, _CPU_NUMBERS)
        if isinstance(original_cpu.get('features'), list):
            cpu['features'] = [item for item in original_cpu['features'][:256] if isinstance(item, str) and item in _FEATURES]
        for key, allowed in (('vendor', ('intel', 'amd', 'arm', 'nvidia', 'apple', 'other')), ('source_scope', ('bounded_cpuinfo_prefix',)), ('socket_count_status', ('not_collected_prefix_could_be_incomplete',)), ('affinity_status', ('unavailable',))):
            if original_cpu.get(key) in allowed:
                cpu[key] = original_cpu[key]
        for key in ('hw_logicalcpu', 'hw_physicalcpu', 'machdep_cpu_features', 'machdep_cpu_leaf7_features', 'machdep_cpu_extfeatures'):
            item = original_cpu.get(key)
            if isinstance(item, dict):
                cpu[key] = _project(item, ('value',))
                if isinstance(item.get('features'), list):
                    cpu[key]['features'] = [feature for feature in item['features'][:256] if isinstance(feature, str) and feature in _FEATURES]
        result['cpu'] = cpu
    for key, fields in (('uptime', ('seconds',)), ('boot_time', ('epoch_seconds',)), ('hypervisor', ('value',))):
        if isinstance(value.get(key), dict):
            result[key] = _project(value[key], fields)
    metadata_numbers = ('bytes', 'uid', 'gid', 'modified_at_epoch')
    def metadata(item: Any) -> dict[str, Any]:
        out = _project(item, metadata_numbers, booleans=('readable', 'writable'))
        if isinstance(item, dict) and isinstance(item.get('mode'), str) and re.fullmatch(r'[0-7]{4}', item['mode']):
            out['mode'] = item['mode']
        return out
    result['kvm'] = metadata(value.get('kvm'))
    result['firmware'] = _project(value.get('firmware'))
    if isinstance(value.get('firmware'), dict):
        for key in _FIRMWARE:
            if isinstance(value['firmware'].get(key), dict):
                result['firmware'][key] = metadata(value['firmware'][key])
    for section, keys in (('runtime', ('python_version', 'sqlite_version')), ('dependencies', _DEPENDENCIES), ('tools', tuple(_TOOLS))):
        source = value.get(section)
        if not isinstance(source, dict):
            continue
        result[section] = {}
        for key in keys:
            item = source.get(key)
            if section == 'runtime':
                if isinstance(item, str) and re.fullmatch(r'\d{1,6}(?:\.\d{1,6}){1,4}', item):
                    result[section][key] = item
                continue
            if not isinstance(item, dict):
                continue
            out = _project(item, ('exit_code', 'patchlevel'), booleans=('symlink', 'executable'))
            version = item.get('version')
            if isinstance(version, str) and re.fullmatch(r'\d{1,6}(?:\.\d{1,6}){1,4}', version):
                out['version'] = version
            if item.get('discovery') == 'fixed_name_search':
                out['discovery'] = 'fixed_name_search'
            if item.get('reason') == 'snapshot':
                out['reason'] = 'snapshot'
            result[section][key] = out
        if section == 'runtime' and source.get('python_implementation') in ('CPython', 'PyPy', 'GraalVM', 'Jython', 'IronPython', 'other'):
            result[section]['python_implementation'] = source['python_implementation']
    return result
