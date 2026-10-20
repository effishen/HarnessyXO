"""Bounded, read-only storage measurements for fixed VM filesystem roles."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import time

MAX_OUTPUT = 8192
ROLES = {'root', 'temporary'}
FS_KINDS = {'ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'tmpfs', 'ramfs',
            'overlay', 'ntfs', 'refs', 'vfat', 'zfs', 'other'}
LIMA_DISK_NAMES = ('disk', 'diffdisk', 'basedisk')
WINDOWS_DISK_NAMES = ('disk', 'diffdisk')  # basedisk may be installation ISO.

# Only fixed paths are inspected. stdout contains roles and numeric metadata,
# never a filesystem source, path, directory listing, or guest file contents.
OPENWRT_STORAGE_SCRIPT = r'''LC_ALL=C; export LC_ALL
printf 'HX_STORAGE_V1\n'
for role in root temporary; do
  case "$role" in root) p=/ ;; temporary) p=/tmp ;; esac
  kb=$(df -kP "$p" 2>/dev/null | awk 'NR == 2 { print $2, $3, $4 }')
  ino=$(df -iP "$p" 2>/dev/null | awk 'NR == 2 { print $2, $4 }')
  [ -n "$ino" ] || ino=$(stat -f -c '%c %d' "$p" 2>/dev/null)
  if [ -z "$ino" ] && command -v python3 >/dev/null 2>&1; then
    ino=$(python3 -I -S -B -c 'import os,sys; v=os.statvfs(sys.argv[1]); print(v.f_files,v.f_favail)' "$p" 2>/dev/null)
  fi
  [ -n "$ino" ] || ino='- -'
  magic=$(stat -f -c '%t' "$p" 2>/dev/null)
  case "$magic" in
    1021994) kind=tmpfs ;; 858458f6) kind=ramfs ;;
    58465342) kind=xfs ;; 9123683e) kind=btrfs ;; 794c7630) kind=overlay ;;
    *) kind=- ;;
  esac
  ro=$(awk -v p="$p" '$2 == p { if (("," $4 ",") ~ /,ro,/) print 1; else print 0; found=1; exit } END { if (!found) print "-" }' /proc/mounts 2>/dev/null)
  if [ "$kind" = - ]; then
    kind=$(awk -v p="$p" '$2 == p { print $3; found=1; exit } END { if (!found) print "-" }' /proc/mounts 2>/dev/null)
  fi
  printf 'HXFS %s %s %s %s %s\n' "$role" "$kb" "$ino" "$kind" "$ro"
done
'''

LINUX_STORAGE_PYTHON = r'''
import json, os
allowed={'ext2','ext3','ext4','xfs','btrfs','tmpfs','ramfs','overlay','ntfs','refs','vfat','zfs'}
mounts=[]
try:
 with open('/proc/self/mountinfo',encoding='utf-8') as stream: text=stream.read(1048577)
 if len(text)<=1048576:
  for line in text.splitlines():
   left,sep,right=line.partition(' - ')
   fields=left.split(); types=right.split()
   if sep and len(fields)>4 and types:
    p=fields[4]
    for old,new in [(r'\040',' '),(r'\011','\t'),(r'\012','\n'),(r'\134','\\')]: p=p.replace(old,new)
    mounts.append((p,types[0]))
except OSError: pass
rows=[]
for role,path in [('root','/'),('temporary','/tmp')]:
 try:
  v=os.statvfs(path); unit=v.f_frsize or v.f_bsize
  row={'role':role,'total_bytes':v.f_blocks*unit,'used_bytes':(v.f_blocks-v.f_bfree)*unit,
       'available_bytes':v.f_bavail*unit,'free_bytes':v.f_bfree*unit,
       'inodes_total':v.f_files,'inodes_available':v.f_favail,
       'read_only':bool(v.f_flag & getattr(os,'ST_RDONLY',1))}
  actual=os.path.realpath(path)
  candidates=[(len(p),kind) for p,kind in mounts if actual==p or actual.startswith(p.rstrip('/')+'/')]
  if candidates:
   kind=max(candidates)[1]; row['fs_kind']=kind if kind in allowed else 'other'
  rows.append(row)
 except OSError: pass
print(json.dumps({'schema_version':1,'filesystems':rows},separators=(',',':')))
'''


def unavailable_guest(code='GUEST_STORAGE_UNAVAILABLE', *, state='unavailable'):
    return {'state': state, 'filesystems': [], 'error_code': code}


def _integer(value):
    if isinstance(value, bool):
        raise ValueError('Invalid storage number.')
    if isinstance(value, str) and not value.isascii():
        raise ValueError('Invalid storage number.')
    if isinstance(value, str) and not value.isdecimal():
        raise ValueError('Invalid storage number.')
    if not isinstance(value, (str, int)):
        raise ValueError('Invalid storage number.')
    value = int(value)
    if not 0 <= value <= 2**63 - 1:
        raise ValueError('Storage number is out of range.')
    return value


def _filesystem(row):
    if not isinstance(row, dict) or row.get('role') not in ROLES:
        raise ValueError('Invalid storage role.')
    result = {'role': row['role']}
    for name in ('total_bytes', 'used_bytes', 'available_bytes', 'free_bytes'):
        result[name] = _integer(row[name])
    if (result['used_bytes'] + result['free_bytes'] != result['total_bytes'] or
            result['available_bytes'] > result['free_bytes']):
        raise ValueError('Inconsistent filesystem accounting.')
    for name in ('inodes_total', 'inodes_available'):
        if name in row:
            result[name] = _integer(row[name])
    if ('inodes_available' in result and 'inodes_total' in result and
            result['inodes_available'] > result['inodes_total']):
        raise ValueError('Inconsistent inode accounting.')
    if isinstance(row.get('read_only'), bool):
        result['read_only'] = row['read_only']
    kind = row.get('fs_kind')
    if kind in FS_KINDS:
        result['fs_kind'] = kind
        if kind in {'tmpfs', 'ramfs'}:
            result['memory_backed'] = True
        elif kind not in {'overlay', 'other'}:
            result['memory_backed'] = False
    return result


def parse_linux_storage(output):
    try:
        if isinstance(output, bytes):
            output = output.decode('ascii')
        if len(output) > MAX_OUTPUT:
            raise ValueError('Storage output exceeds its bound.')
        data = json.loads(output)
        rows = [_filesystem(row) for row in data['filesystems']]
        if type(data.get('schema_version')) is not int or data['schema_version'] != 1 or len(rows) != 2 or {row['role'] for row in rows} != ROLES:
            raise ValueError('Incomplete filesystem measurements.')
        return {'state': 'ready', 'filesystems': rows, 'error_code': ''}
    except (ValueError, TypeError, KeyError, UnicodeError):
        return unavailable_guest('GUEST_STORAGE_INVALID_OUTPUT')


def parse_openwrt_storage(output):
    try:
        if isinstance(output, bytes):
            output = output.decode('ascii')
        if len(output) > MAX_OUTPUT:
            raise ValueError('Storage output exceeds its bound.')
        lines = output.splitlines()
        if len(lines) != 3 or lines[0] != 'HX_STORAGE_V1':
            raise ValueError('Invalid storage response.')
        rows = []
        for line in lines[1:]:
            fields = line.split()
            if len(fields) != 9 or fields[0] != 'HXFS':
                raise ValueError('Invalid filesystem measurement.')
            _, role, total, used, available, inode_total, inode_available, kind, ro = fields
            total, used, available = (_integer(item) * 1024 for item in (total, used, available))
            row = {'role': role, 'total_bytes': total, 'used_bytes': used,
                   'available_bytes': available, 'free_bytes': total-used}
            if inode_total != '-' and inode_available != '-':
                row.update(inodes_total=_integer(inode_total), inodes_available=_integer(inode_available))
            if kind in FS_KINDS:
                row['fs_kind'] = kind
            if ro in {'0', '1'}:
                row['read_only'] = ro == '1'
            rows.append(row)
        return parse_linux_storage(json.dumps({'schema_version': 1, 'filesystems': rows}))
    except (ValueError, TypeError, UnicodeError):
        return unavailable_guest('GUEST_STORAGE_INVALID_OUTPUT')


def host_disk_usage(root: Path, names: tuple[str, ...]):
    """Stat only known private disk files, without following redirected paths."""
    logical = allocated = 0
    found = errors = 0
    allocation_known = True
    seen = set()
    fd = None
    try:
        root = Path(root)
        if not root.is_absolute() or any(part == '..' for part in root.parts):
            raise ValueError('Disk root must be absolute.')
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        fd = os.open(root.anchor, flags)
        for part in root.parts[1:]:
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd); fd = next_fd
        for name in names:
            if not name or '/' in name or '\\' in name or name in {'.', '..'}:
                raise ValueError('Invalid disk filename.')
            try:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode):
                    errors += 1; continue
                identity = (info.st_dev, info.st_ino)
                if identity in seen:
                    continue
                seen.add(identity); found += 1; logical += info.st_size
                blocks = getattr(info, 'st_blocks', None)
                if blocks is None:
                    allocation_known = False
                else:
                    allocated += blocks * 512
            except FileNotFoundError:
                continue
            except OSError:
                errors += 1
    except FileNotFoundError:
        pass
    except (OSError, ValueError, AttributeError):
        errors += 1
    finally:
        if fd is not None:
            os.close(fd)
    if not found:
        return {'state': 'unavailable', 'allocated_bytes': None, 'logical_bytes': None,
                'error_code': 'HOST_STORAGE_UNAVAILABLE' if errors else 'HOST_STORAGE_MISSING'}
    partial = bool(errors or not allocation_known)
    return {'state': 'partial' if partial else 'ready',
            'allocated_bytes': allocated if allocation_known else None, 'logical_bytes': logical,
            'error_code': 'HOST_STORAGE_PARTIAL' if partial else ''}


def storage_result(guest, host):
    if guest['state'] == 'stopped':
        state = 'stopped'
    elif guest['state'] == 'ready' and host['state'] == 'ready':
        state = 'ready'
    elif guest['state'] == 'ready' or host['state'] in {'ready', 'partial'}:
        state = 'partial'
    elif guest['state'] == 'unsupported':
        state = 'unsupported'
    else:
        state = 'unavailable'
    return {'schema_version': 1, 'state': state, 'captured_at': time.time(), 'guest': guest, 'host': host}
