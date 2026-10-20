"""Fixed, bounded Linux guest metadata probes; never inspect project contents."""
from __future__ import annotations

import math
import re
import time

MAX_OUTPUT = 4096
STORAGE_MARKER = '\nHX_STORAGE_BEGIN\n'
ERROR_CODES = {
    'GUEST_RESOURCES_STOPPED', 'GUEST_RESOURCES_UNSUPPORTED',
    'GUEST_RESOURCES_UNAVAILABLE', 'GUEST_RESOURCES_PROBE_FAILED',
    'GUEST_RESOURCES_INVALID_OUTPUT',
}

# Read only fixed kernel metadata, stop before /proc/stat's potentially large
# interrupt list, and emit only reviewed numeric fields. Original counter strings
# avoid awk's floating point rounding of large cumulative jiffy counts.
RESOURCE_SCRIPT = r'''LC_ALL=C; export LC_ALL
printf 'HX_RESOURCES_V1\n'
awk '
  NR > 16386 { exit }
  $1 == "cpu" { printf "HXCPU"; for (i=2;i<=9;i++) printf " %s", (i<=NF ? $i : "0"); print ""; next }
  $1 ~ /^cpu[0-9]+$/ { n++; next }
  n { print "HXCOUNT", n; exit }
  END { if (!n) print "HXCOUNT 0" }
' /proc/stat 2>/dev/null
awk '
  NR > 256 { exit }
  $1 ~ /^(MemTotal:|MemFree:|MemAvailable:|Buffers:|Cached:|SReclaimable:|Shmem:|SwapTotal:|SwapFree:)$/ && $3 == "kB" { v[$1]=$2 }
  END {
    split("MemTotal: MemFree: MemAvailable: Buffers: Cached: SReclaimable: Shmem: SwapTotal: SwapFree:", keys, " ");
    printf "HXMEM"; for(i=1;i<=9;i++) printf " %s", (keys[i] in v ? v[keys[i]] : "-"); print ""
  }
' /proc/meminfo 2>/dev/null
awk 'NR == 1 { print "HXLOAD", $1, $2, $3; exit }' /proc/loadavg 2>/dev/null
awk 'NR == 1 { print "HXUPTIME", $1; exit }' /proc/uptime 2>/dev/null
printf 'HXEND\n'
'''


def unavailable_resources(code='GUEST_RESOURCES_UNAVAILABLE', *, state='unavailable'):
    if state not in {'unavailable', 'unsupported', 'stopped'}:
        state = 'unavailable'
    if code not in ERROR_CODES:
        code = 'GUEST_RESOURCES_UNAVAILABLE'
    return {
        'schema_version': 1, 'state': state, 'captured_at': time.time(),
        'cpu': {'state': state, 'logical_count': None, 'usage_percent': None,
                'iowait_percent': None, 'steal_percent': None, 'sample_seconds': None},
        'memory': {'state': state, 'total_bytes': None, 'available_bytes': None,
                   'used_bytes': None, 'cache_bytes': None, 'buffers_bytes': None},
        'swap': {'state': state, 'total_bytes': None, 'used_bytes': None, 'free_bytes': None},
        'load': {'state': state, 'one': None, 'five': None, 'fifteen': None},
        'uptime_seconds': None, 'error_code': code,
    }


def _integer(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]{1,20}', value, re.ASCII):
        raise ValueError('Invalid resource counter.')
    number = int(value)
    if number > 2**63 - 1:
        raise ValueError('Resource counter is out of range.')
    return number


def _decimal(value):
    if not re.fullmatch(r'[0-9]{1,12}(?:\.[0-9]{1,9})?', value, re.ASCII):
        raise ValueError('Invalid resource rate.')
    number = float(value)
    if not math.isfinite(number):
        raise ValueError('Invalid resource rate.')
    return number


def parse_resources(output):
    """Parse a fixed numeric receipt, keeping cumulative CPU ticks private."""
    try:
        if isinstance(output, bytes):
            output = output.decode('ascii')
        if not isinstance(output, str) or len(output) > MAX_OUTPUT:
            raise ValueError('Resource output exceeds its bound.')
        lines = output.splitlines()
        if len(lines) != 7 or lines[0] != 'HX_RESOURCES_V1' or lines[-1] != 'HXEND':
            raise ValueError('Invalid resource framing.')
        rows = [line.split() for line in lines[1:-1]]
        if [(row[0], len(row)) for row in rows] != [
            ('HXCPU', 9), ('HXCOUNT', 2), ('HXMEM', 10), ('HXLOAD', 4), ('HXUPTIME', 2)
        ]:
            raise ValueError('Invalid resource fields.')
        ticks = [_integer(value) for value in rows[0][1:]]
        count = _integer(rows[1][1])
        if not 1 <= count <= 16384 or sum(ticks) > 2**63 - 1:
            raise ValueError('Invalid guest CPU counters.')
        # user/nice already include guest/guest_nice; those extra fields must
        # never be added a second time. The wire carries exactly the first eight.
        total_ticks = sum(ticks)
        memory = [None if value == '-' else _integer(value) * 1024 for value in rows[2][1:]]
        total, free, available, buffers, cached, reclaimable, shared, swap_total, swap_free = memory
        if any(value is None for value in (total, free, buffers, cached, reclaimable, shared, swap_total, swap_free)):
            raise ValueError('Incomplete guest memory measurements.')
        if total <= 0 or any(value > 2**63 - 1 for value in memory if value is not None):
            raise ValueError('Invalid guest memory size.')
        if free > total or buffers > total or swap_free > swap_total:
            raise ValueError('Inconsistent guest memory accounting.')
        cache = min(total, max(0, cached + reclaimable - shared))
        estimated = available is None
        if estimated:
            available = min(total, free + buffers + cache)
        elif available > total:
            raise ValueError('Inconsistent available memory.')
        load = [_decimal(value) for value in rows[3][1:]]
        uptime = _decimal(rows[4][1])
        return {
            'schema_version': 1, 'state': 'partial', 'captured_at': time.time(),
            'cpu': {'state': 'pending', 'logical_count': count, 'usage_percent': None,
                    'iowait_percent': None, 'steal_percent': None, 'sample_seconds': None},
            'memory': {'state': 'ready', 'total_bytes': total, 'available_bytes': available,
                       'used_bytes': total - available, 'cache_bytes': cache, 'buffers_bytes': buffers,
                       'available_source': 'estimated' if estimated else 'mem_available',
                       'available_estimated': estimated},
            'swap': {'state': 'ready', 'total_bytes': swap_total,
                     'used_bytes': swap_total - swap_free, 'free_bytes': swap_free},
            'load': dict(state='ready', **dict(zip(('one', 'five', 'fifteen'), load))),
            'uptime_seconds': uptime, 'error_code': '',
            '_cpu_sample': {'total_ticks': total_ticks, 'idle_ticks': ticks[3],
                            'iowait_ticks': ticks[4], 'steal_ticks': ticks[7],
                            'logical_count': count, 'uptime_seconds': uptime},
        }
    except (ValueError, TypeError, IndexError, UnicodeError):
        return unavailable_resources('GUEST_RESOURCES_INVALID_OUTPUT')


def build_usage_script(storage_script=None):
    """Combine fixed probes in one guest transport without installing anything."""
    return RESOURCE_SCRIPT if storage_script is None else RESOURCE_SCRIPT + "\nprintf 'HX_STORAGE_BEGIN\\n'\n" + storage_script


def parse_usage_output(output, *, include_storage, storage_parser=None):
    from .storage_probe import MAX_OUTPUT as STORAGE_MAX, unavailable_guest
    try:
        if isinstance(output, bytes):
            output = output.decode('ascii')
        if not isinstance(output, str) or len(output) > MAX_OUTPUT + STORAGE_MAX:
            raise ValueError('Usage output exceeds its bound.')
        if include_storage:
            resource_output, marker, storage_output = output.partition(STORAGE_MARKER)
            if not marker or STORAGE_MARKER in storage_output:
                raise ValueError('Invalid usage framing.')
            resources = parse_resources(resource_output)
            guest_storage = storage_parser(storage_output)
        else:
            resources = parse_resources(output)
            guest_storage = None
        return resources, guest_storage
    except (ValueError, TypeError, UnicodeError):
        return unavailable_resources('GUEST_RESOURCES_INVALID_OUTPUT'), unavailable_guest('GUEST_STORAGE_INVALID_OUTPUT') if include_storage else None
