"""Validated workspace resource changes and fixed Lima resource projections."""
from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any

from .base import EnvironmentConfig


def _number(value: Any, label: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        raise ValueError(f'{label} must be a number.')
    try:
        number = Decimal(str(value).strip())
    except InvalidOperation as exc:
        raise ValueError(f'{label} must be a number.') from exc
    if not number.is_finite():
        raise ValueError(f'{label} must be a finite number.')
    return number


def resource_values(cpu: Any, memory_gib: Any, disk_gib: Any) -> dict[str, int]:
    """Parse editor values without silently rounding or clamping a request."""
    values = (_number(cpu, 'vCPU count'), _number(memory_gib, 'RAM'), _number(disk_gib, 'Storage'))
    cpus, ram, disk = values
    if cpus != cpus.to_integral_value() or not 1 <= cpus <= 64:
        raise ValueError('vCPU count must be a whole number from 1 to 64.')
    if not 1 <= ram <= 256 or ram * 1024 != (ram * 1024).to_integral_value():
        raise ValueError('RAM must be 1 to 256 GiB in whole MiB increments.')
    if disk != disk.to_integral_value() or not 16 <= disk <= 4096:
        raise ValueError('Storage must be a whole number from 16 to 4096 GiB.')
    return {'cpu': int(cpus), 'memory_mb': int(ram * 1024), 'disk_gb': int(disk)}


def changed_resources(config: EnvironmentConfig, *, cpu: Any, memory_mb: Any, disk_gb: Any) -> EnvironmentConfig:
    for value, label in ((cpu, 'vCPU count'), (memory_mb, 'RAM'), (disk_gb, 'Storage')):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f'{label} must be an integer in the resource request.')
    values = resource_values(cpu, Decimal(memory_mb) / 1024, disk_gb)
    if values['disk_gb'] < config.disk_gb:
        raise ValueError('Storage can only grow. Shrinking an existing workspace VM disk is not supported.')
    return EnvironmentConfig.from_dict({**config.to_dict(), **values})


def lima_resource_values(row: dict[str, Any]) -> dict[str, int]:
    """Read Lima list JSON byte fields; never infer missing controller values."""
    values = {}
    for key, alternate in (('cpus', 'CPUs'), ('memory', 'Memory'), ('disk', 'Disk')):
        value = row.get(key, row.get(alternate))
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise RuntimeError(f'Lima did not report a valid {key} value. No saved resource settings were changed.')
        values[key] = value
    return values


def resources_match(row: dict[str, Any], config: EnvironmentConfig) -> bool:
    return lima_resource_values(row) == {
        'cpus': config.cpu, 'memory': config.memory_mb * 1024 ** 2, 'disk': config.disk_gb * 1024 ** 3,
    }
