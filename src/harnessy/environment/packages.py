"""Package-manager-specific operations for supported systemd Linux guests only."""
from __future__ import annotations
import shlex


def package_commands(manager: str) -> tuple[str, str, str]:
    if manager == 'apt':
        return ('apt-get update', 'apt-get install -y', "dpkg-query -W -f='${Status}' \"$pkg\" 2>/dev/null | grep -qx 'install ok installed'")
    if manager == 'dnf':
        return ('dnf makecache -y', 'dnf install -y', 'rpm -q "$pkg" >/dev/null 2>&1')
    raise ValueError(f'No package adapter for {manager!r}; guest integration is unavailable.')


def missing_packages_script(manager: str, packages: tuple[str, ...]) -> str:
    _, _, check = package_commands(manager)
    return 'for pkg in ' + ' '.join(shlex.quote(p) for p in packages) + '; do if ! ' + check + "; then printf '%s\\n' \"$pkg\"; fi; done"
