"""Small host-platform helpers kept free of UI/runtime dependencies."""
from __future__ import annotations

import os
import platform
import subprocess
import webbrowser
from collections.abc import Mapping


def browser_autostart_available(*, host_os: str | None = None,
                                environ: Mapping[str, str] | None = None) -> bool:
    """Return whether opening a local browser is sensible for this host session.

    Linux hosts are frequently headless servers reached over SSH.  Avoid an
    automatic ``webbrowser`` launch there unless a graphical session (X11 or
    Wayland) or an explicit BROWSER command is advertised.  The HarnessyXO URL
    remains available in stdout either way.  macOS keeps its normal desktop
    launch-service behavior.
    """
    system = str(host_os or platform.system())
    env = os.environ if environ is None else environ
    if system == 'Linux':
        return any(str(env.get(name) or '').strip()
                   for name in ('DISPLAY', 'WAYLAND_DISPLAY', 'BROWSER'))
    return True

def open_browser_url(url: str, *, host_os: str | None = None) -> bool:
    """Open a URL with the host-native launcher without shelling through AppleScript.

    On macOS, Python's ``webbrowser`` fallback chain can emit noisy AppleScript
    errors (for example trying literal applications named ``chrome`` or
    ``firefox``). ``/usr/bin/open`` delegates to LaunchServices directly and
    returns promptly. Output is intentionally suppressed because URLs may be
    private. This utility is not used to launch a browser at app startup.
    """
    system = str(host_os or platform.system())
    if system == 'Darwin':
        try:
            result = subprocess.run(
                ['/usr/bin/open', str(url)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                check=False, timeout=8,
            )
            return result.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False
    try:
        return bool(webbrowser.open(str(url)))
    except Exception:
        return False
