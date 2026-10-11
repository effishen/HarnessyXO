from __future__ import annotations

import os
import stat
from pathlib import Path

# src/harnessy/core/paths.py -> application root is three parents above src/.
APP_ROOT = Path(__file__).resolve().parents[3]


def settings_path() -> Path:
    """Return the configured machine-settings path without creating it."""
    override = os.environ.get('HARNESSY_SETTINGS_DIR')
    path = Path(override).expanduser() if override else APP_ROOT / '.settings'
    # Preserve the final path component. UserStore must be able to reject a
    # settings-root symlink instead of receiving its already-resolved target.
    return path.absolute()


def _tighten_owned_settings_directory(path: Path) -> None:
    """Make a real, current-user-owned POSIX settings directory private.

    Shared Linux systems commonly use umask 0002. A plain mkdir would then
    create `.settings` as 0775 and the credential store correctly refuses it.
    Open the directory without following its final component and repair only a
    directory already owned by this process. Wrong-owner and symlinked paths
    are deliberately left untouched for UserStore to reject.
    """
    if os.name == 'nt':
        return
    flags = os.O_RDONLY
    flags |= getattr(os, 'O_DIRECTORY', 0)
    flags |= getattr(os, 'O_NOFOLLOW', 0)
    flags |= getattr(os, 'O_CLOEXEC', 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return
    try:
        info = os.fstat(descriptor)
        if (
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) != 0o700
        ):
            os.fchmod(descriptor, 0o700)
    finally:
        os.close(descriptor)


def settings_dir() -> Path:
    """Return HarnessyXO's persistent machine settings directory, creating it."""
    path = settings_path()
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    _tighten_owned_settings_directory(path)
    return path


def machine_state_dir() -> Path:
    """Backward-compatible alias used by older modules/tests."""
    return settings_dir()
