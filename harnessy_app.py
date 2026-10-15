#!/usr/bin/env python3
"""Internal HarnessyXO application entry point.

The normal user-facing launcher is ``run.py``. The canonical source layout is::

    run.py
    harnessy_app.py
    src/harnessy/
    .vendor/

It also tolerates older ``harnessy/``-beside-run.py releases and the flattened
layout produced by some archive/file-manager workflows where ``agent/``,
``core/``, ``ui/`` and ``__init__.py`` land directly in the outer folder.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parent
from harnessy_update import (
    StartupAlreadyRunning, StartupLockUnsafe, acquire_install_lock, validate_direct_start,
)

try:
    _INSTALL_LOCK = acquire_install_lock(APP_ROOT)
    # The launcher needs this descriptor across exec handoffs. The final app
    # does not: native VM children must never retain its lifetime lock.
    _INSTALL_LOCK.prevent_child_inheritance()
except StartupAlreadyRunning:
    message = "A process still holds this folder's HarnessyXO launch lock."
    if os.name != 'nt':
        command = ('fuser -v .harnessy-update.lock' if sys.platform.startswith('linux')
                   else 'lsof .harnessy-update.lock')
        message += ("\nA child process may still hold it after the app stops."
                    "\nFrom the HarnessyXO folder, inspect it with:\n  " + command)
    raise SystemExit(message)
except StartupLockUnsafe as exc:
    code = getattr(exc.__cause__, 'errno', None)
    detail = f" (OS error {code})" if type(code) is int else ""
    raise SystemExit("HarnessyXO cannot safely lock this installation" + detail +
                     ". Check the folder permissions and update lock file.")
if validate_direct_start(APP_ROOT)["fatal"]:
    raise SystemExit("A previous startup update needs verification. Run python3 run.py before opening HarnessyXO directly.")
os.environ.setdefault("HARNESSY_APP_ROOT", str(APP_ROOT))
VENDOR_DIR = APP_ROOT / ".vendor"
SRC_DIR = APP_ROOT / "src"
CANONICAL_PACKAGE = SRC_DIR / "harnessy"
LEGACY_PACKAGE = APP_ROOT / "harnessy"
FLAT_PACKAGE_MARKERS = [
    APP_ROOT / "__init__.py",
    APP_ROOT / "agent",
    APP_ROOT / "core",
    APP_ROOT / "ui",
]


def prepend(path: Path) -> None:
    value = str(path)
    if value not in sys.path:
        sys.path.insert(0, value)


if VENDOR_DIR.is_dir():
    prepend(VENDOR_DIR)

if CANONICAL_PACKAGE.joinpath("__init__.py").is_file():
    prepend(SRC_DIR)
elif LEGACY_PACKAGE.joinpath("__init__.py").is_file():
    prepend(APP_ROOT)
elif all(marker.exists() for marker in FLAT_PACKAGE_MARKERS):
    # The outer directory itself has become the ``harnessy`` package. Import
    # it through its parent directory so ``import harnessy`` resolves here.
    prepend(APP_ROOT.parent)
else:
    raise SystemExit(
        "HarnessyXO cannot find its internal application package.\n\n"
        f"Preferred layout: {CANONICAL_PACKAGE}\n"
        f"Legacy layout:    {LEGACY_PACKAGE}\n\n"
        "If your archive manager flattened the package, HarnessyXO also accepts "
        "__init__.py plus agent/, core/ and ui/ directly beside harnessy_app.py."
    )

try:
    from harnessy import __version__
    from harnessy.diagnostics import configure_diagnostics

    configure_diagnostics(APP_ROOT, version=__version__)
    from harnessy.ui.app import run_app
except ModuleNotFoundError as exc:
    if exc.name == "nicegui":
        raise SystemExit(
            "HarnessyXO dependencies are not installed.\n\n"
            "Run this from the HarnessyXO folder:\n"
            "  python3 run.py"
        ) from exc
    raise


if __name__ == "__main__":
    try:
        run_app()
    except KeyboardInterrupt:
        print("\nHarnessyXO server stopped.", flush=True)
        raise SystemExit(130)
    finally:
        _INSTALL_LOCK.close()
