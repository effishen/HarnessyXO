#!/usr/bin/env python3
"""Portable HarnessyXO setup-and-launch helper.

Run with:
    python3 run.py

No executable bit, virtual environment, or system-wide pip install is required.
Dependencies are installed into this release's local ``.vendor/`` directory.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

MIN_PYTHON = (3, 10)
APP_ROOT = Path(__file__).resolve().parent
KVM_REFRESH_ENV = 'HARNESSY_KVM_REFRESH_UID'
try:
    RELEASE_VERSION = (APP_ROOT / 'VERSION').read_text('utf-8').strip() or 'dev'
except OSError:
    RELEASE_VERSION = 'dev'


WEB_ASSETS = {
    "xterm.css": [
        "https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css",
        "https://unpkg.com/xterm@5.3.0/css/xterm.css",
    ],
    "xterm.js": [
        "https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js",
        "https://unpkg.com/xterm@5.3.0/lib/xterm.js",
    ],
    "xterm-addon-fit.js": [
        "https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js",
        "https://unpkg.com/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js",
    ],
}


def ensure_web_assets(vendor_dir: Path) -> None:
    """Cache browser-only assets beside vendored Python dependencies.

    HarnessyXO remains usable if these downloads fail; only the rich terminal
    frontend is unavailable. Once cached, normal launches do not need internet.
    """
    target_dir = vendor_dir / "harnessy_static"
    target_dir.mkdir(parents=True, exist_ok=True)
    missing = [name for name in WEB_ASSETS if not (target_dir / name).is_file() or (target_dir / name).stat().st_size < 500]
    if not missing:
        print("HarnessyXO browser assets: ready (./.vendor/harnessy_static)")
        return

    print("Caching HarnessyXO browser assets in ./.vendor/harnessy_static ...")
    failures: list[str] = []
    for name in missing:
        destination = target_dir / name
        downloaded = False
        last_error = ""
        for url in WEB_ASSETS[name]:
            try:
                request = urllib.request.Request(url, headers={"User-Agent": f"HarnessyXO/{RELEASE_VERSION}"})
                with urllib.request.urlopen(request, timeout=30) as response:
                    data = response.read()
                if len(data) < 500:
                    raise RuntimeError(f"download was unexpectedly small ({len(data)} bytes)")
                temp = destination.with_suffix(destination.suffix + ".tmp")
                temp.write_bytes(data)
                temp.replace(destination)
                downloaded = True
                break
            except Exception as exc:
                last_error = str(exc)
        if not downloaded:
            failures.append(f"{name}: {last_error}")
    if failures:
        print("Warning: terminal browser assets could not be cached:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        print("HarnessyXO will still start; the Terminal tab will explain if its frontend is unavailable.", file=sys.stderr)



def package_layout(app_dir: Path) -> str | None:
    """Return the recognized HarnessyXO package layout name, if any."""
    if (app_dir / "src" / "harnessy" / "__init__.py").is_file():
        return "src"
    if (app_dir / "harnessy" / "__init__.py").is_file():
        return "legacy"
    if (
        (app_dir / "__init__.py").is_file()
        and (app_dir / "agent").is_dir()
        and (app_dir / "core").is_dir()
        and (app_dir / "ui").is_dir()
    ):
        return "flattened"
    return None


def find_app_dir(script_dir: Path) -> Path:
    """Return the HarnessyXO app root, tolerating one accidental wrapper folder."""
    if (script_dir / "harnessy_app.py").is_file() and package_layout(script_dir):
        return script_dir

    matches: list[Path] = []
    for candidate in script_dir.iterdir():
        if not candidate.is_dir():
            continue
        if (
            (candidate / "harnessy_app.py").is_file()
            and (candidate / "requirements.txt").is_file()
            and package_layout(candidate)
        ):
            matches.append(candidate)

    if len(matches) == 1:
        print("HarnessyXO: detected application files in:")
        print(f"  {matches[0]}")
        print()
        return matches[0]

    return script_dir


def prepend_import_path(path: Path) -> None:
    value = str(path)
    if value not in sys.path:
        sys.path.insert(0, value)




def configure_launcher_diagnostics(app_dir: Path, layout: str) -> tuple[object | None, object | None]:
    """Start stdlib-only diagnostics before dependency installation.

    This intentionally imports only HarnessyXO's diagnostics package, which has no
    NiceGUI/httpx/Playwright dependency. If dependency installation itself fails,
    plain ``python3 run.py`` still leaves a useful .logs support bundle. The
    application process reinitializes the same diagnostics tree after ``exec``.
    """
    try:
        if layout == "src":
            package_parent = app_dir / "src"
        elif layout == "legacy":
            package_parent = app_dir
        else:
            package_parent = app_dir.parent
        prepend_import_path(package_parent)
        from harnessy.diagnostics import configure_diagnostics, log_event, refresh_diagnostics_bundle

        configure_diagnostics(app_dir, version=RELEASE_VERSION)
        log_event("harnessy", "launcher_ready", layout=layout, app_root=str(app_dir))
        return log_event, refresh_diagnostics_bundle
    except Exception as exc:
        # Diagnostics must never prevent HarnessyXO from starting. A healthy source
        # tree should not take this path, but retain the original launcher behavior
        # if local files are damaged.
        print(f"Warning: HarnessyXO launcher diagnostics could not start: {exc}", file=sys.stderr)
        return None, None


def fail(message: str) -> "NoReturn":
    print(message, file=sys.stderr)
    raise SystemExit(1)


def launcher_kvm_selection() -> tuple[str, str] | None:
    """Check native Linux workspaces, including a new installation's default.

    A launcher with only foreign-architecture workspaces has no native KVM
    requirement. The regular Create/Start checks remain authoritative later.
    """
    import platform
    if platform.system() != 'Linux':
        return None
    from harnessy.core.machine import MachineStore
    from harnessy.environment.base import load_environment_config
    from harnessy.environment.presets import canonical_arch, execution_mode

    host_arch = canonical_arch(platform.machine())
    configured = False
    for registration in MachineStore().list_workspaces():
        path = Path(registration.path).expanduser()
        if not path.is_dir():
            continue
        config = load_environment_config(path)
        if config is None:
            continue
        configured = True
        vm_type = execution_mode(config.architecture, host_arch=host_arch, host_os='Linux')[0]
        if str(config.provider) == 'lima' and vm_type == 'qemu' and canonical_arch(config.architecture) == host_arch:
            return config.architecture, vm_type
    return None if configured else (host_arch, 'qemu')


def valid_kvm_refresh_identity(refresh_uid: str) -> bool:
    return (1 <= len(refresh_uid) <= 10 and refresh_uid.isascii() and refresh_uid.isdecimal()
            and 0 < int(refresh_uid) < 2**32 and hasattr(os, 'getuid')
            and os.getuid() == int(refresh_uid) and os.geteuid() == int(refresh_uid))


def prepare_launcher_kvm_access(app_dir: Path, install_lock, diagnostic_event=None) -> None:
    """Do terminal-only host setup before VM checks or application startup."""
    refresh_uid = os.environ.pop(KVM_REFRESH_ENV, None)
    refresh_attempted = refresh_uid is not None

    def receipt(**fields) -> None:
        if diagnostic_event:
            diagnostic_event('harnessy', 'launcher_kvm_setup', **fields)

    if refresh_attempted:
        if not valid_kvm_refresh_identity(refresh_uid):
            receipt(status='action_required', reason_code='KVM_IDENTITY_CHANGED', refresh_attempted=True)
            fail('KVM group refresh could not verify the original normal account. '
                 'Start python3 run.py from your normal host account; HarnessyXO was not started.')
    try:
        selection = launcher_kvm_selection()
        if selection is None:
            return
        from harnessy.environment.kvm_startup import prepare_kvm_startup
        plan = prepare_kvm_startup(
            *selection, python_executable=sys.executable, script_path=app_dir / 'run.py',
            script_args=tuple(sys.argv[1:]), refresh_attempted=refresh_attempted,
        )
    except Exception:
        receipt(status='action_required', reason_code='KVM_SETUP_FAILED', refresh_attempted=refresh_attempted)
        print('Automatic KVM setup could not finish. The app will still open; '
              'VM Start will show any remaining host permission requirement.', file=sys.stderr, flush=True)
        return

    receipt(**plan.diagnostic_fields())
    if plan.message:
        print(plan.message, file=sys.stderr if plan.status == 'action_required' else sys.stdout, flush=True)
    if plan.status == 'cancelled':
        raise SystemExit(130)
    if plan.status != 'relaunch':
        return

    # Only host group setup has run; no application is serving yet. Release
    # this launcher's lock immediately before replacing it. sg may close FDs
    # or fork, so the fresh launcher acquires its own normal lifetime lock and
    # repeats source verification instead of weakening updater handoff checks.
    env = dict(os.environ)
    env[KVM_REFRESH_ENV] = str(os.getuid())
    from harnessy_update import HANDOFF_ENV, LOCK_ENV
    env.pop(HANDOFF_ENV, None)
    env.pop(LOCK_ENV, None)
    sys.stdout.flush()
    sys.stderr.flush()
    install_lock.close()
    try:
        os.execve(plan.relaunch_argv[0], list(plan.relaunch_argv), env)
    except OSError:
        receipt(status='action_required', reason_code='KVM_RELAUNCH_FAILED', refresh_attempted=True)
        fail('KVM group setup finished, but the refreshed launcher could not start. '
             'Sign out and back in, then run python3 run.py again. HarnessyXO was not started.')


def check_registered_host_prerequisites() -> None:
    """Use the same selected-backend checks as VM Create/Start.

    Failure does not prevent opening the app to repair settings. New workspaces
    are checked on their first Create/Start, not guessed by this launcher.
    """
    import asyncio
    from harnessy.core.machine import MachineStore
    from harnessy.environment.base import load_environment_config
    from harnessy.environment.host_prerequisites import (
        ensure_host_prerequisites, ensure_lima_controller, restore_host_tool_path,
    )
    from harnessy.environment.presets import execution_mode
    import platform
    restore_host_tool_path()

    async def check() -> None:
        def startup_progress(phase, message, **meta):
            print(message + (' ' + str(meta['detail']) if meta.get('detail') else ''), flush=True)
        try:
            await ensure_lima_controller(progress=startup_progress)
        except Exception as exc:
            print(f'Linux Lima setup: {exc}', file=sys.stderr)
            print('The app will still open. VM Create/Start will retry automatic setup.', file=sys.stderr)
        seen = set()
        for registration in MachineStore().list_workspaces():
            path = Path(registration.path).expanduser()
            if not path.is_dir():
                continue
            config = load_environment_config(path)
            if config is None:
                continue
            vm_type = execution_mode(config.architecture, host_arch=platform.machine(), host_os=platform.system())[0]
            key = (config.provider, config.architecture, vm_type)
            if key in seen:
                continue
            seen.add(key)
            def progress(phase, message, **meta):
                print(message + (' ' + str(meta['detail']) if meta.get('detail') else ''), flush=True)
            try:
                await ensure_host_prerequisites(config, vm_type=vm_type, progress=progress)
            except Exception as exc:
                print(f'Host prerequisite check for {registration.name}: {exc}', file=sys.stderr)
                print('The app will still open. VM Create/Start will recheck; no guest rebuild or network change was made.', file=sys.stderr)
    asyncio.run(check())


def show_source_update_details(result: dict) -> None:
    """Explain a reviewed archive comparison without dumping source or paths."""
    check = result.get('archive_check')
    if not isinstance(check, dict):
        return
    repairs = check.get('executable_repairs', 0)
    if isinstance(repairs, int) and not isinstance(repairs, bool) and repairs > 0:
        print(f'Restored executable permissions on {repairs} verified application file(s).', flush=True)
    if result.get('outcome') != 'zip_local_changes':
        return
    labels = {
        'missing': 'missing file',
        'unsafe_path': 'symlink or unexpected directory',
        'not_regular_file': 'not a regular file',
        'content_size': 'file contents differ',
        'content_hash': 'file contents differ',
        'unreadable': 'file could not be read',
        'executable_mode': 'executable permissions differ',
        'mode_repair_failed': 'executable permissions could not be restored',
    }
    for item in check.get('mismatches', [])[:8]:
        if not isinstance(item, dict):
            continue
        name = str(item.get('path') or '')
        reason = labels.get(item.get('reason'))
        if (reason and name and len(name) <= 180 and not name.startswith('/')
                and all(char.isascii() and (char.isalnum() or char in '_./+@ -') for char in name)
                and '..' not in name.split('/')):
            print(f'  {name}: {reason}.', flush=True)
    print('Keep this folder to preserve local edits; use a clean release folder for automatic updates.', flush=True)


def main() -> None:
    if sys.version_info < MIN_PYTHON:
        fail(
            "Error: HarnessyXO requires Python 3.10 or newer.\n"
            f"Current interpreter: Python {sys.version.split()[0]}\n\n"
            "Run this launcher with a newer Python, for example:\n"
            "  python3.12 run.py"
        )

    refresh_uid = os.environ.get(KVM_REFRESH_ENV)
    if refresh_uid is not None and not valid_kvm_refresh_identity(refresh_uid):
        # Check before source/dependency/diagnostic writes as well as before
        # application startup. A group refresh must never switch accounts.
        fail('KVM group refresh could not verify the original normal account. '
             'Start python3 run.py from your normal host account; HarnessyXO was not started.')

    script_dir = Path(__file__).resolve().parent
    app_dir = find_app_dir(script_dir)
    # Hold the install lock through dependency setup and the application exec.
    # Source updates run before importing any Harnessy application modules.
    from harnessy_update import (
        StartupAlreadyRunning, StartupLockUnsafe, acquire_install_lock,
        check_for_updates, consume_update_handoff, make_update_handoff,
    )
    try:
        install_lock = acquire_install_lock(app_dir)
    except StartupAlreadyRunning:
        fail("HarnessyXO is already running from this folder. Close it before starting again.")
    except StartupLockUnsafe:
        fail("HarnessyXO cannot safely lock this installation. Check the folder permissions and update lock file.")
    update_result = {"outcome": "restart_handoff", "changed": False, "fatal": False}
    if not consume_update_handoff(app_dir):
        print("Checking HarnessyXO updates ...", flush=True)
        update_result = check_for_updates(app_dir, RELEASE_VERSION)
        outcome = update_result["outcome"]
        show_source_update_details(update_result)
        if update_result["fatal"]:
            fail("HarnessyXO found an incomplete or unsafe source update and stopped. "
                 "Keep your .settings and workspaces, and restore the application files from a verified release.")
        if update_result["changed"]:
            print("HarnessyXO updated. Restarting the launcher ...", flush=True)
            make_update_handoff(app_dir)
            os.execv(sys.executable, [sys.executable, str(app_dir / "run.py"), *sys.argv[1:]])
            raise RuntimeError("The updated launcher did not restart.")
        messages = {
            "up_to_date": "HarnessyXO source: up to date.",
            "local_changes": "Source update skipped: local code changes are present. Starting the installed version.",
            "zip_local_changes": "Source update skipped: application files differ from verified source. Starting the installed version.",
            "history_not_fast_forward": "Source update skipped: local Git history needs review. Starting the installed version.",
            "windows_updates_unsupported": "Automatic source updates currently support macOS and Linux. Starting the installed version.",
            "branch_not_managed": "Source update skipped: this checkout is not on main. Starting the installed version.",
            "check_unavailable": "Source update unavailable. Check internet access to the public GitHub repository; starting the installed version.",
            "zip_bootstrap_unavailable": "Source update unavailable. Check Git and internet access to the public GitHub repository; starting the installed version.",
        }
        print(messages.get(outcome, f"Source update skipped ({outcome}). Starting the installed version."), flush=True)
    app_entry = app_dir / "harnessy_app.py"
    requirements = app_dir / "requirements.txt"
    vendor_dir = app_dir / ".vendor"
    layout = package_layout(app_dir)

    if not app_entry.is_file():
        fail(
            "Error: harnessy_app.py is missing from the HarnessyXO application folder:\n"
            f"  {app_dir}"
        )

    if not layout:
        fail(
            "Error: the internal HarnessyXO package is missing.\n\n"
            "Current releases use this layout:\n"
            "  run.py\n"
            "  harnessy_app.py\n"
            "  requirements.txt\n"
            "  src/harnessy/\n\n"
            "HarnessyXO also recognizes the older harnessy/ layout and the "
            "flattened Cloud Commander layout (agent/, core/, ui/, __init__.py "
            "beside run.py)."
        )

    if not requirements.is_file():
        fail(
            "Error: requirements.txt is missing from the HarnessyXO application folder:\n"
            f"  {app_dir}"
        )

    diagnostic_event, diagnostic_bundle = configure_launcher_diagnostics(app_dir, layout)
    if diagnostic_event:
        diagnostic_event("harnessy", "launcher_source_update", state=update_result["outcome"],
                         changed=update_result["changed"], archive_check=update_result.get('archive_check'))

    print(f"Using Python {sys.version.split()[0]}")
    print(f"Interpreter: {sys.executable}")
    print(f"HarnessyXO package layout: {layout}")
    vendor_dir.mkdir(parents=True, exist_ok=True)

    requirements_hash = hashlib.sha256(
        requirements.read_bytes() + f"\npy={sys.version_info.major}.{sys.version_info.minor}".encode()
    ).hexdigest()
    marker = vendor_dir / ".harnessy_requirements.sha256"
    vendor_ready = (
        marker.is_file()
        and marker.read_text("utf-8", errors="ignore").strip() == requirements_hash
        and (vendor_dir / "nicegui").is_dir()
        and (vendor_dir / "httpx").is_dir()
        and (vendor_dir / "playwright").is_dir()
        and (vendor_dir / "segno").is_dir()
    )

    if vendor_ready:
        print("HarnessyXO dependencies: ready (./.vendor)")
        if diagnostic_event:
            diagnostic_event("harnessy", "launcher_dependencies_ready", cached=True)
    else:
        print()
        print("Installing/updating HarnessyXO dependencies in ./.vendor ...")
        if diagnostic_event:
            diagnostic_event("harnessy", "launcher_dependency_install_start", cached=False)
        install_cmd = [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--target",
            str(vendor_dir),
            "--upgrade",
            "-r",
            str(requirements),
        ]
        try:
            subprocess.run(install_cmd, cwd=app_dir, check=True)
            marker.write_text(requirements_hash + "\n", encoding="utf-8")
            if diagnostic_event:
                diagnostic_event("harnessy", "launcher_dependency_install_complete")
        except subprocess.CalledProcessError as exc:
            if diagnostic_event:
                diagnostic_event(
                    "harnessy", "launcher_dependency_install_failed",
                    returncode=int(exc.returncode), requirements=str(requirements),
                )
            fail(f"\nHarnessyXO dependency installation failed with exit code {exc.returncode}.")

    # This optional pre-check runs in the launcher process, before
    # harnessy_app.py prepends .vendor. Make the dependencies which were just
    # verified or installed importable here as well.
    prepend_import_path(vendor_dir)
    prepare_launcher_kvm_access(app_dir, install_lock, diagnostic_event)
    try:
        check_registered_host_prerequisites()
    except Exception as exc:
        print(f'Host prerequisite checks could not run: {exc}. VM Create/Start will retry.', file=sys.stderr)

    ensure_web_assets(vendor_dir)

    print()
    print("Starting HarnessyXO ...")
    if diagnostic_event:
        diagnostic_event("harnessy", "launcher_exec_application", entry=str(app_entry))
    os.chdir(app_dir)
    os.execv(sys.executable, [sys.executable, str(app_entry)])


if __name__ == "__main__":
    main()
