from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import subprocess
import sys
import threading


_MACOS_ROUTE_TIMEOUT_SECONDS = 0.20
_MACOS_INTERFACE_TIMEOUT_SECONDS = 0.20
_DEFAULT_PROBE_TIMEOUT_SECONDS = 0.80


def _is_usable_ipv4(value: str | None) -> bool:
    if not value:
        return False
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return bool(
        address.version == 4
        and not address.is_loopback
        and not address.is_unspecified
        and not address.is_link_local
        and not address.is_multicast
    )


def _run_text_command(args: list[str], *, timeout: float) -> str:
    """Run a tiny host network-inspection command with a hard timeout.

    This is HarnessyXO startup/controller plumbing, never model-controlled shell
    execution. Failures intentionally return an empty string so LAN discovery
    can fall through without blocking application startup.
    """
    try:
        completed = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
            timeout=max(0.01, float(timeout)),
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return completed.stdout.strip() if completed.returncode == 0 else ""


def _macos_command(name: str, fallback: str) -> str:
    return shutil.which(name) or fallback


def probe_macos_lan_ipv4() -> str | None:
    """Read the Mac's active LAN IPv4 directly from network interfaces.

    Do not use hostname resolution here. `route` identifies the interface used
    by the default route and `ipconfig getifaddr` reads that interface's IPv4
    straight from macOS. If the default route is a VPN/tunnel or unavailable,
    enumerate Ethernet/Wi-Fi style interfaces and use the first active one.
    """
    route_cmd = _macos_command("route", "/sbin/route")
    ipconfig_cmd = _macos_command("ipconfig", "/usr/sbin/ipconfig")
    ifconfig_cmd = _macos_command("ifconfig", "/sbin/ifconfig")

    default_interface: str | None = None
    route_output = _run_text_command(
        [route_cmd, "-n", "get", "default"],
        timeout=_MACOS_ROUTE_TIMEOUT_SECONDS,
    )
    match = re.search(r"(?m)^\s*interface:\s*([^\s]+)\s*$", route_output)
    if match:
        default_interface = match.group(1).strip()

    def interface_ipv4(interface: str | None) -> str | None:
        if not interface:
            return None
        value = _run_text_command(
            [ipconfig_cmd, "getifaddr", interface],
            timeout=_MACOS_INTERFACE_TIMEOUT_SECONDS,
        ).strip()
        return value if _is_usable_ipv4(value) else None

    # Fast path: for normal Wi-Fi/Ethernet, use the physical default-route
    # interface immediately. This is the common macOS case and avoids any
    # hostname/mDNS lookup or broad interface scan.
    if default_interface and (default_interface.startswith("en") or default_interface.startswith("bridge")):
        value = interface_ipv4(default_interface)
        if value:
            return value

    interface_names: list[str] = []
    listed = _run_text_command(
        [ifconfig_cmd, "-l"],
        timeout=_MACOS_INTERFACE_TIMEOUT_SECONDS,
    )
    if listed:
        interface_names.extend(part for part in listed.split() if part)

    # If a VPN/tunnel owns the default route, prefer physical en*/bridge*
    # interfaces so the printed address remains useful to another LAN device.
    candidates: list[str] = []

    def add(interface: str | None) -> None:
        if interface and interface not in candidates:
            candidates.append(interface)

    add("en0")
    add("en1")
    for interface in interface_names:
        if interface.startswith("en"):
            add(interface)
    for interface in interface_names:
        if interface.startswith("bridge"):
            add(interface)
    add(default_interface)

    for interface in candidates:
        value = interface_ipv4(interface)
        if value:
            return value
    return None


def probe_socket_route_ipv4() -> str | None:
    """Kernel-route fallback which performs no DNS/hostname lookup."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.2)
            # UDP connect sends no application payload; it asks the kernel which
            # local source address would be used for this route.
            sock.connect(("192.0.2.1", 9))
            value = str(sock.getsockname()[0])
            return value if _is_usable_ipv4(value) else None
    except OSError:
        return None


def probe_lan_ipv4() -> str | None:
    """Best-effort LAN IPv4 probe without hostname/mDNS resolution on macOS."""
    if sys.platform == "darwin":
        direct = probe_macos_lan_ipv4()
        if direct:
            return direct
        return probe_socket_route_ipv4()

    direct = probe_socket_route_ipv4()
    if direct:
        return direct

    # Non-macOS fallback for platforms where hostname lookup is normally cheap.
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM):
            value = str(info[4][0])
            if _is_usable_ipv4(value):
                return value
    except OSError:
        pass
    return None


def preferred_lan_ipv4(timeout_seconds: float = _DEFAULT_PROBE_TIMEOUT_SECONDS) -> str | None:
    """Return a LAN IPv4 while strictly bounding startup latency.

    The probe runs in a daemon thread. macOS normally completes quickly because
    it inspects interfaces directly rather than touching hostname/mDNS services;
    the timeout remains a fail-safe so network tooling can never block NiceGUI.
    """
    result: list[str | None] = []
    finished = threading.Event()

    def worker() -> None:
        try:
            result.append(probe_lan_ipv4())
        except Exception:
            result.append(None)
        finally:
            finished.set()

    thread = threading.Thread(
        target=worker,
        name="harnessy-lan-ip-probe",
        daemon=True,
    )
    thread.start()
    if not finished.wait(max(0.0, float(timeout_seconds))):
        return None
    return result[0] if result else None
