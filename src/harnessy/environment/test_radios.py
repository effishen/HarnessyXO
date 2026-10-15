"""Optional, verified guest-kernel radios for an OpenWrt test target.

These are software radios inside the guest, not QEMU USB devices.  No command
touches the host's adapters, guest LAN/WAN, wireless configuration or firewall.
Guest output is reduced to a small fixed vocabulary before model exposure.
"""
from __future__ import annotations

import re
from typing import Any, Awaitable, Callable

RunGuest = Callable[..., Awaitable[str]]
_STATUSES = {'disabled', 'active', 'unavailable', 'error', 'unverified'}
_REASONS = {
    'not_requested', 'verified', 'not_detected', 'probe_failed', 'setup_failed',
    'package_install_failed', 'feed_update_failed', 'stock_feeds_unavailable', 'module_load_failed',
    'iw_missing', 'insufficient_radios', 'btvirt_missing', 'vhci_missing',
    'service_conflict', 'service_start_failed', 'insufficient_controllers',
    'interfaces_missing', 'interface_create_failed',
}
_DETAIL_CODES = {
    'none', 'unknown', 'dns_resolution_failed', 'tls_verification_failed',
    'network_unreachable', 'connection_failed', 'kernel_abi_mismatch',
    'signature_failed', 'disk_full', 'package_unavailable', 'operation_timeout',
    'ssh_command_failed', 'interface_create_failed',
    'network_permission_denied',
}
_DESCRIPTIONS = {
    'wifi': 'Guest Linux mac80211_hwsim virtual Wi-Fi radios. Inspect with iw dev and iw phy; configure AP/station roles separately. Software tests only; no physical RF, nearby-network scan, USB dongle or chipset emulation.',
    'bluetooth': 'Guest BlueZ btvirt with Linux VHCI virtual Bluetooth controllers. Software Bluetooth tests only; no physical RF, nearby-device scan or USB dongle emulation. Stock OpenWrt images lack these prerequisites.',
}

# A service belongs to us only when its complete body still matches. procd owns
# the child lifetime, so cleanup never sends a signal to a PID read from disk.
BT_SERVICE = '''#!/bin/sh /etc/rc.common
# HarnessyXO managed test-only btvirt service v1
USE_PROCD=1
START=99
start_service() {
    local binary
    binary="$(command -v btvirt)" || return 1
    case "$binary" in /usr/bin/btvirt|/usr/sbin/btvirt|/usr/libexec/btvirt) ;; *) return 1 ;; esac
    procd_open_instance main
    procd_set_param command "$binary" -l2
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
'''

def _service_stage() -> str:
    return """service_file=/etc/init.d/harnessy-test-btvirt
service_stage="$(mktemp /tmp/harnessy-test-btvirt.XXXXXX)" || exit 1
trap 'rm -f "$service_stage"' EXIT HUP INT TERM
cat > "$service_stage" <<'HARNESSY_BT_SERVICE'
""" + BT_SERVICE + "HARNESSY_BT_SERVICE\n"


PROBE_SCRIPT = r'''# HarnessyXO radio probe v1 (read only)
set -eu
wifi=0
wifi_interfaces=0
iw_present=0
command -v iw >/dev/null 2>&1 && iw_present=1
if [ "$iw_present" = 1 ]; then
    for phy in /sys/class/ieee80211/phy*; do
        [ -e "$phy" ] || continue
        module="$(readlink -f "$phy/device/driver/module" 2>/dev/null || true)"
        [ "${module##*/}" = mac80211_hwsim ] || continue
        iw phy "${phy##*/}" info >/dev/null 2>&1 || continue
        wifi=$((wifi + 1))
        for interface in "$phy"/device/net/*; do
            [ -e "$interface/phy80211" ] || continue
            linked="$(readlink -f "$interface/phy80211" 2>/dev/null || true)"
            [ "${linked##*/}" = "${phy##*/}" ] || continue
            wifi_interfaces=$((wifi_interfaces + 1))
        done
    done
fi
bluetooth=0
for controller in /sys/class/bluetooth/hci*; do
    [ -e "$controller" ] || continue
    location="$(readlink -f "$controller" 2>/dev/null || true)"
    case "$location" in /sys/devices/virtual/bluetooth/hci*) bluetooth=$((bluetooth + 1));; esac
done
vhci=0
[ -c /dev/vhci ] && vhci=1
btvirt=0
command -v btvirt >/dev/null 2>&1 && btvirt=1
btvirt_running=0
for process in /proc/[0-9]*/exe; do
    binary="$(readlink -f "$process" 2>/dev/null || true)"
    case "$binary" in /usr/bin/btvirt|/usr/sbin/btvirt|/usr/libexec/btvirt) btvirt_running=1; break;; esac
done
printf 'HX_RADIO_V1 wifi=%s wifi_interfaces=%s iw=%s bluetooth=%s vhci=%s btvirt=%s btvirt_running=%s\n' "$wifi" "$wifi_interfaces" "$iw_present" "$bluetooth" "$vhci" "$btvirt" "$btvirt_running"
'''

# Use only signed official repositories for the *installed* release. Never
# upgrade the kernel, force dependencies or replace configured feeds. opkg/apk
# enforce the running image's kernel ABI through normal dependency resolution.
WIFI_SETUP_SCRIPT = r'''# HarnessyXO optional Wi-Fi setup v2
set -eu
reason=verified
detail=none
work=''
if ! command -v iw >/dev/null 2>&1 || ! modprobe mac80211_hwsim radios=2 >/dev/null 2>&1; then
    work="$(mktemp -d /tmp/harnessy-test-wifi.XXXXXX)" || exit 1
    trap 'rm -rf "$work"' EXIT HUP INT TERM
    release="$(sed -n "s/^DISTRIB_RELEASE=['\"]\([^'\"]*\)['\"]$/\1/p" /etc/openwrt_release)"
    case "$release" in ''|*[!0-9.]*|.*|*..) reason=stock_feeds_unavailable;; esac
    prefix="https://downloads.openwrt.org/releases/$release/"
    if [ "$reason" = verified ] && command -v apk >/dev/null 2>&1; then
        for feed in /etc/apk/repositories /etc/apk/repositories.d/*.list; do
            [ -f "$feed" ] || continue
            awk -v prefix="$prefix" 'NF == 1 && index($1, prefix) == 1 { print $1 }' "$feed"
        done > "$work/repositories"
        if [ ! -s "$work/repositories" ]; then
            reason=stock_feeds_unavailable
        else
            kernel_version="$(apk info -v kernel 2>/dev/null | sed -n 's/^kernel-//p')"
            case "$kernel_version" in ''|*[!a-zA-Z0-9._+~:-]*) reason=package_install_failed;; esac
            if [ "$reason" = verified ]; then
                if ! apk --repositories-file "$work/repositories" update > "$work/install.log" 2>&1; then
                    reason=feed_update_failed
                elif ! apk --repositories-file "$work/repositories" add "kernel=$kernel_version" kmod-mac80211-hwsim iw >> "$work/install.log" 2>&1; then
                    reason=package_install_failed
                fi
            fi
        fi
    elif [ "$reason" = verified ] && command -v opkg >/dev/null 2>&1; then
        cat > "$work/opkg.conf" <<CONFIG
dest root /
dest ram /tmp
lists_dir ext $work/lists
option overlay_root /overlay
option check_signature
CONFIG
        awk -v prefix="$prefix" 'NF == 3 && $1 == "src/gz" && index($3, prefix) == 1 { print }' /etc/opkg/distfeeds.conf > "$work/feeds"
        if [ ! -s "$work/feeds" ]; then
            reason=stock_feeds_unavailable
        else
            cat "$work/feeds" >> "$work/opkg.conf"
            mkdir "$work/lists" "$work/no-conf"
            # --conf alone still reads /etc/opkg/*.conf. Isolate that search
            # too, keeping custom feeds outside this optional installation.
            if ! OPKG_CONF_DIR="$work/no-conf" opkg --conf "$work/opkg.conf" update > "$work/install.log" 2>&1; then
                reason=feed_update_failed
            elif ! OPKG_CONF_DIR="$work/no-conf" opkg --conf "$work/opkg.conf" install kmod-mac80211-hwsim iw >> "$work/install.log" 2>&1; then
                reason=package_install_failed
            fi
        fi
    elif [ "$reason" = verified ]; then
        reason=stock_feeds_unavailable
    fi
fi
if [ "$reason" = verified ]; then
    if ! command -v iw >/dev/null 2>&1; then reason=iw_missing
    elif ! modprobe mac80211_hwsim radios=2 >/dev/null 2>&1; then reason=module_load_failed
    fi
fi
if [ "$reason" = verified ]; then
    # A reload can leave hwsim PHYs without netdevs. Add one managed test
    # interface only where none exists; retain every existing guest interface.
    index=0
    for phy in /sys/class/ieee80211/phy*; do
        [ -e "$phy" ] || continue
        module="$(readlink -f "$phy/device/driver/module" 2>/dev/null || true)"
        [ "${module##*/}" = mac80211_hwsim ] || continue
        present=0
        for interface in "$phy"/device/net/*; do
            [ -e "$interface/phy80211" ] || continue
            linked="$(readlink -f "$interface/phy80211" 2>/dev/null || true)"
            [ "${linked##*/}" = "${phy##*/}" ] && present=1
        done
        [ "$present" = 0 ] || continue
        while [ -e "/sys/class/net/hxsim$index" ] && [ "$index" -lt 256 ]; do index=$((index + 1)); done
        if [ "$index" -ge 256 ] || ! iw phy "${phy##*/}" interface add "hxsim$index" type managed >/dev/null 2>&1; then
            reason=interface_create_failed
            detail=interface_create_failed
            break
        fi
        index=$((index + 1))
    done
fi
if [ "$reason" != verified ] && [ "$detail" = none ]; then
    detail=unknown
    if [ -n "$work" ] && [ -f "$work/install.log" ]; then
        # Preserve fixed technical evidence, never package output or feed URLs.
        if grep -Eiq 'no space left|not enough space' "$work/install.log"; then detail=disk_full
        elif grep -Eiq 'kernel.*(incompatible|mismatch)|cannot (find dependency|satisfy).*kernel|kernel.*dependency|dependency.*kernel' "$work/install.log"; then detail=kernel_abi_mismatch
        elif grep -Eiq 'certificate|ssl.*(fail|error)|tls.*(fail|error)' "$work/install.log"; then detail=tls_verification_failed
        elif grep -Eiq 'signature.*(fail|invalid)|verification.*fail|bad signature' "$work/install.log"; then detail=signature_failed
        elif grep -Eiq '(unable|cannot|could not|failed) to resolve|name resolution|name or service not known|bad address' "$work/install.log"; then detail=dns_resolution_failed
        elif grep -Eiq 'operation not permitted|permission denied' "$work/install.log"; then detail=network_permission_denied
        elif grep -Eiq 'network.*unreachable|no route to host' "$work/install.log"; then detail=network_unreachable
        elif grep -Eiq 'connection.*(refused|failed|timed out)|failed to send request' "$work/install.log"; then detail=connection_failed
        elif grep -Eiq 'unknown package|no such package|unable to select packages|package.*not found' "$work/install.log"; then detail=package_unavailable
        fi
    fi
fi
printf 'HX_RADIO_SETUP wifi=%s\n' "$reason"
printf 'HX_RADIO_DETAIL wifi=%s\n' "$detail"
'''

BLUETOOTH_SETUP_SCRIPT = r'''# HarnessyXO optional Bluetooth setup v1
set -eu
reason=verified
if ! command -v btvirt >/dev/null 2>&1; then
    reason=btvirt_missing
elif [ ! -c /dev/vhci ]; then
    modprobe hci_vhci >/dev/null 2>&1 || true
    [ -c /dev/vhci ] || reason=vhci_missing
fi
if [ "$reason" != verified ]; then
    printf 'HX_RADIO_SETUP bluetooth=%s\n' "$reason"
    exit 0
fi
''' + _service_stage() + r'''
if [ -L "$service_file" ] || { [ -e "$service_file" ] && ! cmp -s "$service_stage" "$service_file"; }; then
    reason=service_conflict
else
    if [ ! -e "$service_file" ]; then
        chmod 755 "$service_stage"
        mv "$service_stage" "$service_file"
    fi
    if ! "$service_file" running >/dev/null 2>&1; then
        "$service_file" start >/dev/null 2>&1 || reason=service_start_failed
        sleep 1
    fi
    "$service_file" running >/dev/null 2>&1 || reason=service_start_failed
fi
printf 'HX_RADIO_SETUP bluetooth=%s\n' "$reason"
'''

BLUETOOTH_STOP_SCRIPT = r'''# HarnessyXO stop owned Bluetooth emulation v1
set -eu
''' + _service_stage() + r'''
if [ ! -L "$service_file" ] && [ -f "$service_file" ] && cmp -s "$service_stage" "$service_file"; then
    "$service_file" stop >/dev/null 2>&1
fi
'''


def _requested(value: Any) -> dict[str, bool]:
    raw = value if isinstance(value, dict) else {}
    return {key: raw.get(key) is True for key in ('wifi', 'bluetooth')}


def _record(kind: str, requested: bool, *, status: str = 'disabled', reason: str = 'not_requested', count: int = 0, interface_count: int = 0, detail_code: str = 'none') -> dict[str, Any]:
    active = status == 'active'
    return {
        'requested': requested, 'enabled': active, 'verified': active,
        'status': status, 'reason': reason,
        'backend': 'mac80211_hwsim' if kind == 'wifi' else 'bluez_btvirt_vhci',
        'source_kind': 'emulated', 'radio_count': count,
        'interface_count': interface_count, 'physical_rf': False,
        'usb_dongle_emulation': False, 'description': _DESCRIPTIONS[kind],
        'detail_code': detail_code,
    }


def public_radio_snapshot(value: Any) -> dict[str, Any]:
    """Return no guest-controlled prose, paths or interface names to the model."""
    raw = value if isinstance(value, dict) else {}
    output: dict[str, Any] = {'schema_version': 1}
    for kind in ('wifi', 'bluetooth'):
        item = raw.get(kind) if isinstance(raw.get(kind), dict) else {}
        status = item.get('status')
        status = status if isinstance(status, str) and status in _STATUSES else 'unverified'
        reason = item.get('reason')
        reason = reason if isinstance(reason, str) and reason in _REASONS else 'not_detected'
        def count(key: str) -> int:
            number = item.get(key)
            return min(number, 256) if isinstance(number, int) and not isinstance(number, bool) and number >= 0 else 0
        radios = count('radio_count')
        interfaces = count('interface_count')
        # A cached/requested flag alone can never confer verified hardware.
        if status == 'active' and (item.get('verified') is not True or radios < 1):
            status, reason = 'unverified', 'not_detected'
        if kind == 'wifi' and status == 'active' and interfaces < 1:
            status, reason = 'unavailable', 'interfaces_missing'
        detail = item.get('detail_code')
        detail = detail if isinstance(detail, str) and detail in _DETAIL_CODES else 'unknown'
        output[kind] = _record(kind, item.get('requested') is True, status=status, reason=reason, count=radios, interface_count=interfaces, detail_code=detail)
    return output


def _parse_probe(output: str) -> dict[str, int] | None:
    match = re.search(r'^HX_RADIO_V1 wifi=(\d{1,3}) wifi_interfaces=(\d{1,3}) iw=([01]) bluetooth=(\d{1,3}) vhci=([01]) btvirt=([01]) btvirt_running=([01])$', str(output)[-8192:], re.MULTILINE)
    if not match:
        return None
    return dict(zip(('wifi', 'wifi_interfaces', 'iw', 'bluetooth', 'vhci', 'btvirt', 'btvirt_running'), map(int, match.groups())))


async def probe_radios(requested: dict[str, Any], run_guest: RunGuest) -> dict[str, Any]:
    """Read live guest capabilities; a stopped/unreachable guest is unverified."""
    wanted = _requested(requested)
    result = {'schema_version': 1, **{kind: _record(kind, enabled) for kind, enabled in wanted.items()}}
    try:
        probe = _parse_probe(await run_guest(PROBE_SCRIPT, timeout=15))
    except (OSError, RuntimeError, TimeoutError):
        probe = None
    if probe is None:
        for kind in wanted:
            result[kind] = _record(kind, wanted[kind], status='unverified', reason='probe_failed')
        return result
    for kind in wanted:
        count = min(probe[kind], 256)
        # Sysfs identifies only hwsim phys / virtual HCI controllers. Real USB
        # adapters or virtio Ethernet can never satisfy this test.
        verified = count >= 1 and (bool(probe['iw'] and probe['wifi_interfaces']) if kind == 'wifi' else bool(probe['vhci'] and probe['btvirt'] and probe['btvirt_running']))
        if verified:
            result[kind] = _record(kind, wanted[kind], status='active', reason='verified', count=count, interface_count=min(probe['wifi_interfaces'], 256) if kind == 'wifi' else count)
        elif wanted[kind]:
            reason = 'iw_missing' if kind == 'wifi' and not probe['iw'] else 'not_detected'
            if kind == 'wifi' and count and probe['iw'] and not probe['wifi_interfaces']:
                reason = 'interfaces_missing'
            if kind == 'bluetooth':
                reason = 'btvirt_missing' if not probe['btvirt'] else ('vhci_missing' if not probe['vhci'] else 'not_detected')
            result[kind] = _record(kind, True, status='unavailable', reason=reason, count=count)
    return result


async def configure_radios(requested: dict[str, Any], run_guest: RunGuest) -> dict[str, Any]:
    """Attempt requested optional setup; its failure never invalidates the shell."""
    wanted = _requested(requested)
    reasons = {}
    details = {}
    for kind, script in (('wifi', WIFI_SETUP_SCRIPT), ('bluetooth', BLUETOOTH_SETUP_SCRIPT)):
        if not wanted[kind]:
            continue
        try:
            output = await run_guest(script, timeout=180 if kind == 'wifi' else 20)
            match = re.search(r'^HX_RADIO_SETUP ' + kind + r'=([a-z_]+)$', str(output)[-8192:], re.MULTILINE)
            reason = match.group(1) if match else 'setup_failed'
            reasons[kind] = reason if reason in _REASONS else 'setup_failed'
            detail = re.search(r'^HX_RADIO_DETAIL ' + kind + r'=([a-z_]+)$', str(output)[-8192:], re.MULTILINE)
            details[kind] = detail.group(1) if detail and detail.group(1) in _DETAIL_CODES else 'none'
        except (OSError, RuntimeError, TimeoutError) as error:
            reasons[kind] = 'setup_failed'
            details[kind] = 'operation_timeout' if isinstance(error, TimeoutError) else 'ssh_command_failed'
    result = await probe_radios(wanted, run_guest)
    for kind, reason in reasons.items():
        # An independent probe determines capability. A failed install may
        # coexist with an already functioning user-created simulated radio.
        if result[kind]['verified']:
            if reason != 'verified':
                result[kind]['reason'] = reason
                result[kind]['detail_code'] = details.get(kind, 'none')
            elif result[kind]['radio_count'] < 2:
                result[kind]['reason'] = 'insufficient_radios' if kind == 'wifi' else 'insufficient_controllers'
            continue
        result[kind]['detail_code'] = details.get(kind, 'none')
        if reason != 'verified':
            result[kind]['status'] = 'error' if reason in {'setup_failed', 'package_install_failed', 'feed_update_failed', 'module_load_failed', 'service_start_failed', 'interface_create_failed'} else 'unavailable'
            result[kind]['reason'] = reason
    return public_radio_snapshot(result)


async def stop_radios(run_guest: RunGuest) -> None:
    """Stop our procd instance. Never unload Wi-Fi or disturb user processes."""
    await run_guest(BLUETOOTH_STOP_SCRIPT, timeout=15)


def radio_summary(snapshot: Any) -> str:
    clean = public_radio_snapshot(snapshot)
    states = []
    for kind, label in (('wifi', 'Wi-Fi'), ('bluetooth', 'Bluetooth')):
        entry = clean[kind]
        states.append(f"{label}: {entry['status']} ({entry['reason']}); requested={str(entry['requested']).lower()}, verified_virtual_radios={entry['radio_count']}, interfaces={entry['interface_count']}, detail={entry['detail_code']}")
    return '; '.join(states) + '. Active radios are emulated inside this guest; they cannot communicate over physical RF or validate a USB dongle chipset/driver.'


def radio_guidance(snapshot: Any) -> str:
    clean = public_radio_snapshot(snapshot)
    lines = []
    wifi = clean['wifi']
    if wifi['requested']:
        if wifi['verified']:
            lines.append('Wi-Fi: run iw dev and iw phy in this target Shell. Interfaces start without AP/station network configuration; configure that for your test. They do not appear as USB devices.')
        else:
            lines.append('Wi-Fi is not ready. Use Set up / repair radios while this VM is running. Check its per-radio result and Activity output; iw is installed only when the matching signed packages can be fetched.')
    if clean['bluetooth']['requested'] and not clean['bluetooth']['verified']:
        lines.append('Bluetooth is unavailable in stock OpenWrt images. A custom image must provide btvirt and the Linux VHCI driver; selecting the option cannot add missing kernel support.')
    return '\n'.join(lines)
