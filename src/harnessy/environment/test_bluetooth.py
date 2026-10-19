"""Install the bundled software Bluetooth controller only inside a test guest."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import re
from typing import Any

HELPER_DIRECTORY = Path(__file__).with_name('bluetooth_helpers')
HELPER_VERSION = 'harnessy-test-bt1'
BLUETOOTH_RADIO_PACKAGES = (
    'kmod-bluetooth', 'kmod-crypto-user', 'kmod-crypto-cmac', 'kmod-crypto-ecb',
    'dbus', 'bluez-daemon', 'bluez-utils', 'bluez-utils-extra',
    'coreutils-base64', 'coreutils-sha256sum',
)
_ELF_ARCHITECTURES = {
    'x86_64': (62, 2, 'little'), 'arm64': (183, 2, 'little'),
    'mips': (8, 1, 'big'), 'mipsel': (8, 1, 'little'),
    'mips64': (8, 2, 'big'), 'mips64el': (8, 2, 'little'),
}


class BluetoothHelperError(RuntimeError):
    """Fixed error identity; never expose an artifact path or file contents."""
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def helper_asset(arch: str) -> tuple[bytes, str]:
    if not isinstance(arch, str) or arch not in _ELF_ARCHITECTURES:
        raise BluetoothHelperError('helper_unavailable')
    try:
        manifest_path = HELPER_DIRECTORY / 'manifest.json'
        if HELPER_DIRECTORY.is_symlink() or manifest_path.is_symlink():
            raise BluetoothHelperError('helper_integrity_failed')
        if manifest_path.stat().st_size > 64 * 1024:
            raise BluetoothHelperError('helper_integrity_failed')
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        if manifest.get('schema_version') != 1 or manifest.get('helper_version') != '1':
            raise BluetoothHelperError('helper_integrity_failed')
        entry = manifest.get('files', {}).get(arch)
        if not isinstance(entry, dict) or entry.get('file') != 'harnessy-test-bt-' + arch:
            raise BluetoothHelperError('helper_integrity_failed')
        digest, size = entry.get('sha256'), entry.get('size')
        if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise BluetoothHelperError('helper_integrity_failed')
        if type(size) is not int or not 20 <= size <= 8 * 1024 * 1024:
            raise BluetoothHelperError('helper_integrity_failed')
        path = HELPER_DIRECTORY / entry['file']
        if path.is_symlink() or path.stat().st_size != size:
            raise BluetoothHelperError('helper_integrity_failed')
        data = path.read_bytes()
        machine, elf_class, endianness = _ELF_ARCHITECTURES[arch]
        if (data[:4] != b'\x7fELF' or data[4] != elf_class
                or data[5] != (1 if endianness == 'little' else 2)
                or int.from_bytes(data[18:20], endianness) != machine
                or (entry.get('elf_machine'), entry.get('elf_class'), entry.get('endianness'))
                   != (machine, elf_class, endianness)
                or hashlib.sha256(data).hexdigest() != digest):
            raise BluetoothHelperError('helper_integrity_failed')
        return data, digest
    except BluetoothHelperError:
        raise
    except FileNotFoundError:
        raise BluetoothHelperError('helper_unavailable') from None
    except (OSError, ValueError, TypeError, AttributeError, RecursionError):
        raise BluetoothHelperError('helper_integrity_failed') from None


def helper_install_script(arch: str) -> str:
    """The caller sends this script through SSH stdin, never an argv value."""
    data, digest = helper_asset(arch)
    encoded = base64.b64encode(data).decode('ascii')
    wrapped = '\n'.join(encoded[index:index + 76] for index in range(0, len(encoded), 76))
    return r'''# HarnessyXO verified Bluetooth helper installation v1
set -eu
helper=/usr/libexec/harnessy-test-bt
marker=/usr/libexec/harnessy-test-bt.sha256
result() { printf 'HX_BT_HELPER %s\n' "$1"; exit 0; }
[ ! -L /usr ] && [ ! -L /usr/libexec ] || result service_conflict
mkdir -p /usr/libexec || result helper_install_failed
''' + f"expected={digest}\n" + r'''
if [ -e "$helper" ] || [ -L "$helper" ] || [ -e "$marker" ] || [ -L "$marker" ]; then
    [ ! -L "$helper" ] && [ -f "$helper" ] && [ ! -L "$marker" ] || result service_conflict
    [ ! -e "$marker" ] || [ -f "$marker" ] || result service_conflict
    actual="$(sha256sum "$helper")"
    if [ "${actual%% *}" = "$expected" ] && [ "$("$helper" --version)" = harnessy-test-bt1 ]; then
        if [ -f "$marker" ] && [ "$(cat "$marker")" = "$expected" ]; then result verified; fi
        recovery="$(mktemp /usr/libexec/.harnessy-test-bt-sha.XXXXXX)" || result helper_install_failed
        trap 'rm -f "$recovery"' EXIT HUP INT TERM
        printf '%s\n' "$expected" > "$recovery"
        chmod 644 "$recovery" || result helper_install_failed
        mv "$recovery" "$marker" || result helper_install_failed
        result verified
    fi
    [ -f "$marker" ] || result service_conflict
    previous="$(cat "$marker")"
    printf '%s\n' "$previous" | grep -Eq '^[0-9a-f]{64}$' || result service_conflict
    [ "${actual%% *}" = "$previous" ] || result service_conflict
fi
stage="$(mktemp /usr/libexec/.harnessy-test-bt.XXXXXX)" || result helper_install_failed
stage_marker="$(mktemp /usr/libexec/.harnessy-test-bt-sha.XXXXXX)" || { rm -f "$stage"; result helper_install_failed; }
trap 'rm -f "$stage" "$stage_marker"' EXIT HUP INT TERM
if ! base64 -d > "$stage" <<'HARNESSY_BLUETOOTH_ELF'
''' + wrapped + r'''
HARNESSY_BLUETOOTH_ELF
then result helper_install_failed
fi
''' + r'''
actual="$(sha256sum "$stage")"
[ "${actual%% *}" = "$expected" ] || result helper_integrity_failed
chmod 755 "$stage" || result helper_install_failed
[ "$("$stage" --version)" = harnessy-test-bt1 ] || result helper_integrity_failed
printf '%s\n' "$expected" > "$stage_marker"
chmod 644 "$stage_marker"
mv "$stage" "$helper" || result helper_install_failed
mv "$stage_marker" "$marker" || result helper_install_failed
result verified
'''


BT_SUPERVISOR = r'''#!/bin/sh
# HarnessyXO owned two-controller Bluetooth supervisor v1
set -eu
runtime=/var/run/harnessy-test-bluetooth
helper_pid=''
attach0=''
attach1=''
cleanup() {
    trap - EXIT HUP INT TERM
    for child in "$attach0" "$attach1" "$helper_pid"; do
        [ -z "$child" ] || kill "$child" 2>/dev/null || true
    done
    for child in "$attach0" "$attach1" "$helper_pid"; do
        [ -z "$child" ] || wait "$child" 2>/dev/null || true
    done
}
trap cleanup EXIT HUP INT TERM
/usr/libexec/harnessy-test-bt --runtime "$runtime" &
helper_pid=$!
attempt=0
while [ ! -r "$runtime/ready.json" ] || [ ! -L "$runtime/hci0" ] || [ ! -L "$runtime/hci1" ] || ! grep -Eq '"pid":'"$helper_pid"'[,}]' "$runtime/ready.json"; do
    kill -0 "$helper_pid" 2>/dev/null || exit 1
    attempt=$((attempt + 1))
    [ "$attempt" -lt 10 ] || exit 1
    sleep 1
done
btattach -B "$runtime/hci0" -P h4 -S115200 -N &
attach0=$!
btattach -B "$runtime/hci1" -P h4 -S115200 -N &
attach1=$!
while kill -0 "$helper_pid" 2>/dev/null && kill -0 "$attach0" 2>/dev/null && kill -0 "$attach1" 2>/dev/null; do
    sleep 1
done
exit 1
'''

BT_H4_SERVICE = '''#!/bin/sh /etc/rc.common
# HarnessyXO owned two-controller Bluetooth service v1
USE_PROCD=1
START=99
start_service() {
    procd_open_instance main
    procd_set_param command /bin/sh /usr/libexec/harnessy-test-bluetooth
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_set_param respawn 3600 5 5
    procd_close_instance
}
'''


def _owned_file_stage(path: str, body: str, name: str) -> str:
    return f'''{name}_file={path}
{name}_stage="$(mktemp /tmp/harnessy-test-{name}.XXXXXX)" || result service_start_failed
cat > "${name}_stage" <<'HARNESSY_BT_{name.upper()}'
{body}HARNESSY_BT_{name.upper()}
if [ -L "${name}_file" ] || {{ [ -e "${name}_file" ] && ! cmp -s "${name}_stage" "${name}_file"; }}; then rm -f "${name}_stage"; result service_conflict; fi
if [ ! -e "${name}_file" ]; then chmod 755 "${name}_stage"; mv "${name}_stage" "${name}_file"; fi
rm -f "${name}_stage"
'''


BLUETOOTH_H4_SETUP_SCRIPT = r'''# HarnessyXO automatic software HCI attachment v1
set -eu
result() { printf 'HX_RADIO_SETUP bluetooth=%s\n' "$1"; exit 0; }
[ -x /usr/libexec/harnessy-test-bt ] || result helper_unavailable
[ "$(/usr/libexec/harnessy-test-bt --version)" = harnessy-test-bt1 ] || result helper_integrity_failed
for binary in btattach hciconfig bluetoothctl; do command -v "$binary" >/dev/null 2>&1 || result cli_missing; done
modprobe hci_uart >/dev/null 2>&1 || result module_load_failed
modprobe algif_hash >/dev/null 2>&1 || result module_load_failed
modprobe algif_skcipher >/dev/null 2>&1 || result module_load_failed
modprobe aes_generic >/dev/null 2>&1 || true
modprobe ecb >/dev/null 2>&1 || true
modprobe cmac >/dev/null 2>&1 || true
grep -Eq '^name[[:space:]]*:[[:space:]]*aes[[:space:]]*$' /proc/crypto || result crypto_unavailable
''' + _owned_file_stage('/usr/libexec/harnessy-test-bluetooth', BT_SUPERVISOR, 'supervisor') + _owned_file_stage(
    '/etc/init.d/harnessy-test-bluetooth', BT_H4_SERVICE, 'service') + r'''
/etc/init.d/harnessy-test-bluetooth enable >/dev/null 2>&1 || result service_start_failed
current_helper=0
for process in /proc/[0-9]*/exe; do
    if [ "$(readlink -f "$process" 2>/dev/null || true)" = /usr/libexec/harnessy-test-bt ]; then current_helper=1; break; fi
done
if /etc/init.d/harnessy-test-bluetooth running >/dev/null 2>&1; then
    if [ "$current_helper" = 0 ]; then /etc/init.d/harnessy-test-bluetooth restart >/dev/null 2>&1 || result service_start_failed; fi
else
    /etc/init.d/harnessy-test-bluetooth start >/dev/null 2>&1 || result service_start_failed
fi
[ -x /etc/init.d/dbus ] && [ -x /etc/init.d/bluetoothd ] || result service_start_failed
if ! /etc/init.d/dbus running >/dev/null 2>&1; then /etc/init.d/dbus start >/dev/null 2>&1 || result service_start_failed; fi
bus_attempt=0
while [ ! -S /var/run/dbus/system_bus_socket ] && [ "$bus_attempt" -lt 10 ]; do
    bus_attempt=$((bus_attempt + 1))
    sleep 1
done
[ -S /var/run/dbus/system_bus_socket ] || result service_start_failed
if ! /etc/init.d/bluetoothd running >/dev/null 2>&1; then /etc/init.d/bluetoothd restart >/dev/null 2>&1 || result service_start_failed; fi
attempt=0
while [ "$attempt" -lt 15 ]; do
    info="$(hciconfig -a 2>/dev/null || true)"
    if printf '%s\n' "$info" | grep -qi '00:AA:01:00:48:58' && printf '%s\n' "$info" | grep -qi '00:AA:01:01:48:59'; then result verified; fi
    attempt=$((attempt + 1))
    sleep 1
done
result controller_attach_failed
'''


BLUETOOTH_H4_STOP_SCRIPT = r'''# HarnessyXO stop only its owned Bluetooth supervisor v1
set -eu
stage="$(mktemp /tmp/harnessy-test-bluetooth-stop.XXXXXX)" || exit 1
trap 'rm -f "$stage"' EXIT HUP INT TERM
cat > "$stage" <<'HARNESSY_OWNED_BLUETOOTH_SERVICE'
''' + BT_H4_SERVICE + r'''HARNESSY_OWNED_BLUETOOTH_SERVICE
if [ ! -L /etc/init.d/harnessy-test-bluetooth ] && [ -f /etc/init.d/harnessy-test-bluetooth ] && cmp -s "$stage" /etc/init.d/harnessy-test-bluetooth; then
    /etc/init.d/harnessy-test-bluetooth disable >/dev/null 2>&1 || true
    /etc/init.d/harnessy-test-bluetooth stop >/dev/null 2>&1 || true
fi
'''


BLUETOOTH_PACKAGES_SCRIPT = r'''# HarnessyXO matching signed Bluetooth packages v1
set -eu
reason=verified
detail=none
crypto_ready() {
    modprobe aes_generic >/dev/null 2>&1 || true
    modprobe ecb >/dev/null 2>&1 || true
    modprobe cmac >/dev/null 2>&1 || true
    grep -Eq '^name[[:space:]]*:[[:space:]]*aes[[:space:]]*$' /proc/crypto
}
if command -v dbus-daemon >/dev/null 2>&1 && command -v bluetoothd >/dev/null 2>&1 && command -v btattach >/dev/null 2>&1 && command -v hciconfig >/dev/null 2>&1 && command -v bluetoothctl >/dev/null 2>&1 && command -v base64 >/dev/null 2>&1 && command -v sha256sum >/dev/null 2>&1 && modprobe hci_uart >/dev/null 2>&1 && modprobe algif_hash >/dev/null 2>&1 && modprobe algif_skcipher >/dev/null 2>&1 && crypto_ready; then
    printf 'HX_RADIO_SETUP bluetooth=verified\nHX_RADIO_DETAIL bluetooth=none\n'
    exit 0
fi
work="$(mktemp -d /tmp/harnessy-test-bluetooth-packages.XXXXXX)" || exit 1
trap 'rm -rf "$work"' EXIT HUP INT TERM
release="$(sed -n "s/^DISTRIB_RELEASE=['\"]\([^'\"]*\)['\"]$/\1/p" /etc/openwrt_release)"
packages='kmod-bluetooth kmod-crypto-user kmod-crypto-cmac kmod-crypto-ecb dbus bluez-daemon bluez-utils bluez-utils-extra coreutils-base64 coreutils-sha256sum'
case "$release" in
    23.05.2|23.05.5) ;;
    25.12.5) packages="$packages kmod-hci-uart";;
    *) reason=stock_feeds_unavailable;;
esac
prefix="https://downloads.openwrt.org/releases/$release/"
if [ "$reason" = verified ] && command -v apk >/dev/null 2>&1; then
    for feed in /etc/apk/repositories /etc/apk/repositories.d/*.list; do
        [ -f "$feed" ] || continue
        awk -v prefix="$prefix" 'NF == 1 && index($1, prefix) == 1 { print $1 }' "$feed"
    done > "$work/repositories"
    if [ ! -s "$work/repositories" ]; then reason=stock_feeds_unavailable
    else
        kernel_version="$(apk list -I kernel 2>/dev/null | sed -n '/^kernel-[a-zA-Z0-9._+~:-][a-zA-Z0-9._+~:-]* .*\[installed\]$/{s/^kernel-\([^ ]*\) .*$/\1/;p;q;}')"
        case "$kernel_version" in ''|*[!a-zA-Z0-9._+~:-]*) reason=package_install_failed;; esac
        if [ "$reason" = verified ]; then
            if ! apk --repositories-file "$work/repositories" update > "$work/install.log" 2>&1; then reason=feed_update_failed
            elif ! apk --repositories-file "$work/repositories" add "kernel=$kernel_version" $packages >> "$work/install.log" 2>&1; then reason=package_install_failed
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
    opkg print-architecture | awk 'NF == 3 && $1 == "arch" && $2 ~ /^[A-Za-z0-9_+-]+$/ && $3 ~ /^[0-9]+$/ { print }' >> "$work/opkg.conf"
    awk -v prefix="$prefix" 'NF == 3 && $1 == "src/gz" && index($3, prefix) == 1 { print }' /etc/opkg/distfeeds.conf > "$work/feeds"
    if [ ! -s "$work/feeds" ]; then reason=stock_feeds_unavailable
    else
        cat "$work/feeds" >> "$work/opkg.conf"
        mkdir "$work/lists" "$work/no-conf"
        if ! OPKG_CONF_DIR="$work/no-conf" opkg --conf "$work/opkg.conf" update > "$work/install.log" 2>&1; then reason=feed_update_failed
        elif ! OPKG_CONF_DIR="$work/no-conf" opkg --conf "$work/opkg.conf" install $packages >> "$work/install.log" 2>&1; then reason=package_install_failed
        fi
    fi
elif [ "$reason" = verified ]; then reason=stock_feeds_unavailable
fi
if [ "$reason" != verified ]; then
    detail=unknown
    if [ -f "$work/install.log" ]; then
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
        # Keep bounded package-manager failure evidence before the temporary
        # directory is removed. The controller stores a sanitized setup receipt;
        # the model receives only the fixed reason/detail fields below.
        printf '[%s] ERROR Bluetooth package setup failed: release=%s reason=%s detail=%s\n' "$(date +%s)" "$release" "$reason" "$detail" >&2
        tail -c 16384 "$work/install.log" >&2
    fi
fi
printf 'HX_RADIO_SETUP bluetooth=%s\nHX_RADIO_DETAIL bluetooth=%s\n' "$reason" "$detail"
'''
