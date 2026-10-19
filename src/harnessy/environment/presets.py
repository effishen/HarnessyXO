"""Image catalog and compatible tool bundles, independent of VM execution mode.

Legacy composite preset IDs are retained in environment.json. Image and bundle
specifications are separate so a future OpenWrt/Windows/Pi integration need not
pretend to be an apt/systemd Linux guest. Unimplemented guests are not selectable.
"""
from __future__ import annotations

import platform
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class GuestImage:
    id: str
    name: str
    template: str
    package_manager: str
    description: str
    integration: str = 'linux-systemd'
    architectures: tuple[str, ...] = ('arm64', 'x86_64')
    qemu_mount: str = '9p'
    experimental: bool = True
    capabilities: tuple[str, ...] = ('Terminal / command execution', 'Isolated selected root → /workspace', 'CPU only', 'VM snapshots')


IMAGES = {
    'ubuntu-24.04': GuestImage('ubuntu-24.04', 'Ubuntu 24.04 LTS', '_images/ubuntu-24.04', 'apt',
        'General-purpose Ubuntu cloud image; existing HarnessyXO default.', experimental=False),
    'debian-12': GuestImage('debian-12', 'Debian 12 (Bookworm)', '_images/debian-12', 'apt',
        'Debian cloud image with a smaller base. New HarnessyXO integration.', qemu_mount='reverse-sshfs'),
    'fedora-43': GuestImage('fedora-43', 'Fedora 43', '_images/fedora-43', 'dnf',
        'Fedora Cloud Base image. Uses RPM/DNF, not Ubuntu provisioning.'),
    'ubuntu-26.04': GuestImage('ubuntu-26.04', 'Ubuntu 26.04 LTS', '_images/ubuntu-26.04', 'apt',
        'Ubuntu cloud image with the same isolated project bridge.'),
    'debian-13': GuestImage('debian-13', 'Debian 13', '_images/debian-13', 'apt',
        'Debian cloud image with the same isolated project bridge.', qemu_mount='reverse-sshfs'),
    'fedora-44': GuestImage('fedora-44', 'Fedora 44', '_images/fedora-44', 'dnf',
        'Fedora Cloud Base image with RPM/DNF provisioning.'),
    'kali-2026.2': GuestImage('kali-2026.2', 'Kali Linux 2026.2', '', 'apt',
        'Verified official Kali generic cloud image; isolated project files and optional desktop.'),
    'windows-11': GuestImage('windows-11', 'Windows 11', 'windows-11', 'windows',
        'Install from your own English (United States) ISO. PowerShell, graphical console and explicit project copies.',
        integration='managed', qemu_mount='separate-copy',
        capabilities=('PowerShell command execution', 'Separate deployed project copies', 'Graphical installer / desktop', 'Stopped VM snapshots')),
}
IMAGES['openwrt-23.05.5'] = GuestImage(
    'openwrt-23.05.5', 'OpenWrt 23.05.5 (MIPS big-endian)', '', 'opkg',
    'Malta mips_24kc, big-endian, musl, Linux 5.15.167; Python 3.11.7. Software CPU emulation.',
    integration='openwrt', architectures=('mips',), qemu_mount='synchronized-project',
    capabilities=('Terminal / command execution', 'Authorized project synchronization', 'CPU only', 'Stopped VM snapshots'),
)
FUTURE_IMAGES = {
    'windows': 'Windows as the primary working VM is a future integration. Windows test VMs are available in External/Test Targets.',
    'raspberry-pi-os': 'Future: Raspberry Pi OS/board emulation requires a compatible board and explicit peripheral limitations.',
}
TOOL_BUNDLES = {
    'minimal': 'Minimal',
    'general': 'General Development',
    'reverse': 'Reverse Engineering / Firmware Analysis',
}


@dataclass(frozen=True, slots=True)
class EnvironmentPreset:
    id: str
    name: str
    description: str
    guest_os: str
    packages: tuple[str, ...]
    optional_packages: tuple[str, ...] = ()
    supplemental_tools: tuple[str, ...] = ()
    image_id: str = 'ubuntu-24.04'
    tools_id: str = 'reverse'

    @property
    def image(self) -> GuestImage:
        return IMAGES[self.image_id]

    @property
    def optional_tool_ids(self) -> tuple[str, ...]:
        """Selectable optional tool IDs exposed by the workspace picker.

        Package IDs are the package-manager names themselves; supplemental
        bundles have stable IDs such as ``ghidra`` and ``python-re``.
        """
        return tuple(dict.fromkeys((*self.optional_packages, *self.supplemental_tools)))


# Minimum integration requirements are installed even in the Minimal bundle.
MINIMUM_PACKAGES = ('bash', 'ca-certificates', 'coreutils', 'procps', 'util-linux', 'iptables', 'iproute2', 'sudo')
COMMON_DEV_PACKAGES = (
    'bash', 'ca-certificates', 'curl', 'wget', 'git', 'jq', 'file', 'less', 'nano',
    'procps', 'psmisc', 'lsof', 'unzip', 'zip', 'p7zip-full', 'xz-utils',
    'python3', 'python3-pip', 'python3-venv', 'build-essential', 'cmake', 'ninja-build',
    'pkg-config', 'ripgrep', 'fd-find', 'iptables', 'util-linux',
)
REVERSE_PACKAGES = COMMON_DEV_PACKAGES + (
    'binutils', 'gdb', 'strace', 'ltrace', 'squashfs-tools', 'e2fsprogs',
    'qemu-user', 'qemu-user-static', 'yara', 'binwalk',
)

# Extra reverse-engineering utilities are best-effort because distro package
# names vary. Ubuntu 24.04 is HarnessyXO's default reverse preset and gets the
# broadest curated set; absence of one optional package must never make the VM
# unusable.
UBUNTU_REVERSE_OPTIONAL = (
    'radare2', 'rizin', 'gdb-multiarch', 'patchelf', 'checksec', 'xxd',
    'bsdextrautils', 'cpio', 'lz4', 'zstd', 'cabextract', 'libarchive-tools',
    'device-tree-compiler', 'u-boot-tools', 'mtd-utils', 'sleuthkit', 'foremost',
    'apktool', 'jadx', 'dexdump', 'dexlist', 'elfutils', 'pax-utils', 'nasm', 'clang',
    'llvm', 'lldb', 'valgrind', 'tshark', 'sqlite3', 'libimage-exiftool-perl',
    'python3-capstone', 'python3-unicorn', 'python3-pwntools', 'python3-pefile',
    'python3-pyelftools', 'python3-yara', 'ropgadget', 'upx-ucl', 'pev',
    'mono-utils', 'mingw-w64', 'gcc-multilib', 'libc6-dev-i386', 'libc6-dbg',
    'dwarfdump', 'rpm2cpio', 'tcpdump', 'socat', 'netcat-openbsd', 'arj',
)
GHIDRA_VERSION = '12.1.3'
GHIDRA_RELEASE_TAG = 'Ghidra_12.1.3_build'
GHIDRA_RELEASE_FILE = 'ghidra_12.1.3_PUBLIC_20260817.zip'
GHIDRA_RELEASE_SHA256 = '93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54'
GHIDRA_RELEASE_DIR = 'ghidra_12.1.3_PUBLIC'
RPM_MINIMUM = ('bash', 'ca-certificates', 'coreutils', 'procps-ng', 'util-linux', 'iptables-nft', 'iproute', 'sudo')
RPM_DEV = RPM_MINIMUM + ('curl', 'wget', 'git', 'jq', 'file', 'less', 'nano', 'psmisc', 'lsof', 'unzip', 'zip', 'xz',
    'python3', 'python3-pip', 'gcc', 'gcc-c++', 'make', 'cmake', 'ninja-build', 'pkgconf-pkg-config', 'ripgrep', 'fd-find')
RPM_REVERSE = RPM_DEV + ('binutils', 'gdb', 'strace', 'ltrace', 'squashfs-tools', 'e2fsprogs', 'qemu-user', 'yara')

PRESETS: dict[str, EnvironmentPreset] = {}
for image_id, image in IMAGES.items():
    if image.integration != 'linux-systemd':
        continue
    prefix = {'ubuntu-24.04': 'ubuntu', 'debian-12': 'debian', 'fedora-43': 'fedora'}.get(image_id, image_id)
    for tools_id, tools_name in TOOL_BUNDLES.items():
        packages = ({'minimal': MINIMUM_PACKAGES, 'general': COMMON_DEV_PACKAGES, 'reverse': REVERSE_PACKAGES}
                    if image.package_manager == 'apt' else
                    {'minimal': RPM_MINIMUM, 'general': RPM_DEV, 'reverse': RPM_REVERSE})[tools_id]
        optional = ('radare2', 'rizin') if tools_id == 'reverse' else ()
        supplemental: tuple[str, ...] = ()
        if image.package_manager == 'dnf' and tools_id == 'reverse':
            optional += ('binwalk', '7zip')
        if image_id == 'ubuntu-24.04' and tools_id == 'reverse':
            # JDK 21 is a hard dependency of the pinned official Ghidra build;
            # all other additions stay best-effort to preserve provisioning on
            # mirrors where an optional package is temporarily unavailable.
            packages = packages + ('openjdk-21-jdk-headless',)
            optional = UBUNTU_REVERSE_OPTIONAL
            supplemental = ('ghidra', 'python-re')
        if tools_id == 'reverse':
            supplemental += ('rea',)
        if image_id == 'kali-2026.2':
            # Kali rolling mirrors can rename development packages. Keep only
            # the isolation baseline mandatory; selected extras are verified
            # and reported through the existing optional-tool installer.
            optional = tuple(dict.fromkeys((*tuple(package for package in packages if package not in MINIMUM_PACKAGES), *optional)))
            packages = MINIMUM_PACKAGES
        # Preserve the old Ubuntu preset names/IDs for existing workspaces.
        name = f'{image.name.replace(" LTS", "")} — {"Reverse Engineering" if tools_id == "reverse" else tools_name}'
        pid = f'{prefix}-{tools_id}'
        PRESETS[pid] = EnvironmentPreset(pid, name, image.description, image.name,
            packages, optional, supplemental, image_id, tools_id)

PRESETS['windows-11'] = EnvironmentPreset(
    'windows-11', 'Windows 11', IMAGES['windows-11'].description, 'Windows 11',
    (), (), (), 'windows-11', 'minimal')

from .openwrt_tools import OPENWRT_REQUIRED_PACKAGES, OPENWRT_TOOL_BY_ID
PRESETS['openwrt-23.05.5'] = EnvironmentPreset(
    'openwrt-23.05.5', 'OpenWrt 23.05.5 — MIPS big-endian',
    IMAGES['openwrt-23.05.5'].description, 'OpenWrt 23.05.5',
    OPENWRT_REQUIRED_PACKAGES, tuple(OPENWRT_TOOL_BY_ID), (), 'openwrt-23.05.5', 'minimal',
)

DEFAULT_PRESET_ID = 'ubuntu-reverse'


def get_preset(preset_id: str) -> EnvironmentPreset:
    return PRESETS.get(str(preset_id or '').lower(), PRESETS[DEFAULT_PRESET_ID])


def select_preset(image_id: str, tools_id: str) -> EnvironmentPreset:
    for preset in PRESETS.values():
        if preset.image_id == image_id and preset.tools_id == tools_id:
            return preset
    raise ValueError('This image/tool combination is not supported.')


def canonical_arch(value: str) -> str:
    value = str(value or '').lower().strip()
    return {'aarch64': 'arm64', 'amd64': 'x86_64', 'x64': 'x86_64'}.get(value, value)


def execution_mode(architecture: str, *, host_arch: str | None = None, host_os: str | None = None) -> tuple[str, str]:
    host = canonical_arch(host_arch or platform.machine())
    arch = canonical_arch(architecture)
    system = host_os or platform.system()
    if arch != host:
        return 'qemu', 'Emulated CPU — substantially slower than native virtualization'
    if system == 'Darwin' and arch == 'arm64':
        return 'vz', 'Native virtualization — Apple Virtualization.framework'
    return 'qemu', 'Native-architecture QEMU — acceleration depends on host availability'

# Retain the existing pinned OpenWrt image choices in the unified VM catalog.
from .test_catalog import OPENWRT_RELEASE_IMAGES as _OPENWRT_RELEASE_IMAGES
for _release in ('openwrt-23.05.2', 'openwrt-25.12.5'):
    _version = _release.removeprefix('openwrt-')
    IMAGES[_release] = GuestImage(
        _release, 'OpenWrt ' + _version, '', 'apk' if _version.startswith('25.') else 'opkg',
        'Official OpenWrt image; package versions follow this release. Project files use explicit SSH synchronization.',
        integration='openwrt', architectures=tuple(_OPENWRT_RELEASE_IMAGES[_release]),
        qemu_mount='synchronized-project', capabilities=IMAGES['openwrt-23.05.5'].capabilities,
    )
    PRESETS[_release] = EnvironmentPreset(
        _release, 'OpenWrt ' + _version, IMAGES[_release].description, 'OpenWrt ' + _version,
        () if _version.startswith('25.') else OPENWRT_REQUIRED_PACKAGES,
        () if _version.startswith('25.') else tuple(OPENWRT_TOOL_BY_ID), (), _release, 'minimal',
    )
