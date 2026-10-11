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
}
FUTURE_IMAGES = {
    'openwrt': 'OpenWrt as the primary working VM is a future integration. OpenWrt test VMs are available in External/Test Targets; these are not router-board emulators.',
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
    prefix = image_id.split('-')[0]
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
        # Preserve the old Ubuntu preset names/IDs for existing workspaces.
        name = f'{image.name.replace(" LTS", "")} — {"Reverse Engineering" if tools_id == "reverse" else tools_name}'
        pid = f'{prefix}-{tools_id}'
        PRESETS[pid] = EnvironmentPreset(pid, name, image.description, image.name,
            packages, optional, supplemental, image_id, tools_id)

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
