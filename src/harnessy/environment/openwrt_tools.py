"""Optional OpenWrt 23.05.5 packages, verified against its mips_24kc feeds.

Package availability is not a claim that a tool or hardware controller is active.
The provider verifies installed packages and records failures separately.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class OpenWrtTool:
    id: str
    label: str
    group: str
    packages: tuple[str, ...]
    note: str = ''


OPENWRT_REQUIRED_PACKAGES = ('bash', 'unshare', 'mount-utils', 'sudo', 'tar', 'python3-light', 'python3-urllib', 'ca-bundle')
OPENWRT_TOOLS = (
    OpenWrtTool('python3', 'Python 3.11 standard library', 'Python', ('python3',)),
    OpenWrtTool('python3-pip', 'pip', 'Python', ('python3-pip',)),
    OpenWrtTool('python3-setuptools', 'setuptools', 'Python', ('python3-setuptools',)),
    OpenWrtTool('python3-venv', 'Python virtual environments', 'Python', ('python3-venv',), 'OpenWrt may require --without-pip; pip is a separate option.'),
    OpenWrtTool('python3-dev', 'Python development headers', 'Python', ('python3-dev',)),
    OpenWrtTool('python3-pytest', 'pytest', 'Python', ('python3-pytest',)),
    OpenWrtTool('gcc', 'Native GCC / C++ compiler', 'Native development', ('gcc',), 'Software-emulated MIPS builds are slow.'),
    OpenWrtTool('make', 'GNU Make', 'Native development', ('make',)),
    OpenWrtTool('pkgconf', 'pkg-config', 'Native development', ('pkgconf',)),
    OpenWrtTool('binutils', 'Binary utilities', 'Debugging', ('binutils',)),
    OpenWrtTool('gdb', 'GDB', 'Debugging', ('gdb',)),
    OpenWrtTool('gdbserver', 'GDB server', 'Debugging', ('gdbserver',)),
    OpenWrtTool('strace', 'strace', 'Debugging', ('strace',)),
    OpenWrtTool('file', 'file', 'Everyday tools', ('file',)),
    OpenWrtTool('git', 'Git with HTTPS', 'Everyday tools', ('git', 'git-http')),
    OpenWrtTool('curl', 'curl', 'Everyday tools', ('curl',)),
    OpenWrtTool('wget-ssl', 'wget', 'Everyday tools', ('wget-ssl',)),
    OpenWrtTool('openssh-client', 'SSH client', 'Everyday tools', ('openssh-client',)),
    OpenWrtTool('openssh-sftp-client', 'SFTP client', 'Everyday tools', ('openssh-sftp-client',)),
    OpenWrtTool('rsync', 'rsync', 'Everyday tools', ('rsync',)),
    OpenWrtTool('nano', 'nano', 'Everyday tools', ('nano',)),
    OpenWrtTool('jq', 'jq', 'Everyday tools', ('jq',)),
    OpenWrtTool('tcpdump', 'tcpdump', 'Networking', ('tcpdump',)),
    OpenWrtTool('ip-full', 'iproute2', 'Networking', ('ip-full',)),
    OpenWrtTool('bind-dig', 'DNS tools', 'Networking', ('bind-dig',)),
    OpenWrtTool('iperf3', 'iperf3', 'Networking', ('iperf3',)),
    OpenWrtTool('socat', 'socat', 'Networking', ('socat',)),
    OpenWrtTool('bluez', 'BlueZ utilities and daemon', 'Bluetooth', ('bluez-daemon', 'bluez-utils', 'bluez-utils-extra'), 'Installing utilities does not create a Bluetooth controller.'),
    OpenWrtTool('btmon', 'Bluetooth monitor', 'Bluetooth', ('bluez-utils-btmon',), 'Capturing HCI traffic requires an available controller and privileges.'),
)
OPENWRT_TOOL_BY_ID = {tool.id: tool for tool in OPENWRT_TOOLS}
# These need an independently implemented runtime/build integration; never
# expose an enabled switch that silently does nothing on MIPS.
OPENWRT_UNAVAILABLE_TOOLS = {
    'cmake': 'No CMake package is published in the pinned mips_24kc feed.',
    'ninja': 'No Ninja package is published in the pinned mips_24kc feed.',
    'ghidra': 'The curated Ghidra runtime is not supported on MIPS.',
    'rea': 'The REA runtime is not supported on MIPS.',
    'bumble': 'Bumble and its native dependencies need a separately verified MIPS build.',
}


def selected_openwrt_tools(values) -> tuple[str, ...]:
    requested = tuple(values or ())
    if '*' in requested:
        return tuple(OPENWRT_TOOL_BY_ID)
    unknown = set(requested) - OPENWRT_TOOL_BY_ID.keys()
    if unknown:
        raise ValueError('Unsupported OpenWrt tool selections: ' + ', '.join(sorted(unknown)))
    return tuple(dict.fromkeys(requested))
