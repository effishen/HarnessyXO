"""Test guest catalog. UI, validation and controllers share these capabilities.

Official download sources/checksums checked 2026-09-25; OpenWrt 23.05.2 added
and checked 2026-10-10. Release image versions
are deliberately explicit; updating a catalog entry never replaces an existing
guest disk. These are test targets, independent of workspace VM presets.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class GuestOS:
    id: str
    label: str
    description: str
    template: str = ''
    family: str = 'debian'
    cpu: int = 4
    memory: int = 4096
    disk: int = 40
    min_memory: int = 2048
    min_disk: int = 20
    shell: str = 'Bash'
    interface: str = 'desktop'


GUESTS = {item.id: item for item in (
    GuestOS('ubuntu-24.04', 'Ubuntu 24.04 LTS', 'Ubuntu server with an optional Xfce desktop.', '_images/ubuntu-24.04'),
    GuestOS('ubuntu-26.04', 'Ubuntu 26.04 LTS', 'Ubuntu server with an optional Xfce desktop.', '_images/ubuntu-26.04'),
    GuestOS('debian-13', 'Debian 13', 'Debian stable with an optional Xfce desktop.', '_images/debian-13'),
    GuestOS('fedora-44', 'Fedora 44', 'Fedora cloud with an optional Xfce desktop.', '_images/fedora-44', family='fedora'),
    GuestOS('kali-2026.2', 'Kali Linux 2026.2', 'Official generic cloud image; add tools with apt. Optional Xfce desktop.', min_disk=30),
    GuestOS('openwrt-23.05.2', 'OpenWrt 23.05.2', 'Router test VM with an ash shell and LuCI web interface. Internet through private NAT.',
            family='openwrt', cpu=2, memory=512, disk=2, min_memory=256, min_disk=1, shell='ash', interface='web'),
    GuestOS('openwrt-25.12.5', 'OpenWrt 25.12.5', 'Router test VM with an ash shell and LuCI web interface. Internet through private NAT.',
            family='openwrt', cpu=2, memory=512, disk=2, min_memory=256, min_disk=1, shell='ash', interface='web'),
    GuestOS('windows-11', 'Windows 11', 'Install from your own English (United States) ISO. Windows support in Lima is experimental.',
            'windows-11', family='windows', memory=8192, disk=80, min_memory=4096, min_disk=64, shell='PowerShell'),
)}


def guest_os(name: str) -> GuestOS:
    try:
        return GUESTS[name]
    except KeyError:
        raise ValueError('Choose an operating system from the test VM catalog.') from None


# Pinned upstream bytes, not mutable "latest" aliases.
KALI_IMAGES = {
    'x86_64': ('amd64', '3f4ca86ae1eca0dc2bf2092f065a959508e186c6b44f85758813a8e9a0604f3e'),
    'arm64': ('arm64', '9ab19c28d049fdc6f1d5d30f6cc93b8b01997f11c89f6992f690c07b16b7b7e4'),
}
OPENWRT_RELEASE_IMAGES = {
    'openwrt-23.05.2': {
        'x86_64': ('x86/64', 'x86-64',
                   'b48df205150a4465b48a21f9449b3cb79d2dd3181feda0cb0ebd6693e1dc3596',
                   '19ea5d644317bb77931a4f94030b8c2bbd1312c554ec1bf276e80cf4a02f36c6'),
        'arm64': ('armsr/armv8', 'armsr-armv8',
                  '15b08d4fa7ce483b4878866f56e1f520bfa8eada59087a7c46c4613817e12a65',
                  'f969399d881abef448311acddeed519fa500bd8d59622ab471beddf8dd32466d'),
    },
    'openwrt-25.12.5': {
        'x86_64': ('x86/64', 'x86-64',
                   'a1cb366a0af03d0f4afbce90aed9b4db35b07140629eabf7ae21c45dc08eeb23',
                   'e440f082d59550072b1421f10d1a83449c6a4cf356eea5bfa9ac1306978d649b'),
        'arm64': ('armsr/armv8', 'armsr-armv8',
                  '03172dd9a91e7cb477ab73bcb5de544bfe19f42698d7f66d9b2bb80ca692eaa6',
                  '8cf43c4901efae72b0a04bb655158e03335067e8757926bca4c81d5c952aca51'),
    },
}
# Preserve the original current-release mapping for callers which use the alias.
OPENWRT_IMAGES = OPENWRT_RELEASE_IMAGES['openwrt-25.12.5']
