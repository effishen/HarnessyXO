"""Test guest catalog. UI, validation and controllers share these capabilities.

Official download sources/checksums checked 2026-09-25; OpenWrt 23.05.2 added
and checked 2026-10-10. Malta MIPS images checked 2026-10-15. Release image versions
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
    GuestOS('openwrt-23.05.5', 'OpenWrt 23.05.5', 'OpenWrt Malta MIPS32 big-endian, mips_24kc, musl; Linux 5.15.167.',
            family='openwrt', cpu=1, memory=1024, disk=8, min_memory=256, min_disk=1, shell='ash', interface='web'),
    GuestOS('openwrt-25.12.5', 'OpenWrt 25.12.5', 'Router test VM with an ash shell and LuCI web interface. Internet through private NAT.',
            family='openwrt', cpu=2, memory=512, disk=2, min_memory=256, min_disk=1, shell='ash', interface='web'),
    GuestOS('windows-11', 'Windows 11', 'Download the matching Microsoft ISO and install Windows 11 Pro automatically. Windows support in Lima is experimental.',
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
        # This release publishes Malta big-endian 32-bit only.
        'mips': ('malta/be', 'malta-be',
                 '94effccff827cd7ecb20dd8cd39ffecdc96903224b186d21ec7691cda63d08ca',
                 '1b5d129f97f833c4881d579f9cbac1c2037b0331b27ba09b8933cc1f7f9b3e24'),
    },
    'openwrt-23.05.5': {
        'mips': ('malta/be', 'malta-be',
                 '922c04259d0288ae7ee18508627fe798a17ef3be255cfe872d4b14f78ce6273c',
                 '5e7856278e3b0ce4d071a68427d8472ef1ae089448b203126add9b745f75dbef'),
    },
    'openwrt-25.12.5': {
        'x86_64': ('x86/64', 'x86-64',
                   'a1cb366a0af03d0f4afbce90aed9b4db35b07140629eabf7ae21c45dc08eeb23',
                   'e440f082d59550072b1421f10d1a83449c6a4cf356eea5bfa9ac1306978d649b'),
        'arm64': ('armsr/armv8', 'armsr-armv8',
                  '03172dd9a91e7cb477ab73bcb5de544bfe19f42698d7f66d9b2bb80ca692eaa6',
                  '8cf43c4901efae72b0a04bb655158e03335067e8757926bca4c81d5c952aca51'),
        'mips': ('malta/be', 'malta-be',
                 'ce4ac4c84a5e01060f6da1a8e68edccb9cfdd6b3c59ca93675c6eb8e50264fa0',
                 'ced8942d9286483cd29be4ce3b05eff73beb8f9e070d498e484e18c1dbb94c96'),
        'mipsel': ('malta/le', 'malta-le',
                   '04ded27e51a895a19c47278d8a94343343bc1d6b20997b699cf5a35e34ecaa40',
                   'dc38c11c362cdce58ced8e641e20933d4bb0ce052d03f4cdd24b0ab215a8f4e3'),
        'mips64': ('malta/be64', 'malta-be64',
                   'a831396eef699cf6635ffa561f053a60296caab129ce153f4af9f1fba2320574',
                   '57c923eab8be964e9e9e2657dd72afa0d474c94f23b963e8194caa2cf9c89fdb'),
        'mips64el': ('malta/le64', 'malta-le64',
                     '99e435801adcd95b4796d067982eef52e9447a67c70a5cbd8e4e291b387b353c',
                     '50afe00a917b26686c2e48178a744e8778c4e82c458c76e11b634e3beb98a7b8'),
    },
}
# Preserve the original current-release mapping for callers which use the alias.
OPENWRT_IMAGES = OPENWRT_RELEASE_IMAGES['openwrt-25.12.5']


def target_architectures(os_name: str) -> dict[str, str]:
    """Only advertise image variants whose exact upstream bytes are pinned."""
    labels = {
        'arm64': 'ARM64 (Apple Silicon / ARM hosts)',
        'x86_64': 'x86-64 (Intel / AMD)',
        'mips': 'MIPS32 big-endian (Malta)',
        'mipsel': 'MIPS32 little-endian (Malta)',
        'mips64': 'MIPS64 big-endian (Malta)',
        'mips64el': 'MIPS64 little-endian (Malta)',
    }
    supported = OPENWRT_RELEASE_IMAGES[os_name] if guest_os(os_name).family == 'openwrt' else ('arm64', 'x86_64')
    return {arch: labels[arch] for arch in labels if arch in supported}
