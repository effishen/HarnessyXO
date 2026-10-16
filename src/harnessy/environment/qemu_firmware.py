"""Locate default QEMU UEFI data using Lima 2.2.1's firmware search paths.

Firmware is host data rather than an executable. Finding QEMU on PATH does
not establish that a package installation supplied its separate UEFI files.
This check reads metadata only and never downloads firmware or starts a VM.
"""
from __future__ import annotations

from pathlib import Path
import os
import stat


_ARCHITECTURES = {'arm64': 'aarch64', 'aarch64': 'aarch64',
                  'x86_64': 'x86_64', 'amd64': 'x86_64', 'x64': 'x86_64'}
_SYSTEM_FIRMWARE = {
    'aarch64': (
        '/usr/share/edk2/aarch64/QEMU_CODE.fd',
        '/usr/share/AAVMF/AAVMF_CODE.fd',
        '/usr/share/qemu-efi-aarch64/QEMU_EFI.fd',
    ),
    'x86_64': (
        '/usr/share/edk2/x64/OVMF_CODE.4m.fd',
        '/usr/share/OVMF/OVMF_CODE.fd',
        '/usr/share/OVMF/OVMF_CODE_4M.fd',
        '/usr/share/edk2/ovmf/OVMF_CODE.fd',
        '/usr/share/qemu/ovmf-x86_64.bin',
        '/usr/share/qemu/ovmf-x86_64-4m.bin',
    ),
}


def find_qemu_firmware(architecture: str, qemu_binary_path: str | Path | None) -> str | None:
    """Return a nonempty regular firmware file the default Lima driver uses.

    Preserve the discovered executable's prefix: Lima uses ``exec.LookPath``
    without resolving its symlinks. Normal Homebrew share-directory symlinks
    are followed by stat, while an unlinked Cellar copy cannot cause a false
    ready result for a public executable whose share data is missing.
    """
    arch = _ARCHITECTURES.get(str(architecture or '').lower().strip())
    if arch is None:
        return None
    relative = Path('share') / 'qemu' / f'edk2-{arch}-code.fd'
    candidates: list[Path] = []
    try:
        candidates.append(Path.home() / '.local' / relative)
    except (OSError, RuntimeError):
        pass
    if qemu_binary_path:
        executable = Path(qemu_binary_path)
        candidates.extend((executable.parent.parent / relative,
                           executable.parent / 'share' / f'edk2-{arch}-code.fd'))
    candidates.extend(Path(path) for path in _SYSTEM_FIRMWARE[arch])
    for candidate in dict.fromkeys(candidates):
        try:
            metadata = candidate.stat()
            if (stat.S_ISREG(metadata.st_mode) and metadata.st_size > 0
                    and os.access(candidate, os.R_OK)):
                return str(candidate)
            # Lima stops at its first existing candidate. A bad earlier file
            # shadows later valid system data, so do not report the fallback
            # as ready when the driver will actually select this bad entry.
            return None
        except (OSError, RuntimeError):
            continue
    return None
