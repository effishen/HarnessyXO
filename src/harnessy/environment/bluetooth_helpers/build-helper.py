#!/usr/bin/env python3
"""Build the guest controller helper from official BlueZ5.83 sources and the bundled HCI endian patch."""
from __future__ import annotations
import argparse
from pathlib import Path
import subprocess
import hashlib
import tempfile

SOURCES = (
    'emulator/btdev.c', 'src/shared/util.c', 'src/shared/queue.c',
    'src/shared/crypto.c', 'src/shared/ecc.c', 'src/shared/mainloop.c',
    'src/shared/io-mainloop.c', 'src/shared/timeout-mainloop.c',
    'src/shared/mainloop-notify.c', 'lib/bluetooth.c',
)

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bluez', required=True, type=Path, help='Extracted official bluez-5.83 source directory')
    parser.add_argument('--compiler', default='cc', help='Native C compiler, or Zig executable when --target is set')
    parser.add_argument('--target', help='Zig target triple, for example mips-linux-musl')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    source = Path(__file__).resolve().with_name('harnessy-test-bt.c')
    bluez = args.bluez.resolve()
    for item in SOURCES:
        if not (bluez / item).is_file():
            parser.error('Missing BlueZ source: ' + item)
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [args.compiler]
    if args.target:
        command += ['cc', '-target', args.target]
    if args.target and args.target.startswith('mips'):
        command += ['-msoft-float']
    original = bluez / 'emulator/btdev.c'
    if hashlib.sha256(original.read_bytes()).hexdigest() != '0eb3fa1ece53d618b7cf261b99bbe5de94fc0a52cd95ac7639c15f18628b722c':
        parser.error('The emulator source must be the unmodified official BlueZ5.83 file.')
    patch = source.with_name('bluez-5.83-hci-endian.patch')
    with tempfile.TemporaryDirectory(prefix='harnessy-bt-build-') as temporary:
        patched = Path(temporary) / 'btdev.c'
        subprocess.run(['patch', '--batch', '--quiet', '--fuzz=0', '--output', str(patched),
                        str(original), str(patch)], check=True, cwd=bluez)
        command += ['-static', '-Os', '-ffunction-sections', '-fdata-sections', '-I', str(bluez),
                    '-I', str(bluez / 'emulator'), '-Wl,--gc-sections', str(source)]
        command += [str(patched if item == 'emulator/btdev.c' else bluez / item) for item in SOURCES]
        command += ['-o', str(output)]
        subprocess.run(command, check=True, cwd=bluez)

if __name__ == '__main__':
    main()
