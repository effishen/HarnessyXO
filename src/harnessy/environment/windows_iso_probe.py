"""Bounded, read-only Windows installer-media inspection.

Only fixed installer paths are inspected. ISO 9660 and ordinary physical UDF
partitions are supported; virtual/metadata partitions and allocation chains are
rejected rather than guessed. Layouts follow ECMA-119 / ECMA-167. This proves
installer structure and EFI CPU type, not publisher authenticity or licensing.
"""
from __future__ import annotations

import binascii
from dataclasses import dataclass
import os
from pathlib import Path
import stat
import struct
import xml.etree.ElementTree as ET

BLOCK = 2048
MAX_BYTES_READ = 16 * 1024 * 1024
MAX_DIRECTORY_BYTES = 4 * 1024 * 1024
MAX_DIRECTORY_ENTRIES = 8192
MAX_MEDIA_BYTES = 32 * 1024**3
_MACHINES = {'x86_64': 0x8664, 'arm64': 0xAA64}
_BOOT_FILES = {'x86_64': 'BOOTX64.EFI', 'arm64': 'BOOTAA64.EFI'}


class WindowsISOError(ValueError):
    def __init__(self, code: str = 'WINDOWS_ISO_INVALID') -> None:
        messages = {
            'WINDOWS_ISO_INVALID': 'The selected file is not a readable Windows installer ISO.',
            'WINDOWS_ISO_ARCHITECTURE_MISMATCH': 'The Windows installer ISO does not match the selected VM architecture.',
            'WINDOWS_ISO_UNSUPPORTED': 'This ISO layout could not be verified. Choose an official Windows installer ISO.',
            'WINDOWS_ISO_INCOMPATIBLE_INSTALL_IMAGE': 'Choose an English (United States) Windows 11 multi-edition ISO with the matching Windows Pro installer image.',
        }
        self.code = code if code in messages else 'WINDOWS_ISO_INVALID'
        self.error_code = self.code
        super().__init__(messages[self.code])


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from('<H', data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from('<I', data, offset)[0]


@dataclass(frozen=True)
class _File:
    size: int
    directory: bool
    extents: tuple[tuple[int, int], ...] = ()
    inline: bytes | None = None


class _Reader:
    def __init__(self, stream, size: int) -> None:
        self.stream, self.size, self.bytes_read = stream, size, 0

    def read(self, offset: int, length: int) -> bytes:
        if (offset < 0 or length < 0 or offset + length > self.size
                or self.bytes_read + length > MAX_BYTES_READ):
            raise WindowsISOError()
        self.stream.seek(offset)
        data = self.stream.read(length)
        self.bytes_read += len(data)
        if len(data) != length:
            raise WindowsISOError()
        return data

    def prefix(self, file: _File, maximum: int) -> bytes:
        return self.range(file, 0, min(file.size, maximum))

    def range(self, file: _File, start: int, length: int) -> bytes:
        if start < 0 or length < 0 or start + length > file.size:
            raise WindowsISOError()
        if file.inline is not None:
            return file.inline[start:start + length]
        output = bytearray()
        skip = start
        for offset, extent_length in file.extents:
            if skip >= extent_length:
                skip -= extent_length
                continue
            count = min(length - len(output), extent_length - skip)
            if count:
                output.extend(self.read(offset + skip, count))
            skip = 0
            if len(output) == length:
                break
        if len(output) != length:
            raise WindowsISOError()
        return bytes(output)


class _ISO9660:
    name = 'iso9660'

    def __init__(self, reader: _Reader, descriptor: bytes) -> None:
        self.reader = reader
        if _u16(descriptor, 128) != BLOCK or int.from_bytes(descriptor[130:132], 'big') != BLOCK:
            raise WindowsISOError('WINDOWS_ISO_UNSUPPORTED')
        self.root = self._record(descriptor[156:190])
        if not self.root.directory:
            raise WindowsISOError()

    @staticmethod
    def _record(record: bytes) -> _File:
        if (len(record) < 34 or record[0] > len(record) or record[0] < 34
                or record[1] or record[26] or record[27] or _u16(record, 28) != 1
                or record[30:32] != b'\0\x01' or record[25] & 0x80):
            raise WindowsISOError('WINDOWS_ISO_UNSUPPORTED')
        extent, size = _u32(record, 2), _u32(record, 10)
        if (extent != int.from_bytes(record[6:10], 'big')
                or size != int.from_bytes(record[14:18], 'big')):
            raise WindowsISOError()
        return _File(size, bool(record[25] & 2), ((extent * BLOCK, size),))

    def child(self, directory: _File, wanted: str) -> _File | None:
        if not directory.directory or directory.size > MAX_DIRECTORY_BYTES:
            raise WindowsISOError()
        data, position, entries, result = self.reader.prefix(directory, directory.size), 0, 0, None
        while position < len(data):
            length = data[position]
            if not length:
                position = ((position // BLOCK) + 1) * BLOCK
                continue
            if length < 34 or position + length > len(data) or (position % BLOCK) + length > BLOCK:
                raise WindowsISOError()
            record = data[position:position + length]
            name_length = record[32]
            if 33 + name_length > length:
                raise WindowsISOError()
            name = record[33:33 + name_length].decode('ascii', errors='replace').split(';', 1)[0].rstrip('.')
            if name.upper() == wanted:
                if result is not None:
                    raise WindowsISOError()
                result = self._record(record)
            entries += 1
            if entries > MAX_DIRECTORY_ENTRIES:
                raise WindowsISOError()
            position += length
        return result


def _tag(data: bytes, expected: int | None = None, location: int | None = None) -> int:
    if len(data) < 16 or sum(data[:4] + data[5:16]) % 256 != data[4]:
        raise WindowsISOError()
    identifier, version, crc, length = _u16(data, 0), _u16(data, 2), _u16(data, 8), _u16(data, 10)
    if (version not in {2, 3} or 16 + length > len(data)
            or binascii.crc_hqx(data[16:16 + length], 0) != crc
            or (expected is not None and identifier != expected)
            or (location is not None and _u32(data, 12) != location)):
        raise WindowsISOError()
    return identifier


class _UDF:
    name = 'udf'

    def __init__(self, reader: _Reader) -> None:
        self.reader = reader
        anchor = reader.read(256 * BLOCK, BLOCK)
        _tag(anchor, 2, 256)
        length, location = _u32(anchor, 16), _u32(anchor, 20)
        if not BLOCK <= length <= 1024 * 1024 or length % BLOCK:
            raise WindowsISOError()
        partitions, logical = {}, None
        for block in range(location, location + length // BLOCK):
            data = reader.read(block * BLOCK, BLOCK)
            identifier = _tag(data, location=block)
            if identifier == 5:
                number, start, count = _u16(data, 22), _u32(data, 188), _u32(data, 192)
                if not count or (start + count) * BLOCK > reader.size:
                    raise WindowsISOError()
                partitions[number] = (start, count)
            elif identifier == 6:
                logical = data
            elif identifier == 8:
                break
        if logical is None or _u32(logical, 212) != BLOCK:
            raise WindowsISOError('WINDOWS_ISO_UNSUPPORTED')
        table_length, map_count = _u32(logical, 264), _u32(logical, 268)
        if not 1 <= map_count <= 8 or not 6 <= table_length <= BLOCK - 440:
            raise WindowsISOError('WINDOWS_ISO_UNSUPPORTED')
        maps, position = [], 440
        for _ in range(map_count):
            if position + 6 > 440 + table_length or logical[position:position + 2] != b'\x01\x06':
                raise WindowsISOError('WINDOWS_ISO_UNSUPPORTED')
            number = _u16(logical, position + 4)
            if number not in partitions:
                raise WindowsISOError()
            maps.append(partitions[number])
            position += 6
        if position != 440 + table_length:
            raise WindowsISOError('WINDOWS_ISO_UNSUPPORTED')
        self.maps = maps
        block, partition, extent = self._long_ad(logical, 248)
        if extent < 512:
            raise WindowsISOError()
        fileset = self._block(block, partition)
        _tag(fileset, 256, block)
        block, partition, extent = self._long_ad(fileset, 400)
        if extent < 176:
            raise WindowsISOError()
        self.root = self._inode(block, partition)
        if not self.root.directory:
            raise WindowsISOError()

    @staticmethod
    def _long_ad(data: bytes, position: int) -> tuple[int, int, int]:
        length = _u32(data, position)
        if length >> 30:
            raise WindowsISOError('WINDOWS_ISO_UNSUPPORTED')
        return _u32(data, position + 4), _u16(data, position + 8), length

    def _offset(self, block: int, partition: int, length: int = BLOCK) -> int:
        if not 0 <= partition < len(self.maps):
            raise WindowsISOError()
        start, count = self.maps[partition]
        if block < 0 or length < 0 or block * BLOCK + length > count * BLOCK:
            raise WindowsISOError()
        return (start + block) * BLOCK

    def _block(self, block: int, partition: int) -> bytes:
        return self.reader.read(self._offset(block, partition), BLOCK)

    def _inode(self, block: int, partition: int) -> _File:
        data = self._block(block, partition)
        identifier = _tag(data, location=block)
        if identifier not in {261, 266} or data[27] not in {4, 5}:
            raise WindowsISOError('WINDOWS_ISO_UNSUPPORTED')
        flags, size = _u16(data, 34) & 7, struct.unpack_from('<Q', data, 56)[0]
        base, lengths = (176, 168) if identifier == 261 else (216, 208)
        extended, allocated = _u32(data, lengths), _u32(data, lengths + 4)
        position = base + extended
        if position + allocated > BLOCK or size > MAX_MEDIA_BYTES:
            raise WindowsISOError()
        if flags == 3:
            if size > allocated:
                raise WindowsISOError()
            return _File(size, data[27] == 4, inline=data[position:position + size])
        stride = {0: 8, 1: 16}.get(flags)
        if stride is None or allocated % stride or allocated // stride > 128:
            raise WindowsISOError('WINDOWS_ISO_UNSUPPORTED')
        extents = []
        for pos in range(position, position + allocated, stride):
            length, logical = _u32(data, pos), _u32(data, pos + 4)
            if length >> 30:
                raise WindowsISOError('WINDOWS_ISO_UNSUPPORTED')
            reference = partition if stride == 8 else _u16(data, pos + 8)
            if length:
                extents.append((self._offset(logical, reference, length), length))
        if sum(item[1] for item in extents) < size:
            raise WindowsISOError()
        return _File(size, data[27] == 4, tuple(extents))

    def child(self, directory: _File, wanted: str) -> _File | None:
        if not directory.directory or directory.size > MAX_DIRECTORY_BYTES:
            raise WindowsISOError()
        data, position, entries, result = self.reader.prefix(directory, directory.size), 0, 0, None
        while position < len(data):
            if data[position:position + 16] == b'\0' * 16:
                if data[position:].strip(b'\0'):
                    raise WindowsISOError()
                break
            if position + 38 > len(data):
                raise WindowsISOError()
            name_length, implementation = data[position + 19], _u16(data, position + 36)
            length = (38 + implementation + name_length + 3) & ~3
            if position + length > len(data):
                raise WindowsISOError()
            record = data[position:position + length]
            _tag(record, 257)
            flags = record[18]
            if not flags & (4 | 8):
                name = record[38 + implementation:38 + implementation + name_length]
                try:
                    decoded = (name[1:].decode('latin1') if name[:1] == b'\x08' else
                               name[1:].decode('utf-16-be') if name[:1] == b'\x10' else '')
                except UnicodeError:
                    raise WindowsISOError() from None
                if decoded.isascii() and decoded.upper() == wanted:
                    if result is not None:
                        raise WindowsISOError()
                    block, partition, extent = self._long_ad(record, 20)
                    if extent < 176:
                        raise WindowsISOError()
                    result = self._inode(block, partition)
            position += length
            entries += 1
            if entries > MAX_DIRECTORY_ENTRIES:
                raise WindowsISOError()
        return result


def _lookup(filesystem, *parts: str) -> _File | None:
    current = filesystem.root
    for part in parts:
        current = filesystem.child(current, part)
        if current is None:
            return None
    return current


def _install_image(reader: _Reader, file: _File, architecture: str) -> dict:
    header = reader.prefix(file, 208)
    if (len(header) < 208 or header[:8] != b'MSWIM\0\0\0'
            or not 208 <= _u32(header, 8) <= 4096):
        raise WindowsISOError()
    size_flags, offset, expanded = struct.unpack_from('<QQQ', header, 72)
    size, flags = size_flags & ((1 << 56) - 1), size_flags >> 56
    if flags not in {0, 2} or not 0 < size <= 4 * 1024 * 1024 or size != expanded:
        raise WindowsISOError('WINDOWS_ISO_UNSUPPORTED')
    raw = reader.range(file, offset, size)
    try:
        if raw.startswith((b'\xff\xfe', b'\xfe\xff')):
            text = raw.decode('utf-16')
        elif raw[:2] == b'<\0':
            text = raw.decode('utf-16-le')
        elif raw[:2] == b'\0<':
            text = raw.decode('utf-16-be')
        else:
            text = raw.decode('utf-8-sig')
        if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
            raise ValueError()
        document = ET.fromstring(text)
        images = document.findall('IMAGE')
        index = 6 if architecture == 'x86_64' else 3
        matching = [image for image in images if image.get('INDEX') == str(index)]
        if document.tag != 'WIM' or not 1 <= len(images) <= 256 or len(matching) != 1:
            raise ValueError()
        windows = matching[0].find('WINDOWS')
        if windows is None:
            raise ValueError()
        language = windows.findtext('LANGUAGES/DEFAULT')
        build = int(windows.findtext('VERSION/BUILD') or '')
        if (windows.findtext('EDITIONID') != 'Professional' or language is None
                or language.lower() != 'en-us' or build < 22000
                or windows.findtext('ARCH') != ('9' if architecture == 'x86_64' else '12')
                or windows.findtext('VERSION/MAJOR') != '10'):
            raise ValueError()
        return {'pro_image_index': index, 'build': build, 'language': 'en-US'}
    except (UnicodeError, ValueError, ET.ParseError):
        raise WindowsISOError('WINDOWS_ISO_INCOMPATIBLE_INSTALL_IMAGE') from None


def _probe(reader: _Reader, architecture: str) -> dict:
    descriptor = None
    for block in range(16, 48):
        data = reader.read(block * BLOCK, BLOCK)
        if data[1:6] == b'CD001' and data[6] == 1:
            if data[0] == 1:
                descriptor = data
                break
            if data[0] == 255:
                break
    filesystems = []
    if descriptor is not None:
        filesystems.append(_ISO9660(reader, descriptor))
    # UDF-only Microsoft media has no primary ISO9660 descriptor. Bridge media
    # may expose only a README in ISO9660, so try its UDF view as well.
    udf_error = None
    try:
        filesystems.insert(0, _UDF(reader))
    except WindowsISOError as exc:
        udf_error = exc
    mismatch = False
    for filesystem in filesystems:
        boot = _lookup(filesystem, 'EFI', 'BOOT', _BOOT_FILES[architecture])
        if boot is None:
            other = 'arm64' if architecture == 'x86_64' else 'x86_64'
            mismatch = mismatch or _lookup(filesystem, 'EFI', 'BOOT', _BOOT_FILES[other]) is not None
            continue
        if boot.directory:
            raise WindowsISOError()
        prefix = reader.prefix(boot, 1024 * 1024)
        if len(prefix) < 64 or prefix[:2] != b'MZ':
            raise WindowsISOError()
        offset = _u32(prefix, 60)
        if offset + 6 > len(prefix) or prefix[offset:offset + 4] != b'PE\0\0':
            raise WindowsISOError()
        machine = _u16(prefix, offset + 4)
        if machine != _MACHINES[architecture]:
            mismatch = True
            continue
        boot_wim = _lookup(filesystem, 'SOURCES', 'BOOT.WIM')
        install = _lookup(filesystem, 'SOURCES', 'INSTALL.WIM') or _lookup(filesystem, 'SOURCES', 'INSTALL.ESD')
        if (boot_wim is None or install is None or boot_wim.directory or install.directory
                or reader.prefix(boot_wim, 8) != b'MSWIM\0\0\0'
                or reader.prefix(install, 8) != b'MSWIM\0\0\0'):
            raise WindowsISOError()
        return {'schema_version': 1, 'architecture': architecture, 'filesystem': filesystem.name,
                'boot_machine': machine, 'size_bytes': reader.size, 'windows_installer': True,
                **_install_image(reader, install, architecture)}
    if mismatch:
        raise WindowsISOError('WINDOWS_ISO_ARCHITECTURE_MISMATCH')
    if not filesystems and udf_error is not None:
        raise udf_error
    raise WindowsISOError()


def validate_windows_iso(path: str | Path, architecture: str) -> dict:
    """Inspect fixed EFI/installer records without mounting or executing media."""
    normalized = {'x86_64': 'x86_64', 'amd64': 'x86_64', 'x64': 'x86_64',
                  'arm64': 'arm64', 'aarch64': 'arm64'}.get(str(architecture).lower())
    if normalized is None:
        raise WindowsISOError('WINDOWS_ISO_ARCHITECTURE_MISMATCH')
    descriptor = None
    try:
        candidate = Path(path).expanduser()
        before = candidate.lstat()
        if not stat.S_ISREG(before.st_mode) or not 258 * BLOCK <= before.st_size <= MAX_MEDIA_BYTES:
            raise WindowsISOError()
        descriptor = os.open(candidate, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not 258 * BLOCK <= info.st_size <= MAX_MEDIA_BYTES:
            raise WindowsISOError()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
            raise WindowsISOError()
        with os.fdopen(descriptor, 'rb') as stream:
            descriptor = None
            result = _probe(_Reader(stream, info.st_size), normalized)
            after = os.fstat(stream.fileno())
            if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                raise WindowsISOError()
            return result
    except WindowsISOError:
        raise
    except (OSError, ValueError, OverflowError, struct.error):
        raise WindowsISOError() from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
