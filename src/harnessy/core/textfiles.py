"""Read/edit UTF-8 files without corrupting concurrent agent work or encoding."""
from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

MAX_EDITOR_BYTES = 5 * 1024 * 1024


def _read_regular(path: Path) -> tuple[bytes, int]:
    # Avoid blocking on a FIFO or following a last-component symlink swapped in
    # by another process between selection and Save. Cap reads even after growth.
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as stream:
        st = os.fstat(stream.fileno())
        if not stat.S_ISREG(st.st_mode): raise ValueError('Not a regular file.')
        if st.st_size > MAX_EDITOR_BYTES:
            raise ValueError('File is larger than 5 MiB; download it instead of opening in the editor.')
        raw = stream.read(MAX_EDITOR_BYTES + 1)
    if len(raw) > MAX_EDITOR_BYTES: raise ValueError('File grew beyond the 5 MiB editor limit.')
    return raw, stat.S_IMODE(st.st_mode)


@dataclass(slots=True)
class TextFileDraft:
    path: Path
    resolved: Path
    text: str
    digest: str
    bom: bool
    newline: str

    @classmethod
    def open(cls, path: Path) -> 'TextFileDraft':
        path = Path(path).absolute()
        resolved = path.resolve(strict=True)
        raw, _mode = _read_regular(resolved)
        if b'\0' in raw:
            raise ValueError('Binary file: use Download instead.')
        try:
            source = raw.decode('utf-8-sig')
        except UnicodeDecodeError as exc:
            raise ValueError('This file is not valid UTF-8. Download it rather than risk changing its encoding.') from exc
        # Textareas normalise CRLF in the browser. Retain the original newline
        # convention on an edited Save; an unchanged Save never rewrites bytes.
        crlf = source.count('\r\n')
        lone_lf = source.count('\n') - crlf
        newline = '\r\n' if crlf > lone_lf else '\n'
        text = source.replace('\r\n', '\n').replace('\r', '\n')
        return cls(path, resolved, text, hashlib.sha256(raw).hexdigest(), raw.startswith(b'\xef\xbb\xbf'), newline)

    def save(self, value: str) -> bool:
        text = str(value).replace('\r\n', '\n').replace('\r', '\n')
        if text == self.text:
            return False
        if self.path.resolve(strict=True) != self.resolved:
            raise ValueError('The file target changed while the editor was open. Reopen it before saving.')
        raw, mode = _read_regular(self.resolved)
        if hashlib.sha256(raw).hexdigest() != self.digest:
            raise ValueError('The file changed on disk while you were editing (possibly by the agent). Your draft is still open; reopen the file separately to compare before saving.')
        encoded = (b'\xef\xbb\xbf' if self.bom else b'') + text.replace('\n', self.newline).encode('utf-8')
        if len(encoded) > MAX_EDITOR_BYTES:
            raise ValueError('Edited text exceeds the 5 MiB editor limit.')
        fd, temp = tempfile.mkstemp(prefix='.' + self.resolved.name + '.', dir=self.resolved.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temp, mode)
            # Check again after staging. This guards ordinary external edits;
            # it is not a cross-process locking protocol for arbitrary writers.
            if self.path.resolve(strict=True) != self.resolved or hashlib.sha256(_read_regular(self.resolved)[0]).hexdigest() != self.digest:
                raise ValueError('The file changed on disk during Save; your draft has not overwritten it.')
            os.replace(temp, self.resolved)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
        self.text, self.digest = text, hashlib.sha256(encoded).hexdigest()
        return True
