#!/usr/bin/env python3
"""Answer one OpenSSH password prompt from a private inherited pipe."""
from __future__ import annotations

import os
import sys


def main() -> int:
    prompt = ' '.join(sys.argv[1:]).lower()
    if 'password' not in prompt:
        return 1  # Do not disclose the password to an unrelated SSH prompt.
    try:
        descriptor = os.open(os.environ['HARNESSY_SSH_ASKPASS_PIPE'], os.O_RDONLY | os.O_NONBLOCK)
        try:
            password = os.read(descriptor, 4097)
        finally:
            os.close(descriptor)
        if not password or b'\x00' in password or b'\n' in password:
            return 1
        sys.stdout.buffer.write(password + b'\n')
        return 0
    except (KeyError, ValueError, OSError):
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
