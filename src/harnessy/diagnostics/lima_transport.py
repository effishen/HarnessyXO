"""Content-free SSH evidence for Lima shell controller completions.

Exit 255 is an SSH/controller observation, not proof of a particular network
failure. Only explicit stderr signatures establish a more specific stage.
This classifier never retries commands, contacts a guest or retains prose.
"""
from __future__ import annotations

from typing import Any

from .guest_logs import transport_evidence


def lima_shell_transport_evidence(controller_action: str, *, stderr: Any = b'',
                                  returncode: int | None = None,
                                  timed_out: bool = False) -> dict[str, Any]:
    if controller_action != 'shell' or not (type(returncode) is int and returncode == 255
                                           or timed_out is True):
        return {}
    return transport_evidence(stderr, returncode=returncode, timed_out=timed_out is True)
