"""Human-facing Project/Chat identifiers and canonical directory names.

The alphabet intentionally omits characters which are commonly confused in
small UI text: 0/O/Q, 1/I/L, 2/Z, 5/S, 8/B, and G beside 6.  Identifiers are
uppercase, fixed-width, durable, and safe to use as one path component.
"""
from __future__ import annotations

import re
import secrets
from collections import Counter
from collections.abc import Collection
from itertools import product


CHAT_OUTPUT_ID_LENGTH = 4
CHAT_OUTPUT_ALPHABET = '34679ACDEFHJKMNPRTVWXY'
PROJECT_FOLDER_PREFIX = 'Project-'
CHAT_OUTPUT_ID_RE = re.compile(
    rf'^[{re.escape(CHAT_OUTPUT_ALPHABET)}]{{{CHAT_OUTPUT_ID_LENGTH}}}$'
)
CHAT_OUTPUT_DIR_RE = re.compile(
    rf'^{re.escape(PROJECT_FOLDER_PREFIX)}([{re.escape(CHAT_OUTPUT_ALPHABET)}]{{{CHAT_OUTPUT_ID_LENGTH}}})$'
)
LEGACY_CHAT_OUTPUT_ID_RE = re.compile(rf'^[{re.escape(CHAT_OUTPUT_ALPHABET)}]{{8}}$')


def valid_chat_output_id(value: str) -> bool:
    return bool(CHAT_OUTPUT_ID_RE.fullmatch(str(value or '').strip().upper()))


def chat_output_folder_name(public_id: str) -> str:
    value = str(public_id or '').strip().upper()
    if not valid_chat_output_id(value):
        raise ValueError('Invalid Project/Chat output ID')
    return PROJECT_FOLDER_PREFIX + value


def chat_output_id_from_folder(name: str) -> str | None:
    match = CHAT_OUTPUT_DIR_RE.fullmatch(str(name or ''))
    return match.group(1) if match else None


def new_chat_output_id(unavailable: Collection[str] = ()) -> str:
    blocked = {
        str(value or '').strip().upper() for value in unavailable
        if valid_chat_output_id(str(value or ''))
    }
    counts = Counter(value[0] for value in blocked)
    capacity = len(CHAT_OUTPUT_ALPHABET) ** (CHAT_OUTPUT_ID_LENGTH - 1)
    available = [prefix for prefix in CHAT_OUTPUT_ALPHABET if counts[prefix] < capacity]
    if not available:
        raise RuntimeError('All Project/Chat output IDs in this workspace are in use')
    # Prefer a different first character for the first 22 outputs. Thereafter
    # distribute prefixes evenly, including reserved IDs of deleted chats.
    least_used = min(counts[prefix] for prefix in available)
    prefixes = [prefix for prefix in available if counts[prefix] == least_used]
    prefix = secrets.choice(prefixes)
    for _attempt in range(64):
        value = prefix + ''.join(
            secrets.choice(CHAT_OUTPUT_ALPHABET) for _ in range(CHAT_OUTPUT_ID_LENGTH - 1)
        )
        if value not in blocked:
            return value
    # A broken/repeating RNG must not prevent allocation when space remains.
    # At most 22^3 suffixes are checked, even for a nearly-full workspace.
    for suffix in product(CHAT_OUTPUT_ALPHABET, repeat=CHAT_OUTPUT_ID_LENGTH - 1):
        value = prefix + ''.join(suffix)
        if value not in blocked:
            return value
    raise RuntimeError('Could not allocate a unique Project/Chat output ID')
