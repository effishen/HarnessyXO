from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import TypeVar

T = TypeVar('T')


def make_choice_options(
    items: Iterable[T],
    value_fn: Callable[[T], object],
    label_fn: Callable[[T], object],
) -> dict[object, str]:
    """Build NiceGUI select options as value -> display label.

    NiceGUI dictionary-backed selects require ``value`` to match a dictionary
    key. Keeping this conversion in one place prevents the easy-to-miss
    label/value inversion that otherwise raises ``ValueError: Invalid value``.
    """
    return {value_fn(item): str(label_fn(item)) for item in items}
