"""Shared validation for host-owned security and resource ceilings."""

from __future__ import annotations

import math


def bounded_positive_int(value: object, *, name: str, hard_max: int) -> int:
    """Return a positive exact integer that cannot exceed ``hard_max``."""

    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    if value > hard_max:
        raise ValueError(f"{name} must be at most {hard_max}")
    return value


def bounded_positive_finite(
    value: object, *, name: str, hard_max: float
) -> int | float:
    """Return a positive finite number that cannot exceed ``hard_max``."""

    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be finite and positive")
    if value > hard_max:
        raise ValueError(f"{name} must be at most {hard_max:g}")
    return value
