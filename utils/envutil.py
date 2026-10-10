"""Small, dependency-free helpers for reading configuration from the environment."""
from __future__ import annotations

import os


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_non_negative_int(name: str, default: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)).strip())
    except (TypeError, ValueError):
        value = default
    return max(0, min(value, maximum))


def env_positive_float(name: str, default: float, maximum: float) -> float:
    try:
        value = float(os.getenv(name, str(default)).strip())
    except (TypeError, ValueError):
        value = default
    if value <= 0:
        value = default
    return min(value, maximum)


def env_choice_list(name: str, default: list[str], allowed: set[str]) -> list[str]:
    """Comma-separated list restricted to `allowed`, order preserved, duplicates removed.
    Falls back to `default` when unset or when nothing valid remains."""
    raw = os.getenv(name, "")
    items = [part.strip().lower() for part in raw.split(",") if part.strip()]
    chosen = [item for item in dict.fromkeys(items) if item in allowed]
    return chosen or list(default)
