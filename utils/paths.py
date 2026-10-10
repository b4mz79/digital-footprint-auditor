"""Filesystem locations that do not depend on the current working directory.

Before this module, cache directories, the cache key and ignored_domains.txt were resolved
relative to the cwd, so starting the app from another folder silently created a second key
(making the old cache unreadable) and a second cache tree.
"""
from __future__ import annotations

from pathlib import Path


def project_root() -> Path:
    """Directory that contains app.py (walks up from this file)."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "app.py").is_file():
            return parent
    return here.parent.parent


def resolve_data_path(value: str | None, default: str) -> Path:
    """Absolute path for a configurable file/dir. Relative values are anchored to the project
    root; absolute values (and ~) are honoured as-is."""
    raw = (value or "").strip() or default
    path = Path(raw).expanduser()
    return path if path.is_absolute() else project_root() / path
