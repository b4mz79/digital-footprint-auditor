from __future__ import annotations

from pathlib import Path

from typing import Protocol


class _ManifestLike(Protocol):
    entrypoint: str
    ui_entrypoint: str | None



_MAX_PACKAGE_FILES = 500
_MAX_PACKAGE_BYTES = 50 * 1024 * 1024
_ALLOWED_ENTRYPOINT_SUFFIX = ".py"


def validate_package_structure(
    package_root: Path,
    manifest: _ManifestLike,
) -> None:
    """Validate the extracted add-on package without executing its code.

    Archive-level safety is handled by AddonManager._safe_extract().
    Manifest semantics are handled by AddonManager._read_manifest().
    This gate verifies that the resulting package on disk matches the
    manifest's executable structure before anything is installed or imported.
    """
    root = package_root.resolve()
    if not root.is_dir():
        raise ValueError("add-on package root must be a directory")

    manifest_path = root / "manifest.json"
    _ensure_inside(root, manifest_path)
    if not manifest_path.is_file():
        raise ValueError("add-on manifest.json is required")

    file_count = 0
    total_size = 0

    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("add-on package symlinks are not allowed")
        if not path.is_file():
            continue

        file_count += 1
        if file_count > _MAX_PACKAGE_FILES:
            raise ValueError("add-on package contains too many files")

        try:
            total_size += path.stat().st_size
        except OSError as exc:
            raise ValueError(
                f"cannot inspect add-on package file: {path.name}"
            ) from exc

        if total_size > _MAX_PACKAGE_BYTES:
            raise ValueError("add-on package is too large")

    _validate_python_entrypoint(
        root,
        manifest.entrypoint,
        label="add-on entrypoint",
    )

    if manifest.ui_entrypoint:
        _validate_python_entrypoint(
            root,
            manifest.ui_entrypoint,
            label="add-on UI entrypoint",
        )


def _validate_python_entrypoint(
    root: Path,
    relative: str,
    *,
    label: str,
) -> None:
    candidate = (root / relative).resolve()
    _ensure_inside(root, candidate)

    if candidate.suffix.lower() != _ALLOWED_ENTRYPOINT_SUFFIX:
        raise ValueError(f"{label} must be a Python .py file")

    if not candidate.is_file():
        raise ValueError(f"{label} not found: {relative}")


def _ensure_inside(root: Path, candidate: Path) -> None:
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            "add-on package path must stay inside its package"
        ) from exc
