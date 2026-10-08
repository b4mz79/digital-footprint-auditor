from __future__ import annotations

import stat
from pathlib import Path

import pytest

from services.addonsmgr.filesystem_policy import (
    apply_package_permissions,
    remove_package_tree,
)


def test_package_permissions_make_files_and_directories_read_only(
    tmp_path: Path,
) -> None:
    root = tmp_path / "addon"
    nested = root / "resources"
    nested.mkdir(parents=True)
    (root / "plugin.py").write_text("def run(context): return {}\n", encoding="utf-8")
    (nested / "labels.txt").write_text("sample", encoding="utf-8")

    apply_package_permissions(root)

    for path in [root, nested]:
        mode = path.stat().st_mode
        assert mode & stat.S_IWUSR != 0
        assert mode & (stat.S_IWGRP | stat.S_IWOTH) == 0
    for path in [root / "plugin.py", nested / "labels.txt"]:
        assert path.stat().st_mode & stat.S_IWUSR == 0


def test_remove_package_tree_handles_read_only_install_tree(tmp_path: Path) -> None:
    root = tmp_path / "addon"
    nested = root / "resources"
    nested.mkdir(parents=True)
    (root / "plugin.py").write_text("def run(context): return {}\n", encoding="utf-8")
    (nested / "labels.txt").write_text("sample", encoding="utf-8")
    apply_package_permissions(root)

    remove_package_tree(root)

    assert not root.exists()


def test_package_permissions_fail_for_missing_root(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="must be a directory"):
        apply_package_permissions(tmp_path / "missing")
