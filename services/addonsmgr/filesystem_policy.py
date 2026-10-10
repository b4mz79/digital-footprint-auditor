from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path


def apply_package_permissions(package_root: Path) -> None:
    """Protect package files while allowing writes only inside the package directory.

    POSIX filesystems can enforce the intended owner-only mode bits. On Windows,
    Python's chmod support is limited to the read-only attribute, so POSIX group/
    other mode-bit checks are not meaningful there. Windows validation therefore
    checks effective write access instead. Neither mechanism is process isolation.
    """
    root = package_root.resolve()
    if not root.is_dir():
        raise ValueError("installed add-on package root must be a directory")

    paths = sorted(
        root.rglob("*"),
        key=lambda item: (len(item.parts), str(item)),
        reverse=True,
    )
    for path in paths:
        if path.is_symlink():
            raise ValueError("installed add-on package symlinks are not allowed")
        if path.is_dir():
            path.chmod(0o700)
        elif path.is_file():
            path.chmod(0o444)
        else:
            raise ValueError(
                f"unsupported filesystem object in add-on package: {path.name}"
            )

    root.chmod(0o700)

    for path in [root, *paths]:
        if path.is_symlink():
            raise ValueError("installed add-on package symlinks are not allowed")

        if path.is_dir():
            if os.name == "nt":
                if not os.access(path, os.W_OK):
                    raise OSError(
                        f"add-on directory is not writable by the current user: {path.name}"
                    )
            else:
                mode = path.stat().st_mode
                if not mode & stat.S_IWUSR or mode & (stat.S_IWGRP | stat.S_IWOTH):
                    raise OSError(
                        f"add-on directory permissions are too broad or not writable: {path.name}"
                    )
        elif path.is_file():
            if os.name == "nt":
                if os.access(path, os.W_OK):
                    raise OSError(f"add-on file remains writable: {path.name}")
            else:
                mode = path.stat().st_mode
                if mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
                    raise OSError(f"add-on file remains writable: {path.name}")


def remove_package_tree(package_root: Path) -> None:
    """Restore owner write permission before host-controlled package removal."""
    root = Path(package_root)
    if not root.exists() and not root.is_symlink():
        return

    for path in sorted(
        root.rglob("*") if root.is_dir() else (),
        key=lambda item: (len(item.parts), str(item)),
        reverse=True,
    ):
        try:
            if path.is_symlink():
                path.unlink()
            elif path.is_dir():
                path.chmod(0o700)
            elif path.is_file():
                path.chmod(0o600)
        except OSError:
            # Keep walking so a later cleanup attempt can still remove the tree.
            pass

    try:
        if root.is_dir() and not root.is_symlink():
            root.chmod(0o700)
        elif root.is_file() or root.is_symlink():
            root.chmod(0o600)
    except OSError:
        pass

    shutil.rmtree(root, ignore_errors=False)
