from __future__ import annotations

import ast
from pathlib import Path

# This is a conservative static allowlist, not an execution sandbox. Keep the
# import surface small; expand it only with a reviewed use case and tests.
_ALLOWED_IMPORT_ROOTS = frozenset({
    "__future__",
    "collections",
    "collections.abc",
    "dataclasses",
    "datetime",
    "decimal",
    "enum",
    "fractions",
    "functools",
    "itertools",
    "json",
    "math",
    "operator",
    "re",
    "statistics",
    "string",
    "textwrap",
    "typing",
    "streamlit",
})

# Only inert, non-executable support files are accepted alongside Python.
_ALLOWED_RESOURCE_SUFFIXES = frozenset({
    ".json", ".md", ".txt", ".toml", ".yaml", ".yml", ".csv",
    ".png", ".jpg", ".jpeg", ".webp", ".gif",
})
_FORBIDDEN_CALLS = frozenset({
    "__import__", "eval", "exec", "compile", "open", "input",
    "breakpoint", "getattr", "setattr", "delattr", "globals",
    "locals", "vars", "dir", "memoryview",
})
_FORBIDDEN_NAMES = frozenset({
    "__builtins__", "__cached__", "__file__", "__loader__", "__package__",
    "__path__", "__spec__", "breakpoint", "exec", "eval", "compile",
    "__import__",
})
_FORBIDDEN_ATTRIBUTES = frozenset({
    "__bases__", "__builtins__", "__class__", "__closure__", "__code__",
    "__dict__", "__func__", "__globals__", "__mro__", "__subclasses__",
    "func_globals",
})
_MAX_SOURCE_BYTES = 2 * 1024 * 1024


def validate_package_authority(package_root: Path) -> None:
    """Fail closed unless every package file fits the static authority policy.

    This rejects common filesystem, process, network, reflection, and dynamic
    execution routes by allowing only a small set of imports and constructs.
    It cannot prove arbitrary Python safe and does not enforce OS-level access
    controls; add-ons still execute in the host process.
    """
    root = package_root.resolve()
    if not root.is_dir():
        raise ValueError("add-on package root must be a directory")

    try:
        paths = sorted(root.rglob("*"))
    except OSError as exc:
        raise RuntimeError("cannot enumerate add-on package") from exc

    for path in paths:
        try:
            if path.is_symlink():
                raise ValueError(f"add-on package symlinks are not allowed: {path.name}")
            if not path.is_file():
                continue
            resolved = path.resolve()
            resolved.relative_to(root)
            suffix = path.suffix.lower()
            if suffix == ".py":
                _validate_python_file(path)
            elif suffix not in _ALLOWED_RESOURCE_SUFFIXES:
                raise ValueError(
                    f"add-on file type is not allowlisted: {path.relative_to(root)}"
                )
        except ValueError:
            raise
        except OSError as exc:
            raise RuntimeError(
                f"cannot inspect add-on package file: {path.name}"
            ) from exc


def _validate_python_file(path: Path) -> None:
    try:
        source_bytes = path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"cannot read add-on source file: {path.name}") from exc
    if len(source_bytes) > _MAX_SOURCE_BYTES:
        raise ValueError(f"add-on Python source file is too large: {path.name}")
    try:
        source = source_bytes.decode("utf-8")
        tree = ast.parse(source, filename=path.name)
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise ValueError(f"add-on Python source cannot be safely parsed: {path.name}") from exc

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                _validate_import(alias.name, path)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                # Relative imports are permitted only within the scanned package.
                # The target module itself is still scanned as a .py file.
                continue
            if node.module is None:
                raise ValueError(f"unresolved import in add-on source: {path.name}")
            _validate_import(node.module, path)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in _FORBIDDEN_CALLS:
                raise ValueError(
                    f"forbidden dynamic or ambient-authority call "
                    f"{node.func.id} in {path.name}:{node.lineno}"
                )
        elif isinstance(node, ast.Name) and node.id in _FORBIDDEN_NAMES:
            raise ValueError(
                f"forbidden runtime-introspection name {node.id} "
                f"in {path.name}:{node.lineno}"
            )
        elif isinstance(node, ast.Attribute):
            if node.attr.startswith("__") or node.attr in _FORBIDDEN_ATTRIBUTES:
                raise ValueError(
                    f"forbidden runtime-introspection attribute {node.attr} "
                    f"in {path.name}:{node.lineno}"
                )


def _validate_import(module: str, path: Path) -> None:
    root = module.split(".", 1)[0]
    if root not in _ALLOWED_IMPORT_ROOTS:
        raise ValueError(
            f"import is not allowlisted ({module}) in {path.name}"
        )
