from __future__ import annotations

import ast
from pathlib import Path


# The community contract starts with a deliberately small import surface.
# Expand this set only when a reviewed use case requires another dependency.
_ALLOWED_IMPORT_MODULES = frozenset({"__future__", "typing", "streamlit"})
_ALLOWED_RESOURCE_SUFFIXES = frozenset({
    ".py",
    ".json",
    ".md",
    ".txt",
    ".toml",
    ".yaml",
    ".yml",
    ".csv",
    ".css",
})
_FORBIDDEN_CALL_NAMES = frozenset({
    "__import__",
    "breakpoint",
    "compile",
    "delattr",
    "eval",
    "exec",
    "getattr",
    "globals",
    "input",
    "locals",
    "open",
    "setattr",
    "vars",
})
_FORBIDDEN_NAMES = frozenset({"__builtins__", "__loader__", "__spec__"})
_FORBIDDEN_ATTRIBUTES = frozenset({
    "__bases__", "__builtins__", "__class__", "__closure__", "__code__",
    "__dict__", "__globals__", "__getattribute__", "__loader__", "__mro__",
    "__reduce__", "__reduce_ex__", "__spec__", "__subclasses__",
})
_FORBIDDEN_CALL_ATTRIBUTES = frozenset({
    "chmod",
    "chown",
    "connect",
    "execv",
    "execve",
    "fork",
    "mkdir",
    "makedirs",
    "open",
    "popen",
    "read_bytes",
    "read_text",
    "remove",
    "rename",
    "rmdir",
    "rmtree",
    "system",
    "unlink",
    "urlopen",
    "write_bytes",
    "write_text",
})


def validate_package_authority(package_root: Path) -> None:
    """Fail closed when an add-on exceeds the static authority policy.

    This gate scans every package file, including helpers, UI modules and
    lifecycle code. It is a static allowlist, not a Python sandbox: approved
    modules and same-process execution cannot provide OS-level confinement.
    """
    root = package_root.resolve()
    if not root.is_dir():
        raise ValueError("add-on package root must be a directory")

    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("add-on package symlinks are not allowed")
        if not path.is_file():
            continue

        suffix = path.suffix.lower()
        if suffix not in _ALLOWED_RESOURCE_SUFFIXES:
            raise ValueError(
                f"add-on contains an unsupported file type: {path.relative_to(root)}"
            )

        if suffix != ".py":
            continue

        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise ValueError(
                f"cannot read add-on source file: {path.relative_to(root)}"
            ) from exc

        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError as exc:
            raise ValueError(
                f"add-on Python source cannot be parsed: {path.relative_to(root)}"
            ) from exc

        _validate_python_tree(tree, path.relative_to(root).as_posix())


def _validate_python_tree(tree: ast.AST, relative_path: str) -> None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                _validate_import(alias.name, relative_path, node.lineno)

        elif isinstance(node, ast.ImportFrom):
            # Package-local imports are permitted; the whole package is scanned.
            if node.level:
                continue
            module = node.module or ""
            _validate_import(module, relative_path, node.lineno)

        elif isinstance(node, ast.Name) and node.id in _FORBIDDEN_NAMES:
            _reject(relative_path, node.lineno, f"forbidden runtime introspection name: {node.id}")

        elif isinstance(node, ast.Attribute) and node.attr in _FORBIDDEN_ATTRIBUTES:
            _reject(relative_path, node.lineno, f"forbidden runtime introspection attribute: {node.attr}")

        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id in _FORBIDDEN_CALL_NAMES:
                    _reject(relative_path, node.lineno, f"forbidden call {node.func.id}()")
            elif isinstance(node.func, ast.Attribute):
                if node.func.attr in _FORBIDDEN_CALL_ATTRIBUTES:
                    _reject(
                        relative_path,
                        node.lineno,
                        f"forbidden API call .{node.func.attr}()",
                    )

        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            _reject(relative_path, node.lineno, "global/nonlocal state mutation is not allowed")


def _validate_import(module: str, relative_path: str, line_number: int) -> None:
    if module not in _ALLOWED_IMPORT_MODULES:
        _reject(
            relative_path,
            line_number,
            f"import is not allowlisted: {module or '<empty>'}",
        )


def _reject(relative_path: str, line_number: int, reason: str) -> None:
    raise ValueError(
        f"add-on rejected by static authority gate: "
        f"{relative_path}:{line_number}: {reason}"
    )
