from __future__ import annotations

import ast
from pathlib import Path


# The community contract starts with a deliberately small import surface.
# Expand this set only when a reviewed use case requires another dependency.
_ALLOWED_IMPORT_MODULES = frozenset({"__future__", "typing", "streamlit", "pathlib", "json"})
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
    "config", "connection", "connections", "runtime", "secrets", "session_state",
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
    "popen",
    "read_bytes",
    "remove",
    "rename",
    "rmdir",
    "rmtree",
    "system",
    "unlink",
    "urlopen",
    "write_bytes",
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
    # Permit only literal sibling paths derived directly from __file__ for
    # add-on-local lifecycle logs/state. This is a static screening rule, not
    # runtime filesystem confinement.
    local_path_names: set[str] = set()
    approved_path_bindings: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if _is_local_sibling_path(value):
                for target in targets:
                    if isinstance(target, ast.Name):
                        local_path_names.add(target.id)
                        approved_path_bindings.add(id(target))

    # A name that was once bound to a safe sibling path must not be rebound
    # to an arbitrary object or shadowed by a function parameter. Otherwise
    # the later receiver check would trust the name rather than its value.
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Name)
            and node.id in local_path_names
            and isinstance(node.ctx, ast.Store)
            and id(node) not in approved_path_bindings
        ):
            _reject(
                relative_path,
                node.lineno,
                f"local path variable may not be rebound: {node.id}",
            )
        if isinstance(node, ast.arg) and node.arg in local_path_names:
            _reject(
                relative_path,
                node.lineno,
                f"local path variable may not be shadowed: {node.arg}",
            )
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name in local_path_names:
                _reject(
                    relative_path,
                    node.lineno,
                    f"local path variable may not be shadowed: {node.name}",
                )
        if isinstance(node, ast.ExceptHandler) and node.name in local_path_names:
            _reject(
                relative_path,
                node.lineno,
                f"local path variable may not be shadowed: {node.name}",
            )
        if isinstance(node, ast.alias):
            bound_name = node.asname or node.name.split(".", 1)[0]
            if bound_name in local_path_names:
                _reject(
                    relative_path,
                    node.lineno if hasattr(node, "lineno") else 1,
                    f"local path variable may not be shadowed: {bound_name}",
                )
        if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name in local_path_names:
            _reject(
                relative_path,
                node.lineno if hasattr(node, "lineno") else 1,
                f"local path variable may not be shadowed: {node.name}",
            )
        if isinstance(node, ast.MatchMapping) and node.rest in local_path_names:
            _reject(
                relative_path,
                node.lineno if hasattr(node, "lineno") else 1,
                f"local path variable may not be shadowed: {node.rest}",
            )

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
            if isinstance(node.func, ast.Attribute) and node.func.attr in {
                "open", "read_text", "read_bytes", "write_text", "write_bytes"
            }:
                receiver = node.func.value
                if not isinstance(receiver, ast.Name) or receiver.id not in local_path_names:
                    _reject(
                        relative_path,
                        node.lineno,
                        "filesystem access must use a literal sibling path derived from __file__",
                    )
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


def _is_local_sibling_path(node: ast.AST | None) -> bool:
    # Accept Path(__file__).with_name("literal-filename") only.
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return False
    if node.func.attr != "with_name" or len(node.args) != 1:
        return False
    if not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str):
        return False
    base = node.func.value
    if not isinstance(base, ast.Call) or not isinstance(base.func, ast.Name):
        return False
    if base.func.id != "Path" or len(base.args) != 1:
        return False
    return isinstance(base.args[0], ast.Name) and base.args[0].id == "__file__"


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
