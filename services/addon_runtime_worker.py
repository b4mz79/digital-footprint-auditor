from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path
from typing import Any, Mapping


_PROTOCOL_VERSION = 1
_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024


def _error(message: str, error_type: str = "RuntimeError") -> dict[str, Any]:
    return {
        "protocol_version": _PROTOCOL_VERSION,
        "ok": False,
        "error": {
            "type": error_type,
            "message": str(message),
        },
    }


def _safe_entrypoint(package_root: Path, entrypoint: str) -> Path:
    candidate = (package_root / entrypoint).resolve()
    root = package_root.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("entrypoint escapes add-on package") from exc
    if not candidate.is_file():
        raise ValueError("add-on entrypoint does not exist")
    return candidate


def _load_function(
    package_root: Path,
    entrypoint: Path,
    function_name: str,
):
    package_name = "_privacy_auditor_sandbox_addon"
    module_name = f"{package_name}.{entrypoint.stem}"

    package_module = types.ModuleType(package_name)
    package_module.__path__ = [str(package_root)]
    package_module.__package__ = package_name
    sys.modules[package_name] = package_module

    spec = importlib.util.spec_from_file_location(
        module_name,
        entrypoint,
        submodule_search_locations=(
            [str(package_root)] if entrypoint.name == "__init__.py" else None
        ),
    )
    if spec is None or spec.loader is None:
        raise ValueError("cannot load add-on entrypoint")

    module = importlib.util.module_from_spec(spec)
    module.__package__ = package_name
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
        function = getattr(module, function_name, None)
        if not callable(function):
            raise ValueError(
                f"add-on entrypoint must expose {function_name}(context)"
            )
        return module, function
    except Exception:
        for loaded_name in tuple(sys.modules):
            if loaded_name == package_name or loaded_name.startswith(
                package_name + "."
            ):
                sys.modules.pop(loaded_name, None)
        raise


def execute_request(request: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(request, Mapping):
        return _error("request must be a JSON object", "TypeError")

    if request.get("protocol_version") != _PROTOCOL_VERSION:
        return _error("unsupported runtime protocol version", "ValueError")

    package_root = Path(str(request.get("package_root", ""))).resolve()
    if not package_root.is_dir():
        return _error("package_root does not exist", "ValueError")

    entrypoint_raw = str(request.get("entrypoint", "")).replace("\\", "/").strip()
    function_name = str(request.get("function", "")).strip()
    context = request.get("context", {})

    if not entrypoint_raw:
        return _error("entrypoint is required", "ValueError")
    if not function_name:
        return _error("function is required", "ValueError")
    if not isinstance(context, Mapping):
        return _error("context must be a JSON object", "TypeError")

    try:
        entrypoint = _safe_entrypoint(package_root, entrypoint_raw)
        _, function = _load_function(package_root, entrypoint, function_name)
        result = function(dict(context))

        encoded = json.dumps(
            result,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        if len(encoded.encode("utf-8")) > _MAX_RESPONSE_BYTES:
            return _error("add-on result exceeds IPC response limit", "ValueError")

        return {
            "protocol_version": _PROTOCOL_VERSION,
            "ok": True,
            "result": result,
        }
    except Exception as exc:
        return _error(str(exc), type(exc).__name__)


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if len(args) != 1:
        print(
            json.dumps(
                _error("worker requires exactly one request-file argument"),
                ensure_ascii=False,
            )
        )
        return 2

    request_path = Path(args[0]).resolve()
    try:
        payload = request_path.read_bytes()
        if len(payload) > _MAX_REQUEST_BYTES:
            response = _error(
                "runtime request exceeds IPC request limit",
                "ValueError",
            )
        else:
            request = json.loads(payload.decode("utf-8"))
            response = execute_request(request)
    except Exception as exc:
        response = _error(str(exc), type(exc).__name__)

    sys.stdout.write(
        json.dumps(response, ensure_ascii=False, separators=(",", ":"))
    )
    sys.stdout.flush()
    return 0 if response.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
