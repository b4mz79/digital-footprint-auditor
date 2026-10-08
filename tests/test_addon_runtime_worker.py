from __future__ import annotations

import json
from pathlib import Path

from services.addon_runtime_worker import execute_request


def _package(tmp_path: Path, source: str) -> Path:
    root = tmp_path / "addon"
    root.mkdir()
    (root / "plugin.py").write_text(source, encoding="utf-8")
    return root


def test_worker_executes_json_safe_function(tmp_path: Path) -> None:
    root = _package(
        tmp_path,
        "def run(context):\n    return {'value': context['value'] + 1}\n",
    )

    response = execute_request(
        {
            "protocol_version": 1,
            "package_root": str(root),
            "entrypoint": "plugin.py",
            "function": "run",
            "context": {"value": 41},
        }
    )

    assert response == {
        "protocol_version": 1,
        "ok": True,
        "result": {"value": 42},
    }


def test_worker_rejects_entrypoint_escape(tmp_path: Path) -> None:
    root = _package(tmp_path, "def run(context): return {'ok': True}\n")
    (tmp_path / "outside.py").write_text(
        "def run(context): return {'pwned': True}\n",
        encoding="utf-8",
    )

    response = execute_request(
        {
            "protocol_version": 1,
            "package_root": str(root),
            "entrypoint": "../outside.py",
            "function": "run",
            "context": {},
        }
    )

    assert response["ok"] is False
    assert response["error"]["type"] == "ValueError"


def test_worker_requires_json_object_context(tmp_path: Path) -> None:
    root = _package(tmp_path, "def run(context): return {}\n")

    response = execute_request(
        {
            "protocol_version": 1,
            "package_root": str(root),
            "entrypoint": "plugin.py",
            "function": "run",
            "context": ["not", "a", "mapping"],
        }
    )

    assert response["ok"] is False
    assert response["error"]["type"] == "TypeError"


def test_worker_rejects_protocol_mismatch(tmp_path: Path) -> None:
    root = _package(tmp_path, "def run(context): return {}\n")

    response = execute_request(
        {
            "protocol_version": 999,
            "package_root": str(root),
            "entrypoint": "plugin.py",
            "function": "run",
            "context": {},
        }
    )

    assert response["ok"] is False
    assert response["error"]["type"] == "ValueError"


def test_worker_result_must_cross_json_boundary(tmp_path: Path) -> None:
    root = _package(
        tmp_path,
        "def run(context):\n"
        "    return {'bad': object()}\n",
    )

    response = execute_request(
        {
            "protocol_version": 1,
            "package_root": str(root),
            "entrypoint": "plugin.py",
            "function": "run",
            "context": {},
        }
    )

    assert response["ok"] is False
    assert response["error"]["type"] == "TypeError"


def test_worker_response_is_json_serializable(tmp_path: Path) -> None:
    root = _package(
        tmp_path,
        "def run(context): return {'text': 'ok'}\n",
    )

    response = execute_request(
        {
            "protocol_version": 1,
            "package_root": str(root),
            "entrypoint": "plugin.py",
            "function": "run",
            "context": {},
        }
    )

    json.dumps(response, ensure_ascii=False)
