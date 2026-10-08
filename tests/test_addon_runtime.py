from __future__ import annotations

import os
from pathlib import Path

import pytest

from services import addon_runtime


def test_profile_name_is_bounded_and_safe() -> None:
    name = addon_runtime._profile_name("just-sample")
    assert name == "PrivacyAuditorAddon_just-sample"
    assert len(name) <= 64
    assert all(char.isalnum() or char in "-_." for char in name)


def test_windows_attribute_constants_match_win32_contract() -> None:
    assert addon_runtime._PROC_THREAD_ATTRIBUTE_HANDLE_LIST == 0x00020002
    assert addon_runtime._PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES == 0x00020009


def test_windows_creation_flags_include_unicode_environment() -> None:
    assert addon_runtime._CREATE_UNICODE_ENVIRONMENT == 0x00000400


def test_runtime_rejects_non_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(addon_runtime.os, "name", "posix")
    with pytest.raises(RuntimeError, match="requires Windows"):
        addon_runtime._require_windows()


@pytest.mark.skipif(os.name != "nt", reason="Windows AppContainer integration test")
def test_appcontainer_runtime_executes_worker(tmp_path: Path) -> None:
    addon_root = tmp_path / "addon"
    addon_root.mkdir()
    (addon_root / "plugin.py").write_text(
        "def run(context):\n"
        "    return {'value': context['value'] + 1}\n",
        encoding="utf-8",
    )

    result = addon_runtime.execute_addon(
        addon_root,
        entrypoint="plugin.py",
        function="run",
        context={"value": 41},
        addon_id="runtime-test",
    )

    assert result == {"value": 42}


@pytest.mark.skipif(os.name != "nt", reason="Windows AppContainer integration test")
def test_appcontainer_runtime_blocks_network_by_default(tmp_path: Path) -> None:
    addon_root = tmp_path / "addon"
    addon_root.mkdir()
    (addon_root / "plugin.py").write_text(
        "import urllib.request\n"
        "def run(context):\n"
        "    try:\n"
        "        urllib.request.urlopen('https://example.com', timeout=3)\n"
        "    except Exception as exc:\n"
        "        return {'blocked': True, 'error': type(exc).__name__}\n"
        "    return {'blocked': False}\n",
        encoding="utf-8",
    )

    result = addon_runtime.execute_addon(
        addon_root,
        entrypoint="plugin.py",
        function="run",
        context={},
        addon_id="network-test",
    )

    assert result["blocked"] is True


@pytest.mark.skipif(os.name != "nt", reason="Windows AppContainer integration test")
def test_appcontainer_runtime_cannot_read_host_secret(tmp_path: Path) -> None:
    secret = tmp_path / "host-secret.txt"
    secret.write_text("DO-NOT-READ", encoding="utf-8")

    addon_root = tmp_path / "addon"
    addon_root.mkdir()
    (addon_root / "plugin.py").write_text(
        f"def run(context):\n"
        f"    try:\n"
        f"        open({str(secret)!r}, 'r', encoding='utf-8').read()\n"
        f"    except Exception as exc:\n"
        f"        return {{'blocked': True, 'error': type(exc).__name__}}\n"
        f"    return {{'blocked': False}}\n",
        encoding="utf-8",
    )

    result = addon_runtime.execute_addon(
        addon_root,
        entrypoint="plugin.py",
        function="run",
        context={},
        addon_id="filesystem-test",
    )

    assert result["blocked"] is True
