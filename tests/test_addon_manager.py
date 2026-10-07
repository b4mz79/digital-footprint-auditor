from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from services.addon_manager import AddonManager


def _zip_package(
    *,
    addon_id: str = "demo-addon",
    entrypoint: str = "plugin.py",
    plugin_body: str = "def run(context):\n    return {'ok': True, 'value': context['value']}\n",
) -> bytes:
    manifest = {
        "id": addon_id,
        "name": "Demo Add-on",
        "caption": "Demo",
        "version": "1.0.0",
        "entrypoint": entrypoint,
        "default_active": False,
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            f"{addon_id}/manifest.json",
            json.dumps(manifest),
        )
        archive.writestr(f"{addon_id}/{entrypoint}", plugin_body)
    return buffer.getvalue()


def test_install_discover_activate_invoke_uninstall(tmp_path: Path) -> None:
    manager = AddonManager(tmp_path / "addons")

    installed = manager.install_zip(_zip_package())
    assert installed["id"] == "demo-addon"
    assert installed["active"] is False

    listed = manager.get("demo-addon")
    assert listed is not None
    assert listed["caption"] == "Demo"

    with pytest.raises(ValueError, match="not active"):
        manager.invoke("demo-addon", {"value": 7})

    manager.activate("demo-addon")
    addon, result = manager.invoke("demo-addon", {"value": 7})
    assert addon["id"] == "demo-addon"
    assert result == {"ok": True, "value": 7}

    manager.deactivate("demo-addon")
    assert manager.get("demo-addon")["active"] is False

    manager.uninstall("demo-addon")
    assert manager.get("demo-addon") is None


def test_install_rejects_duplicate(tmp_path: Path) -> None:
    manager = AddonManager(tmp_path / "addons")
    payload = _zip_package()

    manager.install_zip(payload)
    with pytest.raises(ValueError, match="already installed"):
        manager.install_zip(payload)


def test_install_rejects_zip_slip(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("../manifest.json", "{}")

    manager = AddonManager(tmp_path / "addons")
    with pytest.raises(ValueError, match="unsafe path"):
        manager.install_zip(buffer.getvalue())


def test_install_rejects_invalid_entrypoint_path(tmp_path: Path) -> None:
    manifest = {
        "id": "demo-addon",
        "name": "Demo",
        "caption": "Demo",
        "version": "1.0.0",
        "entrypoint": "../plugin.py",
        "default_active": False,
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("demo-addon/manifest.json", json.dumps(manifest))
        archive.writestr("demo-addon/plugin.py", "def run(context): return None\n")

    manager = AddonManager(tmp_path / "addons")
    with pytest.raises(ValueError, match="entrypoint"):
        manager.install_zip(buffer.getvalue())
