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
    addon_type: str = "backend",
    mode: str = "on_demand",
    events: list[dict] | None = None,
    return_type: str = "result",
    return_required: bool = True,
) -> bytes:
    manifest = {
        "id": addon_id,
        "name": "Demo Add-on",
        "caption": "Demo",
        "version": "1.0.0",
        "entrypoint": entrypoint,
        "type": addon_type,
        "invocation": {
            "function": "run",
            "mode": mode,
            "input": {"required": True},
            "return": {
                "type": return_type,
                "required": return_required,
            },
        },
        "events": events if events is not None else [],
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
    assert installed["type"] == "backend"
    assert installed["invocation"]["function"] == "run"
    assert installed["invocation"]["mode"] == "on_demand"
    assert installed["invocation"]["input"]["required"] is True
    assert installed["invocation"]["return"] == {
        "type": "result",
        "required": True,
    }
    assert installed["events"] == []

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


def test_invoke_rejects_event_only_addon(tmp_path: Path) -> None:
    manager = AddonManager(tmp_path / "addons")
    payload = _zip_package(
        addon_id="event-addon",
        mode="on_event",
        events=[{"name": "evidence.enriched"}],
        return_required=False,
    )
    manager.install_zip(payload)
    manager.activate("event-addon")

    with pytest.raises(ValueError, match="not configured for on-demand"):
        manager.invoke("event-addon", {})


def test_dispatch_event_invokes_matching_active_addon(tmp_path: Path) -> None:
    manager = AddonManager(tmp_path / "addons")
    payload = _zip_package(
        addon_id="event-addon",
        mode="on_event",
        events=[{"name": "evidence.enriched"}],
        return_required=False,
        plugin_body=(
            "def run(context):\n"
            "    return {'event': context['event'], 'value': context['value']}\n"
        ),
    )
    manager.install_zip(payload)
    manager.activate("event-addon")

    results = manager.dispatch_event(
        "evidence.enriched",
        {"event": "evidence.enriched", "value": 42},
    )

    assert len(results) == 1
    addon, result = results[0]
    assert addon["id"] == "event-addon"
    assert result == {"event": "evidence.enriched", "value": 42}


def test_dispatch_event_skips_non_matching_or_inactive_addons(
    tmp_path: Path,
) -> None:
    manager = AddonManager(tmp_path / "addons")
    manager.install_zip(
        _zip_package(
            addon_id="event-addon",
            mode="on_event",
            events=[{"name": "evidence.enriched"}],
            return_required=False,
        )
    )

    assert manager.dispatch_event("evidence.enriched", {}) == ()


def test_manifest_rejects_invalid_type(tmp_path: Path) -> None:
    manager = AddonManager(tmp_path / "addons")
    with pytest.raises(ValueError, match="type"):
        manager.install_zip(
            _zip_package(addon_id="invalid-type", addon_type="unknown")
        )


def test_manifest_rejects_invalid_invocation_contract(tmp_path: Path) -> None:
    manager = AddonManager(tmp_path / "addons")
    payload = json.loads(
        _zip_package(addon_id="invalid-invocation").decode("latin1")
        if False
        else "{}"
    )
    del payload
    buffer = io.BytesIO()
    manifest = {
        "id": "invalid-invocation",
        "name": "Demo",
        "caption": "Demo",
        "version": "1.0.0",
        "entrypoint": "plugin.py",
        "type": "backend",
        "invocation": {
            "function": "execute",
            "mode": "on_demand",
            "input": {"required": True},
            "return": {"type": "result", "required": True},
        },
        "events": [],
    }
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "invalid-invocation/manifest.json",
            json.dumps(manifest),
        )
        archive.writestr(
            "invalid-invocation/plugin.py",
            "def execute(context): return {}\n",
        )

    with pytest.raises(ValueError, match="invocation.function"):
        manager.install_zip(buffer.getvalue())


def test_install_after_uninstall(tmp_path: Path) -> None:
    manager = AddonManager(tmp_path / "addons")
    payload = _zip_package()

    manager.install_zip(payload)
    manager.uninstall("demo-addon")

    installed = manager.install_zip(payload)
    assert installed["id"] == "demo-addon"
    assert installed["active"] is False


def test_invoke_loads_addon_as_isolated_package(tmp_path: Path) -> None:
    manager = AddonManager(tmp_path / "addons")
    plugin = "from .helper import VALUE\n\ndef run(context):\n    return {'value': VALUE}\n"
    buffer = io.BytesIO()
    manifest = {
        "id": "package-addon",
        "name": "Package Add-on",
        "caption": "Package",
        "version": "1.0.0",
        "entrypoint": "plugin.py",
        "type": "backend",
        "invocation": {
            "function": "run",
            "mode": "on_demand",
            "input": {"required": False},
            "return": {"type": "result", "required": True},
        },
        "events": [],
        "default_active": False,
    }
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("package-addon/manifest.json", json.dumps(manifest))
        archive.writestr("package-addon/plugin.py", plugin)
        archive.writestr("package-addon/helper.py", "VALUE = 42\n")

    manager.install_zip(buffer.getvalue())
    manager.activate("package-addon")

    _, result = manager.invoke("package-addon", {})
    assert result == {"value": 42}


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
        "type": "backend",
        "invocation": {
            "function": "run",
            "mode": "on_demand",
            "input": {"required": True},
            "return": {"type": "result", "required": True},
        },
        "events": [],
        "default_active": False,
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("demo-addon/manifest.json", json.dumps(manifest))
        archive.writestr("demo-addon/plugin.py", "def run(context): return None\n")

    manager = AddonManager(tmp_path / "addons")
    with pytest.raises(ValueError, match="entrypoint"):
        manager.install_zip(buffer.getvalue())
