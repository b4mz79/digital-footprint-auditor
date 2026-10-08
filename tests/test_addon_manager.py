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
    input_fields: list[str] | None = None,
    ui_body: str | None = None,
    lifecycle: dict[str, str | None] | None = None,
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
            "input": {
                "required": True,
                "fields": input_fields if input_fields is not None else ["value"],
            },
            "return": {
                "type": return_type,
                "required": return_required,
            },
        },
        "events": events if events is not None else [],
        "default_active": False,
        "lifecycle": lifecycle or {},
    }
    if ui_body is not None:
        manifest["ui"] = {"entrypoint": "ui.py", "function": "render"}
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            f"{addon_id}/manifest.json",
            json.dumps(manifest),
        )
        archive.writestr(f"{addon_id}/{entrypoint}", plugin_body)
        if ui_body is not None:
            archive.writestr(f"{addon_id}/ui.py", ui_body)
    return buffer.getvalue()


def test_install_discover_activate_invoke_uninstall(tmp_path: Path) -> None:
    manager = AddonManager(tmp_path / "addons")

    installed = manager.install_zip(_zip_package())
    assert installed["id"] == "demo-addon"
    assert installed["active"] is False
    assert installed["type"] == "backend"
    assert installed["invocation"]["function"] == "run"
    assert installed["invocation"]["mode"] == "on_demand"
    assert installed["invocation"]["input"] == {
        "required": True,
        "fields": ["value"],
    }
    assert installed["invocation"]["return"] == {
        "type": "result",
        "required": True,
    }
    assert installed["events"] == []

    listed = manager.get("demo-addon")
    assert listed is not None
    assert listed["caption"] == "Demo"

    with pytest.raises(ValueError, match="not active"):
        manager.invoke("demo-addon", {"data": {"value": 7, "secret": "drop"}})

    manager.activate("demo-addon")
    addon, result = manager.invoke("demo-addon", {"value": 7})
    assert addon["id"] == "demo-addon"
    assert result == {"ok": True, "value": 7}

    manager.deactivate("demo-addon")
    assert manager.get("demo-addon")["active"] is False

    manager.uninstall("demo-addon")
    assert manager.get("demo-addon") is None


def test_manifest_driven_lifecycle_hooks_run_in_order(tmp_path: Path) -> None:
    manager = AddonManager(tmp_path / "addons")
    plugin = """from pathlib import Path

_LOG = Path(__file__).with_name("lifecycle.log")


def _record(name):
    with _LOG.open("a", encoding="utf-8") as handle:
        handle.write(name + "\\n")


def run(context):
    return {"ok": True}


def after_install(context):
    _record("after_install")


def before_activate(context):
    _record("before_activate")


def after_activate(context):
    _record("after_activate")


def before_deactivate(context):
    _record("before_deactivate")


def after_deactivate(context):
    _record("after_deactivate")


def before_uninstall(context):
    _record("before_uninstall")
"""
    manager.install_zip(
        _zip_package(
            addon_id="lifecycle-addon",
            plugin_body=plugin,
            lifecycle={
                "after_install": "after_install",
                "before_activate": "before_activate",
                "after_activate": "after_activate",
                "before_deactivate": "before_deactivate",
                "after_deactivate": "after_deactivate",
                "before_uninstall": "before_uninstall",
            },
        )
    )

    log_path = tmp_path / "addons" / "lifecycle-addon" / "lifecycle.log"
    assert log_path.read_text(encoding="utf-8").splitlines() == [
        "after_install"
    ]

    manager.activate("lifecycle-addon")
    manager.deactivate("lifecycle-addon")
    assert log_path.read_text(encoding="utf-8").splitlines() == [
        "after_install",
        "before_activate",
        "after_activate",
        "before_deactivate",
        "after_deactivate",
    ]

    manager.uninstall("lifecycle-addon")
    assert log_path.exists() is False


def test_lifecycle_before_hook_can_veto_state_change(tmp_path: Path) -> None:
    manager = AddonManager(tmp_path / "addons")
    plugin = """def run(context):
    return {"ok": True}


def before_activate(context):
    raise RuntimeError("activation blocked")
"""
    manager.install_zip(
        _zip_package(
            addon_id="veto-addon",
            plugin_body=plugin,
            lifecycle={"before_activate": "before_activate"},
        )
    )

    with pytest.raises(RuntimeError, match="activation blocked"):
        manager.activate("veto-addon")
    assert manager.get("veto-addon")["active"] is False


def test_after_activate_failure_rolls_back_activation(tmp_path: Path) -> None:
    manager = AddonManager(tmp_path / "addons")
    plugin = """def run(context):
    return {"ok": True}


def after_activate(context):
    raise RuntimeError("post activation failed")
"""
    manager.install_zip(
        _zip_package(
            addon_id="rollback-addon",
            plugin_body=plugin,
            lifecycle={"after_activate": "after_activate"},
        )
    )

    with pytest.raises(RuntimeError, match="post activation failed"):
        manager.activate("rollback-addon")

    assert manager.get("rollback-addon")["active"] is False


def test_manifest_rejects_removed_lifecycle_hooks(tmp_path: Path) -> None:
    manager = AddonManager(tmp_path / "addons")
    for hook_name in ("before_install", "after_uninstall"):
        with pytest.raises(ValueError, match="unsupported add-on lifecycle hook"):
            manager.install_zip(
                _zip_package(
                    addon_id=f"invalid-{hook_name.replace('_', '-')}",
                    lifecycle={hook_name: "hook"},
                )
            )


def test_invoke_ui_for_active_non_backend_addon(tmp_path: Path) -> None:
    manager = AddonManager(tmp_path / "addons")
    payload = _zip_package(
        addon_id="hybrid-addon",
        addon_type="hybrid",
        ui_body="def render(context):\n    return None\n",
    )
    manager.install_zip(payload)
    manager.activate("hybrid-addon")

    addon, result = manager.invoke_ui(
        "hybrid-addon",
        {"result": {"ok": True}},
    )

    assert addon["id"] == "hybrid-addon"
    assert addon["type"] == "hybrid"
    assert result is None


def test_backend_addon_has_no_ui_invoker(tmp_path: Path) -> None:
    manager = AddonManager(tmp_path / "addons")
    manager.install_zip(_zip_package())

    manager.activate("demo-addon")
    with pytest.raises(ValueError, match="no UI entrypoint"):
        manager.invoke_ui("demo-addon", {})


def test_ui_addon_requires_ui_contract(tmp_path: Path) -> None:
    manager = AddonManager(tmp_path / "addons")
    with pytest.raises(ValueError, match="requires a ui entrypoint"):
        manager.install_zip(_zip_package(addon_type="ui"))

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


def test_result_contract_rejects_non_mapping_output(tmp_path: Path) -> None:
    manager = AddonManager(tmp_path / "addons")
    manager.install_zip(
        _zip_package(
            addon_id="bad-result-addon",
            plugin_body="def run(context): return ['not', 'a', 'mapping']\n",
        )
    )
    manager.activate("bad-result-addon")

    with pytest.raises(TypeError, match="result must be a mapping"):
        manager.invoke("bad-result-addon", {})


def test_dispatch_event_invokes_matching_active_addon(tmp_path: Path) -> None:
    manager = AddonManager(tmp_path / "addons")
    payload = _zip_package(
        addon_id="event-addon",
        mode="on_event",
        events=[{"name": "evidence.enriched"}],
        return_required=False,
        input_fields=["value"],
        plugin_body=(
            "def run(context):\n"
            "    return {'event': context['event'], 'value': context['data']['value'], 'keys': sorted(context['data'])}\n"
        ),
    )
    manager.install_zip(payload)
    manager.activate("event-addon")

    results = manager.dispatch_event(
        "evidence.enriched",
        {
            "data": {
                "value": 42,
                "secret": "must-not-reach-addon",
            }
        },
    )

    assert len(results) == 1
    addon, result = results[0]
    assert addon["id"] == "event-addon"
    assert result == {
        "event": "evidence.enriched",
        "value": 42,
        "keys": ["value"],
    }



def test_dispatch_event_filters_undeclared_input_fields(tmp_path: Path) -> None:
    manager = AddonManager(tmp_path / "addons")
    payload = _zip_package(
        addon_id="filtered-addon",
        mode="on_event",
        events=[{"name": "evidence.verified"}],
        input_fields=["evidence"],
        plugin_body=(
            "def run(context):\n"
            "    return {\n"
            "        'data_keys': sorted(context.get('data', {})),\n"
            "        'has_state': 'state' in context,\n"
            "        'event': context.get('event'),\n"
            "    }\n"
        ),
    )
    manager.install_zip(payload)
    manager.activate("filtered-addon")

    results = manager.dispatch_event(
        "evidence.verified",
        {
            "data": {
                "evidence": [{"evidence_id": "e1"}],
                "services": ["must-not-reach-addon"],
                "breach": {"findings": ["must-not-reach-addon"]},
                "secret": "must-not-reach-addon",
            },
            "state": {"email": "must-not-reach-addon"},
        },
    )

    assert len(results) == 1
    assert results[0][1] == {
        "data_keys": ["evidence"],
        "has_state": False,
        "event": "evidence.verified",
    }


def test_dispatch_event_isolates_one_broken_addon_from_others(tmp_path: Path) -> None:
    manager = AddonManager(tmp_path / "addons")
    failing = _zip_package(
        addon_id="failing-addon",
        mode="on_event",
        events=[{"name": "evidence.enriched"}],
        plugin_body="def run(context):\n    raise RuntimeError('boom')\n",
        return_required=True,
    )
    healthy = _zip_package(
        addon_id="healthy-addon",
        mode="on_event",
        events=[{"name": "evidence.enriched"}],
        plugin_body="def run(context):\n    return {'ok': True}\n",
        return_required=True,
    )
    manager.install_zip(failing)
    manager.install_zip(healthy)
    manager.activate("failing-addon")
    manager.activate("healthy-addon")

    results = manager.dispatch_event("evidence.enriched", {})

    assert len(results) == 1
    assert results[0][0]["id"] == "healthy-addon"
    assert results[0][1] == {"ok": True}


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


def test_manifest_rejects_result_key_that_can_mutate_host_state(tmp_path: Path) -> None:
    manager = AddonManager(tmp_path / "addons")

    for index, result_key in enumerate(("services", "evidence", "ai", "tenant_id", "bad-key")):
        addon_id = f"result-key-{index}"
        manifest = {
            "id": addon_id,
            "name": "Demo",
            "caption": "Demo",
            "version": "1.0.0",
            "entrypoint": "plugin.py",
            "type": "backend",
            "invocation": {
                "function": "run",
                "mode": "on_demand",
                "input": {"required": True, "fields": ["value"]},
                "return": {"type": "result", "required": True},
            },
            "events": [],
            "result_key": result_key,
        }
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(
                f"{addon_id}/manifest.json",
                json.dumps(manifest),
            )
            archive.writestr(
                f"{addon_id}/plugin.py",
                "def run(context): return {'ok': True}\n",
            )

        with pytest.raises(ValueError, match="result_key"):
            manager.install_zip(buffer.getvalue())


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
            "input": {"required": True, "fields": ["value"]},
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


def test_install_copy_failure_does_not_leave_partial_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = AddonManager(tmp_path / "addons")
    payload = _zip_package(addon_id="copy-failure-addon")

    original_copytree = __import__("shutil").copytree
    calls = 0

    def failing_copytree(src: Path, dst: Path, *args: object, **kwargs: object):
        nonlocal calls
        calls += 1
        if calls == 1:
            return original_copytree(src, dst, *args, **kwargs)

        Path(dst).mkdir(parents=True, exist_ok=True)
        (Path(dst) / "partial.txt").write_text("partial", encoding="utf-8")
        raise OSError("simulated target copy failure")

    monkeypatch.setattr("services.addon_manager.shutil.copytree", failing_copytree)

    with pytest.raises(OSError, match="simulated target copy failure"):
        manager.install_zip(payload)

    assert calls == 2
    assert not (tmp_path / "addons" / "copy-failure-addon").exists()
    assert not any(
        path.name.startswith(".install-copy-failure-addon-")
        for path in (tmp_path / "addons").iterdir()
    )


def test_install_state_persistence_failure_removes_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = AddonManager(tmp_path / "addons")

    def fail_save_state(state: object) -> None:
        raise OSError("simulated state persistence failure")

    monkeypatch.setattr(manager, "_save_state", fail_save_state)

    with pytest.raises(OSError, match="simulated state persistence failure"):
        manager.install_zip(_zip_package(addon_id="state-failure-addon"))

    assert not (tmp_path / "addons" / "state-failure-addon").exists()


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
