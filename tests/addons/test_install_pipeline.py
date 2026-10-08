from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from services.addon_manager import AddonManager


def _addon_zip(addon_id: str = "pipeline-addon") -> bytes:
    manifest = {
        "id": addon_id,
        "owner": "test",
        "name": "Pipeline Test",
        "caption": "Pipeline",
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
        "default_active": False,
        "lifecycle": {},
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(f"{addon_id}/manifest.json", json.dumps(manifest))
        archive.writestr(
            f"{addon_id}/plugin.py",
            "def run(context):\n    return {'ok': True}\n",
        )
    return buffer.getvalue()


def test_install_pipeline_runs_structural_then_security_then_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = AddonManager(tmp_path / "addons")
    calls: list[str] = []

    def structural(package_root: Path, manifest: object) -> None:
        calls.append("structural")

    def security(package_root: Path) -> tuple[object, ...]:
        calls.append("security")
        return ()

    monkeypatch.setattr(
        "services.addon_manager.validate_package_structure",
        structural,
    )
    monkeypatch.setattr(
        "services.addon_manager.validate_package_security",
        security,
    )

    installed = manager.install_zip(_addon_zip())

    assert installed["id"] == "pipeline-addon"
    assert calls == ["structural", "security"]
    assert (tmp_path / "addons" / "pipeline-addon" / "manifest.json").is_file()


def test_install_pipeline_stops_before_security_when_structural_gate_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = AddonManager(tmp_path / "addons")
    calls: list[str] = []

    def structural(package_root: Path, manifest: object) -> None:
        calls.append("structural")
        raise ValueError("structural rejection")

    def security(package_root: Path) -> tuple[object, ...]:
        calls.append("security")
        return ()

    monkeypatch.setattr(
        "services.addon_manager.validate_package_structure",
        structural,
    )
    monkeypatch.setattr(
        "services.addon_manager.validate_package_security",
        security,
    )

    with pytest.raises(ValueError, match="structural rejection"):
        manager.install_zip(_addon_zip("structural-fail"))

    assert calls == ["structural"]
    assert not (tmp_path / "addons" / "structural-fail").exists()


def test_install_pipeline_stops_before_install_when_security_gate_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = AddonManager(tmp_path / "addons")
    calls: list[str] = []

    def structural(package_root: Path, manifest: object) -> None:
        calls.append("structural")

    def security(package_root: Path) -> tuple[object, ...]:
        calls.append("security")
        raise ValueError("security rejection")

    monkeypatch.setattr(
        "services.addon_manager.validate_package_structure",
        structural,
    )
    monkeypatch.setattr(
        "services.addon_manager.validate_package_security",
        security,
    )

    with pytest.raises(ValueError, match="security rejection"):
        manager.install_zip(_addon_zip("security-fail"))

    assert calls == ["structural", "security"]
    assert not (tmp_path / "addons" / "security-fail").exists()


def test_install_pipeline_does_not_run_after_install_when_security_rejects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = AddonManager(tmp_path / "addons")
    lifecycle_calls: list[str] = []

    def security(package_root: Path) -> tuple[object, ...]:
        raise ValueError("security rejection")

    def lifecycle(*args: object, **kwargs: object) -> None:
        lifecycle_calls.append("after_install")

    monkeypatch.setattr(
        "services.addon_manager.validate_package_security",
        security,
    )
    monkeypatch.setattr(manager, "_run_lifecycle_hook", lifecycle)

    with pytest.raises(ValueError, match="security rejection"):
        manager.install_zip(_addon_zip("lifecycle-blocked"))

    assert lifecycle_calls == []
    assert not (tmp_path / "addons" / "lifecycle-blocked").exists()
