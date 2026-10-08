from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from services.addon_manager import AddonManager


def _zip_with_manifest(
    *,
    addon_id: str = "structural-addon",
    entrypoint: str = "plugin.py",
    plugin_body: str = "def run(context):\n    return {'ok': True}\n",
    extra_files: dict[str, str] | None = None,
    addon_type: str = "backend",
) -> bytes:
    manifest = {
        "id": addon_id,
        "name": "Structural Test",
        "caption": "Structural",
        "version": "1.0.0",
        "entrypoint": entrypoint,
        "type": addon_type,
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
        archive.writestr(
            f"{addon_id}/manifest.json",
            json.dumps(manifest),
        )
        archive.writestr(f"{addon_id}/{entrypoint}", plugin_body)
        for path, body in (extra_files or {}).items():
            archive.writestr(f"{addon_id}/{path}", body)
    return buffer.getvalue()


def test_structural_gate_accepts_valid_python_package(tmp_path: Path) -> None:
    manager = AddonManager(tmp_path / "addons")

    installed = manager.install_zip(
        _zip_with_manifest(
            extra_files={"helper.py": "VALUE = 42\n"},
        )
    )

    assert installed["id"] == "structural-addon"
    assert (tmp_path / "addons" / "structural-addon" / "helper.py").is_file()


def test_structural_gate_rejects_non_python_entrypoint(
    tmp_path: Path,
) -> None:
    manager = AddonManager(tmp_path / "addons")

    payload = _zip_with_manifest(
        entrypoint="plugin.txt",
        plugin_body="def run(context): return {'ok': True}\n",
    )

    with pytest.raises(ValueError, match="entrypoint must be a Python .py file"):
        manager.install_zip(payload)

    assert not (tmp_path / "addons" / "structural-addon").exists()


def test_structural_gate_rejects_missing_entrypoint(
    tmp_path: Path,
) -> None:
    manager = AddonManager(tmp_path / "addons")
    manifest = {
        "id": "missing-entrypoint",
        "name": "Structural Test",
        "caption": "Structural",
        "version": "1.0.0",
        "entrypoint": "plugin.py",
        "type": "backend",
        "invocation": {
            "function": "run",
            "mode": "on_demand",
            "input": {"required": True},
            "return": {"type": "result", "required": True},
        },
        "events": [],
    }

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "missing-entrypoint/manifest.json",
            json.dumps(manifest),
        )

    with pytest.raises(ValueError, match="entrypoint not found"):
        manager.install_zip(buffer.getvalue())

    assert not (tmp_path / "addons" / "missing-entrypoint").exists()


def test_structural_gate_rejects_symlink_after_extraction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = AddonManager(tmp_path / "addons")
    package_root = tmp_path / "extracted"
    package_root.mkdir()
    (package_root / "manifest.json").write_text("{}", encoding="utf-8")
    target = package_root / "target.py"
    target.write_text("def run(context): return {}\n", encoding="utf-8")
    link = package_root / "link.py"
    link.symlink_to(target)

    from services.addonsmgr.structural_validator import (
        validate_package_structure,
    )
    from services.addon_manager import AddonManifest

    manifest = AddonManifest(
        addon_id="structural-addon",
        name="Structural",
        caption="Structural",
        version="1.0.0",
        entrypoint="target.py",
        addon_type="backend",
        invocation_function="run",
        invocation_mode="on_demand",
        input_required=True,
        return_type="result",
        return_required=True,
    )

    with pytest.raises(ValueError, match="package symlinks"):
        validate_package_structure(package_root, manifest)
