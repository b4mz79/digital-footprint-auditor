from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Mapping
from uuid import uuid4


_ADDON_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
_MAX_ZIP_FILES = 500
_MAX_UNCOMPRESSED_BYTES = 50 * 1024 * 1024
_STATE_FILENAME = ".addons-state.json"


@dataclass(frozen=True, slots=True)
class AddonManifest:
    addon_id: str
    name: str
    caption: str
    version: str
    entrypoint: str
    result_key: str | None = None
    pipeline_stage: str | None = None
    ai_context: bool = False
    default_active: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.addon_id,
            "name": self.name,
            "caption": self.caption,
            "version": self.version,
            "entrypoint": self.entrypoint,
            "result_key": self.result_key,
            "pipeline_stage": self.pipeline_stage,
            "ai_context": self.ai_context,
            "default_active": self.default_active,
        }


class AddonManager:
    """Small filesystem-backed add-on installer/registry."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root or os.getenv("ADDONS_DIR", "addons")).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._state_path = self.root / _STATE_FILENAME
        self._ensure_state_file()

    def list(self) -> tuple[dict[str, Any], ...]:
        state = self._load_state()
        records: list[dict[str, Any]] = []

        for manifest_path in sorted(self.root.glob("*/manifest.json")):
            try:
                manifest = self._read_manifest(manifest_path)
            except (OSError, ValueError, json.JSONDecodeError):
                continue

            records.append(
                {
                    **manifest.to_dict(),
                    "active": bool(
                        state.get(manifest.addon_id, manifest.default_active)
                    ),
                    "installed": True,
                }
            )

        return tuple(records)

    def get(self, addon_id: str) -> dict[str, Any] | None:
        self._validate_id(addon_id)
        return next(
            (item for item in self.list() if item["id"] == addon_id),
            None,
        )

    def install_zip(self, source: bytes | bytearray | BinaryIO) -> dict[str, Any]:
        payload = (
            bytes(source)
            if isinstance(source, (bytes, bytearray))
            else source.read()
        )
        if not payload:
            raise ValueError("add-on ZIP is empty")

        with tempfile.TemporaryDirectory(prefix="privacy-auditor-addon-") as temp_dir:
            archive_path = Path(temp_dir) / "addon.zip"
            archive_path.write_bytes(payload)
            extract_root = Path(temp_dir) / "extract"
            extract_root.mkdir()

            self._safe_extract(archive_path, extract_root)
            package_root = self._locate_package_root(extract_root)
            manifest = self._read_manifest(package_root / "manifest.json")

            target = self.root / manifest.addon_id
            if target.exists():
                raise ValueError(
                    f"add-on already installed: {manifest.addon_id}"
                )

            staging = self.root / f".install-{manifest.addon_id}-{uuid4().hex}"
            try:
                shutil.copytree(package_root, staging)
                # Do not rename/replace the directory on Windows.  Replacing
                # a non-empty directory via Path.replace()/os.replace() can
                # raise WinError 5 even when the installation target is valid.
                # Copy the validated staging tree into the final package path
                # instead; the target was checked above and must not exist.
                shutil.copytree(staging, target)
            finally:
                if staging.exists():
                    shutil.rmtree(staging, ignore_errors=True)

        state = self._load_state()
        # ZIP installs are never activated implicitly. The user explicitly
        # activates an installed add-on from the sidebar.
        state[manifest.addon_id] = False
        self._save_state(state)
        return self.get(manifest.addon_id) or {}

    def activate(self, addon_id: str) -> dict[str, Any]:
        return self._set_active(addon_id, True)

    def deactivate(self, addon_id: str) -> dict[str, Any]:
        return self._set_active(addon_id, False)

    def uninstall(self, addon_id: str) -> None:
        self._validate_id(addon_id)
        target = self.root / addon_id
        if not target.is_dir():
            raise ValueError(f"add-on is not installed: {addon_id}")

        shutil.rmtree(target)
        state = self._load_state()
        state.pop(addon_id, None)
        self._save_state(state)

    def invoke(
        self,
        addon_id: str,
        context: Mapping[str, Any],
    ) -> tuple[dict[str, Any], Any]:
        addon = self.get(addon_id)
        if addon is None:
            raise ValueError(f"add-on is not installed: {addon_id}")
        if not addon["active"]:
            raise ValueError(f"add-on is not active: {addon_id}")

        package_root = self.root / addon_id
        entrypoint = self._safe_entrypoint(package_root, addon["entrypoint"])
        module_name = f"_privacy_auditor_addon_{addon_id}_{uuid4().hex}"
        spec = importlib.util.spec_from_file_location(
            module_name,
            entrypoint,
            submodule_search_locations=[str(package_root)],
        )
        if spec is None or spec.loader is None:
            raise ValueError(f"cannot load add-on entrypoint: {addon_id}")

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)

            runner = getattr(module, "run", None)
            if not callable(runner):
                raise ValueError(
                    f"add-on entrypoint must expose run(context): {addon_id}"
                )

            return addon, runner(context)
        finally:
            for loaded_name in tuple(sys.modules):
                if loaded_name == module_name or loaded_name.startswith(
                    module_name + "."
                ):
                    sys.modules.pop(loaded_name, None)

    def _set_active(self, addon_id: str, active: bool) -> dict[str, Any]:
        addon = self.get(addon_id)
        if addon is None:
            raise ValueError(f"add-on is not installed: {addon_id}")

        state = self._load_state()
        state[addon_id] = active
        self._save_state(state)
        return self.get(addon_id) or addon

    def _read_manifest(self, path: Path) -> AddonManifest:
        if not path.is_file():
            raise ValueError("add-on manifest.json is required")

        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("add-on manifest must be a JSON object")

        addon_id = str(payload.get("id", "")).strip()
        self._validate_id(addon_id)

        required = ("name", "caption", "version", "entrypoint")
        if any(not str(payload.get(key, "")).strip() for key in required):
            raise ValueError(
                "add-on manifest requires id, name, caption, version and entrypoint"
            )

        entrypoint = str(payload["entrypoint"]).replace("\\", "/")
        if entrypoint.startswith("/") or ".." in Path(entrypoint).parts:
            raise ValueError("add-on entrypoint must stay inside its package")

        return AddonManifest(
            addon_id=addon_id,
            name=str(payload["name"]).strip(),
            caption=str(payload["caption"]).strip(),
            version=str(payload["version"]).strip(),
            entrypoint=entrypoint,
            result_key=(
                str(payload["result_key"]).strip()
                if payload.get("result_key")
                else None
            ),
            pipeline_stage=(
                str(payload["pipeline_stage"]).strip()
                if payload.get("pipeline_stage")
                else None
            ),
            ai_context=bool(payload.get("ai_context", False)),
            default_active=bool(payload.get("default_active", False)),
        )

    def _safe_extract(self, archive_path: Path, destination: Path) -> None:
        with zipfile.ZipFile(archive_path) as archive:
            infos = archive.infolist()
            if len(infos) > _MAX_ZIP_FILES:
                raise ValueError("add-on ZIP contains too many files")

            total_size = 0
            for info in infos:
                name = info.filename.replace("\\", "/")
                if not name or name.startswith("/") or ".." in Path(name).parts:
                    raise ValueError("add-on ZIP contains an unsafe path")

                mode = (info.external_attr >> 16) & 0o170000
                if mode == 0o120000:
                    raise ValueError("add-on ZIP symlinks are not allowed")

                total_size += max(0, info.file_size)
                if total_size > _MAX_UNCOMPRESSED_BYTES:
                    raise ValueError("add-on ZIP is too large")

            archive.extractall(destination)

    @staticmethod
    def _locate_package_root(extract_root: Path) -> Path:
        manifest = extract_root / "manifest.json"
        if manifest.is_file():
            return extract_root

        children = [item for item in extract_root.iterdir()]
        directories = [item for item in children if item.is_dir()]
        files = [item for item in children if item.is_file()]
        if files or len(directories) != 1:
            raise ValueError(
                "add-on ZIP must contain manifest.json at its root or inside one package directory"
            )

        package_root = directories[0]
        if not (package_root / "manifest.json").is_file():
            raise ValueError("add-on manifest.json is required")
        return package_root

    @staticmethod
    def _safe_entrypoint(package_root: Path, relative: str) -> Path:
        candidate = (package_root / relative).resolve()
        root = package_root.resolve()
        if root != candidate and root not in candidate.parents:
            raise ValueError("add-on entrypoint escapes its package")
        if not candidate.is_file():
            raise ValueError(f"add-on entrypoint not found: {relative}")
        return candidate

    @staticmethod
    def _validate_id(addon_id: str) -> None:
        if not _ADDON_ID_RE.fullmatch(addon_id):
            raise ValueError(
                "add-on id must contain 2-64 lowercase letters, numbers, '-' or '_'"
            )

    def _ensure_state_file(self) -> None:
        if not self._state_path.exists():
            self._save_state({})

    def _load_state(self) -> dict[str, bool]:
        try:
            payload = json.loads(self._state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(payload, dict):
            return {}
        return {str(key): bool(value) for key, value in payload.items()}

    def _save_state(self, state: Mapping[str, bool]) -> None:
        temp_path = self._state_path.with_suffix(".tmp")
        temp_path.write_text(
            json.dumps(
                dict(state),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        temp_path.replace(self._state_path)


_default_manager: AddonManager | None = None


def get_addon_manager() -> AddonManager:
    global _default_manager
    if _default_manager is None:
        _default_manager = AddonManager()
    return _default_manager
