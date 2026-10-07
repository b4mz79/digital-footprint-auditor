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
_ADDON_TYPES = frozenset({"backend", "ui", "hybrid"})
_INVOCATION_MODES = frozenset({"on_demand", "on_event"})
_RETURN_TYPES = frozenset({"result", "none"})
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
    addon_type: str
    invocation_function: str
    invocation_mode: str
    input_required: bool
    return_type: str
    return_required: bool
    events: tuple[dict[str, Any], ...] = ()
    result_key: str | None = None
    ai_context: bool = False
    default_active: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.addon_id,
            "name": self.name,
            "caption": self.caption,
            "version": self.version,
            "entrypoint": self.entrypoint,
            "type": self.addon_type,
            "invocation": {
                "function": self.invocation_function,
                "mode": self.invocation_mode,
                "input": {"required": self.input_required},
                "return": {
                    "type": self.return_type,
                    "required": self.return_required,
                },
            },
            "events": [dict(item) for item in self.events],
            "result_key": self.result_key,
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
                shutil.copytree(staging, target)
            finally:
                if staging.exists():
                    shutil.rmtree(staging, ignore_errors=True)

        state = self._load_state()
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
        if addon["invocation"]["mode"] != "on_demand":
            raise ValueError(
                f"add-on {addon_id} is not configured for on-demand invocation"
            )

        return self._execute(addon, context)

    def dispatch_event(
        self,
        event_name: str,
        context: Mapping[str, Any] | None = None,
    ) -> tuple[tuple[dict[str, Any], Any], ...]:
        if not isinstance(event_name, str) or not event_name.strip():
            raise ValueError("event_name is required")

        payload = context or {}
        results: list[tuple[dict[str, Any], Any]] = []
        for addon in self.list():
            if not addon["active"]:
                continue
            if addon["invocation"]["mode"] != "on_event":
                continue
            if not any(
                event.get("name") == event_name
                for event in addon["events"]
            ):
                continue
            event_spec = next(
                event
                for event in addon["events"]
                if event.get("name") == event_name
            )
            results.append(self._execute(addon, payload, invocation=event_spec))

        return tuple(results)

    def _execute(
        self,
        addon: Mapping[str, Any],
        context: Mapping[str, Any],
        *,
        invocation: Mapping[str, Any] | None = None,
    ) -> tuple[dict[str, Any], Any]:
        package_root = self.root / str(addon["id"])
        entrypoint = self._safe_entrypoint(
            package_root,
            str(addon["entrypoint"]),
        )
        module_name = (
            f"_privacy_auditor_addon_{addon['id']}_{uuid4().hex}"
        )
        spec = importlib.util.spec_from_file_location(
            module_name,
            entrypoint,
            submodule_search_locations=[str(package_root)],
        )
        if spec is None or spec.loader is None:
            raise ValueError(
                f"cannot load add-on entrypoint: {addon['id']}"
            )

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)

            invocation_spec = invocation or addon["invocation"]
            function_name = str(addon["invocation"]["function"])
            runner = getattr(module, function_name, None)
            if not callable(runner):
                raise ValueError(
                    f"add-on entrypoint must expose "
                    f"{function_name}(context): {addon['id']}"
                )

            if invocation_spec["input"]["required"] and not isinstance(
                context, Mapping
            ):
                raise TypeError(
                    f"add-on {addon['id']} requires mapping input"
                )

            result = runner(context)
            return_required = bool(
                invocation_spec["return"]["required"]
            )
            return_type = str(invocation_spec["return"]["type"])
            if return_required and result is None:
                raise ValueError(
                    f"add-on {addon['id']} must return a result"
                )
            if return_type == "none" and result is not None:
                raise ValueError(
                    f"add-on {addon['id']} must not return a result"
                )

            return dict(addon), result
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

        required = ("name", "caption", "version", "entrypoint", "type", "invocation")
        if any(key not in payload for key in required):
            raise ValueError(
                "add-on manifest requires id, name, caption, version, "
                "entrypoint, type and invocation"
            )

        name = str(payload["name"]).strip()
        caption = str(payload["caption"]).strip()
        version = str(payload["version"]).strip()
        entrypoint = str(payload["entrypoint"]).replace("\\", "/")
        if not name or not caption or not version or not entrypoint:
            raise ValueError(
                "add-on manifest requires non-empty id, name, caption, "
                "version and entrypoint"
            )
        if entrypoint.startswith("/") or ".." in Path(entrypoint).parts:
            raise ValueError("add-on entrypoint must stay inside its package")

        addon_type = str(payload["type"]).strip().lower()
        if addon_type not in _ADDON_TYPES:
            raise ValueError(
                "add-on type must be one of: backend, ui, hybrid"
            )

        invocation = payload["invocation"]
        if not isinstance(invocation, dict):
            raise ValueError("add-on invocation must be an object")

        function_name = str(invocation.get("function", "")).strip()
        if function_name != "run":
            raise ValueError(
                "add-on invocation.function must be 'run'"
            )

        mode = str(invocation.get("mode", "")).strip().lower()
        if mode not in _INVOCATION_MODES:
            raise ValueError(
                "add-on invocation.mode must be one of: on_demand, on_event"
            )

        input_spec = invocation.get("input")
        if not isinstance(input_spec, dict) or not isinstance(
            input_spec.get("required"), bool
        ):
            raise ValueError(
                "add-on invocation.input.required must be a boolean"
            )

        return_spec = invocation.get("return")
        if not isinstance(return_spec, dict):
            raise ValueError("add-on invocation.return must be an object")
        return_type = str(return_spec.get("type", "")).strip().lower()
        if return_type not in _RETURN_TYPES:
            raise ValueError(
                "add-on invocation.return.type must be one of: result, none"
            )
        if not isinstance(return_spec.get("required"), bool):
            raise ValueError(
                "add-on invocation.return.required must be a boolean"
            )

        raw_events = payload.get("events", [])
        if not isinstance(raw_events, list):
            raise ValueError("add-on events must be an array")
        events: list[dict[str, Any]] = []
        for item in raw_events:
            if not isinstance(item, dict):
                raise ValueError("each add-on event must be an object")
            event_name = str(item.get("name", "")).strip()
            if not event_name:
                raise ValueError("add-on event name is required")
            event_input = item.get("input", {"required": input_spec["required"]})
            event_return = item.get(
                "return",
                {
                    "type": return_type,
                    "required": return_spec["required"],
                },
            )
            if not isinstance(event_input, dict) or not isinstance(
                event_input.get("required"), bool
            ):
                raise ValueError(
                    f"add-on event input.required must be a boolean: {event_name}"
                )
            if not isinstance(event_return, dict):
                raise ValueError(
                    f"add-on event return must be an object: {event_name}"
                )
            event_return_type = str(event_return.get("type", "")).strip().lower()
            if event_return_type not in _RETURN_TYPES:
                raise ValueError(
                    f"add-on event return.type must be one of: result, none: {event_name}"
                )
            if not isinstance(event_return.get("required"), bool):
                raise ValueError(
                    f"add-on event return.required must be a boolean: {event_name}"
                )
            events.append(
                {
                    "name": event_name,
                    "input": {"required": event_input["required"]},
                    "return": {
                        "type": event_return_type,
                        "required": event_return["required"],
                    },
                }
            )

        if mode == "on_event" and not events:
            raise ValueError(
                "on_event add-on must declare at least one event"
            )
        if mode == "on_demand" and events:
            raise ValueError(
                "on_demand add-on must not declare event subscriptions"
            )

        return AddonManifest(
            addon_id=addon_id,
            name=name,
            caption=caption,
            version=version,
            entrypoint=entrypoint,
            addon_type=addon_type,
            invocation_function=function_name,
            invocation_mode=mode,
            input_required=input_spec["required"],
            return_type=return_type,
            return_required=return_spec["required"],
            events=tuple(events),
            result_key=(
                str(payload["result_key"]).strip()
                if payload.get("result_key")
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
