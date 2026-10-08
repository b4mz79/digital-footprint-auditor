from __future__ import annotations

import copy
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

from services.addonsmgr.security_validator import validate_package_security
from services.addonsmgr.structural_validator import validate_package_structure
from utils.logging_setup import get_logger


_ADDON_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
_OWNER_RE = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")
_ADDON_TYPES = frozenset({"backend", "ui", "hybrid"})
_INVOCATION_MODES = frozenset({"on_demand", "on_event"})
_RETURN_TYPES = frozenset({"result", "none"})
_LIFECYCLE_HOOKS = (
    "after_install",
    "before_activate",
    "after_activate",
    "before_deactivate",
    "after_deactivate",
    "before_uninstall",
)
_MAX_ZIP_FILES = 500
_MAX_UNCOMPRESSED_BYTES = 50 * 1024 * 1024
_ADDON_RESULT_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_RESERVED_RESULT_KEYS = frozenset({
    "email", "phone", "lang", "tenant_id", "events", "services", "evidence",
    "breach", "ai", "ai_lang", "addons", "addon_events", "owner", "event", "state",
})
_STATE_FILENAME = ".addons-state.json"

logger = get_logger("AddonManager")


@dataclass(frozen=True, slots=True)
class AddonManifest:
    addon_id: str
    owner: str
    name: str
    caption: str
    version: str
    entrypoint: str
    addon_type: str
    invocation_function: str
    invocation_mode: str
    input_required: bool
    input_fields: tuple[str, ...]
    return_type: str
    return_required: bool
    events: tuple[dict[str, Any], ...] = ()
    result_key: str | None = None
    ai_context: bool = False
    default_active: bool = False
    ui_entrypoint: str | None = None
    ui_function: str | None = None
    lifecycle: tuple[tuple[str, str | None], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.addon_id,
            "owner": self.owner,
            "name": self.name,
            "caption": self.caption,
            "version": self.version,
            "entrypoint": self.entrypoint,
            "type": self.addon_type,
            "invocation": {
                "function": self.invocation_function,
                "mode": self.invocation_mode,
                "input": {
                    "required": self.input_required,
                    "fields": list(self.input_fields),
                },
                "return": {
                    "type": self.return_type,
                    "required": self.return_required,
                },
            },
            "events": [dict(item) for item in self.events],
            "result_key": self.result_key,
            "ai_context": self.ai_context,
            "default_active": self.default_active,
            "ui": ({
                "entrypoint": self.ui_entrypoint,
                "function": self.ui_function,
            } if self.ui_entrypoint and self.ui_function else None),
            "lifecycle": {
                hook: function_name for hook, function_name in self.lifecycle
            },
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
            validate_package_structure(package_root, manifest)
            validate_package_security(package_root)

            target = self.root / manifest.addon_id
            if target.exists():
                raise ValueError(
                    f"add-on already installed: {manifest.addon_id}"
                )

            staging = self.root / f".install-{manifest.addon_id}-{uuid4().hex}"
            try:
                shutil.copytree(package_root, staging)
                try:
                    shutil.copytree(staging, target)
                except Exception:
                    # Never leave a partially copied target behind when the
                    # final install copy fails.
                    shutil.rmtree(target, ignore_errors=True)
                    raise
            finally:
                if staging.exists():
                    shutil.rmtree(staging, ignore_errors=True)

        state = self._load_state()
        state[manifest.addon_id] = False
        try:
            self._save_state(state)
        except Exception:
            # The package must not remain installed if registry persistence
            # fails before post-install initialization begins.
            shutil.rmtree(target, ignore_errors=True)
            raise

        try:
            self._run_lifecycle_hook(
                manifest.addon_id,
                "after_install",
                {"event": "after_install"},
            )
        except Exception:
            # Installation is transactional from the host perspective: if
            # post-install initialization fails, remove the installed package
            # and its state. There is intentionally no after_uninstall hook.
            shutil.rmtree(target, ignore_errors=True)
            state = self._load_state()
            state.pop(manifest.addon_id, None)
            self._save_state(state)
            raise

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

        self._run_lifecycle_hook(
            addon_id,
            "before_uninstall",
            {"event": "before_uninstall"},
        )

        shutil.rmtree(target)
        state = self._load_state()
        state.pop(addon_id, None)
        self._save_state(state)

    def invoke(
        self,
        addon_id: str,
        context: Mapping[str, Any],
        *,
        owner: str,
    ) -> tuple[dict[str, Any], Any]:
        addon = self.get(addon_id)
        if addon is None:
            raise ValueError(f"add-on is not installed: {addon_id}")
        if not addon["active"]:
            raise ValueError(f"add-on is not active: {addon_id}")
        self._require_owner(addon, owner)
        if addon["invocation"]["mode"] != "on_demand":
            raise ValueError(
                f"add-on {addon_id} is not configured for on-demand invocation"
            )

        logger.info("[Add-On] invoke: id=%s mode=on_demand function=%s", addon_id, addon["invocation"]["function"])
        invocation_context = self._build_invocation_context(
            addon,
            context,
            invocation=addon["invocation"],
        )
        return self._execute(addon, invocation_context)

    def invoke_ui(
        self,
        addon_id: str,
        context: Mapping[str, Any],
        *,
        owner: str,
    ) -> tuple[dict[str, Any], Any]:
        """Invoke the UI entrypoint of an active UI-capable add-on."""
        addon = self.get(addon_id)
        if addon is None:
            raise ValueError(f"add-on is not installed: {addon_id}")
        if not addon["active"]:
            raise ValueError(f"add-on is not active: {addon_id}")
        self._require_owner(addon, owner)
        if addon["type"] == "backend":
            raise ValueError(f"backend add-on has no UI entrypoint: {addon_id}")

        ui_spec = addon.get("ui")
        if not isinstance(ui_spec, Mapping):
            raise ValueError(f"add-on UI contract is missing: {addon_id}")
        logger.info("[Add-On] invoke_ui: id=%s function=%s", addon_id, ui_spec["function"])
        return self._execute_ui(addon, context, ui_spec)

    def dispatch_event(
        self,
        event_name: str,
        context: Mapping[str, Any] | None = None,
        *,
        owner: str,
    ) -> tuple[tuple[dict[str, Any], Any], ...]:
        if not isinstance(event_name, str) or not event_name.strip():
            raise ValueError("event_name is required")

        self._validate_owner(owner)
        payload = context or {}
        logger.info("[Add-On] dispatch_event: owner=%s event=%s", owner, event_name)
        results: list[tuple[dict[str, Any], Any]] = []
        for addon in self.list():
            if not addon["active"]:
                continue
            if addon["owner"] != owner:
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
            logger.info("[Add-On] event hook matched: id=%s event=%s function=%s", addon["id"], event_name, addon["invocation"]["function"])
            try:
                addon_payload = self._build_invocation_context(
                    addon,
                    payload,
                    invocation=event_spec,
                    event_name=event_name,
                )
                result = self._execute(
                    addon,
                    addon_payload,
                    invocation=event_spec,
                )
            except Exception as exc:
                # Isolate failures between optional Add-Ons: one broken
                # extension must not prevent another matching extension from
                # receiving the same canonical event.
                logger.warning(
                    "[Add-On] event hook failed: id=%s event=%s error=%s: %s",
                    addon["id"],
                    event_name,
                    type(exc).__name__,
                    exc,
                )
                continue
            results.append(result)

        return tuple(results)

    def _execute_ui(
        self,
        addon: Mapping[str, Any],
        context: Mapping[str, Any],
        ui_spec: Mapping[str, Any],
    ) -> tuple[dict[str, Any], Any]:
        package_root = self.root / str(addon["id"])
        entrypoint = self._safe_entrypoint(
            package_root,
            str(ui_spec["entrypoint"]),
        )
        module_name = (
            f"_privacy_auditor_addon_ui_{addon['id']}_{uuid4().hex}"
        )
        spec = importlib.util.spec_from_file_location(
            module_name,
            entrypoint,
            submodule_search_locations=[str(package_root)],
        )
        if spec is None or spec.loader is None:
            raise ValueError(
                f"cannot load add-on UI entrypoint: {addon['id']}"
            )

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
            function_name = str(ui_spec["function"])
            renderer = getattr(module, function_name, None)
            if not callable(renderer):
                raise ValueError(
                    f"add-on UI entrypoint must expose "
                    f"{function_name}(context): {addon['id']}"
                )
            if not isinstance(context, Mapping):
                raise TypeError(
                    f"add-on {addon['id']} UI requires mapping input"
                )
            # UI is a presentation boundary. Only the host-approved result
            # and language projection are visible to the add-on renderer.
            ui_context = {
                "result": copy.deepcopy(context["result"])
                if "result" in context
                else None,
                "lang": str(context.get("lang", "")),
            }
            logger.info("[Add-On] UI function start: id=%s function=%s", addon["id"], function_name)
            result = renderer(ui_context)
            logger.info("[Add-On] UI function completed: id=%s function=%s", addon["id"], function_name)
            return dict(addon), result
        finally:
            for loaded_name in tuple(sys.modules):
                if loaded_name == module_name or loaded_name.startswith(
                    module_name + "."
                ):
                    sys.modules.pop(loaded_name, None)

    @staticmethod
    def _build_invocation_context(
        addon: Mapping[str, Any],
        payload: Mapping[str, Any],
        *,
        invocation: Mapping[str, Any],
        event_name: str | None = None,
    ) -> dict[str, Any]:
        """Build the only context visible to an add-on runner."""
        addon_id = str(addon["id"])
        if not isinstance(payload, Mapping):
            raise TypeError(f"add-on {addon_id} requires mapping input")

        input_spec = invocation.get("input")
        if not isinstance(input_spec, Mapping):
            raise ValueError(f"add-on {addon_id} input contract is invalid")

        required = bool(input_spec.get("required"))
        fields = input_spec.get("fields", ())
        if not isinstance(fields, (list, tuple)):
            raise ValueError(f"add-on {addon_id} input.fields must be an array")

        context: dict[str, Any] = {}
        if event_name is not None:
            context["event"] = event_name

        if not fields:
            if required:
                raise ValueError(f"add-on {addon_id} requires input fields")
            return context

        source = payload.get("data")
        if not isinstance(source, Mapping):
            if required:
                raise TypeError(
                    f"add-on {addon_id} requires event data as a mapping"
                )
            return context

        data: dict[str, Any] = {}
        for field in fields:
            if field in source:
                # Do not expose mutable host-owned objects by reference.
                data[str(field)] = copy.deepcopy(source[field])

        if required and any(field not in data for field in fields):
            missing = [field for field in fields if field not in data]
            raise ValueError(
                f"add-on {addon_id} missing declared input field(s): "
                + ", ".join(missing)
            )

        context["data"] = data
        return context

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

            logger.info("[Add-On] run function start: id=%s function=%s", addon["id"], function_name)
            result = runner(context)
            logger.info("[Add-On] run function completed: id=%s function=%s result_type=%s", addon["id"], function_name, type(result).__name__)
            return_required = bool(
                invocation_spec["return"]["required"]
            )
            return_type = str(invocation_spec["return"]["type"])
            if return_required and result is None:
                raise ValueError(
                    f"add-on {addon['id']} must return a result"
                )
            if return_type == "result" and result is not None and not isinstance(result, Mapping):
                raise TypeError(
                    f"add-on {addon['id']} result must be a mapping"
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

    def _execute_function(
        self,
        addon: Mapping[str, Any],
        function_name: str,
        context: Mapping[str, Any],
        *,
        module_prefix: str,
    ) -> Any:
        package_root = self.root / str(addon["id"])
        entrypoint = self._safe_entrypoint(
            package_root,
            str(addon["entrypoint"]),
        )
        module_name = (
            f"_privacy_auditor_addon_{module_prefix}_"
            f"{addon['id']}_{uuid4().hex}"
        )
        spec = importlib.util.spec_from_file_location(
            module_name,
            entrypoint,
            submodule_search_locations=[str(package_root)],
        )
        if spec is None or spec.loader is None:
            raise ValueError(
                f"cannot load add-on {module_prefix} entrypoint: {addon['id']}"
            )

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
            function = getattr(module, function_name, None)
            if not callable(function):
                raise ValueError(
                    f"add-on entrypoint must expose "
                    f"{function_name}(context): {addon['id']}"
                )
            if not isinstance(context, Mapping):
                raise TypeError(
                    f"add-on {addon['id']} requires mapping input"
                )
            return function(context)
        finally:
            for loaded_name in tuple(sys.modules):
                if loaded_name == module_name or loaded_name.startswith(
                    module_name + "."
                ):
                    sys.modules.pop(loaded_name, None)

    def _run_lifecycle_hook(
        self,
        addon_id: str,
        hook_name: str,
        context: Mapping[str, Any],
    ) -> Any:
        if hook_name not in _LIFECYCLE_HOOKS:
            raise ValueError(f"unsupported add-on lifecycle hook: {hook_name}")

        addon = self.get(addon_id)
        if addon is None:
            raise ValueError(f"add-on is not installed: {addon_id}")

        lifecycle = addon.get("lifecycle")
        if not isinstance(lifecycle, Mapping):
            return None

        function_name = lifecycle.get(hook_name)
        if function_name is None:
            return None
        if not isinstance(function_name, str) or not function_name.strip():
            raise ValueError(
                f"add-on lifecycle hook must name a function: "
                f"{addon_id}:{hook_name}"
            )

        logger.info("[Add-On] lifecycle hook start: id=%s hook=%s function=%s", addon_id, hook_name, function_name.strip())
        result = self._execute_function(
            addon,
            function_name.strip(),
            context,
            module_prefix="lifecycle",
        )
        logger.info("[Add-On] lifecycle hook completed: id=%s hook=%s", addon_id, hook_name)
        return result

    def _set_active(self, addon_id: str, active: bool) -> dict[str, Any]:
        addon = self.get(addon_id)
        if addon is None:
            raise ValueError(f"add-on is not installed: {addon_id}")

        self._run_lifecycle_hook(
            addon_id,
            "before_activate" if active else "before_deactivate",
            {"event": "before_activate" if active else "before_deactivate"},
        )

        state = self._load_state()
        state[addon_id] = active
        self._save_state(state)

        try:
            self._run_lifecycle_hook(
                addon_id,
                "after_activate" if active else "after_deactivate",
                {"event": "after_activate" if active else "after_deactivate"},
            )
        except Exception:
            if active:
                # Activation is transactional: post-activation failure must
                # not leave a broken Add-On active in the registry.
                rollback_state = self._load_state()
                rollback_state[addon_id] = False
                self._save_state(rollback_state)
            raise

        return self.get(addon_id) or addon

    def _read_manifest(self, path: Path) -> AddonManifest:
        if not path.is_file():
            raise ValueError("add-on manifest.json is required")

        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("add-on manifest must be a JSON object")

        addon_id = str(payload.get("id", "")).strip()
        self._validate_id(addon_id)

        required = ("owner", "name", "caption", "version", "entrypoint", "type", "invocation")
        if any(key not in payload for key in required):
            raise ValueError(
                "add-on manifest requires id, name, caption, version, "
                "entrypoint, type and invocation"
            )

        owner = str(payload["owner"]).strip().lower()
        self._validate_owner(owner)

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
        input_fields = self._parse_input_fields(
            input_spec,
            "add-on invocation.input.fields",
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
            event_input = item.get(
                "input",
                {
                    "required": input_spec["required"],
                    "fields": list(input_fields),
                },
            )
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
            # Omitted event fields inherit the invocation projection.
            if "fields" not in event_input:
                event_input = {
                    **event_input,
                    "fields": list(input_fields),
                }
            event_fields = self._parse_input_fields(
                event_input,
                f"add-on event input.fields: {event_name}",
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
                    "input": {
                        "required": event_input["required"],
                        "fields": list(event_fields),
                    },
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

        raw_lifecycle = payload.get("lifecycle", {})
        if not isinstance(raw_lifecycle, dict):
            raise ValueError("add-on lifecycle must be an object")

        unknown_hooks = set(raw_lifecycle) - set(_LIFECYCLE_HOOKS)
        if unknown_hooks:
            raise ValueError(
                "unsupported add-on lifecycle hook(s): "
                + ", ".join(sorted(str(item) for item in unknown_hooks))
            )

        lifecycle: list[tuple[str, str | None]] = []
        for hook_name in _LIFECYCLE_HOOKS:
            value = raw_lifecycle.get(hook_name)
            if value is not None and (
                not isinstance(value, str) or not value.strip()
            ):
                raise ValueError(
                    f"add-on lifecycle hook must be a function name or null: "
                    f"{hook_name}"
                )
            lifecycle.append(
                (
                    hook_name,
                    value.strip() if isinstance(value, str) else None,
                )
            )

        raw_ui = payload.get("ui")
        ui_entrypoint: str | None = None
        ui_function: str | None = None
        if addon_type == "backend":
            if raw_ui is not None:
                raise ValueError("backend add-on must not declare a UI entrypoint")
        else:
            if not isinstance(raw_ui, dict):
                raise ValueError("ui-capable add-on requires a ui entrypoint")
            ui_entrypoint = str(raw_ui.get("entrypoint", "")).replace("\\\\", "/").strip()
            ui_function = str(raw_ui.get("function", "")).strip()
            if not ui_entrypoint or not ui_function:
                raise ValueError("add-on ui requires entrypoint and function")
            if ui_entrypoint.startswith("/") or ".." in Path(ui_entrypoint).parts:
                raise ValueError("add-on UI entrypoint must stay inside its package")

        return AddonManifest(
            addon_id=addon_id,
            owner=owner,
            name=name,
            caption=caption,
            version=version,
            entrypoint=entrypoint,
            addon_type=addon_type,
            invocation_function=function_name,
            invocation_mode=mode,
            input_required=input_spec["required"],
            input_fields=tuple(input_fields),
            return_type=return_type,
            return_required=return_spec["required"],
            events=tuple(events),
            result_key=self._parse_result_key(payload.get("result_key")),
            ai_context=bool(payload.get("ai_context", False)),
            default_active=bool(payload.get("default_active", False)),
            ui_entrypoint=ui_entrypoint,
            ui_function=ui_function,
            lifecycle=tuple(lifecycle),
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
    def _parse_input_fields(
        input_spec: Mapping[str, Any],
        label: str,
    ) -> tuple[str, ...]:
        fields = input_spec.get("fields", [])
        if not isinstance(fields, list):
            raise ValueError(f"{label} must be an array")
        normalized: list[str] = []
        for field in fields:
            if not isinstance(field, str):
                raise ValueError(f"{label} entries must be strings")
            name = field.strip()
            if not name or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{0,63}", name):
                raise ValueError(f"{label} entries must be simple field names")
            if name in {"owner", "event", "state"}:
                raise ValueError(f"{label} contains reserved host metadata field: {name}")
            if name not in normalized:
                normalized.append(name)
        if input_spec.get("required") and not normalized:
            raise ValueError(
                f"{label} must declare at least one field when required"
            )
        return tuple(normalized)

    @staticmethod
    def _parse_result_key(value: Any) -> str | None:
        if value is None or value == "":
            return None
        if not isinstance(value, str):
            raise ValueError("add-on result_key must be a string or null")
        result_key = value.strip()
        if not _ADDON_RESULT_KEY_RE.fullmatch(result_key):
            raise ValueError(
                "add-on result_key must be a lowercase identifier of up to 64 characters"
            )
        if result_key in _RESERVED_RESULT_KEYS:
            raise ValueError(
                f"add-on result_key targets a reserved host state key: {result_key}"
            )
        return result_key

    @staticmethod
    def _validate_owner(owner: str) -> None:
        if not isinstance(owner, str) or not _OWNER_RE.fullmatch(owner.strip().lower()):
            raise ValueError("add-on owner must be a lowercase built-in module identifier")

    @classmethod
    def _require_owner(cls, addon: Mapping[str, Any], owner: str) -> None:
        cls._validate_owner(owner)
        addon_owner = str(addon.get("owner", "")).strip().lower()
        if addon_owner != owner.strip().lower():
            raise ValueError(
                f"add-on owner mismatch: {addon.get('id', '<unknown>')} belongs to "
                f"{addon_owner!r}, not {owner!r}"
            )

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
