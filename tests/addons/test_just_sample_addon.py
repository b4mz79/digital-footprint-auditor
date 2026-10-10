from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

from services.addon_manager import AddonManager


def _package_zip() -> bytes:
    source_root = Path(__file__).resolve().parents[2] / "addons" / "just-sample"
    buffer = io.BytesIO()

    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source_root.rglob("*")):
            if not path.is_file():
                continue

            relative_path = path.relative_to(source_root)

            # Exclude generated Python bytecode and cache directories.
            # These are local runtime artifacts, not add-on source files.
            if "__pycache__" in relative_path.parts:
                continue

            if path.suffix.lower() in {".pyc", ".pyo"}:
                continue

            archive.write(
                path,
                f"{source_root.name}/{relative_path.as_posix()}",
            )

    return buffer.getvalue()


def test_just_sample_runs_from_imap_completion_event(tmp_path: Path) -> None:
    manager = AddonManager(tmp_path / "addons")
    manager.install_zip(_package_zip())
    manager.activate("just-sample")

    results = manager.dispatch_event(
        "discovery.imap.completed",
        {
            "state": {},
            "event": "discovery.imap.completed",
            "data": {
                "services": [
                    {"domain": "example.com"},
                    {"domain": "example.org"},
                    {"domain": "example.net"},
                ]
            },
        },
        owner="imap",
    )

    assert len(results) == 1
    addon, result = results[0]
    assert addon["id"] == "just-sample"
    assert result == {"jumlah_email": 3}


def test_just_sample_ignores_other_events(tmp_path: Path) -> None:
    manager = AddonManager(tmp_path / "addons")
    manager.install_zip(_package_zip())
    manager.activate("just-sample")

    results = manager.dispatch_event(
        "discovery.osint.completed",
        {
            "state": {},
            "event": "discovery.osint.completed",
            "data": {"services": [{"domain": "example.com"}]},
        },
        owner="imap",
    )

    assert results == ()


def test_just_sample_manifest_contract() -> None:
    path = (
        Path(__file__).resolve().parents[2]
        / "addons"
        / "just-sample"
        / "manifest.json"
    )
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["id"] == "just-sample"
    assert payload["name"] == "just-sample"
    assert payload["caption"] == "Hello World"
    assert payload["type"] == "hybrid"
    assert payload["invocation"]["function"] == "run"
    assert payload["invocation"]["mode"] == "on_event"
    assert payload["events"][0]["name"] == "discovery.imap.completed"
    assert payload["ui"] == {"entrypoint": "ui.py", "function": "render"}
