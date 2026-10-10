from __future__ import annotations

from typing import Any

import services.pipeline as pipeline


class _FakeAddonManager:
    def __init__(self) -> None:
        self.invocations: list[tuple[str, dict[str, Any]]] = []
        self.events: list[tuple[str, dict[str, Any]]] = []

    def invoke(self, addon_id: str, context: dict[str, Any]):
        self.invocations.append((addon_id, dict(context)))
        return (
            {
                "id": addon_id,
                "result_key": "demo_result",
            },
            {"demo_result": {"ok": True}},
        )

    def dispatch_event(self, event_name: str, context: dict[str, Any], *, owner: str):
        self.events.append((event_name, dict(context)))
        return (
            (
                {
                    "id": "event-addon",
                    "result_key": None,
                },
                {"event": event_name},
            ),
        )


def test_pipeline_dispatches_owned_evidence_events(monkeypatch) -> None:
    manager = _FakeAddonManager()
    emitted: list[dict[str, Any]] = []

    monkeypatch.setattr(pipeline, "get_addon_manager", lambda: manager)

    async def _enrich(evidence, **kwargs):
        return evidence

    async def _verify(evidence):
        return evidence

    monkeypatch.setattr(pipeline, "enrich_evidence", _enrich)
    monkeypatch.setattr(pipeline, "verify_evidence_records", _verify)

    state = pipeline.run_scan(
        email="user@example.com",
        enable_imap=False,
        enable_osint=False,
        enable_breach=False,
        enable_evidence_enrichment=True,
        with_ai=False,
        on_event=emitted.append,
    )

    # The global pipeline must not invoke on-demand add-ons. They are
    # owned and invoked by their built-in module only.
    assert manager.invocations == []

    assert manager.events
    event_names = [name for name, _ in manager.events]
    assert "evidence.enriched" in event_names
    assert "evidence.verified" in event_names

    assert state["addon_events"]["evidence.enriched"]["event-addon"] == {
        "event": "evidence.enriched"
    }
    assert state["addon_events"]["evidence.verified"]["event-addon"] == {
        "event": "evidence.verified"
    }

    assert state["addons"]["event-addon"] == {
        "event": "evidence.verified"
    }
    assert state["addon_owners"]["event-addon"] == "evidence"

    addon_success_events = [
        event
        for event in emitted
        if event.get("stage") == "event-addon"
    ]
    assert addon_success_events
    assert all(
        event.get("stage") != "addon:event-addon"
        for event in emitted
    )


def test_pipeline_real_addon_manager_invokes_just_sample(monkeypatch, tmp_path) -> None:
    """Exercise the production pipeline against the repository's real sample add-on."""
    import io
    import zipfile
    from pathlib import Path

    from services.addon_manager import AddonManager

    addon_root = Path(__file__).resolve().parents[1] / "addons" / "just-sample"
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as package:
        for path in addon_root.iterdir():
            if path.is_file():
                package.write(path, arcname=path.name)

    manager = AddonManager(tmp_path / "addons")
    installed = manager.install_zip(archive.getvalue())
    assert installed["id"] == "just-sample"
    assert installed["owner"] == "imap"
    manager.activate("just-sample")

    monkeypatch.setattr(pipeline, "get_addon_manager", lambda: manager)
    monkeypatch.setattr(pipeline, "imap_cache_enabled", lambda: False)

    def _scan_gmail_inbox(*args, **kwargs):
        return [
            {
                "name": "Example Service",
                "domain": "example.com",
                "source": "imap",
                "subject": "Welcome",
            }
        ]

    monkeypatch.setattr(pipeline, "scan_gmail_inbox", _scan_gmail_inbox)

    emitted: list[dict[str, Any]] = []
    state = pipeline.run_scan(
        email="user@example.com",
        gmail_app_password="test-password",
        enable_imap=True,
        enable_osint=False,
        enable_breach=False,
        enable_evidence_enrichment=False,
        with_ai=False,
        on_event=emitted.append,
    )

    assert state["services"][0]["domain"] == "example.com"
    assert state["addon_events"]["discovery.imap.completed"]["just-sample"] == {
        "jumlah_email": 1,
    }
    assert state["addons"]["just-sample"] == {"jumlah_email": 1}
    assert state["addon_owners"]["just-sample"] == "imap"

    addon_events = [
        event
        for event in emitted
        if event.get("stage") == "just-sample"
    ]
    assert len(addon_events) == 1
    assert addon_events[0]["_live"]["result"] == {"jumlah_email": 1}
    assert addon_events[0]["_live"]["owner"] == "imap"
