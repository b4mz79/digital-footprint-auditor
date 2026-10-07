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

    def dispatch_event(self, event_name: str, context: dict[str, Any]):
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


def test_pipeline_addon_invocation_and_events_are_fully_dynamic(monkeypatch) -> None:
    manager = _FakeAddonManager()
    emitted: list[dict[str, Any]] = []

    monkeypatch.setattr(pipeline, "get_addon_manager", lambda: manager)
    async def _enrich(evidence):
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
        with_ai=False,
        enabled_addons=("demo-addon",),
        addon_contexts={"demo-addon": {"custom_input": 42}},
        on_event=emitted.append,
    )

    assert manager.invocations
    addon_id, context = manager.invocations[0]
    assert addon_id == "demo-addon"
    assert context["custom_input"] == 42
    assert context["state"] is state

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

    addon_success_events = [
        event
        for event in emitted
        if event.get("stage") == "demo-addon"
    ]
    assert addon_success_events
    assert all(
        event.get("stage") != "addon:demo-addon"
        for event in emitted
    )

    assert state["addons"]["demo-addon"] == {
        "demo_result": {"ok": True}
    }
    assert state["demo_result"] == {"ok": True}
