from __future__ import annotations

from services import pipeline


def _definition() -> dict:
    return {
        "schema_version": "scorecard-definition-v1",
        "scorecard_id": "integration-scorecard",
        "version": "v1",
        "score": {
            "canonical_range": {"min": 0.0, "max": 10.0},
            "precision": 2,
            "rounding": "half_even",
        },
        "aggregation": {
            "operation": "weighted_sum",
            "weights": {"service_discovery_count": 1.0},
        },
    }


def _policy() -> dict:
    return {
        "schema_version": "risk-policy-v1",
        "risk_policy_id": "integration-policy",
        "version": "v1",
        "output": {"risk_bands": ["high", "medium", "low", "unknown"]},
        "mapping": {
            "rules": [
                {
                    "rule_id": "high",
                    "priority": 10,
                    "condition": {
                        "type": "score_threshold",
                        "parameters": {"operator": ">=", "value": 0.8},
                    },
                    "then": "high",
                },
                {
                    "rule_id": "low",
                    "priority": 20,
                    "condition": {
                        "type": "score_threshold",
                        "parameters": {"operator": ">=", "value": 0.0},
                    },
                    "then": "low",
                },
            ]
        },
    }


def _patch_pipeline(monkeypatch) -> None:
    monkeypatch.setattr(
        pipeline,
        "scan_osint_footprint",
        lambda email, lang="id": [
            {
                "name": "Example",
                "domain": "example.com",
                "source": "OSINT / Holehe",
                "subject": "Active account detected",
            }
        ],
    )
    monkeypatch.setattr(
        pipeline,
        "verify_evidence_records",
        lambda records: __import__("asyncio").sleep(0, result=list(records)),
    )


def test_scorecard_off_preserves_existing_ai_path(monkeypatch) -> None:
    _patch_pipeline(monkeypatch)
    captured: dict = {}

    monkeypatch.setattr(
        pipeline,
        "analyze_smart_cache",
        lambda **kwargs: (
            captured.update(kwargs)
            or {"provider_used": "test", "analysis": [], "exposures": []}
        ),
    )

    state = pipeline.run_scan(
        email="subject@example.org",
        enable_imap=False,
        enable_osint=True,
        enable_breach=False,
        with_ai=True,
    )

    assert state["scorecard"] is None
    assert state["scorecard_input"] is None
    assert "scorecard_result" not in captured


def test_scorecard_on_augments_existing_ai_payload(monkeypatch) -> None:
    _patch_pipeline(monkeypatch)
    captured: dict = {}

    monkeypatch.setattr(
        pipeline,
        "analyze_smart_cache",
        lambda **kwargs: (
            captured.update(kwargs)
            or {"provider_used": "test", "analysis": [], "exposures": []}
        ),
    )

    state = pipeline.run_scan(
        email="subject@example.org",
        enable_imap=False,
        enable_osint=True,
        enable_breach=False,
        with_ai=True,
        enable_scorecard=True,
        scorecard_definition=_definition(),
        scorecard_risk_policy=_policy(),
    )

    assert state["scorecard_input"]["schema_version"] == "scorecard-input-v1"
    assert state["scorecard"]["schema_version"] == "scorecard-result-v1"
    assert state["scorecard"]["score"] == 0.1
    assert state["scorecard"]["risk_band"] == "low"

    assert captured["evidence_records"]
    assert captured["scorecard_result"]["result_id"] == state["scorecard"]["result_id"]
    assert captured["scorecard_result"]["score"] == state["scorecard"]["score"]


def test_scorecard_failure_does_not_break_existing_ai(monkeypatch) -> None:
    _patch_pipeline(monkeypatch)
    captured: dict = {}

    monkeypatch.setattr(
        pipeline,
        "analyze_smart_cache",
        lambda **kwargs: (
            captured.update(kwargs)
            or {"provider_used": "test", "analysis": [], "exposures": []}
        ),
    )

    state = pipeline.run_scan(
        email="subject@example.org",
        enable_imap=False,
        enable_osint=True,
        enable_breach=False,
        with_ai=True,
        enable_scorecard=True,
        scorecard_definition={"broken": True},
        scorecard_risk_policy=_policy(),
    )

    assert state["scorecard"] is None
    assert state["scorecard_input"] is None
    assert captured.get("scorecard_result") is None
    assert state["ai"]["provider_used"] == "test"
