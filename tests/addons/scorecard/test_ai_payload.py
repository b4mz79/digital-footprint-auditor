from __future__ import annotations

from services.ai_agent import _input_fingerprint, build_user_prompt


def _scorecard() -> dict:
    return {
        "schema_version": "scorecard-result-v1",
        "result_id": "result-1",
        "assessment_id": "assessment-1",
        "scorecard_id": "scorecard-1",
        "scorecard_version": "v1",
        "calculated_at": "2026-10-07T01:00:00+00:00",
        "state": "observed",
        "score": 0.72,
        "risk_band": "medium",
        "dimension_results": [],
        "contributions": [
            {"kpi_id": "service_discovery_count", "value": 8, "weight": 1.0, "contribution": 8.0}
        ],
        "measurement_refs": ["service_discovery_count"],
        "calculation_lineage": {
            "schema_version": "scorecard-lineage-v1",
            "inputs": ["service_discovery_count"],
            "steps": [],
            "output": "score",
        },
        "policy_refs": {"risk_policy": "policy-1", "risk_policy_version": "v1"},
    }


def test_scorecard_result_is_embedded_in_ai_prompt() -> None:
    prompt = build_user_prompt(
        "subject@example.org",
        [{"name": "Example", "domain": "example.com"}],
        evidence_records=[],
        scorecard_result=_scorecard(),
    )

    assert "<SCORECARD_RESULT>" in prompt
    assert '"score":0.72' in prompt
    assert '"risk_band":"medium"' in prompt
    assert "do not recalculate or invent them" in prompt


def test_scorecard_changes_analysis_cache_fingerprint() -> None:
    base = _input_fingerprint(
        [{"name": "Example", "domain": "example.com"}],
        [],
        [],
        None,
        {"breach_scan_complete": True, "failed_engines": []},
    )
    enriched = _input_fingerprint(
        [{"name": "Example", "domain": "example.com"}],
        [],
        [],
        _scorecard(),
        {"breach_scan_complete": True, "failed_engines": []},
    )

    assert base != enriched
