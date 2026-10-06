from __future__ import annotations

import json
from pathlib import Path
from typing import Any

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _assert_assessment_contract(data: dict[str, Any]) -> None:
    assert data["schema_version"] == "scorecard-eval-v1"
    assert isinstance(data["assessment_id"], str) and data["assessment_id"]
    assert isinstance(data["scorecard_definition_version"], str)
    assert isinstance(data["kpis"], list) and data["kpis"]

    ids: list[str] = []
    for kpi in data["kpis"]:
        assert isinstance(kpi, dict)
        assert isinstance(kpi.get("id"), str) and kpi["id"]
        assert kpi["id"] not in ids
        ids.append(kpi["id"])

        assert isinstance(kpi.get("unit"), str) and kpi["unit"]
        assert kpi.get("state") in {"observed", "unknown"}
        assert isinstance(kpi.get("source"), str) and kpi["source"]

        value = kpi.get("value")
        if kpi["state"] == "unknown":
            assert value is None
        else:
            assert value is not None
            assert isinstance(value, (int, float)) and not isinstance(value, bool)

        if "evidence_ids" in kpi:
            assert isinstance(kpi["evidence_ids"], list)
            assert all(isinstance(item, str) and item for item in kpi["evidence_ids"])


def test_basic_assessment_fixture_matches_canonical_contract() -> None:
    _assert_assessment_contract(_load("assessment_basic.json"))


def test_unknown_assessment_fixture_preserves_unknown_semantics() -> None:
    data = _load("assessment_unknown.json")
    _assert_assessment_contract(data)

    unknown = next(
        item for item in data["kpis"] if item["id"] == "relevant_security_evidence"
    )
    assert unknown["state"] == "unknown"
    assert unknown["value"] is None


def test_interlink_fixture_matches_canonical_contract() -> None:
    _assert_assessment_contract(_load("assessment_interlink.json"))


def test_scorecard_definition_contract_locks_canonical_score_policy() -> None:
    data = _load("scorecard_definition_basic.json")
    assert data["schema_version"] == "scorecard-definition-v1"
    assert isinstance(data["scorecard_id"], str) and data["scorecard_id"]
    assert isinstance(data["version"], str) and data["version"]

    score = data["score"]
    assert score["canonical_range"] == {"min": 0.0, "max": 1.0}
    assert score["precision"] == 2
    assert score["rounding"] == "half_even"

    aggregation = data["aggregation"]
    assert aggregation["operation"] == "weighted_sum"
    assert aggregation["weights"] == {"a": 0.6, "b": 0.4}
