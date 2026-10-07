from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _assert_assessment_contract(data: dict[str, Any]) -> None:
    assert data["schema_version"] == "scorecard-eval-v1"
    assert isinstance(data["assessment_id"], str) and data["assessment_id"]
    assert isinstance(data["scorecard_definition_version"], str)
    assert data["scorecard_definition_version"]
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


def _assert_scorecard_definition_contract(data: dict[str, Any]) -> None:
    assert data["schema_version"] == "scorecard-definition-v1"
    assert isinstance(data["scorecard_id"], str) and data["scorecard_id"]
    assert isinstance(data["version"], str) and data["version"]

    score = data["score"]
    assert score["canonical_range"] == {"min": 0.0, "max": 1.0}
    assert score["precision"] == 2
    assert score["rounding"] == "half_even"

    aggregation = data["aggregation"]
    assert aggregation["operation"] == "weighted_sum"

    weights = aggregation["weights"]
    assert isinstance(weights, dict) and weights

    numeric_weights: list[float] = []
    for kpi_id, weight in weights.items():
        assert isinstance(kpi_id, str) and kpi_id
        assert isinstance(weight, (int, float)) and not isinstance(weight, bool)
        assert math.isfinite(float(weight))
        assert float(weight) >= 0.0
        numeric_weights.append(float(weight))

    # A weighted aggregation must have positive declared weight mass. Zero
    # coefficients remain valid; an all-zero configuration does not.
    assert sum(numeric_weights) > 0.0


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
    _assert_scorecard_definition_contract(data)
    assert data["aggregation"]["weights"] == {"a": 0.6, "b": 0.4}


def test_scorecard_definition_rejects_negative_weight() -> None:
    data = _load("scorecard_definition_basic.json")
    data["aggregation"]["weights"]["a"] = -0.1

    with pytest.raises(AssertionError):
        _assert_scorecard_definition_contract(data)


def test_scorecard_definition_rejects_zero_total_weight() -> None:
    data = _load("scorecard_definition_basic.json")
    data["aggregation"]["weights"] = {"a": 0.0, "b": 0.0}

    with pytest.raises(AssertionError):
        _assert_scorecard_definition_contract(data)


def test_scorecard_definition_allows_explicit_non_normalized_weights() -> None:
    data = _load("scorecard_definition_basic.json")
    data["aggregation"]["weights"] = {"a": 2.0, "b": 3.0}

    _assert_scorecard_definition_contract(data)
    assert sum(data["aggregation"]["weights"].values()) == 5.0
    # The definition stores explicit coefficients; it does not rewrite them
    # into a normalized 0..1 distribution.
    assert data["aggregation"]["weights"] == {"a": 2.0, "b": 3.0}


def test_scorecard_definition_rejects_non_finite_weight() -> None:
    data = _load("scorecard_definition_basic.json")
    data["aggregation"]["weights"]["a"] = float("inf")

    with pytest.raises(AssertionError):
        _assert_scorecard_definition_contract(data)
