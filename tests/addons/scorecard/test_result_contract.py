from __future__ import annotations

from datetime import datetime
import json
import math
from pathlib import Path
from typing import Any

FIXTURES = Path(__file__).parent / "fixtures"


def _load() -> dict[str, Any]:
    return json.loads(
        (FIXTURES / "scorecard_result_contract.json").read_text(encoding="utf-8")
    )


def _assert_timezone_aware_iso8601(value: Any) -> None:
    assert isinstance(value, str) and value
    parsed = datetime.fromisoformat(value)
    assert parsed.tzinfo is not None
    assert parsed.utcoffset() is not None


def _assert_scorecard_result_contract(data: dict[str, Any]) -> None:
    assert data["schema_version"] == "scorecard-result-v1"
    for field in (
        "result_id",
        "assessment_id",
        "scorecard_id",
        "scorecard_version",
        "calculated_at",
    ):
        assert isinstance(data.get(field), str) and data[field]

    _assert_timezone_aware_iso8601(data["calculated_at"])

    assert data["state"] in {"observed", "partial", "unknown"}
    assert data["risk_band"] in {"high", "medium", "low", "unknown"}

    score = data.get("score")
    if data["state"] == "unknown":
        assert score is None
    else:
        assert isinstance(score, (int, float)) and not isinstance(score, bool)
        assert math.isfinite(float(score))
        assert 0.0 <= float(score) <= 1.0

    dimensions = data.get("dimension_results")
    assert isinstance(dimensions, list)
    for dimension in dimensions:
        assert isinstance(dimension, dict)
        assert isinstance(dimension.get("dimension_id"), str) and dimension["dimension_id"]
        assert dimension.get("state") in {"observed", "partial", "unknown"}
        dimension_score = dimension.get("score")
        if dimension["state"] == "unknown":
            assert dimension_score is None
        else:
            assert isinstance(dimension_score, (int, float))
            assert not isinstance(dimension_score, bool)
            assert math.isfinite(float(dimension_score))
            assert 0.0 <= float(dimension_score) <= 1.0

    contributions = data.get("contributions")
    assert isinstance(contributions, list)
    if contributions:
        assert data.get("contribution_stage") in {
            "pre_normalization",
            "aggregation",
            "dimension",
            "final_score",
        }
    for contribution in contributions:
        assert isinstance(contribution, dict)
        assert isinstance(contribution.get("kpi_id"), str) and contribution["kpi_id"]
        for field in ("value", "weight", "contribution"):
            assert isinstance(contribution.get(field), (int, float))
            assert not isinstance(contribution[field], bool)
            assert math.isfinite(float(contribution[field]))

    measurement_refs = data.get("measurement_refs")
    assert isinstance(measurement_refs, list)
    assert all(isinstance(item, str) and item for item in measurement_refs)

    lineage = data.get("calculation_lineage")
    assert isinstance(lineage, dict)
    assert lineage.get("schema_version") == "scorecard-lineage-v1"
    assert isinstance(lineage.get("inputs"), list)
    assert all(isinstance(item, str) and item for item in lineage["inputs"])
    assert isinstance(lineage.get("steps"), list) and lineage["steps"]
    assert isinstance(lineage.get("output"), str) and lineage["output"]

    for step in lineage["steps"]:
        assert isinstance(step, dict)
        assert isinstance(step.get("id"), str) and step["id"]
        assert isinstance(step.get("operation"), str) and step["operation"]
        assert isinstance(step.get("inputs"), list) and step["inputs"]
        assert all(isinstance(item, str) and item for item in step["inputs"])
        parameters = step.get("parameters")
        assert isinstance(parameters, dict)
        assert isinstance(step.get("output"), str) and step["output"]

    policy_refs = data.get("policy_refs")
    assert isinstance(policy_refs, dict)
    assert isinstance(policy_refs.get("risk_policy"), str)
    assert policy_refs["risk_policy"]
    assert isinstance(policy_refs.get("risk_policy_version"), str)
    assert policy_refs["risk_policy_version"]

    # Contributions are stage-specific additive decomposition details. They
    # must not be assumed to sum to the reported score when a later affine
    # transformation (such as min-max normalization) produces that score.
    # The producing stage is explicit instead.


def test_scorecard_result_contract_is_self_contained() -> None:
    data = _load()
    _assert_scorecard_result_contract(data)

    assert data["assessment_id"]
    assert data["scorecard_id"]
    assert data["scorecard_version"]
    assert data["measurement_refs"]
    assert data["calculation_lineage"]
    assert data["policy_refs"]


def test_scorecard_result_contract_preserves_unknown_score_semantics() -> None:
    data = _load()
    data["state"] = "unknown"
    data["score"] = None
    data["risk_band"] = "unknown"
    _assert_scorecard_result_contract(data)


def test_scorecard_result_contract_allows_partial_results() -> None:
    data = _load()
    data["state"] = "partial"
    data["score"] = 0.60
    data["contributions"] = []
    data.pop("contribution_stage", None)
    _assert_scorecard_result_contract(data)

def test_scorecard_result_does_not_treat_pre_normalization_contributions_as_final_score() -> None:
    data = _load()
    contribution_total = sum(
        item["contribution"] for item in data["contributions"]
    )
    assert data["contribution_stage"] == "pre_normalization"
    assert math.isclose(contribution_total, 7.6, rel_tol=0.0, abs_tol=1e-12)
    assert math.isclose(float(data["score"]), 0.76, rel_tol=0.0, abs_tol=1e-12)
    assert not math.isclose(
        contribution_total,
        float(data["score"]),
        rel_tol=0.0,
        abs_tol=1e-12,
    )

def test_calculation_lineage_captures_replay_parameters() -> None:
    data = _load()
    steps = data["calculation_lineage"]["steps"]

    weighted = next(step for step in steps if step["operation"] == "weighted_sum")
    assert weighted["parameters"]["weights"] == {
        "service_discovery_count": 0.6,
        "relevant_security_evidence": 0.4,
    }

    normalization = next(step for step in steps if step["operation"] == "normalization")
    assert normalization["parameters"] == {
        "source_min": 0.0,
        "source_max": 10.0,
        "clamp": False,
        "rounding": "half_even",
        "precision": 2,
    }


def test_calculation_lineage_is_parameterized_not_operation_only() -> None:
    data = _load()
    lineage = data["calculation_lineage"]

    assert "operations" not in lineage
    assert all(step.get("parameters") for step in lineage["steps"])


def test_scorecard_result_contract_requires_timezone_for_calculated_at() -> None:
    data = _load()
    valid = data["calculated_at"]
    _assert_timezone_aware_iso8601(valid)

    data["calculated_at"] = "2026-10-07"
    try:
        _assert_timezone_aware_iso8601(data["calculated_at"])
    except (AssertionError, ValueError):
        pass
    else:
        raise AssertionError("date-only calculated_at must be rejected")

    data["calculated_at"] = "2026-10-07T00:01:00"
    try:
        _assert_timezone_aware_iso8601(data["calculated_at"])
    except AssertionError:
        pass
    else:
        raise AssertionError("timezone-naive calculated_at must be rejected")


def test_dimension_result_score_preserves_state_semantics() -> None:
    data = _load()
    _assert_scorecard_result_contract(data)

    unknown = dict(data["dimension_results"][0])
    unknown["state"] = "unknown"
    unknown["score"] = None
    data["dimension_results"] = [unknown]
    _assert_scorecard_result_contract(data)

def test_risk_band_is_policy_output_not_a_score_threshold_contract() -> None:
    data = _load()
    _assert_scorecard_result_contract(data)

    # The result carries a risk-policy reference, but this contract does not
    # define High/Medium/Low thresholds. Threshold semantics remain owned by
    # the referenced policy and are intentionally outside this contract.
    assert data["policy_refs"]["risk_policy"]
    assert data["risk_band"] in {"high", "medium", "low", "unknown"}

    # Band correctness for a given score belongs to the risk-policy layer,
    # not to the structural Result Contract.
    data["risk_band"] = "high"
    _assert_scorecard_result_contract(data)
