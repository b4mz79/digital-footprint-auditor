from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

FIXTURES = Path(__file__).parent / "fixtures"


def _load() -> dict[str, Any]:
    return json.loads(
        (FIXTURES / "scorecard_result_contract.json").read_text(encoding="utf-8")
    )


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
    assert isinstance(lineage.get("inputs"), list)
    assert isinstance(lineage.get("operations"), list)
    assert isinstance(lineage.get("output"), str) and lineage["output"]

    policy_refs = data.get("policy_refs")
    assert isinstance(policy_refs, dict)

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
