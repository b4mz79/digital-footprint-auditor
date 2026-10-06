from __future__ import annotations

import json
import math
from pathlib import Path


FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_assessment_definition_result_and_risk_policy_versions_are_consistent() -> None:
    assessment = _load("assessment_basic.json")
    definition = _load("scorecard_definition_basic.json")
    result = _load("scorecard_result_contract.json")
    risk_policy = _load("risk_policy_contract.json")

    assert assessment["scorecard_definition_version"] == definition["version"]
    assert result["assessment_id"] == assessment["assessment_id"]
    assert result["scorecard_id"] == definition["scorecard_id"]
    assert result["scorecard_version"] == definition["version"]

    assert risk_policy["scope"]["scorecard_id"] == definition["scorecard_id"]
    assert risk_policy["scope"]["scorecard_version"] == definition["version"]

    assert result["policy_refs"]["risk_policy"] == risk_policy["risk_policy_id"]
    assert result["policy_refs"]["risk_policy_version"] == risk_policy["version"]


def test_result_measurement_refs_resolve_to_declared_measurements() -> None:
    result = _load("scorecard_result_contract.json")
    measurement_contract = _load("measurement_contract.json")

    measurements = {
        item["measurement_id"]: item
        for item in measurement_contract["measurements"]
    }

    refs = result["measurement_refs"]

    assert refs
    assert len(refs) == len(set(refs))
    assert set(refs).issubset(measurements)


def test_calculation_lineage_inputs_resolve_to_result_measurement_refs() -> None:
    result = _load("scorecard_result_contract.json")

    measurement_refs = set(result["measurement_refs"])
    lineage = result["calculation_lineage"]

    assert set(lineage["inputs"]) == measurement_refs

    produced = set(lineage["inputs"])
    for step in lineage["steps"]:
        assert set(step["inputs"]).issubset(produced)
        produced.add(step["output"])

    assert lineage["output"] in produced


def test_weighted_sum_inputs_are_numeric_measurements_matching_weighted_kpis() -> None:
    result = _load("scorecard_result_contract.json")
    measurement_contract = _load("measurement_contract.json")

    measurements = {
        item["measurement_id"]: item
        for item in measurement_contract["measurements"]
    }

    weighted_step = next(
        step
        for step in result["calculation_lineage"]["steps"]
        if step["operation"] == "weighted_sum"
    )

    weights = weighted_step["parameters"]["weights"]
    inputs = [measurements[ref] for ref in weighted_step["inputs"]]

    assert set(item["kpi_id"] for item in inputs) == set(weights)

    for item in inputs:
        assert item["measurement_type"] == "quantitative"
        assert item["state"] != "unknown"
        assert item["value"] is not None
        assert isinstance(item["value"], (int, float))
        assert not isinstance(item["value"], bool)
        assert math.isfinite(float(item["value"]))


def test_result_contributions_match_weighted_inputs() -> None:
    result = _load("scorecard_result_contract.json")

    weighted_step = next(
        step
        for step in result["calculation_lineage"]["steps"]
        if step["operation"] == "weighted_sum"
    )
    weights = weighted_step["parameters"]["weights"]

    contribution_by_kpi = {
        item["kpi_id"]: item
        for item in result["contributions"]
    }

    assert set(contribution_by_kpi) == set(weights)

    for kpi_id, weight in weights.items():
        item = contribution_by_kpi[kpi_id]
        assert item["weight"] == weight
        assert math.isclose(
            item["contribution"],
            float(item["value"]) * float(weight),
            rel_tol=0.0,
            abs_tol=1e-12,
        )


def test_result_score_replays_from_declared_pre_normalization_contributions() -> None:
    result = _load("scorecard_result_contract.json")
    normalization = next(
        step
        for step in result["calculation_lineage"]["steps"]
        if step["operation"] == "normalization"
    )

    weighted_total = sum(
        item["contribution"] for item in result["contributions"]
    )
    parameters = normalization["parameters"]

    source_min = float(parameters["source_min"])
    source_max = float(parameters["source_max"])
    normalized = round(
        (weighted_total - source_min) / (source_max - source_min),
        int(parameters["precision"]),
    )

    assert math.isclose(
        normalized,
        float(result["score"]),
        rel_tol=0.0,
        abs_tol=1e-12,
    )


def test_risk_band_has_policy_identity_without_threshold_semantics() -> None:
    result = _load("scorecard_result_contract.json")
    risk_policy = _load("risk_policy_contract.json")

    assert result["risk_band"] in risk_policy["output"]["risk_bands"]
    assert result["policy_refs"]["risk_policy"] == risk_policy["risk_policy_id"]
    assert (
        result["policy_refs"]["risk_policy_version"]
        == risk_policy["version"]
    )

    # The cross-contract layer verifies policy identity/version and allowed
    # output vocabulary only. Numeric High/Medium/Low thresholds remain owned
    # by the policy definition and are intentionally not asserted here.
