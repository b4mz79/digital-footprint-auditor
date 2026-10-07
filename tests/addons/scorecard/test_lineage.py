from __future__ import annotations

import json
from pathlib import Path

from tests.scorecard.reference_engine import evaluate_weighted_sum

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _assert_replayable_lineage(lineage: dict, measurement_refs: list[str]) -> None:
    assert lineage["inputs"] == measurement_refs
    assert len(lineage["inputs"]) == len(set(lineage["inputs"]))

    steps = lineage["steps"]
    step_ids = [step["id"] for step in steps]
    assert len(step_ids) == len(set(step_ids))

    available = set(lineage["inputs"])
    for step in steps:
        assert not set(step["inputs"]) - available
        assert step["output"] not in available
        available.add(step["output"])

    assert lineage["output"] in available
    assert lineage["output"] in {step["output"] for step in steps}


def test_measurement_keeps_evidence_lineage() -> None:
    data = _load("assessment_basic.json")
    evidence_kpi = next(
        item for item in data["kpis"] if item["id"] == "relevant_security_evidence"
    )
    assert evidence_kpi["source"] == "contextual_filter_dump"
    assert evidence_kpi["evidence_ids"] == ["evidence-security-1"]


def test_reference_result_lineage_is_explicit() -> None:
    measurements = {
        "a": {
            "unit": "count",
            "value": 10,
            "state": "observed",
            "evidence_ids": ["evidence-a"],
        },
        "b": {
            "unit": "count",
            "value": 4,
            "state": "observed",
            "evidence_ids": ["evidence-b"],
        },
    }
    result = evaluate_weighted_sum(measurements, {"a": 0.6, "b": 0.4})
    assert result.lineage == ("a", "b")


def test_scorecard_calculation_lineage_is_replayable_and_has_no_dangling_inputs() -> None:
    result = _load("scorecard_result_contract.json")
    lineage = result["calculation_lineage"]

    _assert_replayable_lineage(lineage, result["measurement_refs"])


def test_scorecard_calculation_lineage_rejects_dangling_step_input() -> None:
    result = _load("scorecard_result_contract.json")
    lineage = json.loads(json.dumps(result["calculation_lineage"]))
    lineage["steps"][1]["inputs"] = ["missing-calculation-node"]

    try:
        _assert_replayable_lineage(lineage, result["measurement_refs"])
    except AssertionError:
        pass
    else:
        raise AssertionError("dangling lineage input must be rejected")


def test_scorecard_calculation_lineage_rejects_unresolved_final_output() -> None:
    result = _load("scorecard_result_contract.json")
    lineage = json.loads(json.dumps(result["calculation_lineage"]))
    lineage["output"] = "missing-final-node"

    try:
        _assert_replayable_lineage(lineage, result["measurement_refs"])
    except AssertionError:
        pass
    else:
        raise AssertionError("unresolved lineage output must be rejected")
