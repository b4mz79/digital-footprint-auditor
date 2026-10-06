from __future__ import annotations

from tests.scorecard.reference_engine import evaluate_dependency, evaluate_weighted_sum

def _measurements() -> dict:
    return {
        "a": {"unit": "count", "value": 10, "state": "observed"},
        "b": {"unit": "count", "value": 4, "state": "observed"},
    }

def test_reference_engine_weighted_sum_is_deterministic() -> None:
    result = evaluate_weighted_sum(_measurements(), {"a": 0.6, "b": 0.4})
    assert result.value == 7.6
    assert result.state == "observed"
    assert result.lineage == ("a", "b")

def test_reference_engine_dependency_preserves_lineage() -> None:
    left = evaluate_weighted_sum(_measurements(), {"a": 1.0})
    right = evaluate_weighted_sum(_measurements(), {"b": 1.0})
    result = evaluate_dependency(left, right, relation="sum")
    assert result.value == 14.0
    assert result.state == "observed"
    assert result.lineage == ("a", "b")
