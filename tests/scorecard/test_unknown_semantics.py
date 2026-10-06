from __future__ import annotations

from tests.scorecard.reference_engine import evaluate_dependency, evaluate_weighted_sum

def test_unknown_is_not_coerced_to_zero() -> None:
    measurements = {
        "a": {"unit": "count", "value": 10, "state": "observed"},
        "b": {"unit": "count", "value": None, "state": "unknown"},
    }
    result = evaluate_weighted_sum(measurements, {"a": 0.5, "b": 0.5})
    assert result.value is None
    assert result.state == "unknown"
    assert result.lineage == ("a", "b")

def test_unknown_propagates_through_dependency() -> None:
    observed = evaluate_weighted_sum(
        {"a": {"unit": "count", "value": 10, "state": "observed"}}, {"a": 1.0}
    )
    unknown = evaluate_weighted_sum(
        {"b": {"unit": "count", "value": None, "state": "unknown"}}, {"b": 1.0}
    )
    result = evaluate_dependency(observed, unknown, relation="max")
    assert result.value is None
    assert result.state == "unknown"
    assert result.lineage == ("a", "b")
