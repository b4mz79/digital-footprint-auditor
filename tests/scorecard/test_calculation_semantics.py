from __future__ import annotations

import pytest

from tests.scorecard.reference_engine import (\n    evaluate_aggregation,\n    evaluate_dependency,\n    evaluate_formula,\n    evaluate_weighted_sum,\n)


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
    assert result.contributions == (("a", 6.0), ("b", 1.6))


def test_reference_engine_keeps_weighted_contributions() -> None:
    result = evaluate_weighted_sum(_measurements(), {"a": 2.0, "b": -0.5})
    assert result.value == 18.0
    assert result.contributions == (("a", 20.0), ("b", -2.0))


def test_reference_engine_dependency_preserves_lineage_and_contributions() -> None:
    left = evaluate_weighted_sum(_measurements(), {"a": 1.0})
    right = evaluate_weighted_sum(_measurements(), {"b": 1.0})
    result = evaluate_dependency(left, right, relation="sum")
    assert result.value == 14.0
    assert result.state == "observed"
    assert result.lineage == ("a", "b")
    assert result.contributions == (("a", 10.0), ("b", 4.0))


def test_reference_engine_rejects_non_finite_measurements() -> None:
    with pytest.raises(ValueError):
        evaluate_weighted_sum(
            {"a": {"unit": "count", "value": float("nan"), "state": "observed"}},
            {"a": 1.0},
        )


def test_reference_engine_rejects_non_finite_weights() -> None:
    with pytest.raises(ValueError):
        evaluate_weighted_sum(_measurements(), {"a": float("inf")})


def test_reference_engine_rejects_boolean_measurements() -> None:
    with pytest.raises(TypeError):
        evaluate_weighted_sum(
            {"a": {"unit": "count", "value": True, "state": "observed"}},
            {"a": 1.0},
        )


def test_reference_engine_rejects_boolean_weights() -> None:
    with pytest.raises(TypeError):
        evaluate_weighted_sum(_measurements(), {"a": True})


def test_formula_primitives_are_explicit_and_deterministic() -> None:
    left = evaluate_weighted_sum(_measurements(), {"a": 1.0})
    right = evaluate_weighted_sum(_measurements(), {"b": 1.0})

    assert evaluate_formula(left, right, operation="sum").value == 14.0
    assert evaluate_formula(left, right, operation="difference").value == 6.0
    assert evaluate_formula(left, right, operation="ratio").value == 2.5


def test_ratio_by_zero_becomes_unknown() -> None:
    left = evaluate_weighted_sum(
        {"a": {"unit": "count", "value": 10, "state": "observed"}}, {"a": 1.0}
    )
    zero = evaluate_weighted_sum(
        {"b": {"unit": "count", "value": 0, "state": "observed"}}, {"b": 1.0}
    )
    result = evaluate_formula(left, zero, operation="ratio")
    assert result.value is None
    assert result.state == "unknown"
    assert result.lineage == ("a", "b")


def test_aggregation_primitives_are_explicit() -> None:
    a = evaluate_weighted_sum(_measurements(), {"a": 1.0})
    b = evaluate_weighted_sum(_measurements(), {"b": 1.0})

    assert evaluate_aggregation([a, b], operation="sum").value == 14.0
    assert evaluate_aggregation([a, b], operation="mean").value == 7.0
    assert evaluate_aggregation([a, b], operation="min").value == 4.0
    assert evaluate_aggregation([a, b], operation="max").value == 10.0
    assert evaluate_aggregation([a, b], operation="weighted_sum", weights=[0.6, 0.4]).value == 7.6


def test_aggregation_preserves_unknown_lineage() -> None:
    observed = evaluate_weighted_sum(
        {"a": {"unit": "count", "value": 10, "state": "observed"}}, {"a": 1.0}
    )
    unknown = evaluate_weighted_sum(
        {"b": {"unit": "count", "value": None, "state": "unknown"}}, {"b": 1.0}
    )
    result = evaluate_aggregation([observed, unknown], operation="mean")
    assert result.value is None
    assert result.state == "unknown"
    assert result.lineage == ("a", "b")


def test_aggregation_requires_inputs() -> None:
    with pytest.raises(ValueError):
        evaluate_aggregation([], operation="sum")


def test_aggregation_rejects_weight_count_mismatch() -> None:
    results = [
        evaluate_weighted_sum(_measurements(), {"a": 1.0}),
        evaluate_weighted_sum(_measurements(), {"b": 1.0}),
    ]
    with pytest.raises(ValueError):
        evaluate_aggregation(results, operation="weighted_sum", weights=[1.0])
