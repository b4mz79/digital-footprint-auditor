from __future__ import annotations

import pytest

from tests.scorecard.reference_engine import (
    evaluate_aggregation,
    evaluate_dependency,
    evaluate_formula,
    evaluate_weighted_sum,
    evaluate_normalization,
)


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


def test_weights_are_not_implicitly_normalized() -> None:
    result = evaluate_weighted_sum(_measurements(), {"a": 2.0, "b": 3.0})
    assert result.value == 32.0
    assert result.contributions == (("a", 20.0), ("b", 12.0))


def test_zero_weight_is_a_valid_zero_contribution() -> None:
    result = evaluate_weighted_sum(_measurements(), {"a": 0.0, "b": 1.0})
    assert result.value == 4.0
    assert result.contributions == (("a", 0.0), ("b", 4.0))


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



def test_normalization_uses_canonical_zero_to_one_range() -> None:
    result = evaluate_weighted_sum(
        {"score": {"unit": "points", "value": 75, "state": "observed"}},
        {"score": 1.0},
    )
    normalized = evaluate_normalization(result, source_min=0, source_max=100)
    assert normalized.value == 0.75
    assert normalized.state == "observed"
    assert normalized.lineage == ("score",)
    assert normalized.contributions == (("score", 75.0),)


def test_normalization_rounds_to_two_decimal_places() -> None:
    result = evaluate_weighted_sum(
        {"score": {"unit": "points", "value": 1, "state": "observed"}},
        {"score": 1.0},
    )
    normalized = evaluate_normalization(result, source_min=0, source_max=3)
    assert normalized.value == 0.33


def test_normalization_preserves_exact_boundaries() -> None:
    low = evaluate_weighted_sum(
        {"score": {"unit": "points", "value": 0, "state": "observed"}},
        {"score": 1.0},
    )
    high = evaluate_weighted_sum(
        {"score": {"unit": "points", "value": 100, "state": "observed"}},
        {"score": 1.0},
    )
    assert evaluate_normalization(low, source_min=0, source_max=100).value == 0.0
    assert evaluate_normalization(high, source_min=0, source_max=100).value == 1.0


def test_normalization_rejects_out_of_range_by_default() -> None:
    result = evaluate_weighted_sum(
        {"score": {"unit": "points", "value": 101, "state": "observed"}},
        {"score": 1.0},
    )
    with pytest.raises(ValueError):
        evaluate_normalization(result, source_min=0, source_max=100)


def test_normalization_can_explicitly_clamp_out_of_range_input() -> None:
    result = evaluate_weighted_sum(
        {"score": {"unit": "points", "value": 125, "state": "observed"}},
        {"score": 1.0},
    )
    normalized = evaluate_normalization(
        result, source_min=0, source_max=100, clamp=True
    )
    assert normalized.value == 1.0
    assert normalized.lineage == ("score",)
    assert normalized.contributions == (("score", 125.0),)


def test_normalization_preserves_unknown_semantics() -> None:
    result = evaluate_weighted_sum(
        {"score": {"unit": "points", "value": None, "state": "unknown"}},
        {"score": 1.0},
    )
    normalized = evaluate_normalization(result, source_min=0, source_max=100)
    assert normalized.value is None
    assert normalized.state == "unknown"
    assert normalized.lineage == ("score",)


def test_normalization_rejects_invalid_source_range() -> None:
    result = evaluate_weighted_sum(
        {"score": {"unit": "points", "value": 50, "state": "observed"}},
        {"score": 1.0},
    )
    with pytest.raises(ValueError):
        evaluate_normalization(result, source_min=100, source_max=100)


def test_normalization_rejects_non_finite_configuration() -> None:
    result = evaluate_weighted_sum(
        {"score": {"unit": "points", "value": 50, "state": "observed"}},
        {"score": 1.0},
    )
    with pytest.raises(ValueError):
        evaluate_normalization(result, source_min=float("nan"), source_max=100)
