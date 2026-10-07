from __future__ import annotations

import math

import pytest

from services.scorecard.calculation import (
    CalculationResult,
    ScorecardCalculationEngine,
)


def _observed(value: float, kpi: str) -> CalculationResult:
    return CalculationResult(
        value=value,
        state="observed",
        lineage=(kpi,),
        coverage=1.0,
    )


def _partial(value: float, kpi: str, coverage: float) -> CalculationResult:
    return CalculationResult(
        value=value,
        state="partial",
        lineage=(kpi,),
        coverage=coverage,
    )


def _unknown(kpi: str) -> CalculationResult:
    return CalculationResult(
        value=None,
        state="unknown",
        lineage=(kpi,),
        coverage=0.0,
    )


def test_weighted_sum_preserves_declared_lineage_and_contributions() -> None:
    result = ScorecardCalculationEngine.weighted_sum(
        {
            "a": {"value": 10, "state": "observed"},
            "b": {"value": 4, "state": "observed"},
        },
        {"a": 0.6, "b": 0.4},
    )
    assert result.state == "observed"
    assert result.value == 7.6
    assert result.lineage == ("a", "b")
    assert result.contributions == (("a", 6.0), ("b", 1.6))
    assert result.coverage == 1.0


def test_weighted_sum_propagates_unknown_without_imputation() -> None:
    result = ScorecardCalculationEngine.weighted_sum(
        {"a": {"value": 10, "state": "observed"}, "b": {"value": None, "state": "unknown"}},
        {"a": 0.6, "b": 0.4},
    )
    assert result.state == "unknown"
    assert result.value is None
    assert result.lineage == ("a", "b")
    assert result.contributions == (("a", 6.0),)


def test_formula_sum_and_difference_preserve_additive_details() -> None:
    left = ScorecardCalculationEngine.weighted_sum(
        {"a": {"value": 10, "state": "observed"}}, {"a": 0.6}
    )
    right = ScorecardCalculationEngine.weighted_sum(
        {"b": {"value": 4, "state": "observed"}}, {"b": 0.4}
    )
    summed = ScorecardCalculationEngine.formula(left, right, operation="sum")
    difference = ScorecardCalculationEngine.formula(left, right, operation="difference")
    assert summed.value == 7.6
    assert difference.value == 4.4
    assert summed.lineage == ("a", "b")
    assert difference.contributions == (("a", 6.0), ("b", -1.6))


def test_ratio_by_zero_becomes_unknown() -> None:
    result = ScorecardCalculationEngine.formula(
        _observed(10, "a"), _observed(0, "b"), operation="ratio"
    )
    assert result.state == "unknown"
    assert result.value is None
    assert result.coverage == 0.0


def test_weighted_aggregation_supports_partial_known_weight() -> None:
    result = ScorecardCalculationEngine.aggregation(
        [_observed(0.8, "a"), _partial(0.5, "b", 0.5)],
        operation="weighted_sum",
        weights=[0.6, 0.4],
    )
    assert result.state == "partial"
    assert result.value == pytest.approx(0.68)
    assert result.coverage == pytest.approx(0.8)
    assert result.known_weight == pytest.approx(0.8)
    assert result.unknown_weight == pytest.approx(0.2)


def test_weighted_aggregation_does_not_renormalize_partial_weights() -> None:
    result = ScorecardCalculationEngine.aggregation(
        [_observed(0.8, "a"), _partial(0.5, "b", 0.5)],
        operation="weighted_sum",
        weights=[0.6, 0.4],
    )
    assert result.value == pytest.approx(0.68)


def test_weighted_aggregation_with_no_known_weight_is_unknown() -> None:
    result = ScorecardCalculationEngine.aggregation(
        [_unknown("a"), _unknown("b")],
        operation="weighted_sum",
        weights=[0.6, 0.4],
    )
    assert result.state == "unknown"
    assert result.value is None
    assert result.coverage == 0.0


def test_normalization_is_explicit_and_drops_leaf_contributions() -> None:
    raw = _observed(7.6, "weighted")
    result = ScorecardCalculationEngine.normalization(
        raw, source_min=0.0, source_max=10.0, precision=2
    )
    assert result.value == 0.76
    assert result.state == "observed"
    assert result.coverage == 1.0
    assert result.contributions == ()
    assert result.contribution_details == ()


def test_normalization_rejects_out_of_range_without_clamp() -> None:
    with pytest.raises(ValueError):
        ScorecardCalculationEngine.normalization(
            _observed(11.0, "score"), source_min=0.0, source_max=10.0
        )


def test_normalization_clamps_when_explicitly_requested() -> None:
    result = ScorecardCalculationEngine.normalization(
        _observed(11.0, "score"), source_min=0.0, source_max=10.0, clamp=True
    )
    assert result.value == 1.0


def test_conditional_unknown_condition_stays_unknown() -> None:
    result = ScorecardCalculationEngine.conditional(
        None, _observed(1.0, "a"), _observed(2.0, "b")
    )
    assert result.state == "unknown"
    assert result.value is None
    assert result.coverage == 0.0


def test_dependency_max_is_not_claimed_as_additive() -> None:
    result = ScorecardCalculationEngine.dependency(
        _observed(0.8, "a"), _observed(0.6, "b"), relation="max"
    )
    assert result.value == 0.8
    assert result.contributions == ()
    assert result.contribution_details == ()


def test_calculation_result_rejects_invalid_state_and_unknown_value() -> None:
    with pytest.raises(ValueError):
        CalculationResult(1.0, "invalid", ("a",))
    with pytest.raises(ValueError):
        CalculationResult(1.0, "unknown", ("a",))
    with pytest.raises(ValueError):
        CalculationResult(None, "observed", ("a",))


def test_calculation_result_rejects_invalid_coverage() -> None:
    with pytest.raises(ValueError):
        CalculationResult(1.0, "observed", ("a",), coverage=0.5)
    with pytest.raises(ValueError):
        CalculationResult(1.0, "partial", ("a",), coverage=1.0)


def test_calculation_is_deterministic_for_same_inputs() -> None:
    kwargs = {
        "measurements": {
            "a": {"value": 10, "state": "observed"},
            "b": {"value": 4, "state": "observed"},
        },
        "weights": {"a": 0.6, "b": 0.4},
    }
    first = ScorecardCalculationEngine.weighted_sum(**kwargs)
    second = ScorecardCalculationEngine.weighted_sum(**kwargs)
    assert first == second
