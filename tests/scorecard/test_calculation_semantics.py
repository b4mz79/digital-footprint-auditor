from __future__ import annotations

import pytest

from tests.scorecard.reference_engine import (
    evaluate_aggregation,
    evaluate_dependency,
    evaluate_formula,
    evaluate_weighted_sum,
    evaluate_normalization,
    ContributionDetail,
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


def test_weighted_aggregation_returns_partial_value_and_coverage() -> None:
    observed = evaluate_weighted_sum(
        {"a": {"unit": "count", "value": 10, "state": "observed"}}, {"a": 1.0}
    )
    unknown = evaluate_weighted_sum(
        {"b": {"unit": "count", "value": None, "state": "unknown"}}, {"b": 1.0}
    )
    result = evaluate_aggregation(
        [observed, unknown], operation="weighted_sum", weights=[0.6, 0.4]
    )
    assert result.value == 6.0
    assert result.state == "partial"
    assert result.coverage == 0.6
    assert result.known_weight == 0.6
    assert result.unknown_weight == 0.4
    assert result.lineage == ("a", "b")


def test_partial_aggregation_does_not_renormalize_known_contribution() -> None:
    observed = evaluate_weighted_sum(
        {"a": {"unit": "count", "value": 10, "state": "observed"}}, {"a": 1.0}
    )
    unknown = evaluate_weighted_sum(
        {"b": {"unit": "count", "value": None, "state": "unknown"}}, {"b": 1.0}
    )
    result = evaluate_aggregation(
        [observed, unknown], operation="weighted_sum", weights=[0.6, 0.4]
    )
    assert result.value == 6.0
    assert result.value != result.value / result.coverage


def test_weighted_aggregation_propagates_nested_partial_coverage() -> None:
    inner_observed = evaluate_weighted_sum(
        {"a": {"unit": "count", "value": 10, "state": "observed"}}, {"a": 1.0}
    )
    inner_unknown = evaluate_weighted_sum(
        {"b": {"unit": "count", "value": None, "state": "unknown"}}, {"b": 1.0}
    )
    partial = evaluate_aggregation(
        [inner_observed, inner_unknown],
        operation="weighted_sum",
        weights=[0.6, 0.4],
    )

    outer_observed = evaluate_weighted_sum(
        {"c": {"unit": "count", "value": 5, "state": "observed"}}, {"c": 1.0}
    )
    result = evaluate_aggregation(
        [partial, outer_observed],
        operation="weighted_sum",
        weights=[0.5, 0.5],
    )

    # The inner partial result contributes its measured value (6.0)
    # through the outer weight (0.5): 6.0 * 0.5 + 5.0 * 0.5 = 5.5.
    # Coverage remains separate metadata; it does not renormalize the value.
    assert result.value == 5.5
    assert result.state == "partial"
    assert result.coverage == 0.8
    assert result.known_weight == 0.8
    assert result.unknown_weight == 0.2


def test_zero_weight_unknown_does_not_reduce_coverage() -> None:
    observed = evaluate_weighted_sum(
        {"a": {"unit": "count", "value": 10, "state": "observed"}}, {"a": 1.0}
    )
    unknown = evaluate_weighted_sum(
        {"b": {"unit": "count", "value": None, "state": "unknown"}}, {"b": 1.0}
    )
    result = evaluate_aggregation(
        [observed, unknown], operation="weighted_sum", weights=[1.0, 0.0]
    )
    assert result.value == 10.0
    assert result.state == "observed"
    assert result.coverage == 1.0
    assert result.known_weight == 1.0
    assert result.unknown_weight == 0.0


def test_weighted_aggregation_is_complete_when_all_inputs_are_observed() -> None:
    observed_a = evaluate_weighted_sum(
        {"a": {"unit": "count", "value": 10, "state": "observed"}}, {"a": 1.0}
    )
    observed_b = evaluate_weighted_sum(
        {"b": {"unit": "count", "value": 4, "state": "observed"}}, {"b": 1.0}
    )
    result = evaluate_aggregation(
        [observed_a, observed_b], operation="weighted_sum", weights=[0.6, 0.4]
    )
    assert result.value == 7.6
    assert result.state == "observed"
    assert result.coverage == 1.0
    assert result.known_weight == 1.0
    assert result.unknown_weight == 0.0


def test_weighted_aggregation_is_unknown_when_all_inputs_are_unknown() -> None:
    unknown_a = evaluate_weighted_sum(
        {"a": {"unit": "count", "value": None, "state": "unknown"}}, {"a": 1.0}
    )
    unknown_b = evaluate_weighted_sum(
        {"b": {"unit": "count", "value": None, "state": "unknown"}}, {"b": 1.0}
    )
    result = evaluate_aggregation(
        [unknown_a, unknown_b], operation="weighted_sum", weights=[0.6, 0.4]
    )
    assert result.value is None
    assert result.state == "unknown"
    assert result.coverage == 0.0
    assert result.known_weight == 0.0
    assert result.unknown_weight == 1.0
    assert result.lineage == ("a", "b")


def test_weighted_aggregation_coverage_uses_weight_not_item_count() -> None:
    observed = evaluate_weighted_sum(
        {"a": {"unit": "count", "value": 10, "state": "observed"}}, {"a": 1.0}
    )
    unknown_b = evaluate_weighted_sum(
        {"b": {"unit": "count", "value": None, "state": "unknown"}}, {"b": 1.0}
    )
    unknown_c = evaluate_weighted_sum(
        {"c": {"unit": "count", "value": None, "state": "unknown"}}, {"c": 1.0}
    )
    result = evaluate_aggregation(
        [observed, unknown_b, unknown_c],
        operation="weighted_sum",
        weights=[0.8, 0.1, 0.1],
    )
    assert result.state == "partial"
    assert result.value == 8.0
    assert result.coverage == 0.8
    assert result.known_weight == 0.8
    assert result.unknown_weight == 0.2


def test_weighted_aggregation_rejects_negative_weights_for_partial_coverage() -> None:
    observed = evaluate_weighted_sum(
        {"a": {"unit": "count", "value": 10, "state": "observed"}}, {"a": 1.0}
    )
    unknown = evaluate_weighted_sum(
        {"b": {"unit": "count", "value": None, "state": "unknown"}}, {"b": 1.0}
    )
    with pytest.raises(ValueError, match="non-negative weights"):
        evaluate_aggregation(
            [observed, unknown], operation="weighted_sum", weights=[0.6, -0.4]
        )


def test_weighted_aggregation_rejects_zero_total_weight() -> None:
    observed = evaluate_weighted_sum(
        {"a": {"unit": "count", "value": 10, "state": "observed"}}, {"a": 1.0}
    )
    with pytest.raises(ValueError, match="positive total weight"):
        evaluate_aggregation([observed], operation="weighted_sum", weights=[0.0])


def test_non_weighted_aggregation_keeps_strict_unknown_semantics() -> None:
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


def test_weighted_sum_exposes_explicit_contribution_details() -> None:
    result = evaluate_weighted_sum(_measurements(), {"a": 0.6, "b": 0.4})
    assert result.contribution_details == (
        ContributionDetail("a", 10.0, 0.6, 6.0),
        ContributionDetail("b", 4.0, 0.4, 1.6),
    )

def test_contribution_details_preserve_zero_and_negative_weights() -> None:
    result = evaluate_weighted_sum(_measurements(), {"a": 0.0, "b": -0.5})
    assert result.contribution_details == (
        ContributionDetail("a", 10.0, 0.0, 0.0),
        ContributionDetail("b", 4.0, -0.5, -2.0),
    )

def test_derived_results_preserve_contribution_details_and_lineage() -> None:
    left = evaluate_weighted_sum(_measurements(), {"a": 0.6})
    right = evaluate_weighted_sum(_measurements(), {"b": 0.4})
    result = evaluate_dependency(left, right, relation="sum")
    assert result.contribution_details == (
        ContributionDetail("a", 10.0, 0.6, 6.0),
        ContributionDetail("b", 4.0, 0.4, 1.6),
    )
    assert result.lineage == ("a", "b")

def test_unknown_result_preserves_known_contribution_details() -> None:
    observed = evaluate_weighted_sum(
        {"a": {"unit": "count", "value": 10, "state": "observed"}}, {"a": 0.6}
    )
    unknown = evaluate_weighted_sum(
        {"b": {"unit": "count", "value": None, "state": "unknown"}}, {"b": 0.4}
    )
    result = evaluate_aggregation([observed, unknown], operation="sum")
    assert result.state == "unknown"
    assert result.value is None
    assert result.contribution_details == (ContributionDetail("a", 10.0, 0.6, 6.0),)

def test_unknown_dependency_preserves_known_contribution_details() -> None:
    observed = evaluate_weighted_sum(
        {"a": {"unit": "count", "value": 10, "state": "observed"}}, {"a": 0.6}
    )
    unknown = evaluate_weighted_sum(
        {"b": {"unit": "count", "value": None, "state": "unknown"}}, {"b": 0.4}
    )
    result = evaluate_dependency(observed, unknown, relation="sum")
    assert result.state == "unknown"
    assert result.value is None
    assert result.lineage == ("a", "b")
    assert result.contribution_details == (ContributionDetail("a", 10.0, 0.6, 6.0),)


def test_formula_propagates_partial_state_and_conservative_coverage() -> None:
    observed = evaluate_weighted_sum(
        {"a": {"unit": "count", "value": 10, "state": "observed"}}, {"a": 1.0}
    )
    partial = evaluate_aggregation(
        [
            evaluate_weighted_sum(
                {"b": {"unit": "count", "value": 5, "state": "observed"}}, {"b": 1.0}
            ),
            evaluate_weighted_sum(
                {"c": {"unit": "count", "value": None, "state": "unknown"}}, {"c": 1.0}
            ),
        ],
        operation="weighted_sum",
        weights=[0.6, 0.4],
    )
    result = evaluate_formula(observed, partial, operation="sum")
    assert result.value == 13.0
    assert result.state == "partial"
    assert result.coverage == 0.6
    assert result.lineage == ("a", "b", "c")


def test_formula_unknown_input_remains_unknown() -> None:
    observed = evaluate_weighted_sum(
        {"a": {"unit": "count", "value": 10, "state": "observed"}}, {"a": 1.0}
    )
    unknown = evaluate_weighted_sum(
        {"b": {"unit": "count", "value": None, "state": "unknown"}}, {"b": 1.0}
    )
    result = evaluate_formula(observed, unknown, operation="sum")
    assert result.value is None
    assert result.state == "unknown"
    assert result.coverage == 0.0


def test_normalization_preserves_partial_state_and_coverage() -> None:
    partial = evaluate_aggregation(
        [
            evaluate_weighted_sum(
                {"score": {"unit": "points", "value": 60, "state": "observed"}},
                {"score": 1.0},
            ),
            evaluate_weighted_sum(
                {"missing": {"unit": "points", "value": None, "state": "unknown"}},
                {"missing": 1.0},
            ),
        ],
        operation="weighted_sum",
        weights=[0.6, 0.4],
    )
    normalized = evaluate_normalization(partial, source_min=0, source_max=100)
    assert normalized.value == 0.36
    assert normalized.state == "partial"
    assert normalized.coverage == 0.6


def test_dependency_propagates_partial_state_and_coverage() -> None:
    observed = evaluate_weighted_sum(
        {"a": {"unit": "count", "value": 10, "state": "observed"}}, {"a": 1.0}
    )
    partial = evaluate_aggregation(
        [
            evaluate_weighted_sum(
                {"b": {"unit": "count", "value": 5, "state": "observed"}}, {"b": 1.0}
            ),
            evaluate_weighted_sum(
                {"c": {"unit": "count", "value": None, "state": "unknown"}}, {"c": 1.0}
            ),
        ],
        operation="weighted_sum",
        weights=[0.6, 0.4],
    )
    result = evaluate_dependency(observed, partial, relation="sum")
    assert result.value == 13.0
    assert result.state == "partial"
    assert result.coverage == 0.6


def test_non_weighted_aggregation_propagates_partial_state_and_coverage() -> None:
    observed = evaluate_weighted_sum(
        {"a": {"unit": "count", "value": 10, "state": "observed"}}, {"a": 1.0}
    )
    partial = evaluate_aggregation(
        [
            evaluate_weighted_sum(
                {"b": {"unit": "count", "value": 5, "state": "observed"}}, {"b": 1.0}
            ),
            evaluate_weighted_sum(
                {"c": {"unit": "count", "value": None, "state": "unknown"}}, {"c": 1.0}
            ),
        ],
        operation="weighted_sum",
        weights=[0.6, 0.4],
    )
    result = evaluate_aggregation([observed, partial], operation="sum")
    assert result.value == 13.0
    assert result.state == "partial"
    assert result.coverage == 0.6


def test_ratio_by_zero_is_unknown_with_zero_coverage() -> None:
    left = evaluate_weighted_sum(
        {"a": {"unit": "count", "value": 10, "state": "observed"}}, {"a": 1.0}
    )
    zero = evaluate_weighted_sum(
        {"b": {"unit": "count", "value": 0, "state": "observed"}}, {"b": 1.0}
    )
    result = evaluate_formula(left, zero, operation="ratio")
    assert result.value is None
    assert result.state == "unknown"
    assert result.coverage == 0.0


def test_nested_weighted_aggregation_scales_effective_contribution_details() -> None:
    inner = evaluate_weighted_sum(
        {"a": {"unit": "count", "value": 10, "state": "observed"}}, {"a": 0.6}
    )
    observed = evaluate_weighted_sum(
        {"c": {"unit": "count", "value": 5, "state": "observed"}}, {"c": 1.0}
    )
    result = evaluate_aggregation(
        [inner, observed], operation="weighted_sum", weights=[0.5, 0.5]
    )
    assert result.value == 5.0
    assert result.contribution_details == (
        ContributionDetail("a", 10.0, 0.3, 3.0),
        ContributionDetail("c", 5.0, 0.5, 2.5),
    )
    assert sum(detail.contribution for detail in result.contribution_details) == result.value


def test_difference_flips_right_hand_contribution_sign() -> None:
    left = evaluate_weighted_sum(
        {"a": {"unit": "count", "value": 10, "state": "observed"}}, {"a": 0.6}
    )
    right = evaluate_weighted_sum(
        {"b": {"unit": "count", "value": 4, "state": "observed"}}, {"b": 0.4}
    )
    result = evaluate_formula(left, right, operation="difference")
    assert result.value == 4.4
    assert result.contribution_details == (
        ContributionDetail("a", 10.0, 0.6, 6.0),
        ContributionDetail("b", 4.0, -0.4, -1.6),
    )
    assert sum(detail.contribution for detail in result.contribution_details) == result.value


def test_non_additive_operations_do_not_invent_contribution_details() -> None:
    a = evaluate_weighted_sum(
        {"a": {"unit": "count", "value": 10, "state": "observed"}}, {"a": 1.0}
    )
    b = evaluate_weighted_sum(
        {"b": {"unit": "count", "value": 4, "state": "observed"}}, {"b": 1.0}
    )
    ratio = evaluate_formula(a, b, operation="ratio")
    maximum = evaluate_aggregation([a, b], operation="max")
    dependency_max = evaluate_dependency(a, b, relation="max")
    assert ratio.contribution_details == ()
    assert maximum.contribution_details == ()
    assert dependency_max.contribution_details == ()


def test_normalization_clears_additive_contributions_but_preserves_lineage() -> None:
    result = evaluate_weighted_sum(
        {"score": {"unit": "points", "value": 75, "state": "observed"}},
        {"score": 1.0},
    )
    normalized = evaluate_normalization(result, source_min=0, source_max=100)
    assert normalized.value == 0.75
    assert normalized.contribution_details == ()
    assert normalized.contributions == ()
    assert normalized.lineage == ("score",)
