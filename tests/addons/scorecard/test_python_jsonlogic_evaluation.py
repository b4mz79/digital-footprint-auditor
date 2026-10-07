from __future__ import annotations

import pytest

from tests.addons.scorecard.compatibility import compare_eval_results
from tests.addons.scorecard.engines.native import NativeReferenceAdapter
from tests.addons.scorecard.engines.python_jsonlogic import PythonJsonLogicReferenceAdapter


pytest.importorskip("jsonlogic")


def _observed(value: float, unit: str = "count") -> dict:
    return {"unit": unit, "value": value, "state": "observed"}


def _unknown(unit: str = "count") -> dict:
    return {"unit": unit, "value": None, "state": "unknown"}


def _engines() -> tuple[NativeReferenceAdapter, PythonJsonLogicReferenceAdapter]:
    return NativeReferenceAdapter(), PythonJsonLogicReferenceAdapter()


def test_python_jsonlogic_full_calculation_vocabulary_matches_reference() -> None:
    reference, candidate = _engines()
    measurements = {"a": _observed(10), "b": _observed(4), "c": _observed(2)}
    weights = {"a": 0.6, "b": 0.4}

    ref_a = reference.weighted_sum(measurements, weights)
    cand_a = candidate.weighted_sum(measurements, weights)
    compare_eval_results(ref_a, cand_a).assert_compatible()

    ref_c = reference.weighted_sum({"c": measurements["c"]}, {"c": 1.0})
    cand_c = candidate.weighted_sum({"c": measurements["c"]}, {"c": 1.0})

    ref_b = reference.formula(ref_a, ref_c, operation="sum")
    cand_b = candidate.formula(cand_a, cand_c, operation="sum")
    compare_eval_results(ref_b, cand_b).assert_compatible()

    ref_d = reference.aggregation([ref_a, ref_b], operation="mean")
    cand_d = candidate.aggregation([cand_a, cand_b], operation="mean")
    compare_eval_results(ref_d, cand_d).assert_compatible()

    ref_e = reference.conditional(True, ref_d, ref_a)
    cand_e = candidate.conditional(True, cand_d, cand_a)
    compare_eval_results(ref_e, cand_e).assert_compatible()

    ref_f = reference.normalization(ref_e, source_min=0.0, source_max=20.0)
    cand_f = candidate.normalization(cand_e, source_min=0.0, source_max=20.0)
    compare_eval_results(ref_f, cand_f).assert_compatible()

    ref_g = reference.dependency(ref_f, ref_a, relation="sum")
    cand_g = candidate.dependency(cand_f, cand_a, relation="sum")
    compare_eval_results(ref_g, cand_g).assert_compatible()


@pytest.mark.parametrize(
    ("operation", "expected"),
    [("sum", 14.0), ("difference", 6.0), ("ratio", 2.5)],
)
def test_python_jsonlogic_formula_operations_match_reference(operation: str, expected: float) -> None:
    reference, candidate = _engines()
    left = reference.weighted_sum({"a": _observed(10)}, {"a": 1.0})
    right = reference.weighted_sum({"b": _observed(4)}, {"b": 1.0})
    candidate_left = candidate.weighted_sum({"a": _observed(10)}, {"a": 1.0})
    candidate_right = candidate.weighted_sum({"b": _observed(4)}, {"b": 1.0})

    ref_result = reference.formula(left, right, operation=operation)
    cand_result = candidate.formula(candidate_left, candidate_right, operation=operation)
    compare_eval_results(ref_result, cand_result).assert_compatible()
    assert ref_result.value == expected


@pytest.mark.parametrize("operation", ["sum", "mean", "min", "max"])
def test_python_jsonlogic_aggregation_operations_match_reference(operation: str) -> None:
    reference, candidate = _engines()
    ref_results = [
        reference.weighted_sum({"a": _observed(10)}, {"a": 1.0}),
        reference.weighted_sum({"b": _observed(4)}, {"b": 1.0}),
        reference.weighted_sum({"c": _observed(2)}, {"c": 1.0}),
    ]
    cand_results = [
        candidate.weighted_sum({"a": _observed(10)}, {"a": 1.0}),
        candidate.weighted_sum({"b": _observed(4)}, {"b": 1.0}),
        candidate.weighted_sum({"c": _observed(2)}, {"c": 1.0}),
    ]
    compare_eval_results(
        reference.aggregation(ref_results, operation=operation),
        candidate.aggregation(cand_results, operation=operation),
    ).assert_compatible()


def test_python_jsonlogic_weighted_aggregation_preserves_partial_semantics() -> None:
    reference, candidate = _engines()
    ref_observed = reference.weighted_sum({"a": _observed(10)}, {"a": 1.0})
    ref_unknown = reference.weighted_sum({"b": _unknown()}, {"b": 1.0})
    cand_observed = candidate.weighted_sum({"a": _observed(10)}, {"a": 1.0})
    cand_unknown = candidate.weighted_sum({"b": _unknown()}, {"b": 1.0})

    ref_result = reference.aggregation(
        [ref_observed, ref_unknown], operation="weighted_sum", weights=[0.6, 0.4]
    )
    cand_result = candidate.aggregation(
        [cand_observed, cand_unknown], operation="weighted_sum", weights=[0.6, 0.4]
    )
    compare_eval_results(ref_result, cand_result).assert_compatible()
    assert cand_result.state == "partial"
    assert cand_result.coverage == 0.6


def test_python_jsonlogic_conditional_matches_reference_and_preserves_unknown() -> None:
    reference, candidate = _engines()
    true_ref = reference.weighted_sum({"a": _observed(10)}, {"a": 1.0})
    false_ref = reference.weighted_sum({"b": _observed(4)}, {"b": 1.0})
    true_cand = candidate.weighted_sum({"a": _observed(10)}, {"a": 1.0})
    false_cand = candidate.weighted_sum({"b": _observed(4)}, {"b": 1.0})

    compare_eval_results(
        reference.conditional(True, true_ref, false_ref),
        candidate.conditional(True, true_cand, false_cand),
    ).assert_compatible()

    unknown = candidate.conditional(None, true_cand, false_cand)
    assert unknown.value is None
    assert unknown.state == "unknown"


def test_python_jsonlogic_normalization_matches_reference() -> None:
    reference, candidate = _engines()
    ref = reference.weighted_sum({"score": _observed(60, "points")}, {"score": 1.0})
    cand = candidate.weighted_sum({"score": _observed(60, "points")}, {"score": 1.0})

    compare_eval_results(
        reference.normalization(ref, source_min=0, source_max=100),
        candidate.normalization(cand, source_min=0, source_max=100),
    ).assert_compatible()


def test_python_jsonlogic_dependency_matches_reference() -> None:
    reference, candidate = _engines()
    ref_left = reference.weighted_sum({"a": _observed(10)}, {"a": 1.0})
    ref_right = reference.weighted_sum({"b": _observed(5)}, {"b": 1.0})
    cand_left = candidate.weighted_sum({"a": _observed(10)}, {"a": 1.0})
    cand_right = candidate.weighted_sum({"b": _observed(5)}, {"b": 1.0})

    compare_eval_results(
        reference.dependency(ref_left, ref_right, relation="sum"),
        candidate.dependency(cand_left, cand_right, relation="sum"),
    ).assert_compatible()


def test_python_jsonlogic_definition_inputs_are_isolated_between_replays() -> None:
    _, candidate = _engines()
    measurements = {"a": _observed(10), "b": _observed(4)}
    first = candidate.weighted_sum(measurements, {"a": 0.6, "b": 0.4})
    second = candidate.weighted_sum(measurements, {"a": 0.2, "b": 0.8})
    assert first.value == 7.6
    assert second.value == 5.2
    assert first.lineage == ("a", "b")
    assert second.lineage == ("a", "b")


def test_python_jsonlogic_full_replay_is_deterministic() -> None:
    _, candidate = _engines()

    def replay() -> tuple[float | None, str, tuple[str, ...]]:
        base = candidate.weighted_sum(
            {"a": _observed(10), "b": _observed(4)}, {"a": 0.6, "b": 0.4}
        )
        adjustment = candidate.weighted_sum({"c": _observed(2)}, {"c": 1.0})
        formula = candidate.formula(base, adjustment, operation="sum")
        aggregate = candidate.aggregation([base, formula], operation="mean")
        conditional = candidate.conditional(True, aggregate, base)
        normalized = candidate.normalization(conditional, source_min=0.0, source_max=20.0)
        final = candidate.dependency(normalized, base, relation="sum")
        return final.value, final.state, final.lineage

    assert replay() == replay()
