from __future__ import annotations

from tests.scorecard.compatibility import compare_eval_results
from tests.scorecard.reference_engine import evaluate_weighted_sum
from tests.scorecard.engines.simpleeval import SimpleEvalReferenceAdapter


MEASUREMENTS = {
    "a": {"state": "observed", "value": 10},
    "b": {"state": "observed", "value": 4},
}


def _adapter() -> SimpleEvalReferenceAdapter:
    return SimpleEvalReferenceAdapter()


def test_simpleeval_weighted_sum_matches_native_reference() -> None:
    weights = {"a": 0.6, "b": 0.4}
    expected = evaluate_weighted_sum(MEASUREMENTS, weights)
    actual = _adapter().weighted_sum(MEASUREMENTS, weights)
    compare_eval_results(expected, actual).assert_compatible()


def test_simpleeval_preserves_domain_unknown_semantics() -> None:
    measurements = {
        "a": {"state": "observed", "value": 10},
        "b": {"state": "unknown", "value": None},
    }
    weights = {"a": 0.6, "b": 0.4}
    expected = evaluate_weighted_sum(measurements, weights)
    actual = _adapter().weighted_sum(measurements, weights)
    compare_eval_results(expected, actual).assert_compatible()
    assert actual.value is None
    assert actual.state == "unknown"


def test_simpleeval_weighted_sum_is_deterministic_for_repeated_evaluation() -> None:
    weights = {"a": 0.6, "b": 0.4}
    adapter = _adapter()
    first = adapter.weighted_sum(MEASUREMENTS, weights)
    second = adapter.weighted_sum(MEASUREMENTS, weights)
    compare_eval_results(first, second).assert_compatible()


def test_simpleeval_keeps_definition_inputs_isolated_between_evaluations() -> None:
    adapter = _adapter()
    first = adapter.weighted_sum(MEASUREMENTS, {"a": 0.6, "b": 0.4})
    second = adapter.weighted_sum(MEASUREMENTS, {"a": 0.2, "b": 0.8})
    assert first.value == 7.6
    assert second.value == 5.2


def test_simpleeval_reconstructs_domain_contribution_semantics() -> None:
    actual = _adapter().weighted_sum(MEASUREMENTS, {"a": 0.6, "b": 0.4})
    assert actual.contributions == (("a", 6.0), ("b", 1.6))
    assert [
        (item.kpi_id, item.value, item.weight, item.contribution)
        for item in actual.contribution_details
    ] == [
        ("a", 10.0, 0.6, 6.0),
        ("b", 4.0, 0.4, 1.6),
    ]
