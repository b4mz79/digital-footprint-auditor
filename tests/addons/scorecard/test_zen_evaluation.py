from __future__ import annotations

import pytest

from tests.scorecard.compatibility import compare_eval_results
from tests.scorecard.engines.native import NativeReferenceAdapter
from tests.scorecard.engines.zen import ZenReferenceAdapter


pytest.importorskip("zen")


def _observed(value: float) -> dict:
    return {"unit": "count", "value": value, "state": "observed"}


def test_zen_weighted_sum_matches_native_reference() -> None:
    reference = NativeReferenceAdapter()
    candidate = ZenReferenceAdapter()

    measurements = {
        "a": _observed(10),
        "b": _observed(4),
    }
    weights = {"a": 0.6, "b": 0.4}

    report = compare_eval_results(
        reference.weighted_sum(measurements, weights),
        candidate.weighted_sum(measurements, weights),
    )

    report.assert_compatible()


def test_zen_weighted_sum_preserves_domain_unknown_semantics() -> None:
    reference = NativeReferenceAdapter()
    candidate = ZenReferenceAdapter()

    measurements = {
        "a": _observed(10),
        "b": {"unit": "count", "value": None, "state": "unknown"},
    }
    weights = {"a": 0.6, "b": 0.4}

    report = compare_eval_results(
        reference.weighted_sum(measurements, weights),
        candidate.weighted_sum(measurements, weights),
    )

    report.assert_compatible()


def test_zen_weighted_sum_is_deterministic_for_repeated_evaluation() -> None:
    candidate = ZenReferenceAdapter()
    measurements = {"a": _observed(10), "b": _observed(4)}
    weights = {"a": 0.6, "b": 0.4}

    first = candidate.weighted_sum(measurements, weights)
    second = candidate.weighted_sum(measurements, weights)

    assert first == second


def test_zen_adapter_keeps_definition_inputs_isolated_between_evaluations() -> None:
    candidate = ZenReferenceAdapter()
    measurements = {"a": _observed(10), "b": _observed(4)}

    first = candidate.weighted_sum(measurements, {"a": 0.6, "b": 0.4})
    second = candidate.weighted_sum(measurements, {"a": 0.2, "b": 0.8})

    assert first.value == 7.6
    assert second.value == 5.2
    assert first.value != second.value
    assert first.lineage == ("a", "b")
    assert second.lineage == ("a", "b")


def test_zen_adapter_reconstructs_contribution_semantics_from_domain_inputs() -> None:
    candidate = ZenReferenceAdapter()
    result = candidate.weighted_sum(
        {"a": _observed(10), "b": _observed(4)},
        {"a": 0.6, "b": 0.4},
    )

    assert result.contributions == (("a", 6.0), ("b", 1.6))
    assert tuple(
        (item.kpi_id, item.value, item.weight, item.contribution)
        for item in result.contribution_details
    ) == (
        ("a", 10.0, 0.6, 6.0),
        ("b", 4.0, 0.4, 1.6),
    )
