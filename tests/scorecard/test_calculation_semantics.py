from __future__ import annotations

import pytest

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
