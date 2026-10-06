from __future__ import annotations

import pytest

from tests.scorecard.engines.native import NativeReferenceAdapter


def _observed(value: float, unit: str = "count") -> dict:
    return {"unit": unit, "value": value, "state": "observed"}


def _unknown(unit: str = "count") -> dict:
    return {"unit": unit, "value": None, "state": "unknown"}


def test_native_adapter_exposes_stable_candidate_engine_surface() -> None:
    engine = NativeReferenceAdapter()
    assert engine.name == "native-reference"

    for method in (
        "weighted_sum",
        "formula",
        "aggregation",
        "normalization",
        "dependency",
    ):
        assert callable(getattr(engine, method))


def test_native_adapter_is_reference_engine_baseline() -> None:
    engine = NativeReferenceAdapter()
    result = engine.weighted_sum(
        {"a": _observed(10), "b": _observed(4)},
        {"a": 0.6, "b": 0.4},
    )
    assert result.value == 7.6
    assert result.state == "observed"
    assert result.contributions == (("a", 6.0), ("b", 1.6))


def test_candidate_surface_preserves_unknown_weighted_sum_semantics() -> None:
    engine = NativeReferenceAdapter()
    result = engine.weighted_sum(
        {"a": _observed(10), "b": _unknown()},
        {"a": 0.6, "b": 0.4},
    )

    assert result.value is None
    assert result.state == "unknown"
    assert result.lineage == ("a", "b")


def test_candidate_surface_preserves_partial_weighted_aggregation_semantics() -> None:
    engine = NativeReferenceAdapter()
    observed = engine.weighted_sum({"a": _observed(10)}, {"a": 1.0})
    unknown = engine.weighted_sum({"b": _unknown()}, {"b": 1.0})

    result = engine.aggregation(
        [observed, unknown],
        operation="weighted_sum",
        weights=[0.6, 0.4],
    )

    assert result.value == 6.0
    assert result.state == "partial"
    assert result.coverage == 0.6
    assert result.known_weight == 0.6
    assert result.unknown_weight == 0.4


@pytest.mark.parametrize(
    ("operation", "expected"),
    [
        ("sum", 14.0),
        ("difference", 6.0),
        ("ratio", 2.5),
    ],
)
def test_candidate_surface_formula_operations_are_deterministic(
    operation: str, expected: float
) -> None:
    engine = NativeReferenceAdapter()
    left = engine.weighted_sum({"a": _observed(10)}, {"a": 1.0})
    right = engine.weighted_sum({"b": _observed(4)}, {"b": 1.0})

    result = engine.formula(left, right, operation=operation)

    assert result.value == expected
    assert result.state == "observed"
    assert result.lineage == ("a", "b")


def test_candidate_surface_ratio_by_zero_is_unknown() -> None:
    engine = NativeReferenceAdapter()
    left = engine.weighted_sum({"a": _observed(10)}, {"a": 1.0})
    zero = engine.weighted_sum({"b": _observed(0)}, {"b": 1.0})

    result = engine.formula(left, zero, operation="ratio")

    assert result.value is None
    assert result.state == "unknown"
    assert result.coverage == 0.0
    assert result.lineage == ("a", "b")


def test_candidate_surface_normalization_preserves_partial_semantics() -> None:
    engine = NativeReferenceAdapter()
    observed = engine.weighted_sum({"score": _observed(60, "points")}, {"score": 1.0})
    unknown = engine.weighted_sum({"missing": _unknown("points")}, {"missing": 1.0})
    partial = engine.aggregation(
        [observed, unknown],
        operation="weighted_sum",
        weights=[0.6, 0.4],
    )

    result = engine.normalization(partial, source_min=0, source_max=100)

    assert result.value == 0.36
    assert result.state == "partial"
    assert result.coverage == 0.6
    assert result.lineage == ("missing", "score")


def test_candidate_surface_dependency_preserves_partial_state_and_lineage() -> None:
    engine = NativeReferenceAdapter()
    left = engine.weighted_sum({"a": _observed(10)}, {"a": 1.0})
    right_observed = engine.weighted_sum({"b": _observed(5)}, {"b": 1.0})
    right_unknown = engine.weighted_sum({"c": _unknown()}, {"c": 1.0})
    right = engine.aggregation(
        [right_observed, right_unknown],
        operation="weighted_sum",
        weights=[0.6, 0.4],
    )

    result = engine.dependency(left, right, relation="sum")

    assert result.value == 13.0
    assert result.state == "partial"
    assert result.coverage == 0.6
    assert result.lineage == ("a", "b", "c")


def test_candidate_surface_rejects_invalid_normalization_range() -> None:
    engine = NativeReferenceAdapter()
    result = engine.weighted_sum({"score": _observed(50)}, {"score": 1.0})

    with pytest.raises(ValueError):
        engine.normalization(result, source_min=100, source_max=100)


def test_candidate_surface_does_not_implicitly_normalize_weights() -> None:
    engine = NativeReferenceAdapter()
    result = engine.weighted_sum(
        {"a": _observed(10), "b": _observed(4)},
        {"a": 2.0, "b": 3.0},
    )

    assert result.value == 32.0
    assert result.contributions == (("a", 20.0), ("b", 12.0))
