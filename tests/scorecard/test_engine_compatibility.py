from __future__ import annotations

from tests.scorecard.engines.native import NativeReferenceAdapter


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
        {
            "a": {"unit": "count", "value": 10, "state": "observed"},
            "b": {"unit": "count", "value": 4, "state": "observed"},
        },
        {"a": 0.6, "b": 0.4},
    )
    assert result.value == 7.6
    assert result.state == "observed"
    assert result.contributions == (("a", 6.0), ("b", 1.6))
