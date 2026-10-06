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
