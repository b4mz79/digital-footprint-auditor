from __future__ import annotations

import math
from typing import Any, Protocol

from tests.scorecard.reference_engine import EvalResult


VALID_STATES = {"observed", "partial", "unknown"}


def assert_eval_result_semantics(result: EvalResult) -> None:
    """Validate the semantic output contract shared by engine adapters.

    This is intentionally independent of any implementation or OSS engine.
    It checks only invariants owned by the Scorecard domain.
    """
    assert result.state in VALID_STATES

    if result.state == "unknown":
        assert result.value is None
    else:
        assert result.value is not None
        assert isinstance(result.value, (int, float))
        assert not isinstance(result.value, bool)
        assert math.isfinite(float(result.value))

    assert isinstance(result.lineage, tuple)
    assert all(isinstance(item, str) and item for item in result.lineage)
    assert len(result.lineage) == len(set(result.lineage))

    for contribution in result.contributions:
        assert isinstance(contribution, tuple) and len(contribution) == 2
        kpi_id, value = contribution
        assert isinstance(kpi_id, str) and kpi_id
        assert isinstance(value, (int, float))
        assert not isinstance(value, bool)
        assert math.isfinite(float(value))

    for detail in result.contribution_details:
        assert isinstance(detail.kpi_id, str) and detail.kpi_id
        assert math.isfinite(float(detail.value))
        assert math.isfinite(float(detail.weight))
        assert math.isfinite(float(detail.contribution))

    if result.coverage is not None:
        assert 0.0 <= float(result.coverage) <= 1.0
        if result.state == "observed":
            assert float(result.coverage) == 1.0

    if result.state == "partial":
        assert result.coverage is not None
        assert 0.0 < float(result.coverage) < 1.0

    if result.known_weight is not None:
        assert float(result.known_weight) >= 0.0
    if result.unknown_weight is not None:
        assert float(result.unknown_weight) >= 0.0


def assert_weighted_sum_semantics(
    result: EvalResult,
    measurements: dict[str, dict[str, Any]],
    weights: dict[str, float],
) -> None:
    """Validate weighted-sum semantics without prescribing implementation."""
    assert_eval_result_semantics(result)
    declared = tuple(weights)
    assert result.lineage == declared

    for kpi_id, weight in weights.items():
        assert isinstance(weight, (int, float))
        assert not isinstance(weight, bool)
        assert math.isfinite(float(weight))

        item = measurements.get(kpi_id)
        available = (
            isinstance(item, dict)
            and item.get("state") != "unknown"
            and item.get("value") is not None
        )
        if not available:
            assert kpi_id not in {item_id for item_id, _ in result.contributions}


class ScorecardEngineAdapter(Protocol):
    """Compatibility surface for reference and candidate calculation engines.

    The adapter deliberately exposes our semantic operations rather than the
    API of any particular OSS engine. Candidate engines must map into this
    contract; our domain semantics remain authoritative.
    """

    name: str

    def weighted_sum(
        self,
        measurements: dict[str, dict[str, Any]],
        weights: dict[str, float],
    ) -> EvalResult: ...

    def formula(
        self,
        left: EvalResult,
        right: EvalResult,
        *,
        operation: str,
    ) -> EvalResult: ...

    def aggregation(
        self,
        results: list[EvalResult],
        *,
        operation: str,
        weights: list[float] | None = None,
    ) -> EvalResult: ...

    def normalization(
        self,
        result: EvalResult,
        *,
        source_min: float,
        source_max: float,
        clamp: bool = False,
    ) -> EvalResult: ...

    def dependency(
        self,
        left: EvalResult,
        right: EvalResult,
        *,
        relation: str,
    ) -> EvalResult: ...
