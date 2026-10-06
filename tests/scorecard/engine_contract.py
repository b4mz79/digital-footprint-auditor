from __future__ import annotations

from typing import Any, Protocol

from tests.scorecard.reference_engine import EvalResult


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
