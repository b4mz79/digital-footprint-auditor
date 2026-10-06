from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any

from tests.scorecard.engine_contract import assert_eval_result_semantics
from tests.scorecard.policy_engine_contract import (
    PolicyDecision,
    assert_policy_decision_semantics,
)
from tests.scorecard.reference_engine import EvalResult


@dataclass(frozen=True, slots=True)
class CompatibilityDiff:
    """One semantic difference between reference and candidate outputs."""

    field: str
    reference: Any
    candidate: Any


@dataclass(frozen=True, slots=True)
class CompatibilityReport:
    """Engine-neutral result of one differential comparison."""

    compatible: bool
    diffs: tuple[CompatibilityDiff, ...] = ()

    def assert_compatible(self) -> None:
        if not self.compatible:
            details = "; ".join(
                f"{diff.field}: reference={diff.reference!r}, "
                f"candidate={diff.candidate!r}"
                for diff in self.diffs
            )
            raise AssertionError(f"semantic incompatibility: {details}")


def _numeric_equal(left: Any, right: Any, *, abs_tol: float) -> bool:
    if left is None or right is None:
        return left is right
    if isinstance(left, bool) or isinstance(right, bool):
        return left == right
    if not isinstance(left, (int, float)) or not isinstance(right, (int, float)):
        return left == right
    if not math.isfinite(float(left)) or not math.isfinite(float(right)):
        return False
    return math.isclose(float(left), float(right), rel_tol=0.0, abs_tol=abs_tol)


def _append_diff(
    diffs: list[CompatibilityDiff],
    field: str,
    reference: Any,
    candidate: Any,
) -> None:
    if reference != candidate:
        diffs.append(CompatibilityDiff(field, reference, candidate))


def compare_eval_results(
    reference: EvalResult,
    candidate: EvalResult,
    *,
    abs_tol: float = 1e-12,
) -> CompatibilityReport:
    """Compare only Scorecard-domain semantics shared by engine adapters.

    Engine-specific metadata, object identity and representation are ignored.
    Numeric values use an explicit absolute tolerance so equivalent floating
    point implementations are not rejected for harmless arithmetic noise.
    """

    assert_eval_result_semantics(reference)
    assert_eval_result_semantics(candidate)

    diffs: list[CompatibilityDiff] = []

    if not _numeric_equal(reference.value, candidate.value, abs_tol=abs_tol):
        diffs.append(
            CompatibilityDiff("value", reference.value, candidate.value)
        )

    _append_diff(diffs, "state", reference.state, candidate.state)
    _append_diff(diffs, "lineage", reference.lineage, candidate.lineage)

    if len(reference.contributions) != len(candidate.contributions):
        diffs.append(
            CompatibilityDiff(
                "contributions.length",
                len(reference.contributions),
                len(candidate.contributions),
            )
        )
    else:
        for index, (ref_item, cand_item) in enumerate(
            zip(reference.contributions, candidate.contributions)
        ):
            if ref_item[0] != cand_item[0]:
                diffs.append(
                    CompatibilityDiff(
                        f"contributions[{index}].kpi_id",
                        ref_item[0],
                        cand_item[0],
                    )
                )
            if not _numeric_equal(
                ref_item[1], cand_item[1], abs_tol=abs_tol
            ):
                diffs.append(
                    CompatibilityDiff(
                        f"contributions[{index}].value",
                        ref_item[1],
                        cand_item[1],
                    )
                )

    if len(reference.contribution_details) != len(
        candidate.contribution_details
    ):
        diffs.append(
            CompatibilityDiff(
                "contribution_details.length",
                len(reference.contribution_details),
                len(candidate.contribution_details),
            )
        )
    else:
        for index, (ref_detail, cand_detail) in enumerate(
            zip(reference.contribution_details, candidate.contribution_details)
        ):
            for field in ("kpi_id", "value", "weight", "contribution"):
                ref_value = getattr(ref_detail, field)
                cand_value = getattr(cand_detail, field)
                equal = (
                    ref_value == cand_value
                    if field == "kpi_id"
                    else _numeric_equal(
                        ref_value, cand_value, abs_tol=abs_tol
                    )
                )
                if not equal:
                    diffs.append(
                        CompatibilityDiff(
                            f"contribution_details[{index}].{field}",
                            ref_value,
                            cand_value,
                        )
                    )

    for field in ("coverage", "known_weight", "unknown_weight"):
        reference_value = getattr(reference, field)
        candidate_value = getattr(candidate, field)
        if not _numeric_equal(
            reference_value, candidate_value, abs_tol=abs_tol
        ):
            diffs.append(
                CompatibilityDiff(
                    field, reference_value, candidate_value
                )
            )

    return CompatibilityReport(not diffs, tuple(diffs))


def compare_policy_decisions(
    reference: PolicyDecision,
    candidate: PolicyDecision,
) -> CompatibilityReport:
    """Compare the semantic policy-resolution result of two engines."""

    diffs: list[CompatibilityDiff] = []
    _append_diff(diffs, "status", reference.status, candidate.status)
    _append_diff(
        diffs, "risk_band", reference.risk_band, candidate.risk_band
    )
    _append_diff(
        diffs,
        "applied_rule_id",
        reference.applied_rule_id,
        candidate.applied_rule_id,
    )
    _append_diff(
        diffs,
        "evaluated_rule_ids",
        reference.evaluated_rule_ids,
        candidate.evaluated_rule_ids,
    )
    _append_diff(
        diffs,
        "condition_outcomes",
        reference.condition_outcomes,
        candidate.condition_outcomes,
    )
    return CompatibilityReport(not diffs, tuple(diffs))


def validate_policy_decision(
    result: PolicyDecision,
    *,
    risk_bands: set[str],
) -> PolicyDecision:
    """Validate a candidate policy result before differential comparison."""

    assert_policy_decision_semantics(result, risk_bands=risk_bands)
    return result
