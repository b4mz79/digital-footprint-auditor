from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Protocol


CONDITION_MATCH = "match"
CONDITION_NO_MATCH = "no_match"
CONDITION_UNKNOWN = "unknown"
CONDITION_OUTCOMES = {
    CONDITION_MATCH,
    CONDITION_NO_MATCH,
    CONDITION_UNKNOWN,
}

DECISION_MATCHED = "matched"
DECISION_NO_MATCH = "no_match"
DECISION_CONDITION_UNKNOWN = "condition_unknown"
DECISION_STATUSES = {
    DECISION_MATCHED,
    DECISION_NO_MATCH,
    DECISION_CONDITION_UNKNOWN,
}


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """Engine-neutral policy execution result.

    This contract deliberately separates condition evaluation from risk-band
    output. It gives OSS candidates a stable semantic target without forcing
    our domain model to adopt an engine-specific predicate language.
    """

    status: str
    risk_band: str | None
    applied_rule_id: str | None
    evaluated_rule_ids: tuple[str, ...]
    condition_outcomes: tuple[tuple[str, str], ...]


ConditionEvaluator = Callable[
    [dict[str, Any], dict[str, Any]],
    str,
]


def assert_policy_decision_semantics(
    result: PolicyDecision,
    *,
    risk_bands: set[str],
) -> None:
    assert result.status in DECISION_STATUSES

    assert isinstance(result.evaluated_rule_ids, tuple)
    assert all(
        isinstance(item, str) and item for item in result.evaluated_rule_ids
    )
    assert len(result.evaluated_rule_ids) == len(
        set(result.evaluated_rule_ids)
    )

    assert isinstance(result.condition_outcomes, tuple)
    seen = set()
    for rule_id, outcome in result.condition_outcomes:
        assert isinstance(rule_id, str) and rule_id
        assert rule_id not in seen
        seen.add(rule_id)
        assert outcome in CONDITION_OUTCOMES

    if result.status == DECISION_MATCHED:
        assert isinstance(result.applied_rule_id, str)
        assert result.applied_rule_id
        assert result.applied_rule_id in result.evaluated_rule_ids
        assert result.risk_band in risk_bands
    elif result.status == DECISION_NO_MATCH:
        assert result.applied_rule_id is None
        assert result.risk_band is None
    else:
        assert result.applied_rule_id is None
        assert result.risk_band is None


class RiskPolicyEngineAdapter(Protocol):
    """Engine-neutral compatibility surface for executable risk policies."""

    name: str

    def evaluate(
        self,
        policy: dict[str, Any],
        context: dict[str, Any],
        *,
        condition_evaluator: ConditionEvaluator,
    ) -> PolicyDecision: ...
