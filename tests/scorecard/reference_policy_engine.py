from __future__ import annotations

from typing import Any

from tests.scorecard.policy_engine_contract import (
    CONDITION_MATCH,
    CONDITION_NO_MATCH,
    CONDITION_UNKNOWN,
    DECISION_CONDITION_UNKNOWN,
    DECISION_MATCHED,
    DECISION_NO_MATCH,
    ConditionEvaluator,
    PolicyDecision,
)


def evaluate_policy(
    policy: dict[str, Any],
    context: dict[str, Any],
    *,
    condition_evaluator: ConditionEvaluator,
) -> PolicyDecision:
    """Reference policy-resolution semantics for compatibility tests only.

    The evaluator deliberately does not interpret condition.parameters. The
    injected evaluator owns predicate semantics; this function owns rule
    ordering, outcome preservation, and applied-rule identity.
    """
    mapping = policy["mapping"]
    rules = sorted(mapping["rules"], key=lambda rule: rule["priority"])

    evaluated_rule_ids: list[str] = []
    condition_outcomes: list[tuple[str, str]] = []

    for rule in rules:
        rule_id = rule["rule_id"]
        outcome = condition_evaluator(rule["condition"], context)
        if outcome not in {
            CONDITION_MATCH,
            CONDITION_NO_MATCH,
            CONDITION_UNKNOWN,
        }:
            raise ValueError(f"unsupported condition outcome: {outcome!r}")

        evaluated_rule_ids.append(rule_id)
        condition_outcomes.append((rule_id, outcome))

        if outcome == CONDITION_MATCH:
            return PolicyDecision(
                status=DECISION_MATCHED,
                risk_band=rule["then"],
                applied_rule_id=rule_id,
                evaluated_rule_ids=tuple(evaluated_rule_ids),
                condition_outcomes=tuple(condition_outcomes),
            )

        if outcome == CONDITION_UNKNOWN:
            return PolicyDecision(
                status=DECISION_CONDITION_UNKNOWN,
                risk_band=None,
                applied_rule_id=None,
                evaluated_rule_ids=tuple(evaluated_rule_ids),
                condition_outcomes=tuple(condition_outcomes),
            )

    return PolicyDecision(
        status=DECISION_NO_MATCH,
        risk_band=None,
        applied_rule_id=None,
        evaluated_rule_ids=tuple(evaluated_rule_ids),
        condition_outcomes=tuple(condition_outcomes),
    )
