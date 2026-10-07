from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping


CONDITION_MATCH = "match"
CONDITION_NO_MATCH = "no_match"
CONDITION_UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    status: str
    risk_band: str | None
    applied_rule_id: str | None
    evaluated_rule_ids: tuple[str, ...]
    condition_outcomes: tuple[tuple[str, str], ...]


ConditionEvaluator = Callable[[Mapping[str, Any], Mapping[str, Any]], str]


class RiskPolicyEngine:
    """Deterministic executable risk-policy layer for the Scorecard add-on."""

    name = "native"

    def evaluate(
        self,
        policy: Mapping[str, Any],
        context: Mapping[str, Any],
        *,
        condition_evaluator: ConditionEvaluator,
    ) -> PolicyDecision:
        mapping = policy.get("mapping")
        if not isinstance(mapping, Mapping):
            raise ValueError("risk policy mapping is required")

        rules = mapping.get("rules")
        if not isinstance(rules, list):
            raise ValueError("risk policy mapping.rules must be a list")

        bands = set(policy.get("output", {}).get("risk_bands", ()))
        ordered = sorted(
            rules,
            key=lambda rule: (
                self._priority(rule),
                self._rule_id(rule),
            ),
        )

        evaluated: list[str] = []
        outcomes: list[tuple[str, str]] = []

        for rule in ordered:
            rule_id = self._rule_id(rule)
            outcome = condition_evaluator(rule["condition"], context)
            if outcome not in {
                CONDITION_MATCH,
                CONDITION_NO_MATCH,
                CONDITION_UNKNOWN,
            }:
                raise ValueError(f"unsupported condition outcome: {outcome!r}")

            evaluated.append(rule_id)
            outcomes.append((rule_id, outcome))

            if outcome == CONDITION_MATCH:
                risk_band = rule.get("then")
                if risk_band not in bands:
                    raise ValueError(
                        f"rule {rule_id!r} produces undeclared risk band {risk_band!r}"
                    )
                return PolicyDecision(
                    "matched",
                    risk_band,
                    rule_id,
                    tuple(evaluated),
                    tuple(outcomes),
                )

            if outcome == CONDITION_UNKNOWN:
                return PolicyDecision(
                    "condition_unknown",
                    None,
                    None,
                    tuple(evaluated),
                    tuple(outcomes),
                )

        return PolicyDecision(
            "no_match",
            None,
            None,
            tuple(evaluated),
            tuple(outcomes),
        )

    @staticmethod
    def _priority(rule: Mapping[str, Any]) -> int:
        value = rule.get("priority")
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError("risk policy rule priority must be an integer")
        return value

    @staticmethod
    def _rule_id(rule: Mapping[str, Any]) -> str:
        value = rule.get("rule_id")
        if not isinstance(value, str) or not value:
            raise ValueError("risk policy rule_id must be a non-empty string")
        return value
