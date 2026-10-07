from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from operator import eq, ge, gt, le, lt
from typing import Any, Callable, Mapping
from uuid import uuid4

from .engine import ScorecardEngine
from .policy import CONDITION_MATCH, CONDITION_NO_MATCH, CONDITION_UNKNOWN, ConditionEvaluator
from .result import ScorecardResult


@dataclass(frozen=True, slots=True)
class ScorecardInput:
    """Canonical assessment input produced by an external adapter."""

    assessment_id: str
    created_at: str
    source: str
    measurements: Mapping[str, Mapping[str, Any]]
    metadata: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not self.assessment_id:
            raise ValueError("assessment_id must not be empty")
        if not self.created_at:
            raise ValueError("created_at must not be empty")
        parsed = datetime.fromisoformat(self.created_at)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        if not isinstance(self.measurements, Mapping):
            raise TypeError("measurements must be a mapping")
        if not isinstance(self.metadata, Mapping):
            raise TypeError("metadata must be a mapping")
        object.__setattr__(self, "measurements", deepcopy(dict(self.measurements)))
        object.__setattr__(self, "metadata", deepcopy(dict(self.metadata)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "scorecard-input-v1",
            "assessment_id": self.assessment_id,
            "created_at": self.created_at,
            "source": self.source,
            "measurements": deepcopy(dict(self.measurements)),
            "metadata": deepcopy(dict(self.metadata)),
        }


class PipelineAssessmentAdapter:
    """Map existing Privacy Auditor state into the canonical ScorecardInput.

    This adapter is deliberately downstream of the existing evidence chain.
    It does not scan, enrich, verify, calculate risk, or call an AI provider.
    """

    name = "privacy_auditor_pipeline"
    version = "v1"

    @classmethod
    def to_input(
        cls,
        state: Mapping[str, Any],
        *,
        assessment_id: str | None = None,
        created_at: str | None = None,
    ) -> ScorecardInput:
        if not isinstance(state, Mapping):
            raise TypeError("pipeline state must be a mapping")

        services = state.get("services")
        evidence = state.get("evidence")
        breach = state.get("breach")

        services = services if isinstance(services, list) else []
        evidence = evidence if isinstance(evidence, list) else []
        breach = breach if isinstance(breach, Mapping) else {}

        service_keys = {
            cls._service_key(item)
            for item in services
            if cls._service_key(item)
        }
        service_count = len(service_keys)

        service_evidence = [
            item for item in evidence
            if isinstance(item, Mapping)
            and item.get("metadata", {}).get("finding_type") == "service_discovery"
        ]

        evidence_backed_keys = set()
        for item in service_evidence:
            provenance = item.get("provenance")
            provenance = provenance if isinstance(provenance, Mapping) else {}
            service_name = cls._text(provenance.get("service_name"))
            domain = cls._text(item.get("domain"))
            if service_name:
                evidence_backed_keys.add(cls._service_key({"service": service_name}))
            elif domain:
                evidence_backed_keys.add(cls._domain_key(domain))

        evidence_backed_count = 0
        for service in services:
            key = cls._service_key(service)
            domain_key = cls._domain_key(service.get("domain")) if isinstance(service, Mapping) else ""
            if key in evidence_backed_keys or domain_key in evidence_backed_keys:
                evidence_backed_count += 1

        relevant_security = [
            item for item in evidence
            if isinstance(item, Mapping)
            and item.get("relation") == "security_publication"
        ]

        lineage_complete = 0
        for item in service_evidence:
            provenance = item.get("provenance")
            provenance = provenance if isinstance(provenance, Mapping) else {}
            required = (
                item.get("evidence_id"),
                item.get("source"),
                item.get("source_type"),
                item.get("relation"),
                item.get("directness"),
                item.get("observed_at"),
                provenance,
            )
            if all(required):
                lineage_complete += 1

        verification_known = [
            item for item in evidence
            if isinstance(item, Mapping)
            and item.get("verification_state") in {"reachable", "unreachable"}
        ]

        measurements: dict[str, dict[str, Any]] = {
            "service_discovery_count": cls._measurement(
                value=service_count if service_count else None,
                state="observed" if service_count else "unknown",
                unit="count",
                source=cls.name,
            ),
            "evidence_backed_service_count": cls._measurement(
                value=evidence_backed_count if service_count else None,
                state="observed" if service_count else "unknown",
                unit="count",
                source=cls.name,
                evidence_ids=[str(item.get("evidence_id")) for item in service_evidence if item.get("evidence_id")],
            ),
            "relevant_security_evidence": cls._measurement(
                value=len(relevant_security),
                state="observed",
                unit="count",
                source=cls.name,
                evidence_ids=[str(item.get("evidence_id")) for item in relevant_security if item.get("evidence_id")],
            ),
            "evidence_record_coverage": cls._measurement(
                value=(len(service_evidence) / service_count) if service_count else None,
                state="observed" if service_count else "unknown",
                unit="ratio",
                source=cls.name,
                evidence_ids=[str(item.get("evidence_id")) for item in service_evidence if item.get("evidence_id")],
            ),
            "evidence_lineage_coverage": cls._measurement(
                value=(lineage_complete / len(service_evidence)) if service_evidence else None,
                state="observed" if service_evidence else "unknown",
                unit="ratio",
                source=cls.name,
                evidence_ids=[str(item.get("evidence_id")) for item in service_evidence if item.get("evidence_id")],
            ),
            "verification_coverage": cls._measurement(
                value=(len(verification_known) / len(evidence)) if evidence else None,
                state="observed" if evidence else "unknown",
                unit="ratio",
                source=cls.name,
                evidence_ids=[str(item.get("evidence_id")) for item in verification_known if item.get("evidence_id")],
            ),
            "url_accessibility_state": {
                "unit": "distribution",
                "value": cls._verification_distribution(evidence),
                "state": "observed" if evidence else "unknown",
                "source": cls.name,
                "method": "verification_state_distribution",
                "method_version": cls.version,
            },
            "breach_finding_count": cls._measurement(
                value=(
                    len(breach.get("findings", []))
                    if bool(breach.get("complete")) and isinstance(breach.get("findings"), list)
                    else None
                ),
                state=(
                    "observed"
                    if bool(breach.get("complete")) and isinstance(breach.get("findings"), list)
                    else "unknown"
                ),
                unit="count",
                source=cls.name,
            ),
        }

        metadata = {
            "adapter": cls.name,
            "adapter_version": cls.version,
            "pipeline_state_scope": "existing_pipeline_result",
            "service_count": service_count,
            "service_evidence_count": len(service_evidence),
            "evidence_count": len(evidence),
            "breach_scan_complete": bool(breach.get("complete")),
        }

        return ScorecardInput(
            assessment_id=assessment_id or f"assessment-{uuid4()}",
            created_at=created_at or datetime.now(timezone.utc).isoformat(),
            source=cls.name,
            measurements=measurements,
            metadata=metadata,
        )

    @staticmethod
    def _measurement(
        *,
        value: Any,
        state: str,
        unit: str,
        source: str,
        evidence_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        item = {
            "unit": unit,
            "value": value,
            "state": state,
            "source": source,
            "method": "pipeline_state_derivation",
            "method_version": PipelineAssessmentAdapter.version,
        }
        if evidence_ids:
            item["evidence_ids"] = list(dict.fromkeys(evidence_ids))
        return item

    @staticmethod
    def _verification_distribution(evidence: list[Mapping[str, Any]]) -> dict[str, int]:
        result = {"reachable": 0, "unreachable": 0, "unknown": 0}
        for item in evidence:
            state = item.get("verification_state")
            result[state if state in result else "unknown"] += 1
        return result

    @staticmethod
    def _text(value: Any) -> str:
        return str(value or "").strip().casefold()

    @classmethod
    def _domain_key(cls, value: Any) -> str:
        text = cls._text(value)
        return text.removeprefix("www.")

    @classmethod
    def _service_key(cls, item: Any) -> str:
        if not isinstance(item, Mapping):
            return ""
        return cls._text(item.get("service") or item.get("name"))


def threshold_condition_evaluator(
    condition: Mapping[str, Any],
    context: Mapping[str, Any],
) -> str:
    """Reference threshold evaluator for scorecard integration.

    Business thresholds remain in the supplied risk-policy configuration.
    """

    if not isinstance(condition, Mapping):
        raise TypeError("condition must be a mapping")
    if condition.get("type") != "score_threshold":
        raise ValueError("unsupported scorecard integration condition type")

    parameters = condition.get("parameters")
    if not isinstance(parameters, Mapping):
        raise ValueError("score_threshold parameters are required")

    score = context.get("score")
    if score is None:
        return CONDITION_UNKNOWN

    try:
        threshold = float(parameters["value"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("score_threshold value must be numeric") from exc

    operators: dict[str, Callable[[float, float], bool]] = {
        ">": gt,
        ">=": ge,
        "<": lt,
        "<=": le,
        "==": eq,
    }
    operator = str(parameters.get("operator", ">="))
    comparator = operators.get(operator)
    if comparator is None:
        raise ValueError(f"unsupported score_threshold operator: {operator!r}")

    return CONDITION_MATCH if comparator(float(score), threshold) else CONDITION_NO_MATCH


def evaluate_pipeline_scorecard(
    state: Mapping[str, Any],
    *,
    scorecard_definition: Mapping[str, Any],
    risk_policy: Mapping[str, Any],
    assessment_id: str | None = None,
    result_id: str | None = None,
    calculated_at: str | None = None,
    condition_evaluator: ConditionEvaluator = threshold_condition_evaluator,
) -> tuple[ScorecardInput, ScorecardResult]:
    """Evaluate the existing pipeline result through the independent add-on."""

    scorecard_input = PipelineAssessmentAdapter.to_input(
        state,
        assessment_id=assessment_id,
        created_at=calculated_at,
    )
    definition_id = str(scorecard_definition.get("scorecard_id", ""))
    definition_version = str(scorecard_definition.get("version", ""))
    if not definition_id or not definition_version:
        raise ValueError("scorecard definition identity is required")

    result = ScorecardEngine().evaluate(
        assessment_id=scorecard_input.assessment_id,
        scorecard_id=definition_id,
        scorecard_version=definition_version,
        result_id=result_id or f"result-{uuid4()}",
        measurements=scorecard_input.measurements,
        scorecard_definition=scorecard_definition,
        risk_policy=risk_policy,
        condition_evaluator=condition_evaluator,
        measurement_refs=tuple(scorecard_input.measurements.keys()),
        calculated_at=calculated_at or scorecard_input.created_at,
    )
    return scorecard_input, result
