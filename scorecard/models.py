from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


JsonObject = dict[str, Any]


def _copy_json_object(value: Mapping[str, Any], *, label: str) -> JsonObject:
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be a mapping")
    return dict(value)


@dataclass(frozen=True, slots=True)
class ScorecardDefinitionRecord:
    """Versioned scorecard definition snapshot owned by the add-on."""

    scorecard_id: str
    version: str
    definition: JsonObject

    def __post_init__(self) -> None:
        if not self.scorecard_id:
            raise ValueError("scorecard_id must not be empty")
        if not self.version:
            raise ValueError("version must not be empty")
        object.__setattr__(
            self, "definition", _copy_json_object(self.definition, label="definition")
        )


@dataclass(frozen=True, slots=True)
class RiskPolicyRecord:
    """Versioned risk-policy snapshot."""

    policy_id: str
    version: str
    policy: JsonObject

    def __post_init__(self) -> None:
        if not self.policy_id:
            raise ValueError("policy_id must not be empty")
        if not self.version:
            raise ValueError("version must not be empty")
        object.__setattr__(self, "policy", _copy_json_object(self.policy, label="policy"))


@dataclass(frozen=True, slots=True)
class AssessmentRecord:
    """Immutable assessment/measurement snapshot used for calculation replay."""

    assessment_id: str
    created_at: str
    assessment: JsonObject

    def __post_init__(self) -> None:
        if not self.assessment_id:
            raise ValueError("assessment_id must not be empty")
        if not self.created_at:
            raise ValueError("created_at must not be empty")
        object.__setattr__(
            self,
            "assessment",
            _copy_json_object(self.assessment, label="assessment"),
        )


@dataclass(frozen=True, slots=True)
class ScorecardResultRecord:
    """Immutable final scorecard result snapshot.

    The result JSON is persisted as a complete snapshot so consumers can read
    historical results without recalculating them from mutable current state.
    """

    result_id: str
    assessment_id: str
    calculated_at: str
    result: JsonObject

    def __post_init__(self) -> None:
        if not self.result_id:
            raise ValueError("result_id must not be empty")
        if not self.assessment_id:
            raise ValueError("assessment_id must not be empty")
        if not self.calculated_at:
            raise ValueError("calculated_at must not be empty")
        object.__setattr__(
            self, "result", _copy_json_object(self.result, label="result")
        )
