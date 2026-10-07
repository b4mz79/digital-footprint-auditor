from __future__ import annotations

from typing import Protocol

from .models import (
    AssessmentRecord,
    RiskPolicyRecord,
    ScorecardDefinitionRecord,
    ScorecardResultRecord,
)


class ScorecardDefinitionStore(Protocol):
    def save_definition(self, record: ScorecardDefinitionRecord) -> None: ...

    def get_definition(
        self, scorecard_id: str, version: str
    ) -> ScorecardDefinitionRecord | None: ...


class RiskPolicyStore(Protocol):
    def save_policy(self, record: RiskPolicyRecord) -> None: ...

    def get_policy(self, policy_id: str, version: str) -> RiskPolicyRecord | None: ...


class AssessmentStore(Protocol):
    def save_assessment(self, record: AssessmentRecord) -> None: ...

    def get_assessment(self, assessment_id: str) -> AssessmentRecord | None: ...


class ScorecardResultStore(Protocol):
    def save_result(self, record: ScorecardResultRecord) -> None: ...

    def get_result(self, result_id: str) -> ScorecardResultRecord | None: ...

    def list_results_for_assessment(
        self, assessment_id: str
    ) -> tuple[ScorecardResultRecord, ...]: ...
