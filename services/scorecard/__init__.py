"""Privacy Auditor Scorecard Add-on Core.

The package is storage-backend agnostic. SQLite is the reference persistence
adapter; calculation, policy, and result semantics remain inside the add-on.
"""

from .calculation import CalculationResult, ContributionDetail, ScorecardCalculationEngine
from .engine import ScorecardEngine
from .integration import (
    PipelineAssessmentAdapter,
    ScorecardInput,
    evaluate_pipeline_scorecard,
    threshold_condition_evaluator,
)
from .policy import PolicyDecision, RiskPolicyEngine
from .result import ScorecardResult, build_scorecard_result
from .sqlite_store import SQLiteScorecardStore
from .storage import (
    AssessmentStore,
    RiskPolicyStore,
    ScorecardDefinitionStore,
    ScorecardResultStore,
)

__all__ = [
    "AssessmentStore",
    "RiskPolicyStore",
    "ScorecardDefinitionStore",
    "ScorecardResultStore",
    "SQLiteScorecardStore",
    "CalculationResult",
    "ContributionDetail",
    "ScorecardCalculationEngine",
    "PolicyDecision",
    "RiskPolicyEngine",
    "ScorecardResult",
    "ScorecardEngine",
    "build_scorecard_result",
    "ScorecardInput",
    "PipelineAssessmentAdapter",
    "evaluate_pipeline_scorecard",
    "threshold_condition_evaluator",
]