"""Scorecard add-on package.

All calculation, policy, measurement-adapter, result, replay, and persistence
semantics required to produce a ScorecardResult live inside this add-on.
"""
from .calculation import CalculationResult, ContributionDetail, ScorecardCalculationEngine
from .engine import ScorecardEngine
from .integration import (
    PipelineAssessmentAdapter,
    ScorecardInput,
    evaluate_pipeline_scorecard,
    threshold_condition_evaluator,
)
from .models import (
    AssessmentRecord,
    RiskPolicyRecord,
    ScorecardDefinitionRecord,
    ScorecardResultRecord,
)
from .policy import (
    CONDITION_MATCH,
    CONDITION_NO_MATCH,
    CONDITION_UNKNOWN,
    PolicyDecision,
    RiskPolicyEngine,
)
from .result import ScorecardResult, build_scorecard_result
from .sqlite_store import SQLiteScorecardStore
from .storage import (
    AssessmentStore,
    RiskPolicyStore,
    ScorecardDefinitionStore,
    ScorecardResultStore,
)

__all__ = [
    "AssessmentStore", "RiskPolicyStore", "ScorecardDefinitionStore",
    "ScorecardResultStore", "SQLiteScorecardStore", "AssessmentRecord",
    "RiskPolicyRecord", "ScorecardDefinitionRecord", "ScorecardResultRecord",
    "CalculationResult", "ContributionDetail", "ScorecardCalculationEngine",
    "CONDITION_MATCH", "CONDITION_NO_MATCH", "CONDITION_UNKNOWN",
    "PolicyDecision", "RiskPolicyEngine", "ScorecardResult", "ScorecardEngine",
    "build_scorecard_result", "ScorecardInput", "PipelineAssessmentAdapter",
    "evaluate_pipeline_scorecard", "threshold_condition_evaluator",
]
