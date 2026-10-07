"""Privacy Auditor Scorecard Add-on Core.

The package is storage-backend agnostic. SQLite is the reference persistence
adapter; calculation and policy semantics remain outside the storage layer.
"""

from scorecard.storage import (
    AssessmentStore,
    RiskPolicyStore,
    ScorecardDefinitionStore,
    ScorecardResultStore,
)
from scorecard.sqlite_store import SQLiteScorecardStore

__all__ = [
    "AssessmentStore",
    "RiskPolicyStore",
    "ScorecardDefinitionStore",
    "ScorecardResultStore",
    "SQLiteScorecardStore",
]
