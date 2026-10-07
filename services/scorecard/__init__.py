"""Privacy Auditor Scorecard Add-on Core.

The package is storage-backend agnostic. SQLite is the reference persistence
adapter; calculation and policy semantics remain outside the storage layer.
"""

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
]
