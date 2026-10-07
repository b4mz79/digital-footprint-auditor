from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from scorecard.models import (
    AssessmentRecord,
    RiskPolicyRecord,
    ScorecardDefinitionRecord,
    ScorecardResultRecord,
)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS scorecard_definitions (
    scorecard_id TEXT NOT NULL,
    version TEXT NOT NULL,
    definition_json TEXT NOT NULL,
    PRIMARY KEY (scorecard_id, version)
);

CREATE TABLE IF NOT EXISTS risk_policies (
    policy_id TEXT NOT NULL,
    version TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    PRIMARY KEY (policy_id, version)
);

CREATE TABLE IF NOT EXISTS assessments (
    assessment_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    assessment_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS results (
    result_id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL,
    calculated_at TEXT NOT NULL,
    result_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_results_assessment_id
    ON results (assessment_id);
"""


def _json_dumps(value: dict[str, Any]) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    )


def _json_loads(value: str, *, label: str) -> dict[str, Any]:
    decoded = json.loads(value)
    if not isinstance(decoded, dict):
        raise ValueError(f"stored {label} must be a JSON object")
    return decoded


class SQLiteScorecardStore:
    """Minimal SQLite persistence adapter for the Scorecard Add-on.

    This adapter owns persistence only. It does not calculate scores, execute
    formulas, evaluate risk policies, or mutate UNKNOWN/PARTIAL semantics.

    Definitions, policies, assessments, and results are stored as immutable
    snapshots. Replacing an existing version/id is intentionally rejected.
    """

    def __init__(self, path: str | Path = "scorecard.db") -> None:
        self.path = Path(path)
        self.initialize()

    def initialize(self) -> None:
        if self.path.parent != Path("."):
            self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(_SCHEMA)

    def close(self) -> None:
        # Connections are deliberately short-lived; this is a no-op retained
        # as an explicit lifecycle hook for callers that prefer a store API.
        return None

    def save_definition(self, record: ScorecardDefinitionRecord) -> None:
        self._execute_insert(
            """
            INSERT INTO scorecard_definitions
                (scorecard_id, version, definition_json)
            VALUES (?, ?, ?)
            """,
            (record.scorecard_id, record.version, _json_dumps(record.definition)),
        )

    def get_definition(
        self, scorecard_id: str, version: str
    ) -> ScorecardDefinitionRecord | None:
        row = self._fetchone(
            """
            SELECT scorecard_id, version, definition_json
            FROM scorecard_definitions
            WHERE scorecard_id = ? AND version = ?
            """,
            (scorecard_id, version),
        )
        if row is None:
            return None
        return ScorecardDefinitionRecord(
            scorecard_id=row[0],
            version=row[1],
            definition=_json_loads(row[2], label="definition"),
        )

    def save_policy(self, record: RiskPolicyRecord) -> None:
        self._execute_insert(
            """
            INSERT INTO risk_policies
                (policy_id, version, policy_json)
            VALUES (?, ?, ?)
            """,
            (record.policy_id, record.version, _json_dumps(record.policy)),
        )

    def get_policy(self, policy_id: str, version: str) -> RiskPolicyRecord | None:
        row = self._fetchone(
            """
            SELECT policy_id, version, policy_json
            FROM risk_policies
            WHERE policy_id = ? AND version = ?
            """,
            (policy_id, version),
        )
        if row is None:
            return None
        return RiskPolicyRecord(
            policy_id=row[0],
            version=row[1],
            policy=_json_loads(row[2], label="policy"),
        )

    def save_assessment(self, record: AssessmentRecord) -> None:
        self._execute_insert(
            """
            INSERT INTO assessments
                (assessment_id, created_at, assessment_json)
            VALUES (?, ?, ?)
            """,
            (record.assessment_id, record.created_at, _json_dumps(record.assessment)),
        )

    def get_assessment(self, assessment_id: str) -> AssessmentRecord | None:
        row = self._fetchone(
            """
            SELECT assessment_id, created_at, assessment_json
            FROM assessments
            WHERE assessment_id = ?
            """,
            (assessment_id,),
        )
        if row is None:
            return None
        return AssessmentRecord(
            assessment_id=row[0],
            created_at=row[1],
            assessment=_json_loads(row[2], label="assessment"),
        )

    def save_result(self, record: ScorecardResultRecord) -> None:
        self._execute_insert(
            """
            INSERT INTO results
                (result_id, assessment_id, calculated_at, result_json)
            VALUES (?, ?, ?, ?)
            """,
            (
                record.result_id,
                record.assessment_id,
                record.calculated_at,
                _json_dumps(record.result),
            ),
        )

    def get_result(self, result_id: str) -> ScorecardResultRecord | None:
        row = self._fetchone(
            """
            SELECT result_id, assessment_id, calculated_at, result_json
            FROM results
            WHERE result_id = ?
            """,
            (result_id,),
        )
        if row is None:
            return None
        return ScorecardResultRecord(
            result_id=row[0],
            assessment_id=row[1],
            calculated_at=row[2],
            result=_json_loads(row[3], label="result"),
        )

    def list_results_for_assessment(
        self, assessment_id: str
    ) -> tuple[ScorecardResultRecord, ...]:
        rows = self._fetchall(
            """
            SELECT result_id, assessment_id, calculated_at, result_json
            FROM results
            WHERE assessment_id = ?
            ORDER BY calculated_at ASC, result_id ASC
            """,
            (assessment_id,),
        )
        return tuple(
            ScorecardResultRecord(
                result_id=row[0],
                assessment_id=row[1],
                calculated_at=row[2],
                result=_json_loads(row[3], label="result"),
            )
            for row in rows
        )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _execute_insert(self, sql: str, parameters: tuple[Any, ...]) -> None:
        with self._connect() as connection:
            try:
                connection.execute(sql, parameters)
            except sqlite3.IntegrityError as exc:
                raise ValueError(
                    "immutable scorecard snapshot already exists"
                ) from exc

    def _fetchone(
        self, sql: str, parameters: tuple[Any, ...]
    ) -> tuple[Any, ...] | None:
        with self._connect() as connection:
            row = connection.execute(sql, parameters).fetchone()
        return row

    def _fetchall(
        self, sql: str, parameters: tuple[Any, ...]
    ) -> list[tuple[Any, ...]]:
        with self._connect() as connection:
            rows = connection.execute(sql, parameters).fetchall()
        return rows
