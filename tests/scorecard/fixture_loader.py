from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_DUMP_RE = re.compile(
    r"(?ms)^BEFORE\s*\n```json\s*\n(?P<before>.*?)\n```\s*\n"
    r"---\s*\nAFTER\s*\n```json\s*\n(?P<after>.*?)\n```\s*$"
)

def load_contextual_filter_dump(path: str | Path) -> dict[str, Any]:
    """Load the application dump without coupling tests to its formatting."""
    raw = Path(path).read_text(encoding="utf-8")
    match = _DUMP_RE.search(raw.strip())
    if not match:
        raise ValueError("Unsupported contextual_filter_dump.md format")
    before = json.loads(match.group("before"))
    after = json.loads(match.group("after"))
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise ValueError("Dump BEFORE/AFTER sections must contain JSON objects")
    return {"before": before, "after": after}

def accepted_contextual_records(dump: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract accepted AFTER records as a stable list for scorecard fixtures."""
    after = dump["after"]
    for key in ("accepted", "accepted_records", "records"):
        value = after.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []

def contextual_security_evidence_measurement(dump: dict[str, Any]) -> dict[str, Any]:
    """Derive only the KPI measurement supported by the contextual dump."""
    records = accepted_contextual_records(dump)
    return {
        "kpi_id": "relevant_security_evidence",
        "unit": "count",
        "value": len(records),
        "state": "observed",
        "source": "contextual_filter_dump",
        "evidence_ids": [
            str(item["evidence_id"]) for item in records if item.get("evidence_id")
        ],
    }
