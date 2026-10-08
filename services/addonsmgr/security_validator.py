from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


_BANDIT_TIMEOUT_SECONDS = 60
_HIGH_SEVERITY = "HIGH"


@dataclass(frozen=True, slots=True)
class SecurityFinding:
    test_id: str
    severity: str
    confidence: str
    filename: str
    line_number: int
    issue_text: str


def validate_package_security(
    package_root: Path,
    *,
    timeout_seconds: int = _BANDIT_TIMEOUT_SECONDS,
) -> tuple[SecurityFinding, ...]:
    """Run Bandit against an extracted add-on package.

    This is a security screening gate, not a malware-proof sandbox. The
    package must pass the structural gate before this function is called.
    Only HIGH-severity Bandit findings are blocking at this stage.
    """
    root = package_root.resolve()
    if not root.is_dir():
        raise ValueError("add-on package root must be a directory")

    command = [
        sys.executable,
        "-m",
        "bandit",
        "-r",
        str(root),
        "--severity-level=high",
        "-f",
        "json",
        "-q",
    ]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "Bandit security scanner is unavailable"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Bandit security scan timed out after {timeout_seconds} seconds"
        ) from exc
    except OSError as exc:
        raise RuntimeError(
            f"Bandit security scanner could not be started: {exc}"
        ) from exc

    report = _parse_report(completed.stdout, completed.stderr)

    errors = report.get("errors")
    if errors:
        raise RuntimeError(
            "Bandit security scan failed: "
            + _format_bandit_errors(errors)
        )

    raw_results = report.get("results", [])
    if not isinstance(raw_results, list):
        raise RuntimeError("Bandit security scan returned an invalid results field")

    findings = tuple(
        _parse_finding(item)
        for item in raw_results
        if isinstance(item, dict)
    )

    if completed.returncode not in (0, 1):
        detail = completed.stderr.strip()
        raise RuntimeError(
            "Bandit security scan failed"
            + (f": {detail}" if detail else "")
        )

    if findings:
        raise ValueError(_format_findings(findings))

    return findings


def _parse_report(stdout: str, stderr: str) -> dict[str, Any]:
    if not stdout.strip():
        detail = stderr.strip()
        raise RuntimeError(
            "Bandit security scanner returned no report"
            + (f": {detail}" if detail else "")
        )

    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        detail = stderr.strip()
        raise RuntimeError(
            "Bandit security scanner returned invalid JSON"
            + (f": {detail}" if detail else "")
        ) from exc

    if not isinstance(payload, dict):
        raise RuntimeError("Bandit security scanner returned an invalid report")

    return payload


def _parse_finding(item: dict[str, Any]) -> SecurityFinding:
    return SecurityFinding(
        test_id=str(item.get("test_id", "UNKNOWN")),
        severity=str(item.get("issue_severity", _HIGH_SEVERITY)),
        confidence=str(item.get("issue_confidence", "UNKNOWN")),
        filename=str(item.get("filename", "<unknown>")),
        line_number=int(item.get("line_number", 0) or 0),
        issue_text=str(item.get("issue_text", "")).strip(),
    )


def _format_findings(findings: tuple[SecurityFinding, ...]) -> str:
    details = []
    for finding in findings[:10]:
        details.append(
            f"{finding.test_id} {finding.severity}/{finding.confidence} "
            f"{finding.filename}:{finding.line_number} "
            f"{finding.issue_text}"
        )

    suffix = ""
    if len(findings) > 10:
        suffix = f" (+{len(findings) - 10} more)"

    return "add-on rejected by Bandit security gate: " + " | ".join(details) + suffix


def _format_bandit_errors(errors: Any) -> str:
    if isinstance(errors, list):
        messages = [str(item) for item in errors if str(item).strip()]
        if messages:
            return " | ".join(messages[:5])
    return str(errors)
