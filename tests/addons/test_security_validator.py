from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from services.addonsmgr.security_validator import validate_package_security


def _bandit_report(
    *,
    results: list[dict[str, object]] | None = None,
    errors: list[str] | None = None,
) -> str:
    return json.dumps(
        {
            "errors": errors or [],
            "results": results or [],
        }
    )


def test_security_gate_accepts_clean_package(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package_root = tmp_path / "package"
    package_root.mkdir()
    (package_root / "plugin.py").write_text(
        "def run(context):\n    return {'ok': True}\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "services.addonsmgr.security_validator.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout=_bandit_report(),
            stderr="",
        ),
    )

    assert validate_package_security(package_root) == ()


def test_security_gate_rejects_high_severity_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package_root = tmp_path / "package"
    package_root.mkdir()
    (package_root / "plugin.py").write_text(
        "import os\nos.system('whoami')\n",
        encoding="utf-8",
    )

    report = _bandit_report(
        results=[
            {
                "test_id": "B605",
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "filename": str(package_root / "plugin.py"),
                "line_number": 2,
                "issue_text": "Starting a process with a shell.",
            }
        ]
    )
    monkeypatch.setattr(
        "services.addonsmgr.security_validator.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=args[0],
            returncode=1,
            stdout=report,
            stderr="",
        ),
    )

    with pytest.raises(ValueError, match="rejected by Bandit security gate"):
        validate_package_security(package_root)


def test_security_gate_fails_closed_when_bandit_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package_root = tmp_path / "package"
    package_root.mkdir()
    (package_root / "plugin.py").write_text(
        "def run(context):\n    return {}\n",
        encoding="utf-8",
    )

    def _raise(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError("bandit")

    monkeypatch.setattr(
        "services.addonsmgr.security_validator.subprocess.run",
        _raise,
    )

    with pytest.raises(RuntimeError, match="Bandit security scanner is unavailable"):
        validate_package_security(package_root)


def test_security_gate_rejects_bandit_report_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package_root = tmp_path / "package"
    package_root.mkdir()
    (package_root / "plugin.py").write_text(
        "def run(context):\n    return {}\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "services.addonsmgr.security_validator.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=args[0],
            returncode=1,
            stdout=_bandit_report(errors=["syntax error"]),
            stderr="",
        ),
    )

    with pytest.raises(RuntimeError, match="Bandit security scan failed"):
        validate_package_security(package_root)
