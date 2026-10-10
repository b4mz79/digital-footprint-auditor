from __future__ import annotations

import importlib.util
import os
import stat
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "privacy_auditor_launcher_under_test",
    ROOT / "packaging" / "launcher.py",
)
assert SPEC is not None and SPEC.loader is not None
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits are not portable to Windows")
def test_launcher_user_data_directory_is_owner_only(tmp_path, monkeypatch):
    monkeypatch.setattr(launcher, "sys", type("Runtime", (), {"platform": "linux"})())
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))

    data_dir = launcher.user_data_dir()

    assert stat.S_IMODE(data_dir.stat().st_mode) == 0o700


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits are not portable to Windows")
def test_launcher_config_save_keeps_env_file_owner_only(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("GMAIL_APP_PASSWORD=secret\n", encoding="utf-8")
    config = launcher.LauncherConfig(env_file)

    config.save({"GMAIL_APP_PASSWORD": "rotated-secret"})

    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
