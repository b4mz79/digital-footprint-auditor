from __future__ import annotations

import base64

import pytest
from cryptography.fernet import Fernet

import cache_security
from services import breach_scanner


def test_encrypted_cache_roundtrip_is_tenant_bound(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("CACHE_SECRET_KEY", Fernet.generate_key().decode("ascii"))

    path = tmp_path / "audit_cache_test.json"
    payload = {"provider_used": "Groq Cloud", "analysis": [{"service": "Example"}]}

    cache_security.save_encrypted_json(path, payload, tenant_id="tenant-a")

    assert cache_security.load_encrypted_json(path, tenant_id="tenant-a") == payload
    assert cache_security.load_encrypted_json(path, tenant_id="tenant-b") is None
    assert path.read_bytes() != (
        str(payload).encode("utf-8")
    )


def test_cache_load_rejects_negative_ttl(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("CACHE_SECRET_KEY", Fernet.generate_key().decode("ascii"))

    with pytest.raises(ValueError, match="max_age_seconds"):
        cache_security.load_encrypted_json(
            tmp_path / "missing.json",
            tenant_id="default",
            max_age_seconds=-1,
        )


def test_purge_expired_rejects_negative_retention(tmp_path) -> None:
    with pytest.raises(ValueError, match="max_age_seconds"):
        cache_security.purge_expired(tmp_path, -1, now=100.0)


def test_purge_expired_removes_only_cache_files(tmp_path) -> None:
    old_audit = tmp_path / "audit_cache_old.json"
    old_breach = tmp_path / "breach_cache_old.json"
    fresh_audit = tmp_path / "audit_cache_fresh.json"
    unrelated = tmp_path / "notes.txt"

    for path in (old_audit, old_breach, fresh_audit, unrelated):
        path.write_text("x", encoding="utf-8")

    old_mtime = 10.0
    fresh_mtime = 95.0
    import os

    os.utime(old_audit, (old_mtime, old_mtime))
    os.utime(old_breach, (old_mtime, old_mtime))
    os.utime(fresh_audit, (fresh_mtime, fresh_mtime))
    os.utime(unrelated, (old_mtime, old_mtime))

    removed = cache_security.purge_expired(tmp_path, 50.0, now=100.0)

    assert removed == 2
    assert not old_audit.exists()
    assert not old_breach.exists()
    assert fresh_audit.exists()
    assert unrelated.exists()


def test_breach_cache_schema_mismatch_is_a_cache_miss(monkeypatch) -> None:
    monkeypatch.setattr(
        breach_scanner,
        "get_breach_cache_filepath",
        lambda *args, **kwargs: "ignored",
    )
    monkeypatch.setattr(
        breach_scanner,
        "load_encrypted_json",
        lambda *args, **kwargs: {
            "results": [],
            "complete": True,
            "cache_schema_version": breach_scanner.BREACH_CACHE_SCHEMA_VERSION - 1,
        },
    )

    result = breach_scanner.load_breach_cache(
        "example@example.com",
        tenant_id="default",
    )

    assert result is None


def test_breach_cache_current_schema_is_reusable(monkeypatch) -> None:
    monkeypatch.setattr(
        breach_scanner,
        "get_breach_cache_filepath",
        lambda *args, **kwargs: "ignored",
    )
    cached = {
        "results": [],
        "complete": True,
        "cache_schema_version": breach_scanner.BREACH_CACHE_SCHEMA_VERSION,
    }
    monkeypatch.setattr(
        breach_scanner,
        "load_encrypted_json",
        lambda *args, **kwargs: cached.copy(),
    )

    result = breach_scanner.load_breach_cache(
        "example@example.com",
        tenant_id="default",
    )

    assert result is not None
    assert result["is_from_cache"] is True
