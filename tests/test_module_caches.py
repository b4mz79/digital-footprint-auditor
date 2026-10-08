from __future__ import annotations

import os

from cryptography.fernet import Fernet

from services import imap_cache, osint_cache
from services import pipeline


def test_osint_cache_disabled_by_default(monkeypatch):
    monkeypatch.delenv("OSINT_CACHE_ENABLED", raising=False)
    assert osint_cache.osint_cache_enabled() is False


def test_osint_cache_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setenv("CACHE_SECRET_KEY", Fernet.generate_key().decode("ascii"))
    monkeypatch.setenv("PII_PEPPER_KEY", "p" * 32)
    monkeypatch.setattr(
        osint_cache,
        "_cache_path",
        lambda *args, **kwargs: tmp_path / "osint_cache_test.json",
    )
    findings = [{"name": "Example", "domain": "example.com"}]

    osint_cache.save_osint_cache("user@example.com", findings)

    assert osint_cache.load_osint_cache("user@example.com") == findings


def test_osint_cache_rejects_schema_mismatch(monkeypatch):
    monkeypatch.setattr(
        osint_cache,
        "load_encrypted_json",
        lambda *args, **kwargs: {
            "cache_schema_version": osint_cache.OSINT_CACHE_SCHEMA_VERSION - 1,
            "findings": [],
        },
    )
    assert osint_cache.load_osint_cache("user@example.com") is None


def test_pipeline_osint_cache_hit_skips_scanner(monkeypatch):
    monkeypatch.setenv("OSINT_CACHE_ENABLED", "true")
    monkeypatch.setattr(
        pipeline,
        "load_osint_cache",
        lambda email, tenant_id="default": [
            {"name": "Cached", "domain": "cached.example", "source": "cache"}
        ],
    )
    monkeypatch.setattr(
        pipeline,
        "scan_osint_footprint",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("OSINT must be skipped")
        ),
    )
    monkeypatch.setenv("FIRECRAWL_API_KEY", "")

    state = pipeline.run_scan(
        email="user@example.com",
        enable_imap=False,
        enable_osint=True,
        enable_breach=False,
        with_ai=False,
    )

    assert state["services"][0]["domain"] == "cached.example"


def test_pipeline_osint_cache_off_runs_and_writes(monkeypatch):
    monkeypatch.setenv("OSINT_CACHE_ENABLED", "false")
    saved = []

    monkeypatch.setattr(
        pipeline,
        "scan_osint_footprint",
        lambda email, lang="id": [
            {"name": "Fresh", "domain": "fresh.example", "source": "OSINT"}
        ],
    )
    monkeypatch.setattr(
        pipeline,
        "save_osint_cache",
        lambda email, findings, tenant_id="default": saved.append(findings),
    )
    monkeypatch.setenv("FIRECRAWL_API_KEY", "")

    state = pipeline.run_scan(
        email="user@example.com",
        enable_imap=False,
        enable_osint=True,
        enable_breach=False,
        with_ai=False,
    )

    assert state["services"][0]["domain"] == "fresh.example"
    assert saved == [
        [{"name": "Fresh", "domain": "fresh.example", "source": "OSINT"}]
    ]



def test_imap_cache_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setenv("CACHE_SECRET_KEY", Fernet.generate_key().decode("ascii"))
    monkeypatch.setenv("PII_PEPPER_KEY", "p" * 32)
    monkeypatch.setattr(
        imap_cache,
        "_cache_path",
        lambda *args, **kwargs: tmp_path / "imap_cache_test.json",
    )
    findings = [{"name": "Example", "domain": "example.com"}]

    imap_cache.save_imap_cache("user@example.com", findings)

    assert imap_cache.load_imap_cache("user@example.com") == findings


def test_pipeline_force_refresh_bypasses_osint_cache(monkeypatch):
    monkeypatch.setenv("OSINT_CACHE_ENABLED", "true")
    monkeypatch.setattr(
        pipeline,
        "load_osint_cache",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("force refresh must bypass OSINT cache")
        ),
    )
    monkeypatch.setattr(
        pipeline,
        "scan_osint_footprint",
        lambda email, lang="id": [
            {"name": "Fresh", "domain": "fresh.example", "source": "OSINT"}
        ],
    )
    monkeypatch.setattr(
        pipeline,
        "save_osint_cache",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setenv("FIRECRAWL_API_KEY", "")

    state = pipeline.run_scan(
        email="user@example.com",
        enable_imap=False,
        enable_osint=True,
        enable_breach=False,
        force_refresh=True,
        with_ai=False,
    )

    assert state["services"][0]["domain"] == "fresh.example"


def test_cache_directories_are_module_specific():
    assert imap_cache.IMAP_CACHE_DIR != osint_cache.OSINT_CACHE_DIR
