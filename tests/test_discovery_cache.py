from __future__ import annotations

from cryptography.fernet import Fernet

from services import pipeline
from services import osint_cache
def test_osint_cache_disabled_by_default(monkeypatch):
    monkeypatch.delenv("OSINT_CACHE_ENABLED", raising=False)
    assert discovery_cache.discovery_cache_enabled() is False


def test_discovery_cache_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setenv("CACHE_SECRET_KEY", Fernet.generate_key().decode("ascii"))
    monkeypatch.setenv("PII_PEPPER_KEY", "p" * 32)
    monkeypatch.setattr(discovery_cache, "_cache_path", lambda *args: tmp_path / "imap_cache_test.json")
    findings = [{"name": "Example", "domain": "example.com"}]

    discovery_cache.save_osint_cache("imap", findings, "user@example.com")

    assert discovery_cache.load_osint_cache("imap", "user@example.com") == findings


def test_discovery_cache_rejects_schema_mismatch(monkeypatch):
    monkeypatch.setattr(
        discovery_cache,
        "load_encrypted_json",
        lambda *args, **kwargs: {
            "cache_schema_version": discovery_cache.DISCOVERY_CACHE_SCHEMA_VERSION - 1,
            "scanner": "imap",
            "findings": [],
        },
    )
    assert discovery_cache.load_discovery_cache("imap", "user@example.com") is None


def test_pipeline_osint_cache_hit_skips_scanner(monkeypatch):
    monkeypatch.setenv("DISCOVERY_CACHE_ENABLED", "true")
    monkeypatch.setattr(
        pipeline,
        "load_discovery_cache",
        lambda scanner, email, phone="", tenant_id="default": (
            [{"name": "Cached", "domain": "cached.example", "source": "cache"}]
            if scanner == "osint" else None
        ),
    )
    monkeypatch.setattr(
        pipeline,
        "scan_osint_footprint",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("OSINT must be skipped")),
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


def test_pipeline_cache_off_runs_and_writes(monkeypatch):
    monkeypatch.setenv("DISCOVERY_CACHE_ENABLED", "false")
    saved = []

    monkeypatch.setattr(pipeline, "scan_osint_footprint", lambda email, lang="id": [
        {"name": "Fresh", "domain": "fresh.example", "source": "OSINT"}
    ])
    monkeypatch.setattr(
        pipeline,
        "save_discovery_cache",
        lambda scanner, findings, email, phone="", tenant_id="default": saved.append(
            (scanner, findings)
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

    assert state["services"][0]["domain"] == "fresh.example"
    assert saved == [
        ("osint", [{"name": "Fresh", "domain": "fresh.example", "source": "OSINT"}])
    ]
