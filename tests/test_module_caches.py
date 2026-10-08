from __future__ import annotations

import os

from cryptography.fernet import Fernet

from services import imap_scanner, osint_scanner
from services import pipeline


def test_osint_cache_disabled_by_default(monkeypatch):
    monkeypatch.delenv("OSINT_CACHE_ENABLED", raising=False)
    assert osint_scanner.osint_cache_enabled() is False


def test_osint_cache_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setenv("CACHE_SECRET_KEY", Fernet.generate_key().decode("ascii"))
    monkeypatch.setenv("PII_PEPPER_KEY", "p" * 32)
    monkeypatch.setattr(
        osint_scanner,
        "_cache_path",
        lambda *args, **kwargs: tmp_path / "osint_cache_test.json",
    )
    findings = [{"name": "Example", "domain": "example.com"}]

    osint_scanner.save_osint_cache("user@example.com", findings)

    assert osint_scanner.load_osint_cache("user@example.com") == findings


def test_osint_cache_rejects_schema_mismatch(monkeypatch):
    monkeypatch.setattr(
        osint_scanner,
        "load_encrypted_json",
        lambda *args, **kwargs: {
            "cache_schema_version": osint_scanner.OSINT_CACHE_SCHEMA_VERSION - 1,
            "findings": [],
        },
    )
    assert osint_scanner.load_osint_cache("user@example.com") is None


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


def test_pipeline_osint_cache_off_runs_without_writing(monkeypatch):
    monkeypatch.setenv("OSINT_CACHE_ENABLED", "false")
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
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("OSINT cache must not be written when disabled")
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


def test_pipeline_osint_cache_enabled_miss_writes(monkeypatch):
    monkeypatch.setenv("OSINT_CACHE_ENABLED", "true")
    saved = []

    monkeypatch.setattr(
        pipeline,
        "load_osint_cache",
        lambda *args, **kwargs: None,
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



def test_holehe_module_concurrency_is_bounded(monkeypatch):
    monkeypatch.setattr(osint_scanner, "HOLEHE_MAX_CONCURRENCY", 3)

    state = {"active": 0, "max_active": 0}

    async def fake_module(email, client, out):
        state["active"] += 1
        state["max_active"] = max(state["max_active"], state["active"])
        await osint_scanner.trio.sleep(0.01)
        state["active"] -= 1

    modules = [fake_module for _ in range(8)]
    monkeypatch.setattr(osint_scanner, "_load_holehe_modules", lambda: modules)

    result = osint_scanner.trio.run(osint_scanner._run_holehe, "user@example.com")

    assert result == ([], 0, 0)
    assert state["max_active"] == 3


def test_imap_header_parser_skips_oversized_payload(monkeypatch):
    monkeypatch.setattr(imap_scanner, "IMAP_MAX_HEADER_BYTES", 32)

    oversized = b"Subject: Welcome\r\n" + (b"x" * 64)
    result = imap_scanner._iter_fetched_messages([(b"1 FETCH", oversized)])

    assert result == []


def test_imap_header_parser_accepts_payload_within_limit(monkeypatch):
    monkeypatch.setattr(imap_scanner, "IMAP_MAX_HEADER_BYTES", 1024)

    payload = b"From: Example <sender@example.com>\r\nSubject: Welcome\r\n\r\n"
    result = imap_scanner._iter_fetched_messages([(b"1 FETCH", payload)])

    assert len(result) == 1
    assert result[0]["Subject"] == "Welcome"


def test_imap_cache_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setenv("CACHE_SECRET_KEY", Fernet.generate_key().decode("ascii"))
    monkeypatch.setenv("PII_PEPPER_KEY", "p" * 32)
    monkeypatch.setattr(
        imap_scanner,
        "_cache_path",
        lambda *args, **kwargs: tmp_path / "imap_cache_test.json",
    )
    findings = [{"name": "Example", "domain": "example.com"}]

    imap_scanner.save_imap_cache("user@example.com", findings)

    assert imap_scanner.load_imap_cache("user@example.com") == findings


def test_pipeline_force_refresh_bypasses_osint_cache_and_writes(monkeypatch):
    monkeypatch.setenv("OSINT_CACHE_ENABLED", "true")
    saved = []
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
        lambda email, findings, tenant_id="default": saved.append(findings),
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
    assert saved == [
        [{"name": "Fresh", "domain": "fresh.example", "source": "OSINT"}]
    ]


def test_cache_directories_are_module_specific():
    assert imap_scanner.IMAP_CACHE_DIR != osint_scanner.OSINT_CACHE_DIR


def test_pipeline_imap_cache_off_runs_without_writing(monkeypatch):
    monkeypatch.setenv("IMAP_CACHE_ENABLED", "false")
    monkeypatch.setattr(
        pipeline,
        "scan_gmail_inbox",
        lambda email, app_password, lang="id": [
            {"name": "Fresh IMAP", "domain": "imap.example", "source": "IMAP"}
        ],
    )
    monkeypatch.setattr(
        pipeline,
        "save_imap_cache",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("IMAP cache must not be written when disabled")
        ),
    )
    monkeypatch.setenv("FIRECRAWL_API_KEY", "")

    state = pipeline.run_scan(
        email="user@example.com",
        gmail_app_password="synthetic-password",
        enable_imap=True,
        enable_osint=False,
        enable_breach=False,
        with_ai=False,
    )

    assert state["services"][0]["domain"] == "imap.example"


def test_pipeline_imap_cache_enabled_miss_writes(monkeypatch):
    monkeypatch.setenv("IMAP_CACHE_ENABLED", "true")
    saved = []
    monkeypatch.setattr(
        pipeline,
        "load_imap_cache",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        pipeline,
        "scan_gmail_inbox",
        lambda email, app_password, lang="id": [
            {"name": "Fresh IMAP", "domain": "imap.example", "source": "IMAP"}
        ],
    )
    monkeypatch.setattr(
        pipeline,
        "save_imap_cache",
        lambda email, findings, tenant_id="default": saved.append(findings),
    )
    monkeypatch.setenv("FIRECRAWL_API_KEY", "")

    state = pipeline.run_scan(
        email="user@example.com",
        gmail_app_password="synthetic-password",
        enable_imap=True,
        enable_osint=False,
        enable_breach=False,
        with_ai=False,
    )

    assert state["services"][0]["domain"] == "imap.example"
    assert saved == [
        [{"name": "Fresh IMAP", "domain": "imap.example", "source": "IMAP"}]
    ]


def test_pipeline_imap_cache_hit_skips_scanner(monkeypatch):
    monkeypatch.setenv("IMAP_CACHE_ENABLED", "true")
    monkeypatch.setattr(
        pipeline,
        "load_imap_cache",
        lambda email, tenant_id="default": [
            {"name": "Cached IMAP", "domain": "imap.example", "source": "cache"}
        ],
    )
    monkeypatch.setattr(
        pipeline,
        "scan_gmail_inbox",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("IMAP must be skipped")
        ),
    )
    monkeypatch.setenv("FIRECRAWL_API_KEY", "")

    state = pipeline.run_scan(
        email="user@example.com",
        gmail_app_password="synthetic-password",
        enable_imap=True,
        enable_osint=False,
        enable_breach=False,
        with_ai=False,
    )

    assert state["services"][0]["domain"] == "imap.example"
