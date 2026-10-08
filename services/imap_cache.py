"""Persistent cache owned by the IMAP discovery module."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from cache_security import load_encrypted_json, save_encrypted_json
from utils.cache_identity import hmac_identity, tenant_identity
from utils.envutil import env_bool
from utils.paths import resolve_data_path

IMAP_CACHE_ENABLED_ENV = "IMAP_CACHE_ENABLED"
IMAP_CACHE_SCHEMA_VERSION = 1
IMAP_CACHE_MAX_AGE_HOURS = 12.0
IMAP_CACHE_DIR = resolve_data_path(os.getenv("IMAP_CACHE_DIR"), "cache/imap")


def imap_cache_enabled() -> bool:
    return env_bool(IMAP_CACHE_ENABLED_ENV, False)


def _cache_path(email: str, tenant_id: str) -> Path:
    tenant_dir = IMAP_CACHE_DIR / tenant_identity(tenant_id)
    tenant_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        try:
            os.chmod(tenant_dir, 0o700)
        except OSError:
            pass
    identity = hmac_identity(email.strip().lower())
    return tenant_dir / f"imap_cache_{identity}.json"


def load_imap_cache(
    email: str,
    *,
    tenant_id: str = "default",
    max_age_hours: float = IMAP_CACHE_MAX_AGE_HOURS,
) -> list[dict[str, Any]] | None:
    if max_age_hours < 0:
        raise ValueError("max_age_hours must be >= 0")
    try:
        data = load_encrypted_json(
            _cache_path(email, tenant_id),
            tenant_id=tenant_id,
            max_age_seconds=int(max_age_hours * 3600),
        )
        if not isinstance(data, dict):
            return None
        if data.get("cache_schema_version") != IMAP_CACHE_SCHEMA_VERSION:
            return None
        findings = data.get("findings")
        if not isinstance(findings, list) or not all(isinstance(x, dict) for x in findings):
            return None
        return findings
    except Exception:
        return None


def save_imap_cache(
    email: str,
    findings: list[dict[str, Any]],
    *,
    tenant_id: str = "default",
) -> None:
    if not isinstance(findings, list):
        raise TypeError("findings must be a list")
    payload = {
        "cache_schema_version": IMAP_CACHE_SCHEMA_VERSION,
        "findings": [item for item in findings if isinstance(item, dict)],
    }
    try:
        path = _cache_path(email, tenant_id)
        save_encrypted_json(path, payload, tenant_id=tenant_id)
        if os.name != "nt":
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
    except Exception:
        return
