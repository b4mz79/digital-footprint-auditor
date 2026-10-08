"""Encrypted cache owned by the Evidence Enrichment module.

The cache stores only completed enrichment output. URL verification remains a
separate pipeline stage and therefore is intentionally not part of this cache.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from cache_security import load_encrypted_json, save_encrypted_json
from utils.cache_identity import hmac_identity, tenant_identity
from utils.envutil import env_bool
from utils.paths import resolve_data_path

ENRICHMENT_CACHE_ENABLED_ENV = "EVIDENCE_ENRICHMENT_CACHE_ENABLED"
ENRICHMENT_CACHE_SCHEMA_VERSION = 1
ENRICHMENT_CACHE_MAX_AGE_HOURS = 12.0
ENRICHMENT_CACHE_DIR = resolve_data_path(
    os.getenv("EVIDENCE_ENRICHMENT_CACHE_DIR"),
    "cache/enrichment",
)


def enrichment_cache_enabled() -> bool:
    return env_bool(ENRICHMENT_CACHE_ENABLED_ENV, False)


def _cache_path(input_fingerprint: str, tenant_id: str) -> Path:
    tenant_dir = ENRICHMENT_CACHE_DIR / tenant_identity(tenant_id)
    tenant_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        try:
            os.chmod(tenant_dir, 0o700)
        except OSError:
            pass
    identity = hmac_identity(input_fingerprint)
    return tenant_dir / f"enrichment_cache_{identity}.json"


def load_enrichment_cache(
    input_fingerprint: str,
    *,
    tenant_id: str = "default",
    max_age_hours: float = ENRICHMENT_CACHE_MAX_AGE_HOURS,
) -> list[dict[str, Any]] | None:
    if max_age_hours < 0:
        raise ValueError("max_age_hours must be >= 0")
    try:
        data = load_encrypted_json(
            _cache_path(input_fingerprint, tenant_id),
            tenant_id=tenant_id,
            max_age_seconds=int(max_age_hours * 3600),
        )
        if not isinstance(data, dict):
            return None
        if data.get("cache_schema_version") != ENRICHMENT_CACHE_SCHEMA_VERSION:
            return None
        if data.get("input_fingerprint") != input_fingerprint:
            return None
        records = data.get("records")
        if not isinstance(records, list) or not all(isinstance(x, dict) for x in records):
            return None
        return records
    except Exception:
        return None


def save_enrichment_cache(
    input_fingerprint: str,
    records: list[dict[str, Any]],
    *,
    tenant_id: str = "default",
) -> None:
    if not isinstance(records, list):
        raise TypeError("records must be a list")
    payload = {
        "cache_schema_version": ENRICHMENT_CACHE_SCHEMA_VERSION,
        "input_fingerprint": input_fingerprint,
        "records": [item for item in records if isinstance(item, dict)],
    }
    try:
        path = _cache_path(input_fingerprint, tenant_id)
        save_encrypted_json(path, payload, tenant_id=tenant_id)
        if os.name != "nt":
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
    except Exception:
        return
