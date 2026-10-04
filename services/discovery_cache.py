"""Encrypted persistent cache for discovery-stage scanner results."""
from __future__ import annotations
import os
from pathlib import Path
from cache_security import load_encrypted_json, save_encrypted_json
from utils.envutil import env_bool
from utils.paths import resolve_data_path
from services.breach_scanner import safe_filename_identity, safe_tenant_identity

DISCOVERY_CACHE_ENABLED_ENV = "DISCOVERY_CACHE_ENABLED"
DISCOVERY_CACHE_SCHEMA_VERSION = 1
DISCOVERY_CACHE_MAX_AGE_HOURS = 12.0
DISCOVERY_CACHE_DIR = resolve_data_path(os.getenv("DISCOVERY_CACHE_DIR"), "cache/discovery")
DISCOVERY_CACHE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
if os.name != "nt":
    try: os.chmod(DISCOVERY_CACHE_DIR, 0o700)
    except OSError: pass

def discovery_cache_enabled() -> bool:
    return env_bool(DISCOVERY_CACHE_ENABLED_ENV, False)

def _cache_path(scanner: str, email: str, phone: str, tenant_id: str) -> Path:
    tenant_hash = safe_tenant_identity(tenant_id)
    identity_hash = safe_filename_identity(email, phone)
    scanner_dir = DISCOVERY_CACHE_DIR / tenant_hash
    scanner_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        try: os.chmod(scanner_dir, 0o700)
        except OSError: pass
    return scanner_dir / f"{scanner}_cache_{identity_hash}.json"

def load_discovery_cache(scanner: str, email: str, phone: str = "", tenant_id: str = "default", max_age_hours: float = DISCOVERY_CACHE_MAX_AGE_HOURS) -> list[dict] | None:
    if max_age_hours < 0: raise ValueError("max_age_hours must be >= 0")
    try:
        data = load_encrypted_json(_cache_path(scanner, email, phone, tenant_id), tenant_id=tenant_id, max_age_seconds=int(max_age_hours * 3600))
        if not isinstance(data, dict): return None
        if data.get("cache_schema_version") != DISCOVERY_CACHE_SCHEMA_VERSION or data.get("scanner") != scanner: return None
        findings = data.get("findings")
        if not isinstance(findings, list) or not all(isinstance(x, dict) for x in findings): return None
        return findings
    except Exception:
        return None

def save_discovery_cache(scanner: str, findings: list[dict], email: str, phone: str = "", tenant_id: str = "default") -> None:
    if not isinstance(findings, list): raise TypeError("findings must be a list")
    payload = {"cache_schema_version": DISCOVERY_CACHE_SCHEMA_VERSION, "scanner": scanner, "findings": [x for x in findings if isinstance(x, dict)]}
    try:
        path = _cache_path(scanner, email, phone, tenant_id)
        save_encrypted_json(path, payload, tenant_id=tenant_id)
        if os.name != "nt":
            try: os.chmod(path, 0o600)
            except OSError: pass
    except Exception:
        return
