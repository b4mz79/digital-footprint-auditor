import os
import re
import time
from pathlib import Path
from typing import Any

import httpx
import trio
from dotenv import load_dotenv
from cache_security import load_encrypted_json, save_encrypted_json
from utils.cache_identity import hmac_identity, tenant_identity
from utils.envutil import env_bool
from utils.paths import resolve_data_path

from utils.domains import display_name
from utils.logging_setup import get_logger
from utils.envutil import env_bool
from utils.privacy import mask_email
from utils.translations import t

load_dotenv()
logger = get_logger("OSINTScanner")

# Module-owned persistent cache.
OSINT_CACHE_ENABLED_ENV = "OSINT_CACHE_ENABLED"
OSINT_CACHE_SCHEMA_VERSION = 1
OSINT_CACHE_MAX_AGE_HOURS = 12.0
OSINT_CACHE_DIR = resolve_data_path(os.getenv("OSINT_CACHE_DIR"), "cache/osint")

def osint_cache_enabled() -> bool:
    return env_bool(OSINT_CACHE_ENABLED_ENV, True)

def _cache_path(email: str, tenant_id: str) -> Path:
    tenant_dir = OSINT_CACHE_DIR / tenant_identity(tenant_id)
    tenant_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        try: os.chmod(tenant_dir, 0o700)
        except OSError: pass
    return tenant_dir / f"osint_cache_{hmac_identity(email.strip().lower())}.json"

def load_osint_cache(email: str, *, tenant_id: str = "default", max_age_hours: float = OSINT_CACHE_MAX_AGE_HOURS) -> list[dict[str, Any]] | None:
    if max_age_hours < 0: raise ValueError("max_age_hours must be >= 0")
    try:
        data = load_encrypted_json(_cache_path(email, tenant_id), tenant_id=tenant_id, max_age_seconds=int(max_age_hours * 3600))
        if not isinstance(data, dict) or data.get("cache_schema_version") != OSINT_CACHE_SCHEMA_VERSION: return None
        findings = data.get("findings")
        return findings if isinstance(findings, list) and all(isinstance(x, dict) for x in findings) else None
    except Exception: return None

def save_osint_cache(email: str, findings: list[dict[str, Any]], *, tenant_id: str = "default") -> None:
    if not isinstance(findings, list): raise TypeError("findings must be a list")
    try:
        path = _cache_path(email, tenant_id)
        save_encrypted_json(path, {"cache_schema_version": OSINT_CACHE_SCHEMA_VERSION, "findings": [x for x in findings if isinstance(x, dict)]}, tenant_id=tenant_id)
        if os.name != "nt":
            try: os.chmod(path, 0o600)
            except OSError: pass
    except Exception: return


EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
HOLEHE_TIMEOUT_SECONDS = 180
HOLEHE_HTTP_TIMEOUT_SECONDS = 10
# Hard ceiling for concurrently executing third-party Holehe modules.
# This bounds outbound request pressure even when Holehe exposes many modules.
HOLEHE_MAX_CONCURRENCY = 12


class OSINTScanError(RuntimeError):
    """The scan could not be completed. An error must never look like 'no accounts found'."""


def _load_holehe_modules() -> list:
    """Load Holehe site modules without starting its CLI or update checker."""
    try:
        from holehe.core import get_functions, import_submodules
        modules = import_submodules("holehe.modules")
        return get_functions(modules)
    except Exception as exc:
        logger.error("[OSINT Error] Failed to load Holehe modules: %s", type(exc).__name__)
        raise OSINTScanError(f"Holehe modules failed to load: {type(exc).__name__}") from exc


def _module_domain(module) -> str:
    """Resolve a Holehe function's domain from its function name."""
    name = getattr(module, "__name__", "").strip()
    try:
        source = module.__globals__.get("__name__", "")
        if source.startswith("holehe.modules."):
            from importlib import import_module
            module_obj = import_module(source)
            return str(getattr(module_obj, "domain", "")).strip().lower()
    except Exception:
        pass
    return name.lower()


async def _run_holehe(email_address: str) -> tuple[list[dict], int, int]:
    """Run embedded Holehe modules concurrently and return raw results plus counters."""
    modules = _load_holehe_modules()
    results: list[dict] = []
    errors = 0
    rate_limited = 0
    trust_env = env_bool("HTTPX_TRUST_ENV", False)
    client = httpx.AsyncClient(
        timeout=HOLEHE_HTTP_TIMEOUT_SECONDS,
        follow_redirects=False,
        trust_env=trust_env,
    )
    limiter = trio.Semaphore(HOLEHE_MAX_CONCURRENCY)

    async def run_module(module) -> None:
        nonlocal errors, rate_limited
        try:
            async with limiter:
                out: list[dict] = []
                await module(email_address, client, out)
            for item in out:
                if isinstance(item, dict):
                    results.append(item)
                    if item.get("rateLimit"):
                        rate_limited += 1
                    if item.get("error"):
                        errors += 1
        except Exception as exc:
            errors += 1
            logger.warning(
                "[OSINT] Holehe module %s failed: %s",
                getattr(module, "__name__", "unknown"),
                type(exc).__name__,
            )

    try:
        with trio.move_on_after(HOLEHE_TIMEOUT_SECONDS) as scope:
            async with trio.open_nursery() as nursery:
                for module in modules:
                    nursery.start_soon(run_module, module)
        if scope.cancelled_caught:
            raise OSINTScanError(f"Holehe melewati batas waktu {HOLEHE_TIMEOUT_SECONDS} detik.")
    finally:
        await client.aclose()

    return results, errors, rate_limited


def parse_holehe_results(raw_results: list[dict], lang: str = "en") -> tuple[list[dict], int]:
    """Convert embedded Holehe dictionaries to the application's stable service format."""
    results: list[dict] = []
    seen_domains: set[str] = set()

    for item in raw_results:
        if not item.get("exists") or item.get("rateLimit") or item.get("error"):
            continue

        service_domain = str(item.get("domain") or "").strip().lower().rstrip(":")
        if not service_domain or service_domain == "email" or service_domain in seen_domains:
            continue

        name = display_name(service_domain) if "." in service_domain else service_domain.capitalize()
        if not name or name == "Email":
            continue

        seen_domains.add(service_domain)
        logger.info("[OSINT] Target registration signal found for service: %s", service_domain)
        results.append({
            "name": name,
            "domain": service_domain,
            "source": t("source_osint", lang=lang),
            "subject": t("active_account_osint", lang=lang),
        })

    return results, len(seen_domains)


def scan_osint_footprint(email: str, lang: str = "en") -> list[dict]:
    logger.info("[OSINT] Scanning target: %s", mask_email(email))
    clean_email = email.strip()
    if not EMAIL_REGEX.fullmatch(clean_email):
        raise ValueError("Invalid email format.")

    started = time.monotonic()
    raw_results, errors, rate_limited = trio.run(_run_holehe, clean_email)
    results, matched = parse_holehe_results(raw_results, lang=lang)
    duration = time.monotonic() - started

    logger.info(
        "[OSINT] Stats: modules=%d, matched=%d, errors=%d, rate_limited=%d, duration=%.2fs",
        len(raw_results), matched, errors, rate_limited, duration,
    )

    if errors and not raw_results:
        raise OSINTScanError("Holehe gagal menghasilkan hasil yang dapat diproses.")

    return results
