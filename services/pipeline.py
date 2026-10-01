"""The scan flow, independent of Streamlit.

`run_scan` returns one plain dict ("scan state") that the UI keeps in st.session_state and
re-renders on every rerun. Before this, results lived inside `if run_scan:` and vanished on the
next interaction (a download click, a language switch). Messages are stored as keys + arguments
so they can be re-translated when the language changes.
"""
from __future__ import annotations

import asyncio
import os
import re
from typing import Any

from cache_security import clear_cache_files, purge_expired
from services.ai_agent import CACHE_DIR as AI_CACHE_DIR, analyze_smart_cache
from services.breach_scanner import BREACH_CACHE_DIR, scan_data_breaches
from services.imap_scanner import scan_gmail_inbox
from services.osint_scanner import scan_osint_footprint
from utils.envutil import env_non_negative_int
from utils.logging_setup import get_logger

logger = get_logger("Pipeline")

_TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")


def get_tenant_id() -> str:
    """TENANT_ID (default "default") isolates caches when several people share one install."""
    value = os.getenv("TENANT_ID", "default").strip()
    if _TENANT_RE.fullmatch(value):
        return value
    logger.warning("TENANT_ID tidak valid; memakai 'default'.")
    return "default"


def _event(level: str, key: str | None = None, text: str | None = None, **args: Any) -> dict[str, Any]:
    return {"level": level, "key": key, "text": text, "args": args}


def run_scan(
    *,
    email: str,
    phone: str = "",
    gmail_app_password: str = "",
    enable_imap: bool = True,
    enable_osint: bool = True,
    enable_breach: bool = True,
    force_refresh: bool = False,
    lang: str = "id",
    tenant_id: str | None = None,
    with_ai: bool = True,
) -> dict[str, Any]:
    tenant_id = tenant_id or get_tenant_id()
    email = email.strip()
    phone = (phone or "").strip()

    state: dict[str, Any] = {
        "email": email,
        "phone": phone,
        "lang": lang,
        "tenant_id": tenant_id,
        "events": [],
        "services": [],
        "breach": {
            "enabled": bool(enable_breach),
            "findings": [],
            "engine": "None",
            "cached": False,
            "engines": {},
            "complete": False,
            "error": None,
        },
        "ai": None,
        "ai_lang": None,
    }
    events: list[dict[str, Any]] = state["events"]

    # Step 1: Gmail via IMAP
    if enable_imap:
        if not gmail_app_password:
            events.append(_event("warning", "warn_no_gmail_pass"))
        else:
            events.append(_event("info", "info_imap_scanning"))
            try:
                found = scan_gmail_inbox(email, gmail_app_password, lang=lang)
                state["services"].extend(found)
                events.append(_event("success", "success_imap", count=len(found)))
            except Exception as exc:
                events.append(_event("error", text=f"Error IMAP: {exc}"))

    # Step 2: OSINT (Holehe)
    if enable_osint:
        events.append(_event("info", "info_osint_scanning"))
        try:
            found = scan_osint_footprint(email, lang=lang)
            state["services"].extend(found)
            events.append(_event("success", "success_osint", count=len(found)))
        except Exception as exc:
            events.append(_event("error", text=f"Error OSINT: {exc}"))

    # Step 3: breach scan (async)
    if enable_breach:
        events.append(_event("info", "info_breach_scanning"))
        try:
            output = asyncio.run(
                scan_data_breaches(
                    email=email,
                    phone=phone,
                    force_refresh=force_refresh,
                    lang=lang,
                    tenant_id=tenant_id,
                )
            )
            state["breach"].update(
                findings=output.get("results", []),
                engine=output.get("engine", "None"),
                cached=bool(output.get("is_from_cache", False)),
                engines=output.get("engines", {}),
                complete=bool(output.get("complete", False)),
            )
        except Exception as exc:
            state["breach"]["error"] = str(exc)
            events.append(_event("error", text=f"Error Breach Scan: {exc}"))

    if with_ai:
        run_ai(state, lang, force_refresh=force_refresh)
    return state


def run_ai(state: dict[str, Any], lang: str, force_refresh: bool = False) -> dict[str, Any]:
    """(Re)build the AI analysis for the language `lang`. Cheap when the per-language cache is
    warm, so the UI calls it again after a language switch."""
    findings = state["breach"]["findings"]
    if not state["services"] and not findings:
        state["ai"], state["ai_lang"] = None, lang
        return state
    try:
        state["ai"] = asyncio.run(
            analyze_smart_cache(
                email=state["email"],
                found_services=state["services"],
                phone=state["phone"],
                force_refresh=force_refresh,
                lang=lang,
                tenant_id=state["tenant_id"],
                breach_findings=findings,
            )
        )
    except Exception as exc:
        state["ai"] = None
        state["events"].append(_event("error", text=f"Error AI: {exc}"))
    state["ai_lang"] = lang
    return state


def purge_expired_caches() -> int:
    """Delete cache files older than CACHE_RETENTION_HOURS (default 24h; the cache TTL itself is
    12h, so anything older can never be read again)."""
    hours = env_non_negative_int("CACHE_RETENTION_HOURS", 24, 24 * 30) or 24
    removed = 0
    for directory in {AI_CACHE_DIR, BREACH_CACHE_DIR}:
        removed += purge_expired(directory, hours * 3600)
    if removed:
        logger.info("Cache kedaluwarsa dihapus: %d berkas.", removed)
    return removed


def clear_all_caches() -> int:
    return clear_cache_files(AI_CACHE_DIR, BREACH_CACHE_DIR)
