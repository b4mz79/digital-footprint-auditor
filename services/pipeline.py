"""The scan flow, independent of Streamlit."""
from __future__ import annotations

import asyncio
import os
import re
from typing import Any, Callable

from cache_security import clear_cache_files, purge_expired
from services.ai_agent import CACHE_DIR as AI_CACHE_DIR, analyze_smart_cache
from services.breach_scanner import BREACH_CACHE_DIR, scan_data_breaches
from services.evidence import evidence_to_dicts, service_findings_to_evidence
from services.imap_scanner import scan_gmail_inbox
from services.osint_scanner import scan_osint_footprint
from utils.envutil import env_non_negative_int
from utils.logging_setup import get_logger

logger = get_logger("Pipeline")

_TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")


def get_tenant_id() -> str:
    """TENANT_ID isolates caches when several people share one install."""
    value = os.getenv("TENANT_ID", "default").strip()
    if _TENANT_RE.fullmatch(value):
        return value
    logger.warning("TENANT_ID tidak valid; memakai 'default'.")
    return "default"


def _event(
    level: str,
    key: str | None = None,
    text: str | None = None,
    stage: str | None = None,
    **args: Any,
) -> dict[str, Any]:
    return {
        "level": level,
        "key": key,
        "text": text,
        "stage": stage,
        "args": args,
    }


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
    on_event: Callable[[dict[str, Any]], None] | None = None,
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
        "evidence": [],
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

    def emit(
        event: dict[str, Any],
        live_data: dict[str, Any] | None = None,
    ) -> None:
        events.append(event)
        if on_event:
            if live_data is not None:
                live_event = dict(event)
                live_event["_live"] = live_data
                on_event(live_event)
            else:
                on_event(event)

    # Step 1: Gmail via IMAP
    if enable_imap:
        if not gmail_app_password:
            emit(_event("warning", "warn_no_gmail_pass", stage="imap"))
        else:
            emit(_event("info", "info_imap_scanning", stage="imap"))
            try:
                found = scan_gmail_inbox(email, gmail_app_password, lang=lang)
                state["services"].extend(found)
                emit(
                    _event("success", "success_imap", stage="imap", count=len(found)),
                    {"services": found},
                )
            except Exception as exc:
                emit(_event("error", text=f"Error IMAP: {exc}", stage="imap"))

    # Step 2: OSINT via Holehe
    if enable_osint:
        emit(_event("info", "info_osint_scanning", stage="osint"))
        try:
            found = scan_osint_footprint(email, lang=lang)
            state["services"].extend(found)
            emit(
                _event("success", "success_osint", stage="osint", count=len(found)),
                {"services": found},
            )
        except Exception as exc:
            emit(_event("error", text=f"Error OSINT: {exc}", stage="osint"))

    # Step 3: Multi-layer breach scan
    if enable_breach:
        emit(_event("info", "info_breach_scanning", stage="breach"))
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
            emit(
                _event(
                    "info",
                    text="Breach scan selesai.",
                    stage="breach",
                ),
                {"breach": dict(state["breach"])},
            )
        except Exception as exc:
            state["breach"]["error"] = str(exc)
            emit(_event("error", text=f"Error Breach Scan: {exc}", stage="breach"))

    # Normalize scanner output into stable evidence records after all discovery stages.
    # This is lineage only: it does not calculate risk and does not alter findings.
    local_evidence = service_findings_to_evidence(state["services"])
    state["evidence"] = evidence_to_dicts(local_evidence)
    emit(
        _event(
            "success",
            text="Evidence normalization selesai.",
            stage="evidence",
            count=len(state["evidence"]),
        ),
        {"evidence": list(state["evidence"])},
    )

    if with_ai:
        run_ai(
            state,
            lang,
            force_refresh=force_refresh,
            on_event=on_event,
        )

    return state


def run_ai(
    state: dict[str, Any],
    lang: str,
    force_refresh: bool = False,
    on_event: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Build or rebuild the AI analysis for the requested language."""
    findings = state["breach"]["findings"]

    def emit(
        event: dict[str, Any],
        live_data: dict[str, Any] | None = None,
    ) -> None:
        state["events"].append(event)
        if on_event:
            if live_data is not None:
                live_event = dict(event)
                live_event["_live"] = live_data
                on_event(live_event)
            else:
                on_event(event)

    if not state["services"] and not findings:
        state["ai"], state["ai_lang"] = None, lang
        return state

    emit(_event("info", text="Memulai AI Privacy Audit...", stage="ai"))

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
                evidence_records=state.get("evidence", []),
            )
        )
        emit(
            _event(
                "success",
                text="AI Privacy Audit selesai.",
                stage="ai",
            ),
            {"ai": state["ai"]},
        )
    except Exception as exc:
        state["ai"] = None
        emit(_event("error", text=f"Error AI: {exc}", stage="ai"))

    state["ai_lang"] = lang
    return state


def purge_expired_caches() -> int:
    """Delete cache files older than CACHE_RETENTION_HOURS."""
    hours = env_non_negative_int("CACHE_RETENTION_HOURS", 24, 24 * 30) or 24
    removed = 0
    for directory in {AI_CACHE_DIR, BREACH_CACHE_DIR}:
        removed += purge_expired(directory, hours * 3600)
    if removed:
        logger.info("Cache kedaluwarsa dihapus: %d berkas.", removed)
    return removed


def clear_all_caches() -> int:
    return clear_cache_files(AI_CACHE_DIR, BREACH_CACHE_DIR)