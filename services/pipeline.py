"""The scan flow, independent of Streamlit."""
from __future__ import annotations

import asyncio
import os
import re
from typing import Any, Callable

from cache_security import clear_cache_files, purge_expired
from services.addon_manager import get_addon_manager
from services.ai_agent import (
    CACHE_DIR as AI_CACHE_DIR,
    CACHE_WRITE_LOCK,
    analyze_smart_cache,
)
import services.ai_agent as ai_agent
from services.breach_scanner import BREACH_CACHE_DIR, scan_data_breaches
from services.discovery_cache import (
    DISCOVERY_CACHE_DIR,
    discovery_cache_enabled,
    load_discovery_cache,
    save_discovery_cache,
)
from services.evidence_enrichment import enrich_evidence
from services.evidence_verification import verify_evidence_records
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
    enable_scorecard: bool = False,
    scorecard_definition: dict[str, Any] | None = None,
    scorecard_risk_policy: dict[str, Any] | None = None,
    enabled_addons: tuple[str, ...] | list[str] = (),
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
        "scorecard": None,
        "scorecard_input": None,
        "addons": {},
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

    cache_enabled = discovery_cache_enabled()

    # Step 1: Gmail via IMAP
    if enable_imap:
        if not gmail_app_password:
            emit(_event("warning", "warn_no_gmail_pass", stage="imap"))
        else:
            cached = load_discovery_cache("imap", email, tenant_id=tenant_id) if cache_enabled else None
            if cached is not None:
                logger.info("[Discovery Cache] IMAP HIT")
                found = cached
            else:
                logger.info("[Discovery Cache] IMAP %s", "MISS" if cache_enabled else "OFF -> fresh scan")
                emit(_event("info", "info_imap_scanning", stage="imap"))
                try:
                    found = scan_gmail_inbox(email, gmail_app_password, lang=lang)
                    save_discovery_cache("imap", found, email, tenant_id=tenant_id)
                except Exception as exc:
                    emit(_event("error", text=f"Error IMAP: {exc}", stage="imap"))
                    found = None
            if found is not None:
                state["services"].extend(found)
                emit(_event("success", "success_imap", stage="imap", count=len(found)), {"services": found})

    # Step 2: OSINT via Holehe
    if enable_osint:
        cached = load_discovery_cache("osint", email, tenant_id=tenant_id) if cache_enabled else None
        if cached is not None:
            logger.info("[Discovery Cache] OSINT HIT")
            found = cached
        else:
            logger.info("[Discovery Cache] OSINT %s", "MISS" if cache_enabled else "OFF -> fresh scan")
            emit(_event("info", "info_osint_scanning", stage="osint"))
            try:
                found = scan_osint_footprint(email, lang=lang)
                save_discovery_cache("osint", found, email, tenant_id=tenant_id)
            except Exception as exc:
                emit(_event("error", text=f"Error OSINT: {exc}", stage="osint"))
                found = None
        if found is not None:
            state["services"].extend(found)
            emit(_event("success", "success_osint", stage="osint", count=len(found)), {"services": found})

    # Step 3: Multi-layer breach scan
    if enable_breach:
        emit(_event("info", "info_breach_scanning", stage="breach"))
        try:
            output = asyncio.run(
                scan_data_breaches(
                    email=email,
                    phone=phone,
                    force_refresh=(force_refresh or not cache_enabled),
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

    # Enrichment is downstream of normalization and upstream of AI.
    # It only augments evidence; it never changes scanner findings or calculates risk.
    emit(
        _event(
            "info",
            text=(
                "Memulai Evidence & Enrichment..."
                if os.getenv("FIRECRAWL_API_KEY", "").strip()
                else "Evidence & Enrichment dilewati: Firecrawl API tidak dikonfigurasi."
            ),
            stage="evidence_start",
        ),
    )

    try:
        enriched_evidence = asyncio.run(enrich_evidence(local_evidence))
    except Exception as exc:
        # Preserve normalized evidence if optional enrichment is unavailable.
        logger.warning("[Pipeline] Evidence enrichment failed: %s", exc)
        enriched_evidence = local_evidence

    try:
        verified_evidence = asyncio.run(verify_evidence_records(enriched_evidence))
    except Exception as exc:
        # Verification is a quality/provenance signal only. If the verifier
        # itself is unavailable, preserve the enriched evidence unchanged.
        logger.warning("[Pipeline] Evidence URL verification failed: %s", exc)
        verified_evidence = enriched_evidence

    state["evidence"] = evidence_to_dicts(verified_evidence)
    contextual_count = sum(
        1
        for item in state["evidence"]
        if item.get("relation") == "security_publication"
    )
    emit(
        _event(
            "success",
            text=(
                "Evidence normalization & enrichment selesai. "
                f"Total={len(state['evidence'])}; "
                f"contextual={contextual_count}."
            ),
            stage="evidence",
            count=len(state["evidence"]),
            contextual_count=contextual_count,
        ),
        {"evidence": list(state["evidence"])},
    )

    # Optional add-ons. The application supplies only the IDs that are active;
    # the manager owns discovery, loading, activation and invocation.
    addon_ids = list(enabled_addons)
    if enable_scorecard and not addon_ids:
        # Backward-compatible bridge for existing callers. New callers should
        # use enabled_addons so the pipeline remains add-on-name agnostic.
        addon_ids.append("scorecard")

    if addon_ids:
        addon_manager = get_addon_manager()
        for addon_id in dict.fromkeys(str(item) for item in addon_ids if str(item).strip()):
            addon = None
            try:
                addon, addon_output = addon_manager.invoke(
                    addon_id,
                    {"state": state},
                )
                if not isinstance(addon_output, dict):
                    raise TypeError(
                        f"add-on {addon_id!r} returned an invalid result "
                        f"({type(addon_output).__name__})"
                    )

                state["addons"][addon_id] = addon_output
                result_key = addon.get("result_key") if addon else None
                if result_key:
                    result_value = addon_output.get(result_key)
                    state[result_key] = result_value
                    if result_key == "scorecard":
                        state["scorecard_input"] = addon_output.get("scorecard_input")

                stage = (addon or {}).get("pipeline_stage") or f"addon:{addon_id}"
                live_payload = (
                    {result_key: result_value}
                    if result_key
                    else {"addon": addon_id, "result": addon_output}
                )
                emit(
                    _event(
                        "success",
                        text=f"Add-on {addon_id} selesai.",
                        stage=stage,
                    ),
                    live_payload,
                )
            except Exception as exc:
                stage = (addon or {}).get("pipeline_stage") or f"addon:{addon_id}"
                logger.warning("[Pipeline] Add-on %s failed: %s", addon_id, exc)
                if addon and addon.get("result_key"):
                    state[addon["result_key"]] = None
                emit(
                    _event(
                        "error",
                        text=f"Error Add-on {addon_id}: {exc}",
                        stage=stage,
                    )
                )

    if with_ai:
        run_ai(
            state,
            lang,
            force_refresh=force_refresh,
            on_event=on_event,
        )

    logger.info(
        "[Pipeline] run_scan selesai; mengembalikan state. services=%d evidence=%d breach=%d ai=%s",
        len(state["services"]),
        len(state["evidence"]),
        len(state["breach"]["findings"]),
        bool(state.get("ai")),
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

    def on_analysis_item(item: dict[str, Any]) -> None:
        emit(
            _event("info", stage="ai"),
            {"ai_item": item},
        )

    def on_analysis_reset() -> None:
        # Ollama may have emitted provisional batches before a later batch
        # failed. Those items are not valid final AI output and must disappear
        # before the failover provider/final fallback is rendered.
        emit(
            _event("warning", stage="ai"),
            {"ai_reset": True},
        )

    try:
        ai_kwargs: dict[str, Any] = {
            "email": state["email"],
            "found_services": state["services"],
            "phone": state["phone"],
            "force_refresh": force_refresh,
            "lang": lang,
            "tenant_id": state["tenant_id"],
            "breach_findings": findings,
            "evidence_records": state.get("evidence", []),
            "scan_status": {
                "breach_scan_complete": bool(state["breach"].get("complete", False)),
                "failed_engines": [
                    name
                    for name, info in state["breach"].get("engines", {}).items()
                    if info.get("status") in {"error", "partial"}
                ],
            },
            "on_analysis_item": on_analysis_item,
            "on_analysis_reset": on_analysis_reset,
        }
        if state.get("scorecard") is not None:
            ai_kwargs["scorecard_result"] = state["scorecard"]

        result = asyncio.run(analyze_smart_cache(**ai_kwargs))
        if not isinstance(result, dict):
            raise TypeError(
                "analyze_smart_cache() mengembalikan hasil AI yang tidak valid "
                f"({type(result).__name__})."
            )
        state["ai"] = result
        logger.info(
            "[Pipeline] AI result diterima: provider=%s analysis=%d exposures=%d",
            result.get("provider_used", "Unknown"),
            len(result.get("analysis", []) or []),
            len(result.get("exposures", []) or []),
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
        logger.exception("[Pipeline] AI execution failed")
        emit(_event("error", text=f"Error AI: {type(exc).__name__}: {exc}", stage="ai"))

    state["ai_lang"] = lang
    return state


def purge_expired_caches() -> int:
    """Delete cache files older than CACHE_RETENTION_HOURS."""
    hours = env_non_negative_int("CACHE_RETENTION_HOURS", 24, 24 * 30) or 24
    removed = 0
    # Coordinate with the AI background writer so retention cleanup cannot
    # race a force-refresh result that is being persisted.
    with CACHE_WRITE_LOCK:
        for directory in {AI_CACHE_DIR, BREACH_CACHE_DIR, DISCOVERY_CACHE_DIR}:
            removed += purge_expired(directory, hours * 3600)
    if removed:
        logger.info("Cache kedaluwarsa dihapus: %d berkas.", removed)
    return removed


def clear_all_caches() -> int:
    # Invalidate queued AI writers before deleting cache files. A daemon writer
    # may still start after this function returns, so the generation check in
    # ai_agent must reject results dispatched before the explicit clear.
    with CACHE_WRITE_LOCK:
        ai_agent.CACHE_INVALIDATION_GENERATION += 1
        return clear_cache_files(AI_CACHE_DIR, BREACH_CACHE_DIR, DISCOVERY_CACHE_DIR)
