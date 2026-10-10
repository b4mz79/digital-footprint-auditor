"""The scan flow, independent of Streamlit."""
from __future__ import annotations

import asyncio
import os
import re
from typing import Any, Callable, Mapping

from cache_security import clear_cache_files, purge_expired
from services.addon_manager import get_addon_manager
from services.ai_agent import (
    CACHE_DIR as AI_CACHE_DIR,
    CACHE_WRITE_LOCK,
    analyze_smart_cache,
)
import services.ai_agent as ai_agent
from services.breach_scanner import BREACH_CACHE_DIR, scan_data_breaches
from services.evidence_enrichment import ENRICHMENT_CACHE_DIR, enrich_evidence
from services.enrichment.verification import (
    mark_verification_unknown,
    verify_evidence_records,
)
from services.enrichment.evidence import evidence_to_dicts, service_findings_to_evidence
from services.imap_scanner import IMAP_CACHE_DIR, imap_cache_enabled, load_imap_cache, save_imap_cache, scan_gmail_inbox
from services.osint_scanner import OSINT_CACHE_DIR, load_osint_cache, osint_cache_enabled, save_osint_cache, scan_osint_footprint
from utils.envutil import env_bool, env_non_negative_int
from utils.logging_setup import get_logger
from utils.translations import t

logger = get_logger("Pipeline")

_TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")


def _validate_tenant_id(value: str) -> str:
    """Validate tenant identity without silently crossing into the shared default."""
    if not isinstance(value, str):
        raise TypeError("tenant_id harus berupa string.")
    normalized = value.strip()
    if not _TENANT_RE.fullmatch(normalized):
        raise ValueError(
            "TENANT_ID tidak valid; pemakaian cache dihentikan untuk menjaga isolasi tenant."
        )
    return normalized


def get_tenant_id() -> str:
    """TENANT_ID isolates caches when several people share one install."""
    value = os.getenv("TENANT_ID")
    if value is None:
        return "default"
    return _validate_tenant_id(value)


def clear_all_caches() -> int:
    """Clear all application caches and invalidate pending AI cache writes."""
    with ai_agent.CACHE_WRITE_LOCK:
        ai_agent.CACHE_INVALIDATION_GENERATION += 1

    return clear_cache_files(
        AI_CACHE_DIR,
        BREACH_CACHE_DIR,
        IMAP_CACHE_DIR,
        OSINT_CACHE_DIR,
        ENRICHMENT_CACHE_DIR,
    )


def purge_expired_caches() -> int:
    """Purge expired application cache files using the configured retention window."""
    retention_hours = env_non_negative_int(
        "CACHE_RETENTION_HOURS",
        24,
        24 * 365,
    )
    max_age_seconds = retention_hours * 3600
    return purge_expired(
        AI_CACHE_DIR,
        max_age_seconds,
    ) + purge_expired(
        BREACH_CACHE_DIR,
        max_age_seconds,
    ) + purge_expired(
        IMAP_CACHE_DIR,
        max_age_seconds,
    ) + purge_expired(
        OSINT_CACHE_DIR,
        max_age_seconds,
    ) + purge_expired(
        ENRICHMENT_CACHE_DIR,
        max_age_seconds,
    )


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
    enable_evidence_enrichment: bool = True,
    force_refresh: bool = False,
    lang: str = "en",
    tenant_id: str | None = None,
    with_ai: bool = True,
    on_event: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    tenant_id = get_tenant_id() if tenant_id is None else _validate_tenant_id(tenant_id)
    email = email.strip()
    phone = (phone or "").strip()

    # Resolve each module's cache policy at the pipeline boundary. Cache
    # ownership remains in the scanner modules; the pipeline only orchestrates.
    imap_cache_on = imap_cache_enabled()
    osint_cache_on = osint_cache_enabled()

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
        "addons": {},
        "addon_events": {},
        "addon_owners": {},
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

    def dispatch_addon_event(
        owner: str,
        event_name: str,
        data: Mapping[str, Any] | None = None,
    ) -> None:
        """Dispatch one canonical lifecycle event without knowing any add-on domain."""
        try:
            addon_manager = get_addon_manager()
            results = addon_manager.dispatch_event(
                event_name,
                {
                    "data": dict(data or {}),
                },
                owner=owner,
            )
        except Exception as exc:
            logger.warning(
                "[Pipeline] Add-on event dispatch failed for %s: %s",
                event_name,
                exc,
            )
            emit(
                _event(
                    "error",
                    key="error_addon_event",
                    event_name=event_name,
                    error=str(exc),
                )
            )
            return

        if not results:
            return

        event_results = state["addon_events"].setdefault(event_name, {})
        for addon, addon_output in results:
            addon_id = str(addon["id"])
            event_results[addon_id] = addon_output
            state["addons"][addon_id] = addon_output
            state["addon_owners"][addon_id] = owner
            logger.info(
                "[Pipeline] Add-on result stored: id=%s result_type=%s result_keys=%s",
                addon_id,
                type(addon_output).__name__,
                sorted(str(key) for key in addon_output.keys())
                if isinstance(addon_output, Mapping)
                else [],
            )

            result_key = addon.get("result_key")
            if result_key:
                if isinstance(addon_output, Mapping):
                    state[result_key] = addon_output.get(result_key)
                else:
                    state[result_key] = None

            live_payload = (
                {result_key: state[result_key]}
                if result_key
                else {"addon": addon_id, "result": addon_output}
            )
            # Producer ownership comes from the trusted built-in caller,
            # not from add-on metadata. This value is provenance for the UI
            # and rerender path; it is not add-on-controlled input.
            live_payload["owner"] = owner
            logger.info(
                "[Pipeline] Add-on live payload: id=%s result_present=%s payload_keys=%s",
                addon_id,
                addon_output is not None,
                sorted(str(key) for key in live_payload.keys()),
            )
            emit(
                _event(
                    "success",
                    key="addon_event_finished",
                    addon_id=addon_id,
                    event_name=event_name,
                    stage=addon_id,
                ),
                live_payload,
            )

    # Step 1: Gmail via IMAP
    if enable_imap:
        if not gmail_app_password:
            emit(_event("warning", "warn_no_gmail_pass", stage="imap"))
        else:
            cached = load_imap_cache(email, tenant_id=tenant_id) if (imap_cache_on and not force_refresh) else None
            if cached is not None:
                logger.info("[IMAP Cache] HIT")
                found = cached
            else:
                logger.info("[IMAP Cache] %s", "MISS" if imap_cache_on else "OFF -> fresh scan")
                emit(_event("info", "info_imap_scanning", stage="imap"))
                try:
                    found = scan_gmail_inbox(email, gmail_app_password, lang=lang)
                    if imap_cache_on:
                        save_imap_cache(email, found, tenant_id=tenant_id)
                except Exception as exc:
                    emit(_event("error", "error_imap", stage="imap", error=str(exc)))
                    found = None
            if found is not None:
                state["services"].extend(found)
                emit(_event("success", "success_imap", stage="imap", count=len(found)), {"services": found})
                dispatch_addon_event(
                    "imap",
"discovery.imap.completed",
                    {"services": list(found)},
                )

    # Step 2: OSINT via Holehe
    if enable_osint:
        cached = load_osint_cache(email, tenant_id=tenant_id) if (osint_cache_on and not force_refresh) else None
        if cached is not None:
            logger.info("[OSINT Cache] HIT")
            found = cached
        else:
            logger.info("[OSINT Cache] %s", "MISS" if osint_cache_on else "OFF -> fresh scan")
            emit(_event("info", "info_osint_scanning", stage="osint"))
            try:
                found = scan_osint_footprint(email, lang=lang)
                if osint_cache_on:
                    save_osint_cache(email, found, tenant_id=tenant_id)
            except Exception as exc:
                emit(_event("error", "error_osint", stage="osint", error=str(exc)))
                found = None
        if found is not None:
            state["services"].extend(found)
            emit(_event("success", "success_osint", stage="osint", count=len(found)), {"services": found})
            dispatch_addon_event(
                "osint",
"discovery.osint.completed",
                {"services": list(found)},
            )

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
                    key="breach_scan_complete",
                    stage="breach",
                ),
                {"breach": dict(state["breach"])},
            )
            dispatch_addon_event(
                "breach",
"breach.scan.completed",
                {"breach": dict(state["breach"])},
            )
        except Exception as exc:
            state["breach"]["error"] = str(exc)
            emit(_event("error", "error_breach_scan", stage="breach", error=str(exc)))

    # Step 4: Evidence Enrichment
    #
    # This is a first-class built-in pipeline stage, controlled by the same
    # runtime execution flag pattern as IMAP, OSINT, and Breach.
    #
    # When disabled, do not normalize, enrich, verify, or dispatch any
    # evidence-stage events. The downstream AI therefore receives the
    # pre-enrichment input path: scanner services + breach findings.
    if enable_evidence_enrichment:
        # Normalize scanner output into stable evidence records after all
        # discovery stages. This is lineage only; it does not calculate risk
        # and does not alter scanner findings.
        try:
            local_evidence = service_findings_to_evidence(state["services"])
        except Exception as exc:
            # Evidence normalization is additive. A malformed finding or
            # normalizer regression must not abort the established scan/AI path.
            # Preserve scanner findings and continue with an empty evidence ledger.
            logger.warning(
                "[Pipeline] Evidence normalization failed; continuing without evidence: %s",
                type(exc).__name__,
            )
            local_evidence = []
            emit(
                _event(
                    "warning",
                    key="evidence_normalization_failed",
                    stage="evidence_start",
                    error_type=type(exc).__name__,
                )
            )

        emit(
            _event(
                "info",
                key=(
                    "evidence_enrichment_start"
                    if os.getenv("FIRECRAWL_API_KEY", "").strip()
                    else "evidence_enrichment_skipped"
                ),
                stage="evidence_start",
            ),
        )

        try:
            enriched_evidence = asyncio.run(
                enrich_evidence(
                    local_evidence,
                    force_refresh=force_refresh,
                    tenant_id=tenant_id,
                )
            )
        except Exception as exc:
            # Preserve normalized evidence if optional enrichment is unavailable.
            logger.warning("[Pipeline] Evidence enrichment failed: %s", exc)
            enriched_evidence = local_evidence

        dispatch_addon_event(
            "evidence",
            "evidence.enriched",
            {"evidence": list(evidence_to_dicts(enriched_evidence))},
        )

        try:
            verified_evidence = asyncio.run(
                verify_evidence_records(enriched_evidence)
            )
        except Exception as exc:
            # Verification is a quality/provenance signal only. If the verifier
            # itself is unavailable, preserve the enriched evidence unchanged.
            logger.warning(
                "[Pipeline] Evidence URL verification failed: %s",
                exc,
            )
            # A failed verification pass cannot preserve URL state from an
            # earlier run. Keep the evidence, but invalidate its stale signal.
            verified_evidence = enriched_evidence
            for record in verified_evidence:
                mark_verification_unknown(record)

        state["evidence"] = evidence_to_dicts(verified_evidence)
        dispatch_addon_event(
            "evidence",
"evidence.verified",
            {"evidence": list(state["evidence"])},
        )
        contextual_count = sum(
            1
            for item in state["evidence"]
            if item.get("relation") == "security_publication"
        )
        emit(
            _event(
                "success",
                key="evidence_enrichment_complete",
                stage="evidence",
                count=len(state["evidence"]),
                contextual_count=contextual_count,
            ),
            {"evidence": list(state["evidence"])},
        )
    else:
        logger.info(
            "[Pipeline] Evidence Enrichment disabled; preserving pre-enrichment AI input path. "
            "AI receives scanner services + breach findings only."
        )
        state["evidence"] = []

    # On-demand add-ons are intentionally not invoked from the global
    # pipeline. An on-demand add-on must be called by its owning built-in
    # module through an owner-scoped host call; otherwise the global pipeline
    # would become a cross-owner execution authority.

    if with_ai:
        addon_ai_context: dict[str, Any] = {}
        try:
            addon_manager = get_addon_manager()
            for addon in addon_manager.list():
                addon_id = str(addon.get("id", "")).strip()
                if (
                    addon_id
                    and bool(addon.get("active"))
                    and bool(addon.get("ai_context"))
                    and addon_id in state["addons"]
                ):
                    addon_ai_context[addon_id] = state["addons"][addon_id]
        except Exception as exc:
            # Add-on AI context is optional. A manager failure must not break
            # the established AI path.
            logger.warning("[Pipeline] Failed to prepare Add-On AI context: %s", exc)

        run_ai(
            state,
            lang,
            force_refresh=force_refresh,
            addon_results=addon_ai_context,
            on_event=on_event,
        )

    logger.info(
        "[Pipeline] run_scan completed; returning state. services=%d evidence=%d breach=%d ai=%s",
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
    addon_results: Mapping[str, Any] | None = None,
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

    emit(_event("info", "spinner_ai", stage="ai"))

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
            "addon_results": dict(addon_results or {}),
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
                key="ai_completed",
                stage="ai",
            ),
            {"ai": state["ai"]},
        )
    except Exception as exc:
        state["ai"] = None
        logger.exception("[Pipeline] AI execution failed")
        emit(_event("error", "ai_failed", stage="ai", error_type=type(exc).__name__, error=str(exc)))