import os
from typing import Mapping

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

# Load environment variables before importing modules that read configuration at import time.
load_dotenv(override=False)

from services.addon_manager import get_addon_manager
from services.pipeline import (
    clear_all_caches,
    get_tenant_id,
    purge_expired_caches,
    run_scan as run_scan_pipeline,
)
from utils.logging_setup import configure_logging, get_logger
from utils.risk import normalize_risk, risk_icon
from utils.translations import t

configure_logging()
logger = get_logger("App")
addon_manager = get_addon_manager()
st.set_page_config(
    page_title="Local Digital Footprint & Privacy Auditor",
    page_icon="🛡️",
    layout="wide",
)

LANG_OPTIONS = {
    "English": "en",
    "Bahasa Indonesia": "id",
    "Deutsch": "de",
    "Русский": "ru",
    "Español": "es",
    "العربية": "ar",
    "中文": "zh",
    "Français": "fr",
    "Italiano": "it",
    "Nederlands": "nl",
    "日本語": "ja",
}
ENGINE_STATUS_ICONS = {
    "ok": "✅",
    "partial": "⚠️",
    "error": "❌",
    "skipped": "⏭️",
}

def _md_escape(text: str) -> str:
    """Escape characters that could break out of a markdown link label."""
    return str(text).replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]")


def _finding_text(item: dict, lang: str) -> tuple[str, str]:
    """Localized title/snippet. Database findings are rendered from structured fields."""
    if item.get("kind") == "breach_db":
        title = (
            t("bd_title", lang=lang, name=item["dataset"])
            if item.get("dataset")
            else t(
                "bd_title_unknown",
                lang=lang,
                count=item.get("record_count", 0),
            )
        )
        return title, t(
            "bd_password_yes" if item.get("has_password") else "bd_password_no",
            lang=lang,
        )
    return str(item.get("title", "")), str(item.get("snippet", ""))


def _api_status(*keys: str) -> str:
    return (
        "🟢 Loaded"
        if all(os.getenv(key, "").strip() for key in keys)
        else "⚪ Off"
    )


def render_breach(scan_state: dict) -> None:
    breach = scan_state["breach"]
    if not breach["enabled"] or breach["error"]:
        return

    findings = breach["findings"]
    engines_report = breach["engines"]
    cache_status_msg = t("cached_tag", lang=lang) if breach["cached"] else ""
    failed_engines = [
        name
        for name, info in engines_report.items()
        if info.get("status") in ("error", "partial")
    ]

    if findings:
        st.warning(
            t(
                "warn_breach_found",
                lang=lang,
                count=len(findings),
                engine=breach["engine"],
                cache_status=cache_status_msg,
            )
        )
        if failed_engines:
            st.warning(
                t(
                    "breach_incomplete_with_hits",
                    lang=lang,
                    n_failed=len(failed_engines),
                    failed=", ".join(failed_engines),
                )
            )
    elif breach["complete"]:
        st.success(
            t(
                "success_no_breach",
                lang=lang,
                engine=breach["engine"],
                cache_status=cache_status_msg,
            )
        )
    else:
        # Jangan pernah menampilkan "aman" jika ada engine yang gagal.
        st.warning(
            t(
                "breach_incomplete",
                lang=lang,
                n_failed=len(failed_engines),
                failed=", ".join(failed_engines) or "-",
            )
        )

    if engines_report:
        with st.expander(t("engine_status_title", lang=lang)):
            for name, info in engines_report.items():
                status = info.get("status", "error")
                icon = ENGINE_STATUS_ICONS.get(status, "❔")
                st.write(
                    f"{icon} **{name}** — "
                    f"{t(f'engine_status_{status}', lang=lang)}"
                )

    if findings:
        st.divider()
        cache_badge = (
            t("cache_badge_data", lang=lang)
            if breach["cached"]
            else t("cache_badge_live", lang=lang)
        )
        st.subheader(
            t(
                "breach_details_title",
                lang=lang,
                cache_badge=cache_badge,
            )
        )

        with st.expander(
            t("expander_breach", lang=lang),
            expanded=True,
        ):
            for item in findings:
                finding_title, finding_snippet = _finding_text(item, lang)
                st.markdown(
                    f"**[{_md_escape(finding_title)}]({item['url']})**"
                )
                st.caption(
                    f"{t('source_label', lang=lang)}: {item['source']} | "
                    f"{t('link_label', lang=lang)}: {item['url']}"
                )
                st.write(finding_snippet)

                if item.get("kind") != "breach_db":
                    st.caption(
                        "⚠️ " + t("finding_unverified", lang=lang)
                    )

                st.divider()


def render_services(scan_state: dict) -> None:
    services = scan_state["services"]
    if not services:
        return

    st.divider()
    st.subheader(
        t(
            "services_count_title",
            lang=lang,
            count=len(services),
        )
    )

    df_display = (
        pd.DataFrame(services)
        .rename(
            columns={
                "name": t("col_service", lang=lang),
                "domain": t("col_domain", lang=lang),
                "source": t("col_source", lang=lang),
                "subject": t("col_sample", lang=lang),
            }
        )
        .drop(columns=["service"], errors="ignore")
    )

    st.dataframe(df_display, width="stretch")


def render_evidence(scan_state: dict) -> None:
    """Render newly discovered contextual evidence without duplicating findings.

    Scanner findings already have their own user-facing table. Base
    EvidenceRecords remain available for provenance, verification, AI, and
    future deterministic consumers, but scanner mirrors are not a second
    Findings surface. Only contextual enrichment evidence is presented here.
    """
    evidence = scan_state.get("evidence") or []
    contextual = [
        item
        for item in evidence
        if item.get("relation") == "security_publication"
        and item.get("directness") == "contextual"
    ]
    if not contextual:
        return

    st.divider()
    st.subheader(t("evidence_supporting_title", lang=lang))
    st.caption(
        t(
            "evidence_supporting_caption",
            lang=lang,
            count=len(contextual),
        )
    )

    with st.expander(
        t("evidence_supporting_expander", lang=lang),
        expanded=True,
    ):
        for item in contextual:
            title = str(
                item.get("title")
                or t("evidence_default_title", lang=lang)
            )
            st.markdown(f"**{_md_escape(title)}**")

            metadata = []
            source = item.get("source", "")
            published_at = item.get("published_at")
            observed_at = item.get("observed_at")
            if source:
                metadata.append(
                    f"{t('source_label', lang=lang)}: {_md_escape(source)}"
                )
            if published_at:
                metadata.append(
                    f"{t('evidence_published_label', lang=lang)}: "
                    f"{_md_escape(published_at)}"
                )
            if observed_at:
                metadata.append(
                    f"{t('evidence_observed_label', lang=lang)}: "
                    f"{_md_escape(observed_at)}"
                )
            if metadata:
                st.caption(" | ".join(metadata))

            summary = item.get("summary", "")
            if summary:
                st.text(str(summary))

            url = item.get("url", "")
            if isinstance(url, str) and url.startswith(("https://", "http://")):
                st.markdown(f"🔗 [{_md_escape(url)}]({url})")

            st.caption("---")


_ADDON_UI_ANCHOR_ORDER = ("discovery_imap", "discovery_osint", "breach", "evidence", "final")


def _addon_ui_anchor(addon: Mapping[str, object]) -> str:
    """Return the fixed visual region for an event-driven add-on UI."""
    events = addon.get("events") or []
    names = {
        str(event.get("name", "")).strip()
        for event in events
        if isinstance(event, Mapping)
    }
    if "discovery.imap.completed" in names:
        return "discovery_imap"
    if "discovery.osint.completed" in names:
        return "discovery_osint"
    if "breach.scan.completed" in names:
        return "breach"
    if names & {"evidence.enriched", "evidence.verified"}:
        return "evidence"
    return "final"


def _addon_ui_slot(
    addon_slots: Mapping[str, Mapping[str, object]] | None,
    addon: Mapping[str, object],
) -> object | None:
    if not addon_slots:
        return None
    addon_id = str(addon.get("id", "")).strip()
    anchor = _addon_ui_anchor(addon)
    return addon_slots.get(anchor, {}).get(addon_id)


def render_addon_uis(
    scan_state: dict,
    addon_slots=None,
    anchor: str | None = None,
) -> None:
    """Render active add-on UIs into their canonical visual region."""
    installed = addon_manager.list()
    addon_results = scan_state.get("addons") or {}
    for addon in installed:
        addon_id = str(addon.get("id", "")).strip()
        if (
            not addon_id
            or not addon.get("active")
            or addon.get("type") == "backend"
            or (anchor is not None and _addon_ui_anchor(addon) != anchor)
        ):
            continue

        slot = _addon_ui_slot(addon_slots, addon)
        try:
            ui_result = addon_results.get(addon_id)
            logger.info(
                "[UI] Add-on render dispatch: id=%s result_present=%s result_type=%s result_keys=%s",
                addon_id,
                ui_result is not None,
                type(ui_result).__name__,
                sorted(str(key) for key in ui_result.keys())
                if isinstance(ui_result, Mapping)
                else [],
            )
            ui_context = {
                "result": ui_result,
                "lang": lang,
            }
            if slot is not None:
                # A Streamlit empty placeholder is a replacement anchor.
                # Clear it before recreating its container; otherwise repeated
                # container() calls can accumulate UI blocks on each event.
                slot.empty()
                with slot.container():
                    addon_manager.invoke_ui(addon_id, ui_context, owner=str(addon.get("owner", "")))
            else:
                addon_manager.invoke_ui(addon_id, ui_context, owner=str(addon.get("owner", "")))
        except Exception as exc:
            if slot is not None:
                slot.empty()
                with slot.container():
                    st.error(
                        f"UI Add-On {addon_id} gagal: "
                        f"{type(exc).__name__}: {exc}"
                    )
            else:
                st.error(
                    f"UI Add-On {addon_id} gagal: "
                    f"{type(exc).__name__}: {exc}"
                )

def render_ai(scan_state: dict) -> None:
    ai_output = scan_state.get("ai")
    if not ai_output:
        return

    st.divider()
    st.subheader(t("ai_title", lang=lang))
    st.info(
        t(
            "info_provider_used",
            lang=lang,
            provider=ai_output.get("provider_used", "Local Cache"),
        )
    )

    tab1, tab2 = st.tabs(
        [
            t("tab_risk", lang=lang),
            t("tab_dsr", lang=lang),
        ]
    )

    with tab1:
        analysis_list = ai_output.get("analysis", [])
        exposures = ai_output.get("exposures", [])

        for item in analysis_list:
            risk_key = (
                normalize_risk(item.get("risk_key"))
                or normalize_risk(item.get("risk_level"))
                or "unknown"
            )
            risk_label = t(f"risk_{risk_key}", lang=lang)
            delete_url = item.get("delete_url", "-")

            st.markdown(
                f"**{risk_icon(risk_key)} "
                f"{_md_escape(item.get('service', ''))}** - "
                f"*{t('risk_level_label', lang=lang)}: {risk_label}*"
            )
            st.write(
                f"**{t('reason_label', lang=lang)}:** "
                f"{item.get('reason')}"
            )

            if item.get("evidence_count"):
                st.caption(
                    "⚠️ "
                    + t(
                        "evidence_note",
                        lang=lang,
                        count=item["evidence_count"],
                        level=risk_label,
                    )
                )

            if delete_url and delete_url != "-":
                if (
                    isinstance(delete_url, str)
                    and delete_url.startswith("https://")
                ):
                    st.markdown(
                        t(
                            "delete_link_label",
                            lang=lang,
                            url=delete_url,
                        )
                    )
                else:
                    st.write(f"🔗 {delete_url}")

            st.caption("---")

        if not analysis_list and not exposures:
            st.write(t("no_risk_analysis", lang=lang))

        if exposures:
            st.markdown(
                f"#### {t('exposures_title', lang=lang)}"
            )

            for exposure in exposures:
                exp_key = (
                    normalize_risk(exposure.get("risk_key"))
                    or "unknown"
                )
                exp_title, exp_snippet = _finding_text(
                    {"kind": "breach_db", **exposure},
                    lang,
                )

                st.markdown(
                    f"**{risk_icon(exp_key)} "
                    f"{_md_escape(exp_title)}** - "
                    f"*{t('risk_level_label', lang=lang)}: "
                    f"{t(f'risk_{exp_key}', lang=lang)}*"
                )
                st.write(exp_snippet)

            st.info(t("exposure_action", lang=lang))

    with tab2:
        dsr_text = ai_output.get("dsr_template", "")
        dsr_text = (
            dsr_text.strip()
            if isinstance(dsr_text, str)
            else ""
        )

        st.text_area(
            t("dsr_textarea_label", lang=lang),
            value=dsr_text,
            height=350,
        )
        st.download_button(
            label=t("dsr_download_btn", lang=lang),
            data=dsr_text,
            file_name=f"DSR_Request_{scan_state['email']}.txt",
            mime="text/plain",
        )


# Setup Pilihan Bahasa awal di Session State
st.session_state.setdefault("lang", "id")

# Hapus cache yang sudah kedaluwarsa sekali per sesi.
if not st.session_state.get("cache_purged"):
    purge_expired_caches()
    st.session_state["cache_purged"] = True

# Sidebar Configuration
with st.sidebar:
    st.header("⚙️ Configuration / Konfigurasi")

    current_lang_code = st.session_state.get("lang", "id")
    options_list = list(LANG_OPTIONS)
    default_index = next(
        (
            idx
            for idx, code in enumerate(LANG_OPTIONS.values())
            if code == current_lang_code
        ),
        0,
    )

    selected_lang_label = st.selectbox(
        "🌐 Language / Bahasa",
        options=options_list,
        index=default_index,
    )

    lang = LANG_OPTIONS[selected_lang_label]
    st.session_state["lang"] = lang

    st.subheader(t("sidebar_config", lang=lang))

    env_target_email = os.getenv("GMAIL_TARGET_ADDR", "")
    target_email = st.text_input(
        t("target_email", lang=lang),
        value=env_target_email,
        placeholder="email@gmail.com",
        help=t("target_email_help", lang=lang),
    )

    env_target_phone = os.getenv("TARGET_PHONE_NUM", "")
    target_phone = st.text_input(
        t("target_phone", lang=lang),
        value=env_target_phone,
        placeholder="+6281234567890",
        help=t("target_phone_help", lang=lang),
    )

    st.subheader(t("imap_title", lang=lang))
    enable_imap = st.checkbox(
        t("enable_imap", lang=lang),
        value=True,
    )

    # Password dari .env dipakai di sisi server saja; nilainya tidak pernah dikirim ke browser.
    env_gmail_pass = os.getenv("GMAIL_APP_PASSWORD", "")
    gmail_app_password_input = st.text_input(
        t("gmail_pass", lang=lang),
        value="",
        type="password",
        help=t("gmail_pass_help", lang=lang),
    )

    if env_gmail_pass and not gmail_app_password_input:
        st.caption(t("env_password_loaded", lang=lang))

    gmail_app_password = (
        gmail_app_password_input or env_gmail_pass
    )

    st.subheader(t("osint_title", lang=lang))
    enable_osint = st.checkbox(
        t("enable_osint", lang=lang),
        value=True,
    )
    enable_breach = st.checkbox(
        t("enable_breach", lang=lang),
        value=True,
    )
    enable_evidence_enrichment = st.checkbox(
        t("enable_evidence_enrichment", lang=lang),
        value=True,
        help="Run the Evidence Enrichment pipeline stage.",
    )
    force_refresh_breach = st.checkbox(
        t("force_refresh", lang=lang),
        value=False,
        help=t("force_refresh_help", lang=lang),
    )

    st.subheader(t("api_status_title", lang=lang))

    gemini_count = sum(
        bool(os.getenv(f"GOOGLE_API_KEY_{i}", "").strip())
        for i in range(1, 7)
    )
    has_groq = _api_status("GROQ_API_KEY")
    has_openai = _api_status("OPENAI_API_KEY")
    has_rapidapi = _api_status("RAPIDAPI_KEY")
    has_hibp = _api_status("HIBP_API_KEY")
    has_tavily = _api_status("TAVILY_API_KEY")
    has_firecrawl = _api_status("FIRECRAWL_API_KEY")
    has_gsearch = _api_status(
        "GOOGLE_SEARCH_API_KEY",
        "GOOGLE_CX_ID",
    )

    st.caption(
        f"• **Gemini Keys:** {gemini_count}/6 "
        f"{t('keys_active', lang=lang)}"
    )
    st.caption(f"• **Groq API:** {has_groq}")
    st.caption(f"• **OpenAI API:** {has_openai}")
    st.caption(f"• **RapidAPI (BreachDB):** {has_rapidapi}")
    st.caption(f"• **Have I Been Pwned API:** {has_hibp}")
    st.caption(f"• **Google Custom Search:** {has_gsearch}")
    st.caption(f"• **Tavily AI Search:** {has_tavily}")
    st.caption(f"• **Firecrawl Evidence Enrichment:** {has_firecrawl}")
    st.caption("• **SearXNG & DDG:** 🟢 Active (Always Free)")
    st.subheader("4. Add-On")
    uploaded_addon = st.file_uploader(
        "Install Add-On (.zip)",
        type=["zip"],
        key="addon_zip_upload",
        help="Install Add-On (.zip)",
        label_visibility="collapsed",
    )
    if uploaded_addon is not None and st.button(
        "Install Add-On",
        width="stretch",
        key="addon_install_button",
    ):
        try:
            installed = addon_manager.install_zip(uploaded_addon.getvalue())
            st.success(
                f"{installed['name']} {installed['version']} installed."
            )
            st.rerun()
        except Exception as exc:
            st.error(f"Install Add-On gagal: {type(exc).__name__}: {exc}")

    installed_addons = addon_manager.list()
    if not installed_addons:
        st.caption("Belum ada Add-On terpasang.")
    else:
        for addon in installed_addons:
            addon_label_col, uninstall_col, action_col  = st.columns(3)
            with addon_label_col:
                st.caption(f"**{addon['name']}**  \n"
                    f"Version: {addon['version']}"
                )
            with uninstall_col:
                if st.button(
                    "Uninstall",
                    width="stretch",
                    key=f"addon_uninstall_{addon['id']}",
                    type="tertiary",
                ):
                    try:
                        addon_manager.uninstall(addon["id"])
                        st.rerun()
                    except Exception as exc:
                        st.error(
                            f"Uninstall gagal: {type(exc).__name__}: {exc}"
                        )
            with action_col:
                action_label = "🟢 Deactivate" if addon["active"] else "⚪ Activate"
                if st.button(
                    action_label,
                    width="stretch",
                    key=f"addon_toggle_{addon['id']}",
                    type="tertiary",
                ):
                    try:
                        if addon["active"]:
                            addon_manager.deactivate(addon["id"])
                        else:
                            addon_manager.activate(addon["id"])
                        st.rerun()
                    except Exception as exc:
                        st.error(
                            f"Add-On action gagal: {type(exc).__name__}: {exc}"
                        )

    active_addons = tuple(
        addon["id"]
        for addon in addon_manager.list()
        if addon["active"]
        and addon["invocation"]["mode"] == "on_demand"
    )


    run_scan = st.button(
        t("btn_run", lang=lang),
        type="primary",
        width="stretch",
    )

    if st.button(
        t("btn_clear_cache", lang=lang),
        width="stretch",
    ):
        st.success(
            t(
                "cache_cleared",
                lang=lang,
                count=clear_all_caches(),
            )
        )

# Dashboard Main Header
st.title(t("title", lang=lang))
st.caption(t("caption", lang=lang))

# Dashboard Logic Execution.
# Keep the proven main-branch rendering lifecycle:
# one live surface, append completed stages in pipeline order, and render
# the final AI result once the pipeline returns. Evidence and Scorecard use
# the same append-style lifecycle without placeholder reconciliation.
scan_executed = False

if run_scan:
    if not target_email or not target_email.strip():
        st.error(t("err_no_email", lang=lang))
    else:
        scan_executed = True

        # Keep the proven main-branch visual model: one persistent result
        # surface. Result slots are reserved in canonical pipeline order so
        # downstream stages can never appear above discovery results even when
        # their callbacks arrive later.
        live_area = st.container()

        live_state = {
            "email": target_email.strip(),
            "phone": target_phone.strip(),
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
            "addons": {},
        }

        # Reserve the live pipeline in the same visual order as the
        # established main-branch UX. Discovery is intentionally progressive:
        # IMAP terminal status -> IMAP Add-On UI -> OSINT terminal status ->
        # OSINT Add-On UI -> combined IMAP+OSINT services table -> downstream stages.
        with live_area:
            progress_status = st.empty()

            discovery_status_slots = {
                "imap": st.empty() if enable_imap else None,
            }

            addon_ui_slots = {
                anchor: {}
                for anchor in _ADDON_UI_ANCHOR_ORDER
            }

            for addon in addon_manager.list():
                addon_id = str(addon.get("id", "")).strip()
                if (
                    not addon_id
                    or not addon.get("active")
                    or addon.get("type") == "backend"
                    or _addon_ui_anchor(addon) != "discovery_imap"
                ):
                    continue
                addon_ui_slots["discovery_imap"][addon_id] = st.empty()

            discovery_status_slots["osint"] = (
                st.empty() if enable_osint else None
            )

            for addon in addon_manager.list():
                addon_id = str(addon.get("id", "")).strip()
                if (
                    not addon_id
                    or not addon.get("active")
                    or addon.get("type") == "backend"
                    or _addon_ui_anchor(addon) != "discovery_osint"
                ):
                    continue
                addon_ui_slots["discovery_osint"][addon_id] = st.empty()

            services_slot = st.empty()

            breach_status_slot = st.empty() if enable_breach else None
            breach_slot = st.empty()

            for addon in addon_manager.list():
                addon_id = str(addon.get("id", "")).strip()
                if (
                    not addon_id
                    or not addon.get("active")
                    or addon.get("type") == "backend"
                    or _addon_ui_anchor(addon) != "breach"
                ):
                    continue
                addon_ui_slots["breach"][addon_id] = st.empty()

            evidence_status_slot = st.empty()
            evidence_slot = st.empty()

            for addon in addon_manager.list():
                addon_id = str(addon.get("id", "")).strip()
                if (
                    not addon_id
                    or not addon.get("active")
                    or addon.get("type") == "backend"
                    or _addon_ui_anchor(addon) != "evidence"
                ):
                    continue
                addon_ui_slots["evidence"][addon_id] = st.empty()

            for addon in addon_manager.list():
                addon_id = str(addon.get("id", "")).strip()
                if (
                    not addon_id
                    or not addon.get("active")
                    or addon.get("type") == "backend"
                    or _addon_ui_anchor(addon) != "final"
                ):
                    continue
                addon_ui_slots["final"][addon_id] = st.empty()

            ai_status_slot = st.empty()
            ai_slot = st.empty()

        status_slots = {
            "breach": breach_status_slot,
            "evidence": evidence_status_slot,
            "ai": ai_status_slot,
        }

        def _event_message(event: dict) -> str:
            message = event.get("text")
            if not message and event.get("key"):
                message = t(
                    event["key"],
                    lang=lang,
                    **event.get("args", {}),
                )
            return str(message or "")

        def _clear_status(stage: str) -> None:
            slot = status_slots.get(stage)
            if slot is not None:
                slot.empty()

        def _show_status(stage: str, event: dict) -> None:
            message = _event_message(event)
            slot = status_slots.get(stage)
            if slot is None or not message:
                return

            level = event.get("level", "info")
            renderer = getattr(st, level, st.info)
            with slot.container():
                renderer(message)

        def _render_services() -> None:
            """Replace the discovery result anchor with current accumulated services."""
            services_slot.empty()
            if not live_state["services"]:
                return
            with services_slot.container():
                render_services(live_state)

        def push_event(event: dict) -> None:
            stage = event.get("stage")
            live_data = event.get("_live") or {}

            # Discovery deliberately preserves the main-branch UX:
            # terminal IMAP/OSINT messages remain visible, while the combined
            # services table is rendered only after the final enabled discovery
            # stage completes.
            if stage in ("imap", "osint"):
                if "services" in live_data:
                    live_state["services"].extend(live_data["services"])

                slot = discovery_status_slots.get(stage)
                message = _event_message(event)
                if slot is not None and message:
                    slot.empty()
                    with slot.container():
                        renderer = getattr(
                            st,
                            event.get("level", "info"),
                            st.info,
                        )
                        renderer(message)

                if event.get("level") in {"success", "warning", "error"}:
                    if stage == "osint" or not enable_osint:
                        _render_services()
                return

            # Downstream result anchors are positioned according to the
            # canonical event region, so completion timing cannot change visual order.
            if stage == "breach":
                if "breach" in live_data:
                    _clear_status("breach")
                    live_state["breach"] = live_data["breach"]
                    with breach_slot.container():
                        render_breach(live_state)
                else:
                    _show_status("breach", event)
                return

            if stage == "evidence":
                if "evidence" in live_data:
                    _clear_status("evidence")
                    live_state["evidence"] = live_data["evidence"]
                    with evidence_slot.container():
                        render_evidence(live_state)
                else:
                    _show_status("evidence", event)
                return

            addon = addon_manager.get(str(stage)) if stage else None
            if (
                addon
                and addon.get("active")
                and addon.get("type") != "backend"
            ):
                addon_id = str(stage)
                result = live_data.get("result")
                result_key = addon.get("result_key")
                if result is None and result_key:
                    result = live_data.get(result_key)
                if result is not None:
                    live_state["addons"][addon_id] = result
                    slot = _addon_ui_slot(addon_ui_slots, addon)
                    ui_context = {
                        "result": result,
                        "lang": lang,
                    }
                    try:
                        if slot is not None:
                            # Replace the fixed placeholder contents instead of
                            # appending another UI block for every pipeline event.
                            slot.empty()
                            with slot.container():
                                addon_manager.invoke_ui(addon_id, ui_context, owner=str(live_data.get("owner", addon.get("owner", ""))))
                        else:
                            addon_manager.invoke_ui(addon_id, ui_context, owner=str(live_data.get("owner", addon.get("owner", ""))))
                    except Exception as exc:
                        if slot is not None:
                            slot.empty()
                            with slot.container():
                                st.error(
                                    f"UI Add-On {addon_id} gagal: "
                                    f"{type(exc).__name__}: {exc}"
                                )
                        else:
                            st.error(
                                f"UI Add-On {addon_id} gagal: "
                                f"{type(exc).__name__}: {exc}"
                            )
                else:
                    _show_status(addon_id, event)
                return

            if stage == "ai":
                if "ai" in live_data:
                    _clear_status("ai")
                    live_state["ai"] = live_data["ai"]
                else:
                    _show_status("ai", event)
                return

        progress_status.info(t("spinner_processing", lang=lang))

        final_state = run_scan_pipeline(
            email=target_email,
            phone=target_phone,
            gmail_app_password=gmail_app_password,
            enable_imap=enable_imap,
            enable_osint=enable_osint,
            enable_breach=enable_breach,
            enable_evidence_enrichment=enable_evidence_enrichment,
            force_refresh=force_refresh_breach,
            lang=lang,
            tenant_id=get_tenant_id(),
            with_ai=True,
            enabled_addons=active_addons,
            on_event=push_event,
        )

        # The returned pipeline state is authoritative. Reconcile all result
        # anchors once more so cache-hit/disabled/error paths cannot leave the
        # live UI out of sync with the final state.
        live_state.update(
            {
                "services": list(final_state.get("services") or []),
                "evidence": list(final_state.get("evidence") or []),
                "breach": final_state.get("breach") or live_state["breach"],
                "addons": dict(final_state.get("addons") or {}),
                "ai": final_state.get("ai"),
            }
        )

        _render_services()

        if live_state["breach"].get("enabled"):
            with breach_slot.container():
                render_breach(live_state)

        with evidence_slot.container():
            render_evidence(live_state)

        # On-event Add-Ons are already rendered at their event boundary above.
        # Re-rendering them here would create a second UI invocation after the
        # pipeline completes. Only on-demand Add-Ons need final reconciliation.
        for addon in addon_manager.list():
            addon_id = str(addon.get("id", "")).strip()
            if (
                not addon_id
                or not addon.get("active")
                or addon.get("type") == "backend"
                or addon.get("invocation", {}).get("mode") != "on_demand"
            ):
                continue
            ui_result = live_state["addons"].get(addon_id)
            if ui_result is None:
                continue
            slot = _addon_ui_slot(addon_ui_slots, addon)
            ui_context = {
                "result": ui_result,
                "lang": lang,
            }
            try:
                if slot is not None:
                    slot.empty()
                    with slot.container():
                        addon_manager.invoke_ui(addon_id, ui_context, owner=str(addon.get("owner", "")))
                else:
                    addon_manager.invoke_ui(addon_id, ui_context)
            except Exception as exc:
                if slot is not None:
                    slot.empty()
                    with slot.container():
                        st.error(
                            f"UI Add-On {addon_id} gagal: "
                            f"{type(exc).__name__}: {exc}"
                        )
                else:
                    st.error(
                        f"UI Add-On {addon_id} gagal: "
                        f"{type(exc).__name__}: {exc}"
                    )

        with ai_slot.container():
            render_ai(live_state)

        # No transient "Memindai..." state survives a completed pipeline.
        progress_status.empty()
        for slot in status_slots.values():
            if slot is not None:
                slot.empty()

        st.session_state["scan_state"] = final_state


state = st.session_state.get("scan_state")

# On rerun (download, language change, cache clear, etc.), render the stored
# result in the same pipeline order as the first run.
if state and not scan_executed:
    render_addon_uis(state, anchor="discovery_imap")
    render_addon_uis(state, anchor="discovery_osint")
    render_services(state)
    render_breach(state)
    render_addon_uis(state, anchor="breach")
    render_evidence(state)
    render_addon_uis(state, anchor="evidence")
    render_addon_uis(state, anchor="final")

    if not state["services"] and not state["breach"]["findings"]:
        st.warning(t("warn_no_services", lang=lang))

    render_ai(state)
