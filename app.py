import os

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

# Load environment variables before importing modules that read configuration at import time.
load_dotenv(override=False)

from services.pipeline import (
    clear_all_caches,
    get_tenant_id,
    purge_expired_caches,
    run_scan as run_scan_pipeline,
)
from utils.logging_setup import configure_logging
from utils.risk import normalize_risk, risk_icon
from utils.translations import t

configure_logging()
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

# Temporary application-level integration profile for the Scorecard Add-on.
# This is deliberately NOT the final Privacy Auditor business scorecard.
# It uses bounded evidence-sufficiency measurements so the real pipeline
# integration can be validated without inventing final KPI weights/formulas.
SCORECARD_INTEGRATION_DEFINITION = {
    "schema_version": "scorecard-definition-v1",
    "scorecard_id": "evidence-sufficiency-integration",
    "version": "v1",
    "score": {
        "canonical_range": {"min": 0.0, "max": 1.0},
        "precision": 2,
        "rounding": "half_even",
    },
    "aggregation": {
        "operation": "weighted_sum",
        "weights": {
            "evidence_record_coverage": 0.5,
            "verification_coverage": 0.5,
        },
    },
}

SCORECARD_INTEGRATION_RISK_POLICY = {
    "schema_version": "risk-policy-v1",
    "risk_policy_id": "evidence-sufficiency-integration-policy",
    "version": "v1",
    "output": {"risk_bands": ["high", "medium", "low", "unknown"]},
    "mapping": {
        "rules": [
            {
                "rule_id": "low-evidence-risk",
                "priority": 10,
                "condition": {
                    "type": "score_threshold",
                    "parameters": {"operator": ">=", "value": 0.8},
                },
                "then": "low",
            },
            {
                "rule_id": "medium-evidence-risk",
                "priority": 20,
                "condition": {
                    "type": "score_threshold",
                    "parameters": {"operator": ">=", "value": 0.5},
                },
                "then": "medium",
            },
            {
                "rule_id": "high-evidence-risk",
                "priority": 30,
                "condition": {
                    "type": "score_threshold",
                    "parameters": {"operator": ">=", "value": 0.0},
                },
                "then": "high",
            },
        ]
    },
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
    """Render normalized evidence and contextual enrichment without implying risk."""
    evidence = scan_state.get("evidence") or []
    if not evidence:
        return

    contextual = [
        item for item in evidence
        if item.get("relation") == "security_publication"
    ]
    verified = [
        item for item in evidence
        if item.get("relation") == "verification"
    ]

    st.divider()
    st.subheader("🔎 Evidence & Enrichment")
    st.caption(
        f"{len(evidence)} evidence record(s) • "
        f"{len(contextual)} contextual security-publication record(s) • "
        f"{len(verified)} verification record(s)"
    )

    with st.expander("Evidence provenance / provenance bukti", expanded=False):
        for item in evidence:
            relation = str(item.get("relation", "unknown"))
            directness = str(item.get("directness", "unknown"))
            confidence = float(item.get("confidence", 0.0) or 0.0)

            st.markdown(
                f"**{_md_escape(item.get('title', 'Evidence'))}** "
                f"— `{relation}` / `{directness}` / "
                f"confidence `{confidence:.2f}`"
            )
            source = item.get("source", "")
            source_type = item.get("source_type", "")
            if source or source_type:
                st.caption(
                    f"{t('source_label', lang=lang)}: {source} "
                    f"| type: {source_type}"
                )

            published_at = item.get("published_at")
            observed_at = item.get("observed_at")
            if published_at:
                st.caption(f"Published: {published_at}")
            if observed_at:
                st.caption(f"Observed: {observed_at}")

            summary = item.get("summary", "")
            if summary:
                # Evidence text is untrusted web content. Render it as plain
                # text so Markdown/HTML cannot become UI artefacts.
                st.text(str(summary))

            url = item.get("url", "")
            if isinstance(url, str) and url.startswith(("https://", "http://")):
                st.markdown(f"🔗 [{_md_escape(url)}]({url})")

            st.caption("---")


def render_scorecard(scan_state: dict) -> None:
    """Render the optional Scorecard Add-on result without recalculating it."""
    result = scan_state.get("scorecard")
    if not isinstance(result, dict):
        return

    st.divider()
    st.subheader("📊 Scorecard Add-on")
    risk_key = normalize_risk(result.get("risk_band")) or "unknown"
    score = result.get("score")
    score_text = "UNKNOWN" if score is None else f"{score:.2f}"

    st.metric("Score", score_text)
    st.markdown(
        f"**Risk band:** {risk_icon(risk_key)} "
        f"{risk_key.upper()}  •  **State:** `{result.get('state', 'unknown')}`"
    )
    st.caption(
        f"Scorecard: `{result.get('scorecard_id', '-')}` / "
        f"version `{result.get('scorecard_version', '-')}` • "
        f"Result: `{result.get('result_id', '-')}`"
    )

    contributions = result.get("contributions") or []
    if contributions:
        rows = [
            {
                "KPI": item.get("kpi_id", ""),
                "Value": item.get("value"),
                "Weight": item.get("weight"),
                "Contribution": item.get("contribution"),
            }
            for item in contributions
            if isinstance(item, dict)
        ]
        if rows:
            st.dataframe(pd.DataFrame(rows), width="stretch")

    lineage = result.get("calculation_lineage")
    if lineage:
        with st.expander("Scorecard calculation lineage", expanded=False):
            st.json(lineage)


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
# Saat scan berjalan, hasil setiap stage langsung ditampilkan.
scan_executed = False

if run_scan:
    if not target_email or not target_email.strip():
        st.error(t("err_no_email", lang=lang))
    else:
        scan_executed = True

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
        }

        ui_state = {
            "ai_status": None,
            "ai_live_placeholder": None,
            "ai_live_items": [],
        }

        def push_event(event: dict) -> None:
            stage = event.get("stage")
            live_data = event.get("_live", {})

            # Breach selesai: render hasil breach sebelum stage berikutnya dimulai.
            # Evidence & Enrichment memang berjalan setelah breach di pipeline,
            # tetapi UI harus menampilkan breach terlebih dahulu agar urutan
            # visual mengikuti urutan kerja modul discovery yang sudah ada.
            if stage == "breach" and "breach" in live_data:
                live_state["breach"] = live_data["breach"]
                with live_area:
                    render_breach(live_state)
                return

            if stage == "evidence_start":
                message = event.get("text") or "Memulai Evidence & Enrichment..."
                with live_area:
                    st.info(f"⏳ {message}")
                return

            if stage == "evidence" and "evidence" in live_data:
                # Keep live state in sync. The final renderer below owns the
                # completed evidence block so Streamlit does not show it twice.
                live_state["evidence"] = live_data["evidence"]
                contextual_count = event.get("contextual_count", 0)
                with live_area:
                    st.success(
                        "✅ Evidence & Enrichment selesai — "
                        f"{len(live_state['evidence'])} evidence, "
                        f"{contextual_count} contextual"
                    )
                return

            # AI:
            # Service AI dirender progressive: satu item selesai -> langsung tampil.
            if stage == "ai":
                if "ai_reset" in live_data and live_data["ai_reset"]:
                    ui_state["ai_live_items"].clear()
                    placeholder = ui_state.get("ai_live_placeholder")
                    if placeholder is not None:
                        placeholder.empty()
                    return

                if "ai_item" in live_data:
                    item = live_data["ai_item"]
                    ui_state["ai_live_items"].append(item)

                    placeholder = ui_state.get("ai_live_placeholder")
                    if placeholder is not None:
                        with placeholder.container():
                            for live_item in ui_state["ai_live_items"]:
                                risk_key = (
                                    normalize_risk(live_item.get("risk_key"))
                                    or normalize_risk(live_item.get("risk_level"))
                                    or "unknown"
                                )
                                risk_label = t(f"risk_{risk_key}", lang=lang)
                                st.markdown(
                                    f"**{risk_icon(risk_key)} "
                                    f"{_md_escape(live_item.get('service', ''))}** - "
                                    f"*{t('risk_level_label', lang=lang)}: {risk_label}*"
                                )
                                st.write(
                                    f"**{t('reason_label', lang=lang)}:** "
                                    f"{live_item.get('reason', '')}"
                                )
                                delete_url = live_item.get("delete_url", "-")
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
                    return

                if "ai" in live_data:
                    live_state["ai"] = live_data["ai"]

                    ai_status = ui_state.get("ai_status")
                    if ai_status is not None:
                        ai_status.empty()

                    return

                with live_area:
                    render_services(live_state)

                    ai_status = st.empty()
                    ui_state["ai_status"] = ai_status

                    ai_live_placeholder = st.empty()
                    ui_state["ai_live_placeholder"] = ai_live_placeholder

                    message = event.get("text")
                    if not message and event.get("key"):
                        message = t(
                            event["key"],
                            lang=lang,
                            **event.get("args", {}),
                        )

                    if message:
                        level = event.get("level", "info")
                        with ai_status.container():
                            getattr(st, level, st.info)(message)

                return

            # Progress/status event untuk stage lain.
            message = event.get("text")
            if not message and event.get("key"):
                message = t(
                    event["key"],
                    lang=lang,
                    **event.get("args", {}),
                )

            if message:
                level = event.get("level", "info")
                with live_area:
                    getattr(st, level, st.info)(message)

            # Hasil IMAP/OSINT dikumpulkan untuk ditampilkan ketika
            # stage AI dimulai.
            if stage in ("imap", "osint") and "services" in live_data:
                live_state["services"].extend(live_data["services"])

        # Avoid wrapping the whole synchronous pipeline in st.spinner().
        # The callback already renders live stage updates; a plain placeholder
        # has a deterministic lifecycle and is explicitly cleared after return.
        processing_status = st.empty()
        processing_status.info(t("spinner_processing", lang=lang))

        final_state = run_scan_pipeline(
            email=target_email,
            phone=target_phone,
            gmail_app_password=gmail_app_password,
            enable_imap=enable_imap,
            enable_osint=enable_osint,
            enable_breach=enable_breach,
            force_refresh=force_refresh_breach,
            lang=lang,
            tenant_id=get_tenant_id(),
            with_ai=True,
            enable_scorecard=True,
            scorecard_definition=SCORECARD_INTEGRATION_DEFINITION,
            scorecard_risk_policy=SCORECARD_INTEGRATION_RISK_POLICY,
            on_event=push_event,
        )

        processing_status.empty()

        # Simpan hasil final hanya setelah seluruh pipeline selesai.
        st.session_state["scan_state"] = final_state

        # Jangan biarkan status awal AI tetap tertinggal di UI.
        ai_status = ui_state.get("ai_status")
        if ai_status is not None:
            ai_status.empty()

        # Hasil progressive sudah ditampilkan selama inference.
        # Bersihkan placeholder live sebelum merender hasil final (DSR/exposures).
        ai_live_placeholder = ui_state.get("ai_live_placeholder")
        if ai_live_placeholder is not None:
            ai_live_placeholder.empty()

        with live_area:
            # Breach was rendered when its stage completed; the completed
            # evidence, scorecard, and AI results are rendered in pipeline order.
            render_evidence(final_state)
            render_scorecard(final_state)

            if final_state.get("ai"):
                render_ai(final_state)
            elif (
                not final_state["services"]
                and not final_state["breach"]["findings"]
            ):
                st.warning(t("warn_no_services", lang=lang))


state = st.session_state.get("scan_state")

# AI is now enabled for the integration validation path. Cached results
# remain keyed by the complete evidence + scorecard input fingerprint.


# Pada rerun berikutnya (download, ganti bahasa, clear cache, dll.),
# render ulang hasil yang tersimpan di session_state.
#
# Pada run scan pertama, hasil sudah ditampilkan secara live oleh callback,
# sehingga tidak dirender ulang dan tidak terjadi duplikasi.
if state and not scan_executed:
    render_breach(state)
    render_evidence(state)
    render_scorecard(state)

    if not state["services"] and not state["breach"]["findings"]:
        st.warning(t("warn_no_services", lang=lang))

    render_services(state)
    render_ai(state)
