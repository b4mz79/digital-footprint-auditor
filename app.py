import os
import asyncio
import streamlit as st
import pandas as pd
from dotenv import load_dotenv
from utils.translations import t
from utils.risk import normalize_risk, risk_icon
from services.imap_scanner import scan_gmail_inbox
from services.osint_scanner import scan_osint_footprint
from services.ai_agent import analyze_smart_cache
from services.breach_scanner import scan_data_breaches


# Load environment variables dari file .env
load_dotenv()

def _md_escape(text: str) -> str:
    """Escape characters that could break out of a markdown link label."""
    return str(text).replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]")


def _finding_text(item: dict, lang: str) -> tuple[str, str]:
    """Localized title/snippet. Database findings are rendered from structured fields
    (the stored text is English and the cache is not language-specific)."""
    if item.get("kind") == "breach_db":
        if item.get("dataset"):
            title = t("bd_title", lang=lang, name=item["dataset"])
        else:
            title = t("bd_title_unknown", lang=lang, count=item.get("record_count", 0))
        secret_key = "bd_password_yes" if item.get("has_password") else "bd_password_no"
        return title, t(secret_key, lang=lang)
    return str(item.get("title", "")), str(item.get("snippet", ""))


# Setup Pilihan Bahasa awal di Session State
if "lang" not in st.session_state:
    st.session_state["lang"] = "id"

st.set_page_config(
    page_title="Local Digital Footprint & Privacy Auditor",
    page_icon="🛡️",
    layout="wide"
)

# Sidebar Configuration
with st.sidebar:
    st.header("⚙️ Configuration / Konfigurasi")

    # Map Pilihan Bahasa Ke Kode Bahasa
    LANG_OPTIONS = {
        "English": "en",
        "Bahasa Indonesia": "id",
        "Deutsch (Jerman)": "de",
        "Русский (Rusia)": "ru",
        "Español (Spanyol)": "es",
        "العربية (Arab)": "ar",
        "中文 (Cina)": "zh",
        "Français (Prancis)": "fr",
        "Italiano (Italia)": "it",
        "Nederlands (Belanda)": "nl",
        "日本語 (Jepang)": "ja",
    }
    # Cari index bahasa aktif di session state
    current_lang_code = st.session_state.get("lang", "en")
    options_list = list(LANG_OPTIONS.keys())
    default_index = 0
    for idx, (label, code) in enumerate(LANG_OPTIONS.items()):
        if code == current_lang_code:
            default_index = idx
            break

    selected_lang_label = st.selectbox(
        "🌐 Language / Bahasa",
        options=options_list,
        index=default_index
    )

    # Simpan kode bahasa terpilih
    lang = LANG_OPTIONS[selected_lang_label]
    st.session_state["lang"] = lang

    st.subheader(t("sidebar_config", lang=lang))

    env_target_email = os.getenv("GMAIL_TARGET_ADDR", "")
    target_email = st.text_input(
        t("target_email", lang=lang),
        value=env_target_email,
        placeholder="email@gmail.com",
        help=t("target_email_help", lang=lang)
    )

    env_target_phone = os.getenv("TARGET_PHONE_NUM", "")
    target_phone = st.text_input(
        t("target_phone", lang=lang),
        value=env_target_phone,
        placeholder="+6281234567890",
        help=t("target_phone_help", lang=lang)
    )

    st.subheader(t("imap_title", lang=lang))
    enable_imap = st.checkbox(t("enable_imap", lang=lang), value=True)

    env_gmail_pass = os.getenv("GMAIL_APP_PASSWORD", "")
    gmail_app_password = st.text_input(
        t("gmail_pass", lang=lang),
        value=env_gmail_pass,
        type="password",
        help=t("gmail_pass_help", lang=lang)
    )

    st.subheader(t("osint_title", lang=lang))
    enable_osint = st.checkbox(t("enable_osint", lang=lang), value=True)
    enable_breach = st.checkbox(t("enable_breach", lang=lang), value=True)
    force_refresh_breach = st.checkbox(
        t("force_refresh", lang=lang),
        value=False,
        help=t("force_refresh_help", lang=lang)
    )

    st.subheader(t("api_status_title", lang=lang))

    gemini_count = sum(1 for i in range(1, 7) if os.getenv(f"GOOGLE_API_KEY_{i}"))
    has_groq = "🟢 Loaded" if os.getenv("GROQ_API_KEY") else "⚪ Off"
    has_openai = "🟢 Loaded" if os.getenv("OPENAI_API_KEY") else "⚪ Off"
    has_tavily = "🟢 Loaded" if os.getenv("TAVILY_API_KEY") else "⚪ Off"
    has_gsearch = "🟢 Loaded" if (os.getenv("GOOGLE_SEARCH_API_KEY") and os.getenv("GOOGLE_CX_ID")) else "⚪ Off"
    has_rapidapi = "🟢 Loaded" if os.getenv("RAPIDAPI_KEY") else "⚪ Off"

    st.caption(f"• **Gemini Keys:** {gemini_count}/6 {t('keys_active', lang=lang)}")
    st.caption(f"• **Groq API:** {has_groq}")
    st.caption(f"• **OpenAI API:** {has_openai}")
    st.caption(f"• **RapidAPI (BreachDB):** {has_rapidapi}")
    st.caption(f"• **Google Custom Search:** {has_gsearch}")
    st.caption(f"• **Tavily AI Search:** {has_tavily}")
    st.caption("• **SearXNG & DDG:** 🟢 Active (Always Free)")

    run_scan = st.button(t("btn_run", lang=lang), type="primary", width="stretch")

# Dashboard Main Header
st.title(t("title", lang=lang))
st.caption(t("caption", lang=lang))

# Dashboard Logic Execution
if run_scan:
    if not target_email or not target_email.strip():
        st.error(t("err_no_email", lang=lang))
    else:
        all_detected_services = []

        with st.spinner(t("spinner_processing", lang=lang)):
            # Step 1: Scan Gmail via IMAP
            if enable_imap:
                if not gmail_app_password:
                    st.warning(t("warn_no_gmail_pass", lang=lang))
                else:
                    st.info(t("info_imap_scanning", lang=lang))
                    try:
                        imap_results = scan_gmail_inbox(target_email, gmail_app_password, lang=lang)
                        all_detected_services.extend(imap_results)
                        st.success(t("success_imap", lang=lang, count=len(imap_results)))
                    except Exception as e:
                        st.error(f"Error IMAP: {e}")
                    finally:
                        # Bersihkan variabel password lokal dari ruang lingkup eksekusi
                        del gmail_app_password

            # Step 2: Scan OSINT Holehe
            if enable_osint:
                st.info(t("info_osint_scanning", lang=lang))
                try:
                    osint_results = scan_osint_footprint(target_email, lang=lang)
                    all_detected_services.extend(osint_results)
                    st.success(t("success_osint", lang=lang, count=len(osint_results)))
                except Exception as e:
                    st.error(f"Error OSINT: {e}")

            # Step 3: Multi-Layer Breach Scan (Async Execution)
            breach_findings = []
            is_breach_cached = False
            if enable_breach:
                st.info(t("info_breach_scanning", lang=lang))
                try:
                    breach_output = asyncio.run(scan_data_breaches(
                        email=target_email,
                        phone=target_phone,
                        force_refresh=force_refresh_breach,
                        lang=lang
                    ))
                    breach_findings = breach_output.get("results", [])
                    engine_used = breach_output.get("engine", "None")
                    is_breach_cached = breach_output.get("is_from_cache", False)

                    cache_status_msg = t("cached_tag", lang=lang) if is_breach_cached else ""

                    engines_report = breach_output.get("engines", {})
                    failed_engines = [
                        name for name, info in engines_report.items()
                        if info.get("status") in ("error", "partial")
                    ]
                    scan_complete = bool(breach_output.get("complete", False))

                    if breach_findings:
                        st.warning(t("warn_breach_found", lang=lang, count=len(breach_findings), engine=engine_used, cache_status=cache_status_msg))
                        if failed_engines:
                            st.warning(t("breach_incomplete_with_hits", lang=lang, n_failed=len(failed_engines), failed=", ".join(failed_engines)))
                    elif scan_complete:
                        st.success(t("success_no_breach", lang=lang, engine=engine_used, cache_status=cache_status_msg))
                    else:
                        # Jangan pernah menampilkan "aman" jika ada engine yang gagal.
                        st.warning(t("breach_incomplete", lang=lang, n_failed=len(failed_engines), failed=", ".join(failed_engines) or "-"))

                    if engines_report:
                        icons = {"ok": "✅", "partial": "⚠️", "error": "❌", "skipped": "⏭️"}
                        with st.expander(t("engine_status_title", lang=lang)):
                            for name, info in engines_report.items():
                                status = info.get("status", "error")
                                st.write(f"{icons.get(status, '❔')} **{name}** — {t('engine_status_' + status, lang=lang)}")
                except Exception as e:
                    st.error(f"Error Breach Scan: {e}")

        # Display Results & Breach Warnings
        if breach_findings:
            st.divider()
            cache_badge = t("cache_badge_data", lang=lang) if is_breach_cached else t("cache_badge_live", lang=lang)
            st.subheader(t("breach_details_title", lang=lang, cache_badge=cache_badge))
            with st.expander(t("expander_breach", lang=lang), expanded=True):
                for item in breach_findings:
                    finding_title, finding_snippet = _finding_text(item, lang)
                    st.markdown(f"**[{_md_escape(finding_title)}]({item['url']})**")
                    st.caption(f"{t('source_label', lang=lang)}: {item['source']} | {t('link_label', lang=lang)}: {item['url']}")
                    st.write(finding_snippet)
                    st.divider()

        # Display Account Results & AI Audit
        if not all_detected_services and not breach_findings:
            st.warning(t("warn_no_services", lang=lang))
        else:
            if all_detected_services:
                st.divider()
                st.subheader(t("services_count_title", lang=lang, count=len(all_detected_services)))

                # Format Tabel Sesuai Bahasa Active
                df = pd.DataFrame(all_detected_services)
                df_display = df.rename(columns={
                    "name": t("col_service", lang=lang),
                    "domain": t("col_domain", lang=lang),
                    "source": t("col_source", lang=lang),
                    "subject": t("col_sample", lang=lang)
                })
                if "service" in df_display.columns:
                    df_display = df_display.drop(columns=["service"])

                st.dataframe(df_display, width="stretch")

            # Step 4: AI Audit via Hybrid Cache + Multi-LLM (Executed Async)
            st.divider()
            st.subheader(t("ai_title", lang=lang))

            with st.spinner(t("spinner_ai", lang=lang)):
                ai_output = asyncio.run(analyze_smart_cache(
                    email=target_email,
                    found_services=all_detected_services,
                    phone=target_phone,
                    force_refresh=force_refresh_breach,
                    lang=lang,
                    breach_findings=breach_findings,
                ))

                st.info(t("info_provider_used", lang=lang, provider=ai_output.get("provider_used", "Local Cache")))

                # Tab Tampilan Risiko dan DSR
                tab1, tab2 = st.tabs([t("tab_risk", lang=lang), t("tab_dsr", lang=lang)])

                with tab1:
                    analysis_list = ai_output.get("analysis", [])
                    exposures = ai_output.get("exposures", [])

                    if analysis_list:
                        for item in analysis_list:
                            # Warna/label ditentukan oleh kunci kanonik, bukan teks berbahasa tertentu.
                            risk_key = normalize_risk(item.get("risk_key")) or normalize_risk(item.get("risk_level")) or "unknown"
                            risk_label = t(f"risk_{risk_key}", lang=lang)
                            delete_url = item.get("delete_url", "#")

                            st.markdown(
                                f"**{risk_icon(risk_key)} {_md_escape(item.get('service', ''))}** - "
                                f"*{t('risk_level_label', lang=lang)}: {risk_label}*"
                            )
                            st.write(f"**{t('reason_label', lang=lang)}:** {item.get('reason')}")
                            if item.get("evidence_count"):
                                st.caption("⚠️ " + t("evidence_note", lang=lang, count=item["evidence_count"], level=risk_label))
                            if delete_url and delete_url != "-":
                                if isinstance(delete_url, str) and delete_url.startswith("https://"):
                                    st.markdown(t("delete_link_label", lang=lang, url=delete_url))
                                else:
                                    st.write(f"🔗 {delete_url}")
                            st.caption("---")
                    elif not exposures:
                        st.write(t("no_risk_analysis", lang=lang))

                    if exposures:
                        st.markdown(f"#### {t('exposures_title', lang=lang)}")
                        for exposure in exposures:
                            exp_key = normalize_risk(exposure.get("risk_key")) or "unknown"
                            exp_title, exp_snippet = _finding_text({"kind": "breach_db", **exposure}, lang)
                            st.markdown(
                                f"**{risk_icon(exp_key)} {_md_escape(exp_title)}** - "
                                f"*{t('risk_level_label', lang=lang)}: {t(f'risk_{exp_key}', lang=lang)}*"
                            )
                            st.write(exp_snippet)
                        st.info(t("exposure_action", lang=lang))

                with tab2:
                    dsr_text = ai_output.get("dsr_template", "")
                    if isinstance(dsr_text, str):
                        dsr_text = dsr_text.strip()
                    else:
                        dsr_text = ""

                    st.text_area(t("dsr_textarea_label", lang=lang), value=dsr_text, height=350)
                    st.download_button(
                        label=t("dsr_download_btn", lang=lang),
                        data=dsr_text,
                        file_name=f"DSR_Request_{target_email}.txt",
                        mime="text/plain"
                    )
