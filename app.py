import os
import streamlit as st
from dotenv import load_dotenv
from services.imap_scanner import scan_gmail_inbox
from services.osint_scanner import scan_osint_footprint
from services.ai_agent import analyze_smart_cache
from services.breach_scanner import scan_data_breaches

# Load environment variables dari file .env
load_dotenv()

st.set_page_config(
    page_title="Local Digital Footprint & Privacy Auditor",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Privacy Auditor & Digital Footprint Tracker")
st.caption("Aplikasi Lokal & Privacy-First (Hybrid Cache + Multi-Cloud LLM & Advanced Multi-Engine Breach Scanner)")

# Sidebar Configuration
with st.sidebar:
    st.header("⚙️ Konfigurasi Pemindaian")

    env_target_email = os.getenv("GMAIL_TARGET_ADDR", "")
    target_email = st.text_input(
        "Email Target *",
        value=env_target_email,
        placeholder="email@gmail.com",
        help="Wajib diisi. Bisa diisi di sini atau via GMAIL_TARGET_ADDR di file .env"
    )

    env_target_phone = os.getenv("TARGET_PHONE_NUM", "")
    target_phone = st.text_input(
        "No. Handphone Target (Opsional)",
        value=env_target_phone,
        placeholder="+6281234567890",
        help="Opsional. Sertakan kode negara jika ada (misal: +628...)"
    )

    st.subheader("1. Gmail IMAP Parser")
    enable_imap = st.checkbox("Aktifkan Scan Inbox Gmail", value=True)

    env_gmail_pass = os.getenv("GMAIL_APP_PASSWORD", "")
    gmail_app_password = st.text_input(
        "Gmail App Password",
        value=env_gmail_pass,
        type="password",
        help="Bisa diisi di sini atau via GMAIL_APP_PASSWORD di file .env"
    )

    st.subheader("2. OSINT & Multi-Breach Checker")
    enable_osint = st.checkbox("Aktifkan Scan OSINT (Holehe)", value=True)
    enable_breach = st.checkbox("Aktifkan Advanced Breach Scan (DB & Web)", value=True)
    force_refresh_breach = st.checkbox("Paksa Refresh Cache Breach", value=False, help="Abaikan cache lokal di cache/breach/ dan lakukan pemindaian ulang dari API")

    st.subheader("3. Status API Keys (.env)")

    gemini_count = sum(1 for i in range(1, 7) if os.getenv(f"GOOGLE_API_KEY_{i}"))
    has_groq = "🟢 Loaded" if os.getenv("GROQ_API_KEY") else "⚪ Off"
    has_openai = "🟢 Loaded" if os.getenv("OPENAI_API_KEY") else "⚪ Off"
    has_tavily = "🟢 Loaded" if os.getenv("TAVILY_API_KEY") else "⚪ Off"
    has_gsearch = "🟢 Loaded" if (os.getenv("GOOGLE_SEARCH_API_KEY") and os.getenv("GOOGLE_CX_ID")) else "⚪ Off"
    has_rapidapi = "🟢 Loaded" if os.getenv("RAPIDAPI_KEY") else "⚪ Off"

    st.caption(f"• **Gemini Keys:** {gemini_count}/6 Keys Active")
    st.caption(f"• **Groq API:** {has_groq}")
    st.caption(f"• **OpenAI API:** {has_openai}")
    st.caption(f"• **RapidAPI (BreachDB):** {has_rapidapi}")
    st.caption(f"• **Google Custom Search:** {has_gsearch}")
    st.caption(f"• **Tavily AI Search:** {has_tavily}")
    st.caption("• **SearXNG & DDG:** 🟢 Active (Always Free)")

    run_scan = st.button("🚀 Mulai Audit Jejak Digital", type="primary", width="stretch")

# Main Dashboard
if run_scan:
    if not target_email or not target_email.strip():
        st.error("Alamat Email Target wajib diisi.")
    else:
        all_detected_services = []

        with st.spinner("Memproses pemindaian... Mohon tunggu."):
            # Step 1: Scan Gmail via IMAP
            if enable_imap:
                if not gmail_app_password:
                    st.warning("Gmail App Password kosong. Pemindaian IMAP dilewati.")
                else:
                    st.info("📨 Memindai Inbox Gmail...")
                    try:
                        imap_results = scan_gmail_inbox(target_email, gmail_app_password)
                        all_detected_services.extend(imap_results)
                        st.success(f"Ditemukan {len(imap_results)} akun/layanan dari Inbox Gmail.")
                    except Exception as e:
                        st.error(f"Error IMAP: {e}")

            # Step 2: Scan OSINT Holehe
            if enable_osint:
                st.info("🔍 Memindai Pendaftaran via OSINT (Holehe)...")
                try:
                    osint_results = scan_osint_footprint(target_email)
                    all_detected_services.extend(osint_results)
                    st.success(f"Ditemukan {len(osint_results)} akun terdaftar dari OSINT.")
                except Exception as e:
                    st.error(f"Error OSINT: {e}")

            # Step 3: Multi-Layer Breach Scan (Email + No. HP) dengan Smart Cache
            breach_findings = []
            is_breach_cached = False
            if enable_breach:
                st.info("🔎 Memindai kebocoran data & exposure publik (Email & No. HP)...")
                try:
                    breach_output = scan_data_breaches(
                        email=target_email,
                        phone=target_phone,
                        force_refresh=force_refresh_breach
                    )
                    breach_findings = breach_output.get("results", [])
                    engine_used = breach_output.get("engine", "None")
                    is_breach_cached = breach_output.get("is_from_cache", False)

                    cache_status_msg = " ⚡ [Diambil dari Cache Lokal]" if is_breach_cached else ""

                    if breach_findings:
                        st.warning(f"⚠️ Ditemukan {len(breach_findings)} potensi exposure/leak via: {engine_used}!{cache_status_msg}")
                    else:
                        st.success(f"Tidak ditemukan indikasi exposure publik ({engine_used}).{cache_status_msg}")
                except Exception as e:
                    st.error(f"Error Breach Scan: {e}")

        # Display Results & Breach Warnings
        if breach_findings:
            st.divider()
            cache_badge = "⚡ (Data Cache)" if is_breach_cached else "🔴 (Live Scan)"
            st.subheader(f"🚨 Detail Temuan Kebocoran Data / Exposure Publik {cache_badge}")
            with st.expander("Klik untuk melihat detail jejak exposure & leak", expanded=True):
                for item in breach_findings:
                    st.markdown(f"**[{item['title']}]({item['url']})**")
                    st.caption(f"Sumber: {item['source']} | Tautan: {item['url']}")
                    st.write(item['snippet'])
                    st.divider()

        # Display Account Results & AI Audit
        if not all_detected_services:
            st.warning("Tidak ada akun/layanan aplikasi yang terdeteksi dari modul yang diaktifkan.")
        else:
            st.divider()
            st.subheader(f"📌 Total Layanan Terdeteksi: {len(all_detected_services)}")

            # Tabel hasil pemindaian
            st.dataframe(all_detected_services, width="stretch")

            # Step 4: AI Audit via Hybrid Cache + Multi-LLM
            st.divider()
            st.subheader("🤖 Analisis AI & Recommendations")

            with st.spinner("Sistem sedang menganalisis tingkat risiko & menyusun DSR..."):
                ai_output = analyze_smart_cache(
                    email=target_email,
                    found_services=all_detected_services,
                    phone=target_phone
                )

                st.info(f"⚡ Analisis diselesaikan menggunakan: **{ai_output.get('provider_used', 'Local Cache')}**")

                # Tab Tampilan Risiko dan DSR
                tab1, tab2 = st.tabs(["📊 Analisis Risiko Privasi", "✉️ Draf Surat Penghapusan Data (DSR)"])

                with tab1:
                    analysis_list = ai_output.get("analysis", [])
                    if analysis_list:
                        for item in analysis_list:
                            risk = item.get("risk_level", "Sedang")
                            color = "🔴" if "Tinggi" in risk else ("🟡" if "Sedang" in risk else "🟢")
                            delete_url = item.get("delete_url", "#")

                            st.markdown(f"**{color} {item.get('service')}** - *Tingkat Risiko: {risk}*")
                            st.write(f"**Alasan:** {item.get('reason')}")
                            if delete_url and delete_url != "-":
                                st.markdown(f"🔗 [Hapus / Deaktivasi Akun di Sini]({delete_url})")
                            st.caption("---")
                    else:
                        st.write("Tidak ada analisis risiko yang dihasilkan.")

                with tab2:
                    dsr_text = ai_output.get("dsr_template", "")
                    if isinstance(dsr_text, str):
                        dsr_text = dsr_text.strip()
                    else:
                        dsr_text = ""

                    # Fallback otomatis jika DSR dari LLM kosong
                    if not dsr_text:
                        formatted_services = "\n".join([
                            f"- {item.get('service', 'Layanan Terdaftar')}"
                            for item in all_detected_services
                        ]) if all_detected_services else "- [Sebutkan Nama Layanan]"

                        phone_line = f"\n- No. Handphone  : {target_phone.strip()}" if target_phone and target_phone.strip() else ""

                        dsr_text = f"""Kepada Yth.
Tim Perlindungan Data Pribadi / Data Protection Officer (DPO)
[Nama Perusahaan / Pengelola Layanan]

Perihal: Permohonan Penghapusan Data Pribadi (Data Subject Request / DSR)
Rujukan: UU No. 27 Tahun 2022 tentang Perlindungan Data Pribadi (UU PDP)

Dengan hormat,

Saya yang bertanda tangan di bawah ini:
- Email Terdaftar : {target_email}{phone_line}

Berdasarkan hak subjek data sebagaimana diatur dalam Pasal 8 Undang-Undang Nomor 27 Tahun 2022 tentang Perlindungan Data Pribadi (UU PDP), bersama surat ini saya mengajukan permohonan untuk:

1. Menghapus dan/atau memusnahkan seluruh data pribadi saya yang tersimpan di sistem, database, maupun server pengelola layanan.
2. Menghentikan pemrosesan dan pemanfaatan data pribadi saya untuk keperluan operasional, pemasaran, maupun penyerahan ke pihak ketiga.
3. Memberikan konfirmasi tertulis melalui email setelah proses pemusnahan/penghapusan data selesai dilakukan.

Daftar Layanan Terdeteksi:
{formatted_services}

Demikian permohonan ini saya sampaikan. Atas perhatian dan pemenuhannya sesuai ketentuan perundang-undangan yang berlaku, saya ucapkan terima kasih.

Hormat saya,


[{target_email}]"""

                    st.text_area("Salin Draf Surat di bawah ini (Rujukan UU PDP No. 27/2022):", value=dsr_text, height=350)
                    st.download_button(
                        label="📄 Download Draf Surat (.txt)",
                        data=dsr_text,
                        file_name=f"DSR_Request_{target_email}.txt",
                        mime="text/plain"
                    )