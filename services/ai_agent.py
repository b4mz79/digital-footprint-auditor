import os
import json
import time
import asyncio
from pathlib import Path
import httpx
from dotenv import load_dotenv

load_dotenv()

# --- 0. FILE-BASED JSON CACHE SYSTEM ---

CACHE_DIR = Path("cache")
CACHE_DIR.mkdir(exist_ok=True)
DELAY_SECONDS = int(os.getenv("DELAY_SECONDS", 5))

def get_cache_filepath(email: str, phone: str = "") -> Path:
    """Membuat nama file cache JSON yang aman berdasarkan email dan no. hp (jika diisi)."""
    safe_email = email.strip().lower().replace("@", "_at_").replace(".", "_")
    if phone and phone.strip():
        safe_phone = "".join(filter(str.isalnum, phone.strip()))
        return CACHE_DIR / f"audit_cache_{safe_email}_{safe_phone}.json"
    return CACHE_DIR / f"audit_cache_{safe_email}.json"

def load_analysis_cache(email: str, phone: str = "", max_age_hours: float = 24.0) -> dict | None:
    """Membaca hasil analisis dari file JSON lokal jika file ada dan belum kedaluwarsa."""
    cache_file = get_cache_filepath(email, phone)

    if not cache_file.exists():
        return None

    # Periksa umur file cache dalam jam
    file_age_seconds = time.time() - cache_file.stat().st_mtime
    file_age_hours = file_age_seconds / 3600.0

    if file_age_hours > max_age_hours:
        print(f"[Cache Log] File cache kedaluwarsa ({file_age_hours:.1f} jam). Menjalankan ulang analisis...")
        return None

    try:
        with open(cache_file, "r", encoding="utf-8") as f:
            cached_data = json.load(f)
            cached_data["is_from_cache"] = True
            cached_data["cache_filepath"] = str(cache_file)
            print(f"[Cache Log] SUCCESS: Memuat analisis langsung dari file JSON: {cache_file}")
            return cached_data
    except Exception as e:
        print(f"[Cache Log] Gagal membaca file cache {cache_file}: {e}")
        return None

def save_analysis_cache(email: str, data: dict, phone: str = "") -> None:
    """Menyimpan hasil analisis AI dalam format JSON ke direktori cache/."""
    cache_file = get_cache_filepath(email, phone)
    try:
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"[Cache Log] SUCCESS: Hasil analisis berhasil disimpan ke file JSON: {cache_file}")
    except Exception as e:
        print(f"[Cache Log] Gagal menyimpan cache JSON: {e}")


# --- 1. PROMPT TEMPLATES & DEFAULT GENERATOR ---

SYSTEM_PROMPT = """
Anda adalah AI Privacy & Security Auditor ahli rujukan UU PDP No. 27/2022.
Tugas Anda:
1. Menganalisis tingkat privasi dan risiko dari setiap layanan/aplikasi terdeteksi berdasarkan temuan.
2. Merangkum temuan mentah menjadi alasan risiko yang **padat, jelas, dan langsung pada intinya** (hindari kalimat bertele-tele atau kutipan mentah yang membingungkan).
3. Memberikan tautan / instruksi deaktivasi akun jika memungkinkan.
4. Menyusun Draf Surat Data Subject Request (DSR) resmi permintaan penghapusan data pribadi yang komprehensif.

Format Output WAJIB berupa JSON valid dengan struktur:
{
  "analysis": [
    {
      "service": "Nama Layanan / Platform",
      "risk_level": "Tinggi / Sedang / Rendah",
      "reason": "Ringkasan padat mengapa data ini berisiko atau terekspos (maksimal 2-3 kalimat yang mudah dipahami)",
      "delete_url": "URL hapus akun atau instruksi singkat"
    }
  ],
  "dsr_template": "Isi lengkap draf surat DSR dalam Bahasa Indonesia secara rinci dan komprehensif (WAJIB TERISI)"
}
"""

def build_user_prompt(email: str, found_services: list, phone: str = "") -> str:
    services_text = json.dumps(found_services, indent=2)
    phone_line = f"\nTarget No. Handphone: {phone.strip()}" if phone and phone.strip() else ""
    return f"""
Target Email: {email}{phone_line}
Daftar Layanan Terdeteksi:
{services_text}

Buatkan analisis risiko dan draf surat permintaan penghapusan data (DSR) berbasis UU PDP Indonesia!
"""

def generate_default_dsr_template(email: str, found_services: list, phone: str = "") -> str:
    """Fungsi pembantu untuk menghasilkan template DSR standar jika LLM gagal mengembalikannya."""
    services_str = "\n".join([f"- {s.get('service', 'Layanan Terdaftar')}" for s in found_services]) if found_services else "- [Sebutkan Nama Layanan]"
    phone_str = f"\n- No. Handphone  : {phone.strip()}" if phone and phone.strip() else ""
    return f"""Kepada Yth.
Tim Perlindungan Data Pribadi / Data Protection Officer (DPO)
[Nama Perusahaan / Pengelola Layanan]

Perihal: Permohonan Penghapusan Data Pribadi (Data Subject Request / DSR)
Rujukan: UU No. 27 Tahun 2022 tentang Perlindungan Data Pribadi (UU PDP)

Dengan hormat,

Saya yang bertanda tangan di bawah ini:
- Email Terdaftar : {email}{phone_str}

Berdasarkan hak subjek data sebagaimana diatur dalam Pasal 8 Undang-Undang Nomor 27 Tahun 2022 tentang Perlindungan Data Pribadi (UU PDP), bersama surat ini saya mengajukan permohonan untuk:

1. Menghapus dan/atau memusnahkan seluruh data pribadi saya yang tersimpan di sistem, database, maupun server pengelola layanan.
2. Menghentikan pemrosesan dan pemanfaatan data pribadi saya untuk keperluan operasional, pemasaran, maupun penyerahan ke pihak ketiga.
3. Memberikan konfirmasi tertulis melalui email setelah proses pemusnahan/penghapusan data selesai dilakukan.

Daftar Layanan Terdeteksi:
{services_str}

Demikian permohonan ini saya sampaikan. Atas perhatian dan pemenuhannya sesuai ketentuan perundang-undangan yang berlaku, saya ucapkan terima kasih.

Hormat saya,


[{email}]"""


# --- 2. MULTI-PROVIDER CALLERS ---

def call_gemini(prompt: str, api_key: str) -> str:
    """Menggunakan model Gemini aktif terkini dengan konfigurasi eksplisit untuk menghindari warning AFC."""
    from google import genai
    from google.genai import types

    client = genai.Client(api_key=api_key)
    model_name = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")

    config = types.GenerateContentConfig(
        response_mime_type="application/json"
    )

    response = client.models.generate_content(
        model=model_name,
        contents=f"{SYSTEM_PROMPT}\n\n{prompt}",
        config=config
    )
    return response.text

def call_groq(prompt: str, api_key: str) -> str:
    """Menggunakan model Groq aktif."""
    from groq import Groq
    client = Groq(api_key=api_key)
    model_name = os.getenv("GROQ_MODEL", "qwen/qwen3.8-27b")
    completion = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ],
        response_format={"type": "json_object"}
    )
    return completion.choices[0].message.content

def call_openai(prompt: str, api_key: str) -> str:
    """Menggunakan model OpenAI."""
    from openai import OpenAI
    client = OpenAI(api_key=api_key)
    model_name = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    completion = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ],
        response_format={"type": "json_object"}
    )
    return completion.choices[0].message.content

async def call_ollama_async(prompt: str) -> str:
    """
    Eksekusi Ollama Lokal secara Async menggunakan httpx.AsyncClient.
    Mencegah blocking total pada socket & memberikan tolerance timeout lebih tinggi saat warm-up model.
    """
    model_name = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
    url = "http://localhost:11434/api/generate"
    payload = {
        "model": model_name,
        "prompt": f"{SYSTEM_PROMPT}\n\n{prompt}",
        "stream": False,
        "format": "json"
    }

    timeout_config = httpx.Timeout(connect=10.0, read=180.0, write=10.0, pool=10.0)

    async with httpx.AsyncClient(timeout=timeout_config) as client:
        response = await client.post(url, json=payload)
        response.raise_for_status()
        data = response.json()
        return data.get("response", "")

def call_ollama(prompt: str) -> str:
    """Wrapper synchronous agar kompatibel dengan alur utama Streamlit."""
    try:
        return asyncio.run(call_ollama_async(prompt))
    except Exception as e:
        print(f"[Fallback Log] Ollama Async Execution Error: {e}")
        raise e


# --- 3. MAIN ROUTER WITH JSON CACHING ---

def analyze_smart_cache(email: str, found_services: list, phone: str = "", force_refresh: bool = False) -> dict:
    """
    Eksekusi analisis dengan skema cache & fallback bertingkat:
    1. Cek file cache JSON lokal di folder 'cache/'.
    2. Jika valid dan tidak force_refresh, kembalikan data langsung dari JSON.
    3. Jika tidak ada, jalankan LLM (Gemini -> Groq -> OpenAI -> Ollama Async) dan simpan hasilnya ke file JSON.
    """
    # 1. Cek Cache JSON di Disk
    if not force_refresh:
        cached_result = load_analysis_cache(email, phone, max_age_hours=24.0)
        if cached_result:
            if not cached_result.get("dsr_template"):
                cached_result["dsr_template"] = generate_default_dsr_template(email, found_services, phone)
            return cached_result

    # 2. Panggil LLM jika Cache Miss / Forced Refresh
    log_info = f"{email} | Phone: {phone}" if phone and phone.strip() else email
    print(f"[AI Agent Log] Menjalankan analisis AI baru untuk {log_info}...")
    user_prompt = build_user_prompt(email, found_services, phone)
    raw_response = ""
    provider_used = "None"

    # Try Google Gemini Keys (1-6)
    for i in range(1, 7):
        key = os.getenv(f"GOOGLE_API_KEY_{i}", "").strip()
        if key:
            try:
                raw_response = call_gemini(user_prompt, key)
                provider_used = f"Google Gemini (Key #{i})"
                time.sleep(DELAY_SECONDS)
                break
            except Exception as e:
                print(f"[Fallback Log] Gemini Key #{i} gagal: {e}. Mencoba key berikutnya...")

    # Try Groq Cloud
    if not raw_response:
        groq_key = os.getenv("GROQ_API_KEY", "").strip()
        if groq_key:
            try:
                time.sleep(DELAY_SECONDS)
                raw_response = call_groq(user_prompt, groq_key)
                provider_used = "Groq Cloud (Qwen 3.8)"
            except Exception as e:
                print(f"[Fallback Log] Groq API gagal: {e}. Pindah ke OpenAI...")

    # Try OpenAI
    if not raw_response:
        openai_key = os.getenv("OPENAI_API_KEY", "").strip()
        if openai_key:
            try:
                time.sleep(DELAY_SECONDS)
                raw_response = call_openai(user_prompt, openai_key)
                provider_used = "OpenAI (GPT-4o-mini)"
            except Exception as e:
                print(f"[Fallback Log] OpenAI API gagal: {e}. Pindah ke Ollama...")

    # Try Ollama Local
    if not raw_response:
        try:
            time.sleep(DELAY_SECONDS)
            raw_response = call_ollama(user_prompt)
            provider_used = "Ollama Local (Offline Async)"
        except Exception as e:
            print(f"[Fallback Log] Ollama Local gagal: {e}.")

    # 3. Parse JSON & Simpan Ke Disk
    try:
        parsed_data = json.loads(raw_response)
        parsed_data["provider_used"] = provider_used
        parsed_data["is_from_cache"] = False

        # Validasi dsr_template agar tidak kosong
        if not parsed_data.get("dsr_template"):
            parsed_data["dsr_template"] = generate_default_dsr_template(email, found_services, phone)

        # Simpan ke file cache JSON
        save_analysis_cache(email, parsed_data, phone)
        return parsed_data

    except Exception:
        fallback_dsr = generate_default_dsr_template(email, found_services, phone)
        error_result = {
            "provider_used": provider_used,
            "is_from_cache": False,
            "analysis": [],
            "dsr_template": fallback_dsr
        }
        return error_result