import os
import json
import time
import asyncio
from pathlib import Path
import httpx
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
CACHE_DIR = Path("cache")
CACHE_DIR.mkdir(exist_ok=True)
UTILS_DIR = BASE_DIR / "utils"

DELAY_SECONDS = int(os.getenv("DELAY_SECONDS", 5))

def get_cache_filepath(email: str, phone: str = "", lang: str = "id") -> Path:
    safe_email = email.strip().lower().replace("@", "_at_").replace(".", "_")
    phone_part = f"_{''.join(filter(str.isalnum, phone.strip()))}" if phone and phone.strip() else ""
    return CACHE_DIR / f"audit_cache_{safe_email}{phone_part}_{lang}.json"

def load_analysis_cache(email: str, phone: str = "", max_age_hours: float = 24.0, lang: str = "id") -> dict | None:
    cache_file = get_cache_filepath(email, phone, lang=lang)
    if not cache_file.exists():
        return None

    file_age_hours = (time.time() - cache_file.stat().st_mtime) / 3600.0
    if file_age_hours > max_age_hours:
        return None

    try:
        with open(cache_file, "r", encoding="utf-8") as f:
            cached_data = json.load(f)
            cached_data["is_from_cache"] = True
            cached_data["cache_filepath"] = str(cache_file)
            return cached_data
    except Exception as e:
        print(f"[Cache Log] Error reading cache {cache_file}: {e}")
        return None

def save_analysis_cache(email: str, data: dict, phone: str = "", lang: str = "id") -> None:
    cache_file = get_cache_filepath(email, phone, lang=lang)
    try:
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[Cache Log] Error saving cache: {e}")

# System Prompts per Language
SYSTEM_PROMPTS = {
    "id": """
Anda adalah AI Privacy & Security Auditor ahli rujukan UU PDP No. 27/2022.
Tugas Anda:
1. Menganalisis tingkat privasi dan risiko dari setiap layanan/aplikasi terdeteksi berdasarkan temuan.
2. Merangkum temuan mentah menjadi alasan risiko yang padat, jelas, dan langsung pada intinya (hindari kalimat bertele-tele).
3. Memberikan tautan / instruksi deaktivasi akun jika memungkinkan.
4. Menyusun Draf Surat Data Subject Request (DSR) resmi permintaan penghapusan data pribadi secara komprehensif.

Format Output WAJIB berupa JSON valid dengan struktur:
{
  "analysis": [
    {
      "service": "Nama Layanan / Platform",
      "risk_level": "Tinggi / Sedang / Rendah",
      "reason": "Ringkasan padat mengapa data ini berisiko atau terekspos (maksimal 2-3 kalimat)",
      "delete_url": "URL hapus akun atau instruksi singkat"
    }
  ],
  "dsr_template": "Isi lengkap draf surat DSR dalam Bahasa Indonesia secara rinci (WAJIB TERISI)"
}
""",
    "en": """
You are an expert AI Privacy & Security Auditor specializing in global data privacy regulations (UU PDP No. 27/2022 & GDPR).
Your tasks:
1. Analyze the privacy risk level for each detected service/application based on findings.
2. Summarize raw findings into concise, clear, and direct risk reasons (max 2-3 sentences).
3. Provide account deletion/deactivation links or brief instructions if available.
4. Draft a formal, comprehensive Data Subject Request (DSR) letter for personal data erasure.

Output format MUST be valid JSON with structure:
{
  "analysis": [
    {
      "service": "Service / Platform Name",
      "risk_level": "High / Medium / Low",
      "reason": "Concise summary explaining why this service poses a risk or exposure (max 2-3 sentences)",
      "delete_url": "Account deletion URL or brief instructions"
    }
  ],
  "dsr_template": "Full comprehensive DSR request draft letter in English (MUST BE FILLED)"
}
"""
}

def generate_default_dsr_template(email: str, found_services: list, phone: str = "", lang: str = "id") -> str:
    services_str = "\n".join([f"- {s.get('service', s.get('name', 'Registered Service'))}" for s in found_services]) if found_services else "- [Service Name]"
    phone_str = f"\n- Phone Number   : {phone.strip()}" if phone and phone.strip() else ""

    template_file = UTILS_DIR / f"dsr_{lang}.txt"
    if not template_file.exists():
        template_file = UTILS_DIR / "dsr_id.txt"
        if not template_file.exists():
            template_file = Path("utils") / f"dsr_{lang}.txt"

    try:
        template_content = template_file.read_text(encoding="utf-8")
        return template_content.format(
            email=email,
            phone_str=phone_str,
            services_str=services_str
        )
    except Exception as e:
        print(f"[DSR Template Log] Error reading template file {template_file}: {e}")
        return ""

def build_user_prompt(email: str, found_services: list, phone: str = "", lang: str = "id") -> str:
    services_text = json.dumps(found_services, indent=2)
    phone_line = f"\nTarget Phone: {phone.strip()}" if phone and phone.strip() else ""
    
    if lang == "en":
        return f"""Target Email: {email}{phone_line}
List of Detected Services:
{services_text}

Provide privacy risk analysis and draft a Data Subject Request (DSR) letter for data erasure."""
    else:
        return f"""Target Email: {email}{phone_line}
Daftar Layanan Terdeteksi:
{services_text}

Buatkan analisis risiko dan draf surat permintaan penghapusan data (DSR) berbasis UU PDP Indonesia!"""

def call_gemini(prompt: str, api_key: str, sys_prompt: str) -> str:
    from google import genai
    from google.genai import types

    client = genai.Client(api_key=api_key)
    model_name = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
    config = types.GenerateContentConfig(response_mime_type="application/json")

    response = client.models.generate_content(
        model=model_name,
        contents=f"{sys_prompt}\n\n{prompt}",
        config=config
    )
    return response.text

def call_groq(prompt: str, api_key: str, sys_prompt: str) -> str:
    from groq import Groq
    client = Groq(api_key=api_key)
    model_name = os.getenv("GROQ_MODEL", "qwen/qwen3.8-27b")
    completion = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": prompt}
        ],
        response_format={"type": "json_object"}
    )
    return completion.choices[0].message.content

def call_openai(prompt: str, api_key: str, sys_prompt: str) -> str:
    from openai import OpenAI
    client = OpenAI(api_key=api_key)
    model_name = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    completion = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": prompt}
        ],
        response_format={"type": "json_object"}
    )
    return completion.choices[0].message.content

async def call_ollama_async(prompt: str, sys_prompt: str) -> str:
    model_name = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
    url = "http://localhost:11434/api/generate"
    payload = {
        "model": model_name,
        "prompt": f"{sys_prompt}\n\n{prompt}",
        "stream": False,
        "format": "json"
    }
    timeout_config = httpx.Timeout(connect=10.0, read=180.0, write=10.0, pool=10.0)

    async with httpx.AsyncClient(timeout=timeout_config) as client:
        response = await client.post(url, json=payload)
        response.raise_for_status()
        return response.json().get("response", "")

def call_ollama(prompt: str, sys_prompt: str) -> str:
    try:
        return asyncio.run(call_ollama_async(prompt, sys_prompt))
    except Exception as e:
        print(f"[Fallback Log] Ollama Async Error: {e}")
        raise e

def analyze_smart_cache(email: str, found_services: list, phone: str = "", force_refresh: bool = False, lang: str = "id") -> dict:
    if not force_refresh:
        cached_result = load_analysis_cache(email, phone, max_age_hours=24.0, lang=lang)
        if cached_result:
            if not cached_result.get("dsr_template"):
                cached_result["dsr_template"] = generate_default_dsr_template(email, found_services, phone, lang=lang)
            return cached_result

    sys_prompt = SYSTEM_PROMPTS.get(lang, SYSTEM_PROMPTS["id"])
    user_prompt = build_user_prompt(email, found_services, phone, lang=lang)
    raw_response = ""
    provider_used = "None"

    # Gemini
    for i in range(1, 7):
        key = os.getenv(f"GOOGLE_API_KEY_{i}", "").strip()
        if key:
            try:
                raw_response = call_gemini(user_prompt, key, sys_prompt)
                provider_used = f"Google Gemini (Key #{i})"
                time.sleep(DELAY_SECONDS)
                break
            except Exception as e:
                print(f"[Fallback Log] Gemini Key #{i} error: {e}")

    # Groq
    if not raw_response:
        groq_key = os.getenv("GROQ_API_KEY", "").strip()
        if groq_key:
            try:
                time.sleep(DELAY_SECONDS)
                raw_response = call_groq(user_prompt, groq_key, sys_prompt)
                provider_used = "Groq Cloud"
            except Exception as e:
                print(f"[Fallback Log] Groq error: {e}")

    # OpenAI
    if not raw_response:
        openai_key = os.getenv("OPENAI_API_KEY", "").strip()
        if openai_key:
            try:
                time.sleep(DELAY_SECONDS)
                raw_response = call_openai(user_prompt, openai_key, sys_prompt)
                provider_used = "OpenAI"
            except Exception as e:
                print(f"[Fallback Log] OpenAI error: {e}")

    # Ollama
    if not raw_response:
        try:
            time.sleep(DELAY_SECONDS)
            raw_response = call_ollama(user_prompt, sys_prompt)
            provider_used = "Ollama Local"
        except Exception as e:
            print(f"[Fallback Log] Ollama error: {e}")

    try:
        parsed_data = json.loads(raw_response)
        parsed_data["provider_used"] = provider_used
        parsed_data["is_from_cache"] = False

        if not parsed_data.get("dsr_template"):
            parsed_data["dsr_template"] = generate_default_dsr_template(email, found_services, phone, lang=lang)

        save_analysis_cache(email, parsed_data, phone, lang=lang)
        return parsed_data

    except Exception:
        fallback_dsr = generate_default_dsr_template(email, found_services, phone, lang=lang)
        return {
            "provider_used": provider_used,
            "is_from_cache": False,
            "analysis": [],
            "dsr_template": fallback_dsr
        }