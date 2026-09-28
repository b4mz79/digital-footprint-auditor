import os
import json
import time
import asyncio
import subprocess
from pathlib import Path
import httpx
from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
CACHE_DIR = Path("cache")
CACHE_DIR.mkdir(exist_ok=True)
UTILS_DIR = BASE_DIR / "utils"

DELAY_SECONDS = int(os.getenv("DELAY_SECONDS", 5))

# ==========================================
# 1. CACHE MANAGEMENT
# ==========================================

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

# ==========================================
# 2. SYSTEM PROMPTS & PROMPT BUILDERS (7 LANGUAGES)
# ==========================================

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
You are an expert AI Privacy & Security Auditor specializing in global data privacy regulations (GDPR, CCPA).
Your tasks:
1. Analyze the privacy risk level for each detected service/application based on findings.
2. Summarize raw findings into concise, clear, and direct risk reasons (max 2-3 sentences).
3. Provide account deletion/deactivation links or brief instructions if available.
4. Draft a formal, comprehensive Data Subject Request (DSR) letter for personal data erasure based on GDPR.

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
""",
    "de": """
Sie sind ein Experten-KI-Auditor für Datenschutz und Sicherheit gemäß DSGVO (GDPR) und internationalen Datenschutzgesetzen.
Ihre Aufgaben:
1. Analysieren Sie die Datenschutz-Risikostufe für jeden erkannten Dienst.
2. Fassen Sie die Ergebnisse in prägnanten, klaren Risikogründen zusammen (max. 2-3 Sätze).
3. Geben Sie Links oder Anweisungen zur Kontolöschung an.
4. Erstellen Sie einen formellen Entwurf einer Datenlöschungsanfrage (DSR) auf Deutsch gemäß DSGVO.

Ausgabe MUSS ein gültiges JSON mit folgender Struktur sein:
{
  "analysis": [
    {
      "service": "Name des Dienstes",
      "risk_level": "Hoch / Mittel / Niedrig",
      "reason": "Kurze Risikobegründung (max. 2-3 Sätze)",
      "delete_url": "URL zur Kontolöschung"
    }
  ],
  "dsr_template": "Vollständiger Entwurf des DSR-Schreibens auf Deutsch"
}
""",
    "ru": """
Вы эксперт ИИ по аудиту конфиденциальности и безопасности данных (стандарты GDPR и мировые законы).
Ваши задачи:
1. Проанализировать уровень риска для каждого обнаруженного сервиса.
2. Кратко изложить причины риска (максимум 2-3 предложения).
3. Предоставить ссылки или инструкции по удалению аккаунта.
4. Составить официальный проект запроса на удаление данных (DSR) на русском языке.

Вывод ДОЛЖЕН быть в формате JSON:
{
  "analysis": [
    {
      "service": "Название сервиса",
      "risk_level": "Высокий / Средний / Низкий",
      "reason": "Краткая причина риска (2-3 предложения)",
      "delete_url": "Ссылка для удаления аккаунта"
    }
  ],
  "dsr_template": "Полный проект письма DSR на русском языке"
}
""",
    "es": """
Usted es un auditor experto en privacidad y seguridad digital con referencia a RGPD (GDPR) y leyes internacionales.
Sus tareas:
1. Analizar el nivel de riesgo para cada servicio detectado.
2. Resumir los motivos del riesgo de forma concisa (máximo 2-3 oraciones).
3. Proporcionar enlaces o instrucciones para la desactivación/eliminación de la cuenta.
4. Redactar una solicitud formal de eliminación de datos (DSR) en español basada en el RGPD.

La salida DEBE ser un JSON válido:
{
  "analysis": [
    {
      "service": "Nombre del Servicio",
      "risk_level": "Alto / Medio / Bajo",
      "reason": "Resumen conciso del riesgo (máx. 2-3 oraciones)",
      "delete_url": "URL de eliminación de cuenta"
    }
  ],
  "dsr_template": "Borrador completo de la carta DSR en español"
}
""",
    "ar": """
أنت خبير تدقيق الخصوصية والأمان الرقمي وفقاً للوائح حماية البيانات العامة (GDPR).
مهامك:
1. تحليل مستوى مخاطر الخصوصية لكل خدمة مكتشفة.
2. تلخيص أسباب المخاطر بأسلوب موجز وواضح (2-3 جمل كحد أقصى).
3. توفير روابط أو إرشادات لحذف الحساب.
4. صياغة خطابات رسمية لطلب حذف البيانات (DSR) باللغة العربية استناداً إلى GDPR.

يجب أن يكون الناتج بنسق JSON صالح:
{
  "analysis": [
    {
      "service": "اسم الخدمة",
      "risk_level": "عالي / متوسط / منخفض",
      "reason": "ملخص موجز لسبب الخطر (2-3 جمل)",
      "delete_url": "رابط حذف الحساب"
    }
  ],
  "dsr_template": "مسودة خطاب DSR باللغة العربية"
}
""",
    "zh": """
您是一位精通全球数据隐私法规 (GDPR 及国际标准) 的 AI 隐私与安全审计员。
您的任务：
1. 分析每个检测到的服务的隐私风险等级。
2. 将风险原因精简总结（最多 2-3 句话）。
3. 提供账户注销/删除链接或简要说明。
4. 用中文起草一份基于 GDPR 的正式个人数据删除请求 (DSR) 信函。

输出必须为合法的 JSON 格式：
{
  "analysis": [
    {
      "service": "服务/平台名称",
      "risk_level": "高 / 中 / 低",
      "reason": "精简的风险原因说明（最多 2-3 句）",
      "delete_url": "注销账户 URL 或简要说明"
    }
  ],
  "dsr_template": "完整的中文 DSR 请求信函草案"
}
"""
}

def build_user_prompt(email: str, found_services: list, phone: str = "", lang: str = "id") -> str:
    services_text = json.dumps(found_services, indent=2)
    phone_line = f"\nTarget Phone: {phone.strip()}" if phone and phone.strip() else ""
    
    prompts_map = {
        "en": f"Target Email: {email}{phone_line}\nList of Detected Services:\n{services_text}\n\nProvide privacy risk analysis and draft a Data Subject Request (DSR) letter for data erasure based on GDPR.",
        "de": f"Ziel-E-Mail: {email}{phone_line}\nListe der erkannten Dienste:\n{services_text}\n\nErstellen Sie eine Risikoanalyse und einen DSR-Entwurf zur Datenlöschung gemäß DSGVO.",
        "ru": f"Целевой Email: {email}{phone_line}\nСписок обнаруженных сервисов:\n{services_text}\n\nПредоставьте анализ рисков и проект DSR для удаления данных на основе GDPR.",
        "es": f"Correo Objetivo: {email}{phone_line}\nLista de servicios detectados:\n{services_text}\n\nProporcione un análisis de riesgo y redacte una carta DSR para la eliminación de datos según el RGPD.",
        "ar": f"البريد المستهدف: {email}{phone_line}\nقائمة الخدمات المكتشفة:\n{services_text}\n\nقدم تحليلاً لمخاطر الخصوصية واصغ مسودة خطاب DSR لحذف البيانات استناداً إلى GDPR.",
        "zh": f"目标邮箱: {email}{phone_line}\n检测到的服务列表:\n{services_text}\n\n提供隐私风险分析并基于 GDPR 起草用于数据删除的 DSR 信函。"
    }
    
    return prompts_map.get(
        lang, 
        f"Target Email: {email}{phone_line}\nDaftar Layanan Terdeteksi:\n{services_text}\n\nBuatkan analisis risiko dan draf surat permintaan penghapusan data (DSR) berbasis UU PDP Indonesia!"
    )

def load_local_dsr_template(email: str, found_services: list, phone: str = "", lang: str = "id") -> str:
    """Fallback lokal menggunakan template dsr_*.txt jika AI gagal/offline."""
    template_file = UTILS_DIR / f"dsr_{lang}.txt"
    if not template_file.exists():
        template_file = UTILS_DIR / "dsr_id.txt"
        if not template_file.exists():
            template_file = Path("utils") / f"dsr_{lang}.txt"

    try:
        template_content = template_file.read_text(encoding="utf-8")
        services_str = "\n".join([f"- {s.get('service', s.get('name', 'Registered Service'))}" for s in found_services]) if found_services else "- [Service Name]"
        phone_str = f"\n- Phone Number   : {phone.strip()}" if phone and phone.strip() else ""

        return template_content.format(
            email=email,
            phone_str=phone_str,
            services_str=services_str
        )
    except Exception as e:
        print(f"[DSR Template Log] Error reading template file {template_file}: {e}")
        return f"To DPO / Privacy Team,\n\nPlease delete all personal data for {email}.\n\nThank you."

# ==========================================
# 3. LLM API CALLERS
# ==========================================

def call_gemini(prompt: str, api_key: str, sys_prompt: str) -> str:
    client = genai.Client(api_key=api_key)
    model_name = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    config = types.GenerateContentConfig(
        system_instruction=sys_prompt,
        response_mime_type="application/json",
        temperature=0.2,
    )

    response = client.models.generate_content(
        model=model_name,
        contents=prompt,
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

def get_wsl_host_ip() -> str:
    """Mendeteksi IP Windows Host secara otomatis dari WSL2."""
    try:
        res = subprocess.run(["ip", "route"], capture_output=True, text=True)
        for line in res.stdout.splitlines():
            if "default" in line:
                return f"http://{line.split()[2]}:11434"
    except Exception:
        pass
    return "http://localhost:11434"

async def call_ollama_async(prompt: str, sys_prompt: str) -> str:
    model_name = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
    
    # Prioritas: .env -> Auto-detect IP WSL Host -> Fallback localhost
    base_url = os.getenv("OLLAMA_HOST", "").strip()
    if not base_url:
        base_url = get_wsl_host_ip()
    
    url = f"{base_url.rstrip('/')}/api/generate"
    
    payload = {
        "model": model_name,
        "prompt": f"{sys_prompt}\n\n{prompt}",
        "stream": False,
        "format": "json"
    }
    timeout_config = httpx.Timeout(connect=15.0, read=300.0, write=10.0, pool=10.0)

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

# ==========================================
# 4. MAIN ORCHESTRATOR
# ==========================================

def analyze_smart_cache(email: str, found_services: list, phone: str = "", force_refresh: bool = False, lang: str = "id") -> dict:
    """Orkestrator utama analisis risiko privasi dengan cache & multi-provider fallback."""
    if not force_refresh:
        cached_result = load_analysis_cache(email, phone, max_age_hours=24.0, lang=lang)
        if cached_result:
            if not cached_result.get("dsr_template"):
                cached_result["dsr_template"] = load_local_dsr_template(email, found_services, phone, lang=lang)
            return cached_result

    sys_prompt = SYSTEM_PROMPTS.get(lang, SYSTEM_PROMPTS["id"])
    user_prompt = build_user_prompt(email, found_services, phone, lang=lang)
    raw_response = ""
    provider_used = "None"

    # 1. Google Gemini Multi-Key Strategy
    gemini_keys = [
        os.getenv("GEMINI_API_KEY", "").strip(),
        os.getenv("GOOGLE_API_KEY", "").strip(),
    ] + [os.getenv(f"GOOGLE_API_KEY_{i}", "").strip() for i in range(1, 7)]
    
    # Filter unique non-empty keys
    valid_gemini_keys = list(dict.fromkeys([k for k in gemini_keys if k]))

    for idx, key in enumerate(valid_gemini_keys, 1):
        try:
            raw_response = call_gemini(user_prompt, key, sys_prompt)
            provider_used = f"Google Gemini (Key #{idx})"
            time.sleep(DELAY_SECONDS)
            break
        except Exception as e:
            print(f"[Fallback Log] Gemini Key #{idx} error: {e}")

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

    # Parse and Return Response
    try:
        parsed_data = json.loads(raw_response)
        parsed_data["provider_used"] = provider_used
        parsed_data["is_from_cache"] = False

        if not parsed_data.get("dsr_template"):
            parsed_data["dsr_template"] = load_local_dsr_template(email, found_services, phone, lang=lang)

        save_analysis_cache(email, parsed_data, phone, lang=lang)
        return parsed_data

    except Exception as e:
        print(f"[AI Agent Error] All AI providers failed or returned invalid JSON. Using rule-based fallback. Error: {e}")
        
        fallback_analysis = []
        for s in found_services:
            svc_name = s.get("service", s.get("name", "Unknown"))
            fallback_analysis.append({
                "service": svc_name,
                "risk_level": "Sedang" if lang == "id" else "Medium",
                "reason": f"Terdeteksi dari modul {s.get('source', 'System Scan')}.",
                "delete_url": f"https://www.google.com/search?q=how+to+delete+{svc_name}+account"
            })

        fallback_result = {
            "provider_used": "Local Rule-based Engine (Offline Fallback)",
            "is_from_cache": False,
            "analysis": fallback_analysis,
            "dsr_template": load_local_dsr_template(email, found_services, phone, lang=lang)
        }
        return fallback_result

# Alias untuk kompatibilitas panggil nama fungsi lama
analyze_privacy_footprint = analyze_smart_cache