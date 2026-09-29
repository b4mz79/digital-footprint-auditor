import os
import json
import re
import time
import html
import asyncio
import logging
import hmac
import hashlib
import ipaddress
import socket
from urllib.parse import urlparse
from pathlib import Path
import httpx
from dotenv import load_dotenv
from utils.translations import t
from cache_security import save_encrypted_json, load_encrypted_json

# class Filter khusus untuk Masking
class SensitiveDataFilter(logging.Filter):
    def __init__(self):
        super().__init__()
        self.email_regex = re.compile(r'([\w\.-]+)((?:@|%40))([\w\.-]+)(\.\w+)', re.IGNORECASE)
        self.secret_regex = re.compile(r'(password|token|api_key|secret|code|pin|otp)["\s]*[:=]["\s]*([^\s,]+)', re.IGNORECASE)
        self.phone_regex = re.compile(r'(?:\+|%2B|0)[0-9(?:%20)|\s|+\-]{7,20}\b', re.IGNORECASE)

    def mask_email(self, m):
        username = m.group(1)
        separator = m.group(2)
        domain_name = m.group(3)
        tld = m.group(4)
        if len(username) > 3: masked_user = username[:-3] + "***"
        else: masked_user = "***"
        if len(domain_name) > 3: masked_domain = "***" + domain_name[-3:]
        else: masked_domain = "***"
        return f"{masked_user}{separator}{masked_domain}{tld}"

    def mask_phone(self, match):
        phone = match.group(0)

        # 1. Bersihkan semua karakter encoding dan pemisah agar menjadi angka murni
        # (Menghapus %, B, spasi, +, -, dan angka 20 jika itu bagian dari %20)
        clean_phone = re.sub(r'%20|[\s\+\-]', '', phone)
        clean_phone = re.sub(r'[^0-9]', '', clean_phone)

        # Batasan standar nomor telepon dunia (biasanya 7 hingga 15 digit angka murni)
        if len(clean_phone) < 7 or len(clean_phone) > 16:
            return phone # Jika terlalu pendek/panjang, kembalikan teks asli (bukan nomor telepon)

        # 2. Aturan Masking Dinamis:
        # Apapun kode negaranya, kita amankan bagian tengahnya.
        # Kita sisakan 3 angka di depan dan 2 angka di belakang.
        if len(clean_phone) > 5:
            masked_core = clean_phone[:3] + "*" * (len(clean_phone) - 5) + clean_phone[-2:]

            # Jika di teks aslinya ada tanda '+' atau '%2B', kembalikan tanda '+' di depan log agar rapi
            if phone.upper().startswith("%2B") or phone.startswith("+"):
                return "+" + masked_core
            return masked_core

        return "[PHONE_MASKED]"

    def filter(self, record):
        actual_msg = record.getMessage()
        record.args = ()
        actual_msg = actual_msg.replace('%3F', '?').replace('%3f', '?')

        # 3. POTONG TOTAL SETELAH TANDA TANYA (Jika ada)
        if '?' in actual_msg:
            parts = actual_msg.split('?')
            base_url = parts[0]       # Teks bersih sebelum tanda tanya
            query_string = parts[1]   # Teks yang penuh data bocor setelah tanda tanya
            
            # Cari status HTTP (3 digit angka: 200, 403, 429, dll) di sepanjang query_string
            status_match = re.search(r'\b(200|403|404|429|500|201|302)\b', query_string)
            status_code = f" {status_match.group(1)}" if status_match else ""
            
            # Satukan kembali. Data pencarian/telepon hancur total di sini, tersisa status code saja
            actual_msg = base_url + status_code

        if self.email_regex.search(actual_msg): actual_msg = self.email_regex.sub(self.mask_email, actual_msg)
        if self.secret_regex.search(actual_msg): actual_msg = self.secret_regex.sub(r'\1=[MASKED]', actual_msg)
        if self.phone_regex.search(actual_msg): actual_msg = self.phone_regex.sub(self.mask_phone, actual_msg)
        MAX_LEN = 100
        if len(actual_msg) > MAX_LEN:
            suffix = " ..."
            actual_msg = actual_msg[:MAX_LEN - len(suffix)] + suffix
        record.msg = actual_msg
        return True

load_dotenv()
LOG_LEVEL = os.getenv("LOG_LEVEL", "NOTSET").upper()
num_log_level = getattr(logging, LOG_LEVEL, logging.NOTSET)
logging.basicConfig(
    level=num_log_level,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logging.getLogger("httpx").addFilter(SensitiveDataFilter())
logging.getLogger("httpcore").addFilter(SensitiveDataFilter())
logging.getLogger("httpx").setLevel(logging.ERROR)
logging.getLogger("httpcore").setLevel(logging.ERROR)

logger = logging.getLogger("BreachScanner")
logger.addFilter(SensitiveDataFilter())

BREACH_CACHE_DIR = Path("cache/breach")
BREACH_CACHE_DIR.mkdir(parents=True, exist_ok=True)
DELAY_SECONDS = int(os.getenv("DELAY_SECONDS", 2))

IGNORED_DOMAINS_FILE = Path("ignored_domains.txt")
DEFAULT_IGNORED_DOMAINS = [
    "cbinsights.com", "zoominfo.com", "tracxn.com", "pitchbook.com",
    "crunchbase.com", "craft.co", "datanyze.com", "similarweb.com", "chinsights.com"
]

def load_ignored_domains() -> list[str]:
    if not IGNORED_DOMAINS_FILE.exists():
        try:
            with open(IGNORED_DOMAINS_FILE, "w", encoding="utf-8") as f:
                f.write("\n".join(DEFAULT_IGNORED_DOMAINS) + "\n")
            return DEFAULT_IGNORED_DOMAINS
        except Exception:
            return DEFAULT_IGNORED_DOMAINS

    try:
        with open(IGNORED_DOMAINS_FILE, "r", encoding="utf-8") as f:
            return [line.strip().lower() for line in f if line.strip() and not line.strip().startswith("#")]
    except Exception:
        return DEFAULT_IGNORED_DOMAINS

def is_valid_finding(url: str, target: str = "", title: str = "", snippet: str = "") -> bool:
    if not url:
        return False
    ignored_domains = load_ignored_domains()
    url_lower = url.lower()
    if any(ignored in url_lower for ignored in ignored_domains):
        return False

    if target and target.strip():
        target_lower = target.strip().lower()
        combined_text = f"{title} {snippet}".lower()
        if target_lower not in combined_text:
            return False

    return True

def mask_pii(text: str) -> str:
    """FIX: Memasker PII secara lebih agresif (Strict GDPR)."""
    if not text:
        return ""
    if "@" in text:
        parts = text.split("@")
        domain_parts = parts[1].split(".")
        masked_domain = f"{domain_parts[0][:1]}***.{domain_parts[-1]}" if len(domain_parts) > 1 else "***"
        return f"{parts[0][:2]}***@{masked_domain}"
    clean_num = re.sub(r"\D", "", text)
    if len(clean_num) >= 8:
        return clean_num[:2] + "****" + clean_num[-2:]
    return "***"

def mask_sensitive_snippet(subject_text: str) -> str:
    """Melakukan redaksi pada Email, Nomor Telepon, OTP, PIN, atau Kode dari teks snippet."""
    if not subject_text:
        return ""

    # 1. Masking format Email (Contoh: user@gmail.com -> ***@***)
    masked = re.sub(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', '***@***', subject_text)

    # 2. Masking Nomor Telepon Internasional/Lokal bersambung (Contoh: +6281234567890 -> ***)
    masked = re.sub(r'\+?\b\d{9,15}\b', '***', masked)

    # 3. Masking Nomor Telepon dengan pemisah spasi/strip (Contoh: 0812-3456-7890 -> ***)
    masked = re.sub(r'\b(?:\+62|62|0)[ \-]?\d{2,4}[ \-]?\d{3,4}[ \-]?\d{3,5}\b', '***', masked)

    # 4. Masking angka 4-8 digit yang berdiri sendiri (Contoh: 123456, 9876)
    masked = re.sub(r'\b\d{4,8}\b', '***', masked)

    # 5. Masking format Google Code (Contoh: G-123456)
    masked = re.sub(r'\bG-\d{4,8}\b', 'G-***', masked)

    # 6. Masking string alfanumerik yang mengikuti kata kunci OTP/PIN/Code
    masked = re.sub(r'(?i)\b(otp|pin|kode|code|token|sandi|password)[\s:=]+[A-Za-z0-9_-]{4,12}\b', r'\1 ***', masked)

    return masked

def safe_filename_identity(email_addr: str, phone: str = "") -> str:
    """FIX: Gunakan HMAC dengan Secret Pepper untuk mencegah serangan Rainbow Table."""
    secret_pepper = os.getenv("PII_PEPPER_KEY", "default_insecure_pepper").encode('utf-8')
    raw_id = f"{email_addr.strip().lower()}_{phone.strip()}".encode('utf-8')
    return hmac.new(secret_pepper, raw_id, hashlib.sha256).hexdigest()

def is_safe_external_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False
        if parsed.hostname.lower() in ("localhost", "127.0.0.1", "::1", "169.254.169.254"):
            return False

        resolved_ips = socket.getaddrinfo(parsed.hostname, None)
        for item in resolved_ips:
            ip = ipaddress.ip_address(item[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False
        return True
    except Exception:
        return False

def normalize_phone_number(phone: str) -> list[str]:
    clean_num = re.sub(r"\D", "", phone.strip())
    if not clean_num:
        return []

    formats = set()
    if clean_num.startswith("62"):
        local_num = "0" + clean_num[2:]
        intl_num = clean_num
    elif clean_num.startswith("0"):
        local_num = clean_num
        intl_num = "62" + clean_num[1:]
    else:
        local_num = "0" + clean_num
        intl_num = "62" + clean_num

    formats.add(local_num)
    formats.add(intl_num)
    formats.add("+" + intl_num)

    if len(local_num) >= 10:
        prefix_local = local_num[:4]
        prefix_intl_code = "+62"
        prefix_intl_body = intl_num[2:5]

        rest_local = local_num[4:]
        rest_intl = intl_num[5:]

        mid_len = len(rest_local) // 2
        part1_local = rest_local[:mid_len]
        part2_local = rest_local[mid_len:]

        part1_intl = rest_intl[:mid_len]
        part2_intl = rest_intl[mid_len:]

        formats.add(f"{prefix_local} {part1_local} {part2_local}")
        formats.add(f"{prefix_local}-{part1_local}-{part2_local}")
        formats.add(f"{prefix_intl_code} {prefix_intl_body} {part1_intl} {part2_intl}")
        formats.add(f"{prefix_intl_code}-{prefix_intl_body}-{part1_intl}-{part2_intl}")

    return list(formats)

def clean_snippet(text: str, max_len: int = 220, lang: str = "id") -> str:
    if not text:
        return t("no_summary", lang=lang)

    decoded_text = html.unescape(text)
    clean_tags = re.sub(r'<[^<]+?>', '', decoded_text)
    cleaned = " ".join(clean_tags.split())
    cleaned = mask_sensitive_snippet(cleaned)

    if len(cleaned) > max_len:
        return cleaned[:max_len] + "..."
    return cleaned

def get_breach_cache_filepath(email_addr: str, phone: str = "") -> Path:
    return BREACH_CACHE_DIR / f"breach_cache_{safe_filename_identity(email_addr, phone)}.json"

def load_breach_cache(email_addr: str, phone: str = "", max_age_hours: float = 12.0, tenant_id: str = "default") -> dict | None:
    cache_file = get_breach_cache_filepath(email_addr, phone)
    if not cache_file.exists(): return None
    if (time.time() - cache_file.stat().st_mtime) / 3600.0 > max_age_hours: return None

    try:
        data = load_encrypted_json(cache_file, tenant_id=tenant_id)
        if data: data["is_from_cache"] = True
        return data
    except Exception:
        return None

def save_breach_cache(email_addr: str, data: dict, phone: str = "", tenant_id: str = "default") -> None:
    try:
        save_encrypted_json(get_breach_cache_filepath(email_addr, phone), data, tenant_id=tenant_id)
    except Exception as e:
        logger.error(f"[Breach Cache] Error saving: {e}")

# --- ASYNC & PARALLEL SCANNER ENGINE DENGAN LOGGING ---

async def scan_breachdirectory_async(client: httpx.AsyncClient, target: str, rapidapi_key: str) -> list[dict]:
    logger.info(f"[BreachDirectory] Memulai scan untuk target: {mask_pii(target)}")
    url = "https://breachdirectory.p.rapidapi.com/"
    headers = {
        "X-RapidAPI-Key": rapidapi_key,
        "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com"
    }
    params = {"func": "auto", "term": target}

    try:
        response = await client.get(url, headers=headers, params=params, timeout=12.0)
        logger.info("response: %s://%s%s %s", response.url.scheme, response.url.host, response.url.path, response.status_code)
        response.raise_for_status()
        data = response.json()

        findings = []
        if data.get("success") and data.get("result"):
            for item in data.get("result", []):
                findings.append({
                    "source": "BreachDirectory DB API",
                    "title": f"Leak Detected [{target}]: {item.get('line', 'Database Dump')}",
                    "url": "https://breachdirectory.org",
                    "snippet": f"Credentials exposed. Hash Status: {item.get('has_password', 'Available')}"
                })
        logger.info(f"[BreachDirectory] Selesai. Ditemukan: {len(findings)} temuan.")
        return findings
    except Exception as e:
        logger.warning(f"[BreachDirectory] Gagal/Error: {e}")
        return []

async def scan_google_custom_search_async(client: httpx.AsyncClient, target: str, api_key: str, cx_id: str, lang: str = "id") -> list[dict]:
    logger.info(f"[Google Custom Search] Memulai scan untuk target: {mask_pii(target)}")
    url = "https://www.googleapis.com/customsearch/v1"
    query = f'"{target}" (breach OR leak OR "database dump" OR "combolist" OR "site:pastebin.com")'
    params = {"key": api_key, "cx": cx_id, "q": query, "num": 5}

    try:
        response = await client.get(url, params=params, timeout=12.0)
        logger.info("response: %s://%s%s %s", response.url.scheme, response.url.host, response.url.path, response.status_code)
        response.raise_for_status()
        data = response.json()

        findings = []
        for item in data.get("items", []):
            item_url = item.get("link", "")
            title = item.get("title", "")
            snippet = item.get("snippet", "")

            if is_valid_finding(item_url, target=target, title=title, snippet=snippet):
                findings.append({
                    "source": "Google Custom Search API",
                    "title": title or "Google Exposure Finding",
                    "url": item_url,
                    "snippet": clean_snippet(snippet, lang=lang)
                })
        logger.info(f"[Google Custom Search] Selesai. Ditemukan: {len(findings)} temuan.")
        return findings
    except Exception as e:
        logger.warning(f"[Google Custom Search] Gagal/Error: {e}")
        return []

def scan_googlesearch_python(target: str, lang: str = "id") -> list[dict]:
    """Blocking library Google Search scraper (dijalankan via thread)."""
    logger.info(f"[Google Scraper] Memulai scan via thread untuk target: {mask_pii(target)}")
    try:
        from googlesearch import search
        query = f'"{target}" (breach OR leak OR "database dump" OR "combolist")'
        findings = []

        results = search(query, num_results=5, advanced=True)
        for r in results:
            item_url = getattr(r, "url", "")
            title = getattr(r, "title", "")
            snippet = getattr(r, "description", "")

            if is_valid_finding(item_url, target=target, title=title, snippet=snippet):
                findings.append({
                    "source": "Google Search (Scraper)",
                    "title": title or "Google Exposure Finding",
                    "url": item_url,
                    "snippet": clean_snippet(snippet, lang=lang)
                })
        logger.info(f"[Google Scraper] Selesai. Ditemukan: {len(findings)} temuan.")
        return findings
    except Exception as e:
        logger.warning(f"[Google Scraper] Gagal/Error: {e}")
        return []

async def scan_bing_scrape_async(client: httpx.AsyncClient, target: str, lang: str = "id") -> list[dict]:
    logger.info(f"[Bing Scraper] Memulai scan untuk target: {mask_pii(target)}")
    try:
        from bs4 import BeautifulSoup
        query = f'"{target}" (breach OR leak OR "database dump" OR "combolist")'
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Accept-Language": "en-US,en;q=0.9"}
        url = "https://www.bing.com/search"

        response = await client.get(url, headers=headers, params={"q": query}, timeout=10.0, follow_redirects=True)
        logger.info("response: %s://%s%s %s", response.url.scheme, response.url.host, response.url.path, response.status_code)
        if response.status_code != 200: return []

        soup = BeautifulSoup(response.text, "html.parser")
        findings = []

        for item in soup.select("li.b_algo"):
            title_elem = item.select_one("h2 a")
            if not title_elem:
                continue

            title = title_elem.get_text(strip=True)
            item_url = title_elem.get("href", "")
            snippet_elem = item.select_one("div.b_caption p, p.b_algoSlug, p")
            snippet = snippet_elem.get_text(strip=True) if snippet_elem else ""

            if is_valid_finding(item_url, target=target, title=title, snippet=snippet):
                findings.append({
                    "source": "Bing Search (Scraper)",
                    "title": title or "Bing Exposure Finding",
                    "url": item_url,
                    "snippet": clean_snippet(snippet, lang=lang)
                })
        logger.info(f"[Bing Scraper] Selesai. Ditemukan: {len(findings)} temuan.")
        return findings
    except Exception as e:
        logger.warning(f"[Bing Scraper] Gagal/Error: {e}")
        return []

# Ambil URL instance khusus dari environment / .env
SEARXNG_INSTANCE_URL = os.getenv("SEARXNG_INSTANCE_URL", "").strip().rstrip("/")

async def scan_searxng_async(client: httpx.AsyncClient, target: str, lang: str = "id") -> list[dict]:
    """
    Memindai kebocoran data via SearXNG privat/self-hosted.
    Mengabaikan proses jika tidak ada instance privat yang dikonfigurasi.
    """
    if not SEARXNG_INSTANCE_URL:
        logger.info("[SearXNG] Pemindaian dilewati: SEARXNG_INSTANCE_URL tidak dikonfigurasi.")
        return []

    query = f'"{target}" (breach OR leak OR "database dump" OR "combolist")'
    params = {
        "q": query,
        "format": "json",
        "categories": "general"
    }

    search_endpoint = f"{SEARXNG_INSTANCE_URL}/search"

    try:
        logger.info(f"[SearXNG] Terhubung ke {SEARXNG_INSTANCE_URL} dan memulai scan untuk target: {mask_pii(target)}")
        response = await client.get(search_endpoint, params=params, timeout=10.0)
        logger.info("response: %s://%s%s %s", response.url.scheme, response.url.host, response.url.path, response.status_code)
        if response.status_code == 200:
            data = response.json()
            results = data.get("results", [])
            return [
                {
                    "title": r.get("title", ""),
                    "url": r.get("url", ""),
                    "snippet": r.get("content", ""),
                    "source": "SearXNG (Self-Hosted)"
                }
                for r in results[:5]
            ]
    except Exception as e:
        logger.warning(f"[SearXNG Error] Gagal menghubungkan ke {SEARXNG_INSTANCE_URL}: {e}")

    return []

async def scan_breaches_tavily_async(client: httpx.AsyncClient, target: str, api_key: str, lang: str = "id") -> list[dict]:
    logger.info(f"[Tavily AI] Memulai scan untuk target: {mask_pii(target)}")
    url = "https://api.tavily.com/search"
    query = f'"{target}" "breach" OR "leak" OR "combolist"'
    payload = {"api_key": api_key, "query": query, "search_depth": "basic", "max_results": 7}

    try:
        response = await client.post(url, json=payload, timeout=12.0)
        logger.info("response: %s://%s%s %s", response.url.scheme, response.url.host, response.url.path, response.status_code)
        response.raise_for_status()
        data = response.json()

        findings = []
        for result in data.get("results", []):
            item_url = result.get("url", "")
            raw_content = result.get("content", "")
            title = result.get("title", "")

            if is_valid_finding(item_url, target=target, title=title, snippet=raw_content):
                findings.append({
                    "source": "Tavily AI Search",
                    "title": title or "Tavily AI Exposure Finding",
                    "url": item_url,
                    "snippet": clean_snippet(raw_content, lang=lang)
                })
        logger.info(f"[Tavily AI] Selesai. Ditemukan: {len(findings)} temuan.")
        return findings
    except Exception as e:
        logger.warning(f"[Tavily AI] Gagal/Error: {e}")
        return []

def scan_breaches_ddg(target: str, lang: str = "id") -> list[dict]:
    """Blocking library DuckDuckGo search (dijalankan via thread)."""
    logger.info(f"[DuckDuckGo] Memulai scan via thread untuk target: {mask_pii(target)}")
    try:
        from ddgs import DDGS
        query = f'"{target}" (breach OR leak OR "database dump" OR "combolist")'
        findings = []
        results = list(DDGS().text(query, max_results=5))
        for r in results:
            item_url = r.get("href", "")
            title = r.get("title", "")
            snippet = r.get("body", "")

            if is_valid_finding(item_url, target=target, title=title, snippet=snippet):
                findings.append({
                    "source": "DuckDuckGo Search",
                    "title": title or "DuckDuckGo Exposure Finding",
                    "url": item_url,
                    "snippet": clean_snippet(snippet, lang=lang)
                })
        logger.info(f"[DuckDuckGo] Selesai. Ditemukan: {len(findings)} temuan.")
        return findings
    except Exception as e:
        logger.warning(f"[DuckDuckGo] Gagal/Error: {e}")
        return []

async def scan_data_breaches(email: str, phone: str = "", force_refresh: bool = False, lang: str = "id") -> dict:
    """Orkestrator utama pemindaian kebocoran data secara Async & Paralel."""
    if not force_refresh:
        cached_result = load_breach_cache(email, phone, max_age_hours=12.0)
        if cached_result:
            logger.info("[BreachScan] Memuat hasil dari Local Cache.")
            return cached_result

    search_targets = [email.strip().lower()]
    if phone and phone.strip():
        search_targets.extend(normalize_phone_number(phone))

    tavily_key = os.getenv("TAVILY_API_KEY", "").strip()
    google_search_key = os.getenv("GOOGLE_SEARCH_API_KEY", "").strip()
    google_cx_id = os.getenv("GOOGLE_CX_ID", "").strip()
    rapidapi_key = os.getenv("RAPIDAPI_KEY", "").strip()

    all_findings = []
    active_engines = set()

    start_time = time.time()
    logger.info(f"=== MEMULAI PARALLEL DATA BREACH SCAN ({len(search_targets)} target) ===")

    async with httpx.AsyncClient() as client:
        for idx, target in enumerate(search_targets, start=1):
            if idx > 1:
                logger.info(f"Jeda {DELAY_SECONDS}s sebelum scan target berikutnya...")
                await asyncio.sleep(DELAY_SECONDS)

            tasks = []

            # 1. RapidAPI BreachDirectory
            if rapidapi_key:
                tasks.append(scan_breachdirectory_async(client, target, rapidapi_key))

            # 2. Google Custom Search API
            if google_search_key and google_cx_id:
                tasks.append(scan_google_custom_search_async(client, target, google_search_key, google_cx_id, lang=lang))

            # 3. Google Scraper (Sync -> Thread)
            tasks.append(asyncio.to_thread(scan_googlesearch_python, target, lang=lang))

            # 4. Bing Scraper
            tasks.append(scan_bing_scrape_async(client, target, lang=lang))

            # 5. Tavily AI
            if tavily_key:
                tasks.append(scan_breaches_tavily_async(client, target, tavily_key, lang=lang))

            # 6. SearXNG
            tasks.append(scan_searxng_async(client, target, lang=lang))

            # 7. DuckDuckGo Search (Sync -> Thread)
            tasks.append(asyncio.to_thread(scan_breaches_ddg, target, lang=lang))

            # Jalankan SEMUA scanner secara paralel & serentak
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for res in results:
                if isinstance(res, Exception):
                    logger.error(f"[Task Exec Error]: {res}")
                elif isinstance(res, list) and res:
                    all_findings.extend(res)
                    for item in res:
                        if item.get("source"):
                            active_engines.add(item.get("source"))

    elapsed = time.time() - start_time
    logger.info(f"=== PARALLEL SCAN SELESAI Dalam {elapsed:.2f} detik ===")

    # De-duplikasi URL
    unique_findings = []
    seen_urls = set()
    for item in all_findings:
        url = item.get("url", "")
        if url and url not in seen_urls:
            seen_urls.add(url)
            unique_findings.append(item)

    output = {
        "engine": ", ".join(active_engines) if active_engines else "None",
        "results": unique_findings,
        "is_from_cache": False
    }

    save_breach_cache(email, output, phone)
    return output
