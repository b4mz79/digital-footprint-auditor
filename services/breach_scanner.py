import os
import json
import re
import time
import asyncio
import logging
import hmac
import hashlib
import ipaddress
import socket
from urllib.parse import urlparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import httpx
from dotenv import load_dotenv
from utils.translations import t
from cache_security import save_encrypted_json, load_encrypted_json

load_dotenv()
logger = logging.getLogger("BreachScanner")

BREACH_CACHE_DIR = Path("cache/breach")
BREACH_CACHE_DIR.mkdir(parents=True, exist_ok=True)

# FIX: Gunakan ThreadPoolExecutor khusus untuk mencegah Exhaustion
MAX_WORKER_THREADS = int(os.getenv("MAX_WORKER_THREADS", "5"))
thread_pool = ThreadPoolExecutor(max_workers=MAX_WORKER_THREADS)
SCAN_THREAD_SEMAPHORE = asyncio.Semaphore(MAX_WORKER_THREADS)

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

def get_breach_cache_filepath(email_addr: str, phone: str = "") -> Path:
    return BREACH_CACHE_DIR / f"breach_cache_{safe_filename_identity(email_addr, phone)}.json"

# [Fungsi load_breach_cache dan save_breach_cache tetap sama seperti arsitektur awal Anda]
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

SEARXNG_INSTANCE_URL = os.getenv("SEARXNG_INSTANCE_URL", "").strip().rstrip("/")

async def scan_searxng_async(client: httpx.AsyncClient, target: str, lang: str = "id") -> list[dict]:
    if not SEARXNG_INSTANCE_URL or not is_safe_external_url(SEARXNG_INSTANCE_URL):
        return []
    params = {"q": f'"{target}" (breach OR leak OR "database dump")', "format": "json", "categories": "general"}
    try:
        # FIX: Implementasi Strict Timeout
        response = await client.get(f"{SEARXNG_INSTANCE_URL}/search", params=params, timeout=httpx.Timeout(10.0))
        if response.status_code == 200:
            return [{"title": r.get("title", ""), "url": r.get("url", ""), "snippet": r.get("content", "")[:200], "source": "SearXNG"} for r in response.json().get("results", [])[:5]]
    except Exception as e:
        logger.warning(f"[SearXNG Error] {e}")
    return []

def scan_breaches_ddg_bounded(target: str, lang: str = "id") -> list[dict]:
    try:
        from ddgs import DDGS
        query = f'"{target}" (breach OR leak OR "database dump")'
        return [{"source": "DuckDuckGo Search", "title": r.get("title", ""), "url": r.get("href", ""), "snippet": r.get("body", "")[:200]} for r in list(DDGS().text(query, max_results=5)) if r.get("href")]
    except Exception as e:
        return []

async def scan_data_breaches(email: str, phone: str = "", force_refresh: bool = False, lang: str = "id", tenant_id: str = "default") -> dict:
    if not force_refresh:
        cached = load_breach_cache(email, phone, tenant_id=tenant_id)
        if cached: return cached

    search_target = email.strip().lower()
    all_findings = []
    
    async with httpx.AsyncClient() as client:
        tasks = [scan_searxng_async(client, search_target, lang=lang)]
        
        async def bounded_ddg():
            async with SCAN_THREAD_SEMAPHORE:
                # FIX: Eksekusi menggunakan custom thread pool
                loop = asyncio.get_running_loop()
                return await loop.run_in_executor(thread_pool, scan_breaches_ddg_bounded, search_target, lang)

        tasks.append(bounded_ddg())
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        active_engines = set()
        for res in results:
            if isinstance(res, list) and res:
                all_findings.extend(res)
                active_engines.update([item.get("source") for item in res if item.get("source")])

    output = {"engine": ", ".join(active_engines) if active_engines else "None", "results": all_findings, "is_from_cache": False}
    save_breach_cache(email, output, phone, tenant_id=tenant_id)
    return output