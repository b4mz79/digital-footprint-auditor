import os
import json
import re
import time
import html
from pathlib import Path
import httpx
from dotenv import load_dotenv

load_dotenv()

# --- CACHE SETUP & CONFIGURATION ---

BREACH_CACHE_DIR = Path("cache/breach")
BREACH_CACHE_DIR.mkdir(parents=True, exist_ok=True)
DELAY_SECONDS = int(os.getenv("DELAY_SECONDS", 5))

# --- 0. DYNAMIC NOISE FILTERING & PHONE NORMALIZATION ---

IGNORED_DOMAINS_FILE = Path("ignored_domains.txt")

DEFAULT_IGNORED_DOMAINS = [
    "cbinsights.com",
    "zoominfo.com",
    "tracxn.com",
    "pitchbook.com",
    "crunchbase.com",
    "craft.co",
    "datanyze.com",
    "similarweb.com",
    "chinsights.com"
]

def load_ignored_domains() -> list[str]:
    """
    Membaca daftar domain yang diabaikan dari file ignored_domains.txt secara dinamis.
    Jika file belum ada, akan membuat file default secara otomatis.
    """
    if not IGNORED_DOMAINS_FILE.exists():
        try:
            with open(IGNORED_DOMAINS_FILE, "w", encoding="utf-8") as f:
                f.write("\n".join(DEFAULT_IGNORED_DOMAINS) + "\n")
            print(f"[Breach Scan Log] File '{IGNORED_DOMAINS_FILE}' berhasil dibuat dengan daftar default.")
            return DEFAULT_IGNORED_DOMAINS
        except Exception as e:
            print(f"[Breach Scan Log] Gagal membuat file ignored_domains.txt: {e}")
            return DEFAULT_IGNORED_DOMAINS

    try:
        with open(IGNORED_DOMAINS_FILE, "r", encoding="utf-8") as f:
            domains = [
                line.strip().lower()
                for line in f
                if line.strip() and not line.strip().startswith("#")
            ]
        return domains
    except Exception as e:
        print(f"[Breach Scan Log] Gagal membaca '{IGNORED_DOMAINS_FILE}': {e}")
        return DEFAULT_IGNORED_DOMAINS


def is_valid_finding(url: str, target: str = "", title: str = "", snippet: str = "") -> bool:
    """
    Memfilter false positive (noise) secara dinamis:
    1. Mengabaikan domain terlarang dari ignored_domains.txt
    2. Memastikan string target (email / no HP) benar-benar ada di title atau snippet/content.
    """
    if not url:
        return False

    # 1. Filter Noise Domain
    ignored_domains = load_ignored_domains()
    url_lower = url.lower()
    if any(ignored in url_lower for ignored in ignored_domains):
        return False

    # 2. Filter Relevansi Target (Exact Match pada Content / Title)
    if target and target.strip():
        target_lower = target.strip().lower()
        combined_text = f"{title} {snippet}".lower()
        if target_lower not in combined_text:
            return False

    return True


def normalize_phone_number(phone: str) -> list[str]:
    """
    Mengubah nomor HP ke berbagai format standar & variasi pemisah (spasi/dash/strip)
    seperti: +62 812-3456-7890, 0812 3456 7890, dll.
    """
    clean_num = re.sub(r"\D", "", phone.strip())
    if not clean_num:
        return []

    formats = set()

    # 1. Tentukan nomor dasar nasional (08xxx) dan internasional (628xxx)
    if clean_num.startswith("62"):
        local_num = "0" + clean_num[2:]
        intl_num = clean_num
    elif clean_num.startswith("0"):
        local_num = clean_num
        intl_num = "62" + clean_num[1:]
    else:
        local_num = "0" + clean_num
        intl_num = "62" + clean_num

    # Tambahkan format polos dasar
    formats.add(local_num)
    formats.add(intl_num)
    formats.add("+" + intl_num)

    # 2. Pecah nomor lokal (misal: 081234567890) menjadi chunk 3-4 digit
    if len(local_num) >= 10:
        prefix_local = local_num[:4]         # e.g. 0812
        prefix_intl_code = "+62"            # e.g. +62
        prefix_intl_body = intl_num[2:5]     # e.g. 812

        rest_local = local_num[4:]           # e.g. 34567890
        rest_intl = intl_num[5:]            # e.g. 34567890

        mid_len = len(rest_local) // 2
        part1_local = rest_local[:mid_len]
        part2_local = rest_local[mid_len:]

        part1_intl = rest_intl[:mid_len]
        part2_intl = rest_intl[mid_len:]

        # --- Variasi Format Lokal (08xx) ---
        formats.add(f"{prefix_local} {part1_local} {part2_local}")
        formats.add(f"{prefix_local}-{part1_local}-{part2_local}")
        formats.add(f"{prefix_local} {part1_local}-{part2_local}")

        # --- Variasi Format Internasional (+62 8xx) ---
        formats.add(f"{prefix_intl_code} {prefix_intl_body} {part1_intl} {part2_intl}")
        formats.add(f"{prefix_intl_code} {prefix_intl_body}-{part1_intl}-{part2_intl}")
        formats.add(f"{prefix_intl_code} {prefix_intl_body}-{part1_intl} {part2_intl}")
        formats.add(f"{prefix_intl_code}-{prefix_intl_body}-{part1_intl}-{part2_intl}")

    return list(formats)


# --- HELPER CACHE FUNCTIONS ---

def safe_filename_identity(email_addr: str, phone: str = "") -> str:
    """Mengubah format email & phone menjadi nama file JSON yang aman."""
    safe_email = email_addr.strip().lower().replace("@", "_at_").replace(".", "_")
    if phone and phone.strip():
        safe_phone = "".join(filter(str.isalnum, phone.strip()))
        return f"{safe_email}_{safe_phone}"
    return safe_email

def get_breach_cache_filepath(email_addr: str, phone: str = "") -> Path:
    """Mendapatkan path file cache untuk email dan nomor telepon tertentu."""
    identity = safe_filename_identity(email_addr, phone)
    filename = f"breach_cache_{identity}.json"
    return BREACH_CACHE_DIR / filename

def load_breach_cache(email_addr: str, phone: str = "", max_age_hours: float = 12.0) -> dict | None:
    """Membaca data dari file cache jika ada dan belum kadaluwarsa (Default TTL: 12 jam)."""
    cache_file = get_breach_cache_filepath(email_addr, phone)
    if not cache_file.exists():
        return None

    file_age_hours = (time.time() - cache_file.stat().st_mtime) / 3600.0
    if file_age_hours > max_age_hours:
        return None

    try:
        with open(cache_file, "r", encoding="utf-8") as f:
            cached_data = json.load(f)
            cached_data["is_from_cache"] = True
            return cached_data
    except Exception as e:
        print(f"[Breach Cache Log] Gagal membaca file cache: {e}")
        return None

def save_breach_cache(email_addr: str, data: dict, phone: str = "") -> None:
    """Menyimpan hasil scan ke direktori cache/breach/."""
    cache_file = get_breach_cache_filepath(email_addr, phone)
    try:
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[Breach Cache Log] Gagal menyimpan file cache: {e}")


def clean_snippet(text: str, max_len: int = 220) -> str:
    """Membersihkan teks snippet dari tag/entitas HTML dan merapikan ukurannya."""
    if not text:
        return "Tidak ada ringkasan detail tersedia."

    decoded_text = html.unescape(text)
    clean_tags = re.sub(r'<[^<]+?>', '', decoded_text)
    cleaned = " ".join(clean_tags.split())

    if len(cleaned) > max_len:
        return cleaned[:max_len] + "..."
    return cleaned


# --- 1. SPECIALIZED BREACH DATABASE API (BreachDirectory via RapidAPI) ---

def scan_breachdirectory(target: str, rapidapi_key: str) -> list[dict]:
    """Memeriksa database kebocoran data spesifik via BreachDirectory (RapidAPI)."""
    url = "https://breachdirectory.p.rapidapi.com/"
    headers = {
        "X-RapidAPI-Key": rapidapi_key,
        "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com"
    }
    params = {"func": "auto", "term": target}

    response = httpx.get(url, headers=headers, params=params, timeout=12.0)
    response.raise_for_status()
    data = response.json()

    findings = []
    if data.get("success") and data.get("result"):
        for item in data.get("result", []):
            findings.append({
                "source": "BreachDirectory DB API",
                "title": f"Terdeteksi Leak pada Dump [{target}]: {item.get('line', 'Database Dump')}",
                "url": "https://breachdirectory.org",
                "snippet": f"Kredensial / Hash terekspos pada kebocoran publik. Hash Status: {item.get('has_password', 'Tersedia')}"
            })
    return findings


# --- 2. GOOGLE CUSTOM SEARCH JSON API ---

def scan_google_custom_search(target: str, api_key: str, cx_id: str) -> list[dict]:
    """Mencari jejak exposure menggunakan Google Custom Search API."""
    url = "https://www.googleapis.com/customsearch/v1"
    query = f'"{target}" (breach OR leak OR "database dump" OR "combolist" OR "site:pastebin.com")'
    params = {
        "key": api_key,
        "cx": cx_id,
        "q": query,
        "num": 5
    }

    response = httpx.get(url, params=params, timeout=12.0)
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
                "title": title or "Penemuan Exposure Google",
                "url": item_url,
                "snippet": clean_snippet(snippet)
            })
    return findings


# --- 3. GOOGLESEARCH-PYTHON (SCRAPER FALLBACK/FREE) ---

def scan_googlesearch_python(target: str) -> list[dict]:
    """Mencari exposure menggunakan library googlesearch-python (Tanpa API Key)."""
    try:
        from googlesearch import search
        query = f'"{target}" (breach OR leak OR "database dump" OR "combolist")'
        findings = []

        # advanced=True mengembalikan objek SearchResult (url, title, description)
        results = search(query, num_results=5, advanced=True)
        for r in results:
            item_url = getattr(r, "url", "")
            title = getattr(r, "title", "")
            snippet = getattr(r, "description", "")

            if is_valid_finding(item_url, target=target, title=title, snippet=snippet):
                findings.append({
                    "source": "Google Search (Scraper)",
                    "title": title or "Penemuan Exposure Google",
                    "url": item_url,
                    "snippet": clean_snippet(snippet)
                })
        return findings
    except Exception as e:
        print(f"[Breach Scan Log] Googlesearch-python Error ({target}): {e}")
        return []


# --- 4. BING SEARCH SCRAPER ---

def scan_bing_scrape(target: str) -> list[dict]:
    """Mencari exposure dengan melakukan scraping HTML langsung ke Bing Search."""
    try:
        from bs4 import BeautifulSoup

        query = f'"{target}" (breach OR leak OR "database dump" OR "combolist")'
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9"
        }
        url = "https://www.bing.com/search"
        params = {"q": query}

        response = httpx.get(url, headers=headers, params=params, timeout=10.0, follow_redirects=True)
        if response.status_code != 200:
            return []

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
                    "title": title or "Penemuan Exposure Bing",
                    "url": item_url,
                    "snippet": clean_snippet(snippet)
                })

        return findings
    except Exception as e:
        print(f"[Breach Scan Log] Bing Scraper Error ({target}): {e}")
        return []


# --- 5. SEARXNG METASEARCH ENGINE ---

def scan_searxng(target: str) -> list[dict]:
    """Mencari exposure menggunakan Public Instance SearXNG (Meta-Search Engine)."""
    instances = [
        "https://searx.be/search",
        "https://searx.priv.at/search",
        "https://searxng.site/search"
    ]
    query = f'"{target}" (breach OR leak OR "database dump" OR "combolist")'

    for instance_url in instances:
        try:
            params = {"q": query, "format": "json"}
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            response = httpx.get(instance_url, params=params, headers=headers, timeout=8.0)
            if response.status_code == 200:
                data = response.json()
                findings = []
                for result in data.get("results", [])[:5]:
                    item_url = result.get("url", "")
                    title = result.get("title", "")
                    snippet = result.get("content", "")

                    if is_valid_finding(item_url, target=target, title=title, snippet=snippet):
                        findings.append({
                            "source": f"SearXNG ({result.get('engine', 'MetaSearch')})",
                            "title": title or "Penemuan Exposure",
                            "url": item_url,
                            "snippet": clean_snippet(snippet)
                        })
                if findings:
                    return findings
        except Exception:
            continue
    return []


# --- 6. TAVILY SEARCH API ---

def scan_breaches_tavily(target: str, api_key: str) -> list[dict]:
    """Mencari exposure di web menggunakan Tavily Search API."""
    url = "https://api.tavily.com/search"
    query = f'"{target}" "breach" OR "leak" OR "combolist"'
    payload = {
        "api_key": api_key,
        "query": query,
        "search_depth": "basic",
        "max_results": 7
    }
    response = httpx.post(url, json=payload, timeout=12.0)
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
                "title": title or "Penemuan Exposure Data",
                "url": item_url,
                "snippet": clean_snippet(raw_content)
            })
    return findings


# --- 7. DUCKDUCKGO (FALLBACK) ---

def scan_breaches_ddg(target: str) -> list[dict]:
    """Fallback: Mencari exposure menggunakan DuckDuckGo."""
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
                    "title": title or "Penemuan Exposure Data",
                    "url": item_url,
                    "snippet": clean_snippet(snippet)
                })
        return findings
    except Exception as e:
        print(f"[Breach Scan Log] DuckDuckGo error: {e}")
        return []


# --- MAIN COMPREHENSIVE BREACH AUDITOR ---

def scan_data_breaches(email: str, phone: str = "", force_refresh: bool = False) -> dict:
    """
    Main Engine Scanner Multi-Layer (Email & No. HP) dengan Jeda Rate-Limit & Error Handling.
    - Mengecek cache lokal di `cache/breach/` (TTL 12 Jam).
    - Memindai email (wajib) dan variasi nomor handphone (jika diisi).
    - Layer: BreachDirectory DB, Google API, Google Scraper, Bing Scraper, Tavily, SearXNG, DuckDuckGo.
    """
    # 1. Cek Cache Lokal Terlebih Dahulu
    if not force_refresh:
        cached_result = load_breach_cache(email, phone, max_age_hours=12.0)
        if cached_result:
            print(f"[Breach Scan Log] Data untuk {email} ditemukan di cache lokal.")
            return cached_result

    # 2. Susun Target Pencarian (Email + Variasi Nomor Telepon)
    search_targets = [email.strip().lower()]
    if phone and phone.strip():
        phone_variants = normalize_phone_number(phone)
        search_targets.extend(phone_variants)

    tavily_key = os.getenv("TAVILY_API_KEY", "").strip()
    google_search_key = os.getenv("GOOGLE_SEARCH_API_KEY", "").strip()
    google_cx_id = os.getenv("GOOGLE_CX_ID", "").strip()
    rapidapi_key = os.getenv("RAPIDAPI_KEY", "").strip()

    all_findings = []
    active_engines = set()
    google_search_skip = False

    total_targets = len(search_targets)

    for idx, target in enumerate(search_targets, start=1):
        if idx > 1:
            print(f"[Breach Scan Log] Menunggu jeda rate-limit ({DELAY_SECONDS} detik)...")
            time.sleep(DELAY_SECONDS)

        print(f"\n==================================================")
        print(f"[Breach Scan Log] Target [{idx}/{total_targets}]: '{target}'")
        print(f"==================================================")

        # Layer 1: Specialized Breach DB (BreachDirectory)
        if rapidapi_key:
            print(f"[Breach Scan Log] Executing: BreachDirectory API -> Target: {target}")
            try:
                bd_results = scan_breachdirectory(target, rapidapi_key)
                if bd_results:
                    all_findings.extend(bd_results)
                    active_engines.add("BreachDirectory DB")
                    print(f"   └─ Found: {len(bd_results)} record(s)")
                else:
                    print(f"   └─ Found: 0 record")
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429:
                    print(f"[Breach Scan Log] BreachDirectory Rate Limit (429) untuk {target}. Dilewati.")
                else:
                    print(f"[Breach Scan Log] BreachDirectory Error ({target}): {e}")
            except Exception as e:
                print(f"[Breach Scan Log] BreachDirectory Error ({target}): {e}")

        # Layer 2: Google Custom Search API
        if not google_search_skip and google_search_key and google_cx_id:
            print(f"[Breach Scan Log] Executing: Google Custom Search API -> Target: {target}")
            try:
                gsearch_results = scan_google_custom_search(target, google_search_key, google_cx_id)
                if gsearch_results:
                    all_findings.extend(gsearch_results)
                    active_engines.add("Google Search API")
                    print(f"   └─ Found: {len(gsearch_results)} record(s)")
                else:
                    print(f"   └─ Found: 0 record")
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 403:
                    google_search_skip = True
                    print(f"[Breach Scan Log] Google Custom Search 403 Forbidden. Dialihkan ke Scraper.")
                else:
                    print(f"[Breach Scan Log] Google Custom Search Error ({target}): {e}")
            except Exception as e:
                print(f"[Breach Scan Log] Google Custom Search Error ({target}): {e}")

        # Layer 3: Google Search Scraper (googlesearch-python)
        print(f"[Breach Scan Log] Executing: Google Search (Scraper) -> Target: {target}")
        try:
            gscrape_results = scan_googlesearch_python(target)
            if gscrape_results:
                all_findings.extend(gscrape_results)
                active_engines.add("Google Scraper")
                print(f"   └─ Found: {len(gscrape_results)} record(s)")
            else:
                print(f"   └─ Found: 0 record")
        except Exception as e:
            print(f"[Breach Scan Log] Google Scraper Error ({target}): {e}")

        # Layer 4: Bing Search Scraper
        print(f"[Breach Scan Log] Executing: Bing Search (Scraper) -> Target: {target}")
        try:
            bing_results = scan_bing_scrape(target)
            if bing_results:
                all_findings.extend(bing_results)
                active_engines.add("Bing Scraper")
                print(f"   └─ Found: {len(bing_results)} record(s)")
            else:
                print(f"   └─ Found: 0 record")
        except Exception as e:
            print(f"[Breach Scan Log] Bing Scraper Error ({target}): {e}")

        # Layer 5: Tavily AI Search API
        if tavily_key:
            print(f"[Breach Scan Log] Executing: Tavily AI Search API -> Target: {target}")
            try:
                tavily_results = scan_breaches_tavily(target, tavily_key)
                if tavily_results:
                    all_findings.extend(tavily_results)
                    active_engines.add("Tavily AI")
                    print(f"   └─ Found: {len(tavily_results)} record(s)")
                else:
                    print(f"   └─ Found: 0 record")
            except Exception as e:
                print(f"[Breach Scan Log] Tavily Error ({target}): {e}")

        # Layer 6: SearXNG MetaSearch
        print(f"[Breach Scan Log] Executing: SearXNG MetaSearch -> Target: {target}")
        try:
            searx_results = scan_searxng(target)
            if searx_results:
                all_findings.extend(searx_results)
                active_engines.add("SearXNG MetaSearch")
                print(f"   └─ Found: {len(searx_results)} record(s)")
            else:
                print(f"   └─ Found: 0 record")
        except Exception as e:
            print(f"[Breach Scan Log] SearXNG Error ({target}): {e}")

        # Layer 7: DuckDuckGo Search
        print(f"[Breach Scan Log] Executing: DuckDuckGo Search -> Target: {target}")
        try:
            ddg_results = scan_breaches_ddg(target)
            if ddg_results:
                all_findings.extend(ddg_results)
                active_engines.add("DuckDuckGo")
                print(f"   └─ Found: {len(ddg_results)} record(s)")
            else:
                print(f"   └─ Found: 0 record")
        except Exception as e:
            print(f"[Breach Scan Log] DuckDuckGo Error ({target}): {e}")

    # Deduplikasi hasil berdasarkan URL
    unique_findings = []
    seen_urls = set()
    for item in all_findings:
        url = item.get("url", "")
        if url and url in seen_urls:
            continue
        if url:
            seen_urls.add(url)
        unique_findings.append(item)

    engine_summary = ", ".join(active_engines) if active_engines else "None"

    print(f"\n[Breach Scan Log] Pemindaian selesai. Total temuan unik: {len(unique_findings)}")

    output = {
        "engine": engine_summary,
        "results": unique_findings,
        "is_from_cache": False
    }

    # 3. Simpan Hasil Pemindaian Baru ke Cache
    save_breach_cache(email, output, phone)

    return output