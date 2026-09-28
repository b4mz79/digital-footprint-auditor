import os
import json
import re
import time
import html
from pathlib import Path
import httpx
from dotenv import load_dotenv
from utils.translations import t

load_dotenv()

BREACH_CACHE_DIR = Path("cache/breach")
BREACH_CACHE_DIR.mkdir(parents=True, exist_ok=True)
DELAY_SECONDS = int(os.getenv("DELAY_SECONDS", 5))

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

def safe_filename_identity(email_addr: str, phone: str = "") -> str:
    safe_email = email_addr.strip().lower().replace("@", "_at_").replace(".", "_")
    if phone and phone.strip():
        safe_phone = "".join(filter(str.isalnum, phone.strip()))
        return f"{safe_email}_{safe_phone}"
    return safe_email

def get_breach_cache_filepath(email_addr: str, phone: str = "") -> Path:
    identity = safe_filename_identity(email_addr, phone)
    return BREACH_CACHE_DIR / f"breach_cache_{identity}.json"

def load_breach_cache(email_addr: str, phone: str = "", max_age_hours: float = 12.0) -> dict | None:
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
    except Exception:
        return None

def save_breach_cache(email_addr: str, data: dict, phone: str = "") -> None:
    cache_file = get_breach_cache_filepath(email_addr, phone)
    try:
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[Breach Cache Log] Error saving cache: {e}")

def clean_snippet(text: str, max_len: int = 220, lang: str = "id") -> str:
    if not text:
        return t("no_summary", lang=lang)

    decoded_text = html.unescape(text)
    clean_tags = re.sub(r'<[^<]+?>', '', decoded_text)
    cleaned = " ".join(clean_tags.split())

    if len(cleaned) > max_len:
        return cleaned[:max_len] + "..."
    return cleaned

def scan_breachdirectory(target: str, rapidapi_key: str) -> list[dict]:
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
                "title": f"Leak Detected [{target}]: {item.get('line', 'Database Dump')}",
                "url": "https://breachdirectory.org",
                "snippet": f"Credentials exposed. Hash Status: {item.get('has_password', 'Available')}"
            })
    return findings

def scan_google_custom_search(target: str, api_key: str, cx_id: str, lang: str = "id") -> list[dict]:
    url = "https://www.googleapis.com/customsearch/v1"
    query = f'"{target}" (breach OR leak OR "database dump" OR "combolist" OR "site:pastebin.com")'
    params = {"key": api_key, "cx": cx_id, "q": query, "num": 5}

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
                "title": title or "Google Exposure Finding",
                "url": item_url,
                "snippet": clean_snippet(snippet, lang=lang)
            })
    return findings

def scan_googlesearch_python(target: str, lang: str = "id") -> list[dict]:
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
        return findings
    except Exception:
        return []

def scan_bing_scrape(target: str, lang: str = "id") -> list[dict]:
    try:
        from bs4 import BeautifulSoup
        query = f'"{target}" (breach OR leak OR "database dump" OR "combolist")'
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Accept-Language": "en-US,en;q=0.9"}
        url = "https://www.bing.com/search"

        response = httpx.get(url, headers=headers, params={"q": query}, timeout=10.0, follow_redirects=True)
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
                    "title": title or "Bing Exposure Finding",
                    "url": item_url,
                    "snippet": clean_snippet(snippet, lang=lang)
                })
        return findings
    except Exception:
        return []

def scan_searxng(target: str, lang: str = "id") -> list[dict]:
    instances = ["https://searx.be/search", "https://searx.priv.at/search", "https://searxng.site/search"]
    query = f'"{target}" (breach OR leak OR "database dump" OR "combolist")'

    for instance_url in instances:
        try:
            response = httpx.get(instance_url, params={"q": query, "format": "json"}, headers={"User-Agent": "Mozilla/5.0"}, timeout=8.0)
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
                            "title": title or "Exposure Finding",
                            "url": item_url,
                            "snippet": clean_snippet(snippet, lang=lang)
                        })
                if findings:
                    return findings
        except Exception:
            continue
    return []

def scan_breaches_tavily(target: str, api_key: str, lang: str = "id") -> list[dict]:
    url = "https://api.tavily.com/search"
    query = f'"{target}" "breach" OR "leak" OR "combolist"'
    payload = {"api_key": api_key, "query": query, "search_depth": "basic", "max_results": 7}

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
                "title": title or "Exposure Finding",
                "url": item_url,
                "snippet": clean_snippet(raw_content, lang=lang)
            })
    return findings

def scan_breaches_ddg(target: str, lang: str = "id") -> list[dict]:
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
                    "title": title or "Exposure Finding",
                    "url": item_url,
                    "snippet": clean_snippet(snippet, lang=lang)
                })
        return findings
    except Exception:
        return []

def scan_data_breaches(email: str, phone: str = "", force_refresh: bool = False, lang: str = "id") -> dict:
    if not force_refresh:
        cached_result = load_breach_cache(email, phone, max_age_hours=12.0)
        if cached_result:
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

    for idx, target in enumerate(search_targets, start=1):
        if idx > 1:
            time.sleep(DELAY_SECONDS)

        if rapidapi_key:
            try:
                bd_results = scan_breachdirectory(target, rapidapi_key)
                if bd_results:
                    all_findings.extend(bd_results)
                    active_engines.add("BreachDirectory DB")
            except Exception:
                pass

        if google_search_key and google_cx_id:
            try:
                gsearch_results = scan_google_custom_search(target, google_search_key, google_cx_id, lang=lang)
                if gsearch_results:
                    all_findings.extend(gsearch_results)
                    active_engines.add("Google Search API")
            except Exception:
                pass

        gscrape_results = scan_googlesearch_python(target, lang=lang)
        if gscrape_results:
            all_findings.extend(gscrape_results)
            active_engines.add("Google Scraper")

        bing_results = scan_bing_scrape(target, lang=lang)
        if bing_results:
            all_findings.extend(bing_results)
            active_engines.add("Bing Scraper")

        if tavily_key:
            try:
                tavily_results = scan_breaches_tavily(target, tavily_key, lang=lang)
                if tavily_results:
                    all_findings.extend(tavily_results)
                    active_engines.add("Tavily AI")
            except Exception:
                pass

        searx_results = scan_searxng(target, lang=lang)
        if searx_results:
            all_findings.extend(searx_results)
            active_engines.add("SearXNG")

        ddg_results = scan_breaches_ddg(target, lang=lang)
        if ddg_results:
            all_findings.extend(ddg_results)
            active_engines.add("DuckDuckGo")

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