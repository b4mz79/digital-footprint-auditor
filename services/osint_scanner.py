import subprocess
import sys
import os
import re
import time
import logging
from dotenv import load_dotenv
from utils.translations import t

load_dotenv()
LOG_LEVEL = os.getenv("LOG_LEVEL", "NOTSET").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.NOTSET),
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("OSINTScanner")

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

def mask_email(email_str: str) -> str:
    """Strict PII Masking."""
    if "@" in email_str:
        parts = email_str.split("@")
        return f"{parts[0][:2]}***@{parts[1].split('.')[0][:1]}***.{parts[1].split('.')[-1]}"
    return "***"

def resolve_holehe_binary() -> str | None:
    python_dir = os.path.dirname(sys.executable)
    possible_paths = [
        os.path.join(python_dir, "holehe"),
        os.path.join(python_dir, "holehe.exe"),
        os.path.join(python_dir, "Scripts", "holehe.exe"),
    ]
    for path in possible_paths:
        abs_path = os.path.abspath(path)
        if os.path.isfile(abs_path) and os.access(abs_path, os.X_OK):
            return abs_path
    return None

def scan_osint_footprint(email: str, lang: str = "id") -> list[dict]:
    start_time = time.monotonic()
    logger.info("=== MEMULAI OSINT SCAN (%s) ===", mask_email(email))
    results = []
    clean_email = email.strip()

    if not EMAIL_REGEX.match(clean_email):
        logger.error("[OSINT Error] Format email tidak valid.")
        logger.info("=== OSINT SCAN SELESAI Dalam %.2f detik ===", time.monotonic() - start_time)
        return results

    cmd_path = resolve_holehe_binary()
    if not cmd_path:
        logger.error("[OSINT Error] Executable 'holehe' terisolasi tidak ditemukan.")
        logger.info("=== OSINT SCAN SELESAI Dalam %.2f detik ===", time.monotonic() - start_time)
        return results

    # FIX: Isolasi Environment Variables agar kredensial di .env tidak bocor ke child process (Holehe)
    safe_env = {
        "PATH": os.environ.get("PATH", ""),
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""), # Esensial untuk eksekusi di Windows
        "USERPROFILE": os.environ.get("USERPROFILE", "")
    }

    try:
        process = subprocess.run(
            [cmd_path, "--only-used", "--", clean_email],
            capture_output=True,
            text=True,
            timeout=180,
            env=safe_env # Penerapan isolasi env
        )

        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        for line in process.stdout.splitlines():
            clean_line = ansi_escape.sub('', line).strip()
            if "[+]" in clean_line:
                parts = clean_line.replace("[+]", "").strip().split()
                if parts:
                    service_domain = parts[0].lower()
                    # Mencegah isu subdomain menjadi aneh jika dipotong mentah
                    display_name = service_domain.split('.')[-2].capitalize() if service_domain.count('.') >= 1 else service_domain.capitalize()

                    if display_name != "Email" and service_domain != "email":
                        logger.info(f"[OSINT] menemukan target terdaftar di layanan: {service_domain}")
                        results.append({
                            "name": display_name,
                            "domain": service_domain,
                            "source": t("source_osint", lang=lang),
                            "subject": t("active_account_osint", lang=lang)
                        })
    except subprocess.TimeoutExpired:
        logger.warning("[OSINT Warning] Proses Holehe Timeout.")
    except Exception as e:
        logger.error(f"[OSINT Error] OSINT Engine crash: {e}")
    finally:
        logger.info("=== OSINT SCAN SELESAI Dalam %.2f detik ===", time.monotonic() - start_time)

    return results