import subprocess
import sys
import os
import re
import shutil
import logging
from dotenv import load_dotenv
from utils.translations import t

load_dotenv()
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("OSINTScanner")

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

def resolve_holehe_binary() -> str | None:
    # FIX: Prioritaskan virtualenv eksplisit dan hapus fallback tidak aman dari system PATH
    # untuk mencegah Path Hijacking / Privilege Escalation.
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
    results = []
    clean_email = email.strip()
    
    # Validasi Ketat
    if not EMAIL_REGEX.match(clean_email):
        logger.error("[OSINT Error] Format email tidak valid.")
        return results

    cmd_path = resolve_holehe_binary()
    if not cmd_path:
        logger.error("[OSINT Error] Executable 'holehe' terisolasi tidak ditemukan.")
        return results

    try:
        # FIX: Tambahkan "--" (End of Options) untuk mencegah Argument Injection 
        # jika parameter terdeteksi sebagai flag opsi (misal email aneh "-admin@xyz.com")
        process = subprocess.run(
            [cmd_path, "--only-used", "--", clean_email],
            capture_output=True,
            text=True,
            timeout=180
        )

        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        for line in process.stdout.splitlines():
            clean_line = ansi_escape.sub('', line).strip()
            if "[+]" in clean_line:
                parts = clean_line.replace("[+]", "").strip().split()
                if parts:
                    service_name = parts[0]
                    results.append({
                        "service": service_name.split(".")[0].capitalize(),
                        "name": service_name.split(".")[0].capitalize(),
                        "domain": service_name,
                        "source": t("source_osint", lang=lang),
                        "sample_subject": t("active_account_osint", lang=lang)
                    })
    except subprocess.TimeoutExpired:
        logger.warning("[OSINT Warning] Proses Holehe Timeout.")
    except Exception as e:
        logger.error(f"[OSINT Error] OSINT Engine crash: {e}")

    return results