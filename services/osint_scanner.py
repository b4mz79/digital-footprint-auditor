import subprocess
import sys
import os
import re

from dotenv import load_dotenv

from utils.domains import display_name
from utils.logging_setup import get_logger
from utils.privacy import mask_email
from utils.translations import t

load_dotenv()
logger = get_logger("OSINTScanner")

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
HOLEHE_TIMEOUT_SECONDS = 180
ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

# Variables the child process needs to run and to verify TLS. Secrets from .env (API keys,
# passwords) and proxy settings (which may embed credentials) are deliberately NOT forwarded.
_SAFE_ENV_KEYS = (
    "PATH", "SYSTEMROOT", "USERPROFILE", "HOME", "LANG", "LC_ALL",
    "TMPDIR", "TEMP", "TMP", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE",
)


class OSINTScanError(RuntimeError):
    """The scan could not be completed. An error must never look like 'no accounts found'."""


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


def _safe_env() -> dict[str, str]:
    return {key: os.environ[key] for key in _SAFE_ENV_KEYS if os.environ.get(key)}


def parse_holehe_output(stdout: str, lang: str = "id") -> tuple[list[dict], bool]:
    """Returns (results, recognised) where `recognised` says whether the output looked like
    Holehe's report at all (any [+]/[-]/[x]/[!] status line)."""
    results: list[dict] = []
    recognised = False
    for line in stdout.splitlines():
        clean_line = ANSI_ESCAPE.sub('', line).strip()
        if clean_line[:3] in {"[+]", "[-]", "[x]", "[!]"}:
            recognised = True
        if "[+]" not in clean_line:
            continue
        parts = clean_line.replace("[+]", "").strip().split()
        if not parts:
            continue
        service_domain = parts[0].lower()
        name = display_name(service_domain) if "." in service_domain else service_domain.capitalize()
        if name and name != "Email" and service_domain != "email":
            logger.info(f"[OSINT] menemukan target terdaftar di layanan: {service_domain}")
            results.append({
                "name": name,
                "domain": service_domain,
                "source": t("source_osint", lang=lang),
                "subject": t("active_account_osint", lang=lang),
            })
    return results, recognised


def scan_osint_footprint(email: str, lang: str = "id") -> list[dict]:
    logger.info(f"[OSINT] Scanning target: {mask_email(email)}")
    clean_email = email.strip()

    if not EMAIL_REGEX.match(clean_email):
        raise ValueError("Format email tidak valid.")

    cmd_path = resolve_holehe_binary()
    if not cmd_path:
        raise OSINTScanError("Executable 'holehe' tidak ditemukan di lingkungan Python ini (pip install holehe).")

    try:
        process = subprocess.run(
            [cmd_path, "--only-used", "--", clean_email],
            capture_output=True,
            text=True,
            timeout=HOLEHE_TIMEOUT_SECONDS,
            env=_safe_env(),
        )
    except subprocess.TimeoutExpired:
        logger.warning("[OSINT Warning] Proses Holehe Timeout.")
        raise OSINTScanError(f"Holehe melewati batas waktu {HOLEHE_TIMEOUT_SECONDS} detik.")
    except OSError as exc:
        logger.error(f"[OSINT Error] Holehe tidak dapat dijalankan: {type(exc).__name__}")
        raise OSINTScanError(f"Holehe tidak dapat dijalankan: {type(exc).__name__}")

    results, recognised = parse_holehe_output(process.stdout or "", lang=lang)

    # A crash, or output we do not recognise, is a failed scan - not an empty result.
    if process.returncode != 0 and not results:
        raise OSINTScanError(f"Holehe berakhir dengan kode {process.returncode}.")
    if not recognised and not results and (process.stdout or "").strip():
        raise OSINTScanError("Keluaran Holehe tidak dikenali (versi Holehe mungkin berubah).")

    return results
