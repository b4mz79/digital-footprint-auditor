import subprocess
import sys
import os
import re
import logging
from utils.translations import t

# Setup Logger untuk OSINT Scanner
logger = logging.getLogger("OSINTScanner")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S"
    )

def scan_osint_footprint(email: str, lang: str = "id") -> list[dict]:
    results = []
    logger.info(f"[OSINT] Memulai footprint scan untuk target: {email}")

    try:
        python_executable = sys.executable
        venv_dir = os.path.dirname(python_executable)
        holehe_exe = os.path.join(venv_dir, "holehe.exe")

        cmd_path = holehe_exe if os.path.exists(holehe_exe) else "holehe"
        logger.info(f"[OSINT] Menggunakan executable: {cmd_path}")

        logger.info("[OSINT] Menjalankan Holehe (timeout 180s)...")
        process = subprocess.run(
            [cmd_path, email, "--only-used"],
            capture_output=True,
            text=True,
            timeout=180
        )

        output = process.stdout
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

        for line in output.splitlines():
            clean_line = ansi_escape.sub('', line).strip()

            if "[+]" in clean_line:
                parts = clean_line.replace("[+]", "").strip().split()
                if parts:
                    service_name = parts[0]
                    formatted_name = service_name.split(".")[0].capitalize()
                    logger.info(f"[OSINT] Akun aktif terdeteksi di platform: {formatted_name} ({service_name})")

                    results.append({
                        "service": formatted_name,
                        "name": formatted_name,
                        "domain": service_name,
                        "source": t("source_osint", lang=lang),
                        "sample_subject": t("active_account_osint", lang=lang)
                    })

        logger.info(f"[OSINT] Pemindaian selesai. Total akun aktif ditemukan: {len(results)}")

    except subprocess.TimeoutExpired:
        logger.warning("[OSINT Warning] Proses Holehe melebihi batas waktu (timeout 180s).")
    except Exception as e:
        logger.error(f"[OSINT Error] Terjadi kesalahan saat pemindaian OSINT: {e}")

    return results