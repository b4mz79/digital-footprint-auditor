import subprocess
import sys
import os
import re
from utils.translations import t


def scan_osint_footprint(email: str, lang: str = "id") -> list[dict]:
    results = []
    try:
        python_executable = sys.executable
        venv_dir = os.path.dirname(python_executable)
        holehe_exe = os.path.join(venv_dir, "holehe.exe")

        cmd_path = holehe_exe if os.path.exists(holehe_exe) else "holehe"

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
                    results.append({
                        "service": formatted_name,
                        "name": formatted_name,
                        "domain": service_name,
                        "source": t("source_osint", lang=lang),
                        "sample_subject": t("active_account_osint", lang=lang)
                    })

    except Exception as e:
        print(f"Error OSINT scan: {e}")

    return results