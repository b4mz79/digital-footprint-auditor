import subprocess
import sys
import os
import re

def scan_osint_footprint(email: str) -> list[dict]:
    """
    Memindai pendaftaran email menggunakan holehe CLI.
    Lebih stabil dan kompatibel dengan holehe v1.61+.
    """
    results = []
    try:
        # Menentukan lokasi executable holehe di dalam venv Windows
        python_executable = sys.executable
        venv_dir = os.path.dirname(python_executable)
        holehe_exe = os.path.join(venv_dir, "holehe.exe")

        cmd_path = holehe_exe if os.path.exists(holehe_exe) else "holehe"

        # Opsi --only-used hanya mencetak situs tempat email benar-benar terdaftar
        process = subprocess.run(
            [cmd_path, email, "--only-used"],
            capture_output=True,
            text=True,
            timeout=180
        )

        output = process.stdout

        # Regex untuk menghilangkan ANSI color escape codes dari terminal output
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

        for line in output.splitlines():
            clean_line = ansi_escape.sub('', line).strip()

            # Baris dengan simbol [+] menandakan akun ditemukan/terdaftar
            if "[+]" in clean_line:
                # Ambil nama domain/layanan setelah simbol [+]
                parts = clean_line.replace("[+]", "").strip().split()
                if parts:
                    service_name = parts[0]
                    formatted_name = service_name.split(".")[0].capitalize()
                    results.append({
                        "service": formatted_name,
                        "name": formatted_name,
                        "domain": service_name,
                        "source": "OSINT Checker (Holehe)",
                        "sample_subject": "Akun Terdeteksi Aktif"
                    })

    except Exception as e:
        print(f"Error pemindaian OSINT: {e}")

    return results