from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
required = [
    "app.py",
    ".env.example",
    "requirements.txt",
    "services",
    "utils",
    "prompts",
    "packaging/launcher.py",
    "packaging/locks/windows-py312.lock.txt",
    "packaging/locks/linux-py314.lock.txt",
]
missing = [item for item in required if not (ROOT / item).exists()]
if missing:
    raise SystemExit("Missing required packaging inputs:\n- " + "\n- ".join(missing))

prompt = ROOT / "prompts" / "system_prompt_id.txt"
if not prompt.is_file():
    raise SystemExit(f"Missing required prompt: {prompt}")

def validate_lock(path: Path, expected_python: str) -> None:
    """Validate that the checked-in build lock is complete and exactly pinned."""
    text = path.read_text(encoding="utf-8")
    if expected_python not in text.splitlines()[1]:
        raise SystemExit(f"Wrong Python target declared in lock: {path}")

    packages: dict[str, str] = {}
    for line_number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*==[^=\s]+", line):
            raise SystemExit(
                f"Unpinned or malformed requirement in {path}:{line_number}: {line}"
            )
        name, version = line.split("==", 1)
        normalized = re.sub(r"[-_.]+", "-", name).lower()
        if normalized in packages:
            raise SystemExit(f"Duplicate package in {path}:{line_number}: {name}")
        packages[normalized] = version

    required_packages = {
        "streamlit", "httpx", "holehe", "trio", "python-dotenv", "bandit",
        "cryptography", "pydantic", "google-genai", "groq", "openai",
        "phonenumbers", "requests", "googlesearch-python",
        "beautifulsoup4", "pyinstaller", "pyinstaller-hooks-contrib",
        "pytest", "pytest-asyncio", "pytest-cov",
    }
    missing_packages = sorted(required_packages - packages.keys())
    if missing_packages:
        raise SystemExit(
            f"Missing required locked packages in {path}: "
            + ", ".join(missing_packages)
        )


validate_lock(ROOT / "packaging/locks/windows-py312.lock.txt", "CPython 3.12.x")
validate_lock(ROOT / "packaging/locks/linux-py314.lock.txt", "CPython 3.14.x")

print("[OK] Packaging inputs and pinned environment locks are valid.")

