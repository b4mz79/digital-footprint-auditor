from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist" / "PrivacyAuditor"
required = [
    DIST / "PrivacyAuditor.exe",
    DIST / "_internal" / "app.py",
    DIST / "_internal" / ".env.example",
    DIST / "_internal" / "prompts" / "system_prompt_id.txt",
]
missing = [str(path.relative_to(ROOT)) for path in required if not path.exists()]
if missing:
    raise SystemExit("[ERROR] Missing build artifacts:\n- " + "\n- ".join(missing))
print("[OK] Main and build artifacts are present.")
