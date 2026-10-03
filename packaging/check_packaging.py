from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
required = [
    "app.py",
    ".env.example",
    "requirements.txt",
    "services",
    "utils",
    "prompts",
    "packaging/launcher.py",
]
missing = [item for item in required if not (ROOT / item).exists()]
if missing:
    raise SystemExit("Missing required packaging inputs:\n- " + "\n- ".join(missing))

prompt = ROOT / "prompts" / "system_prompt_id.txt"
if not prompt.is_file():
    raise SystemExit(f"Missing required prompt: {prompt}")

print("[OK] Packaging inputs are present.")
