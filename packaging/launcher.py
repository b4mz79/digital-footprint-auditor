from __future__ import annotations

import logging
import os
import secrets
import socket
import subprocess
import sys
import time
import webbrowser
from pathlib import Path
from threading import Thread
from urllib.request import urlopen

from dotenv import load_dotenv

APP_NAME = "DigitalFootprintAuditor"
DEFAULT_PORT = 8501
PORT_RANGE = 10
HOST = "127.0.0.1"
LOG_NAME = "privacy_auditor.log"
SERVE_FLAG = "--serve"

# User-facing .env settings. Internal cache/security paths are managed by the launcher.
CONFIG_GROUPS = {
    "Target": (
        ("GMAIL_TARGET_ADDR", "Target email", False),
        ("TARGET_PHONE_NUM", "Target phone", False),
        ("GMAIL_APP_PASSWORD", "Gmail App Password", True),
    ),
    "AI Providers": (
        ("LLM_PROVIDER_ORDER", "Provider order", False),
        ("LLM_LOCAL_ONLY", "Local LLM only (true/false)", False),
        ("GEMINI_API_KEY", "Gemini API key", True),
        ("GOOGLE_API_KEY", "Google API key", True),
        ("GOOGLE_API_KEY_1", "Gemini / Google API key 1", True),
        ("GOOGLE_API_KEY_2", "Gemini / Google API key 2", True),
        ("GOOGLE_API_KEY_3", "Gemini / Google API key 3", True),
        ("GOOGLE_API_KEY_4", "Gemini / Google API key 4", True),
        ("GOOGLE_API_KEY_5", "Gemini / Google API key 5", True),
        ("GOOGLE_API_KEY_6", "Gemini / Google API key 6", True),
        ("GROQ_API_KEY", "Groq API key", True),
        ("OPENAI_API_KEY", "OpenAI API key", True),
        ("GEMINI_MODEL", "Gemini model", False),
        ("GROQ_MODEL", "Groq model", False),
        ("OPENAI_MODEL", "OpenAI model", False),
        ("OLLAMA_HOST", "Ollama host", False),
        ("OLLAMA_MODEL", "Ollama model", False),
        ("OLLAMA_ALLOW_REMOTE", "Allow remote Ollama (true/false)", False),
        ("OLLAMA_TRUST_ENV", "Ollama trust environment (true/false)", False),
        ("OLLAMA_TIMEOUT_SECONDS", "Ollama timeout (seconds)", False),
        ("AI_TIMEOUT_SECONDS", "AI timeout (seconds)", False),
        ("AI_CONCURRENCY", "AI concurrency", False),
        ("MAX_LLM_OUTPUT_TOKENS", "Max LLM output tokens", False),
    ),
    "Breach / OSINT": (
        ("RAPIDAPI_KEY", "RapidAPI key", True),
        ("TAVILY_API_KEY", "Tavily API key", True),
        ("GOOGLE_SEARCH_API_KEY", "Google Search API key", True),
        ("GOOGLE_CX_ID", "Google CX ID", False),
        ("SEARXNG_INSTANCE_URL", "SearXNG instance URL", False),
        ("HIBP_API_KEY", "Have I Been Pwned API key", True),
        ("HIBP_USER_AGENT", "HIBP user agent", False),
        ("BREACH_QUEUE_WORKERS", "Breach queue workers", False),
        ("BREACH_ENGINE_COOLDOWN", "Breach engine cooldown (seconds)", False),
        ("HTTP_RETRY_ATTEMPTS", "HTTP retry attempts", False),
        ("HTTP_RETRY_BASE_SECONDS", "HTTP retry base delay (seconds)", False),
        ("HTTPX_TRUST_ENV", "Trust HTTP proxy environment (true/false)", False),
        ("DELAY_SECONDS", "Delay between targets (seconds)", False),
    ),
    "IMAP": (
        ("IMAP_MAX_EMAILS", "Max matching emails", False),
        ("DEFAULT_PHONE_REGION", "Default phone region", False),
        ("PHONE_VARIANTS_MAX", "Phone variants max", False),
    ),
    "Advanced": (
        ("TENANT_ID", "Tenant ID", False),
        ("CACHE_RETENTION_HOURS", "Cache retention (hours)", False),
        ("LOG_LEVEL", "Log level", False),
        ("EXPOSE_CACHE_PATH", "Expose cache path (true/false)", False),
        ("IGNORED_DOMAINS_FILE", "Ignored domains file", False),
    ),
}


class LauncherConfig:
    def __init__(self, env_file: Path):
        self.env_file = env_file
        self.values = self._read()

    def _read(self) -> dict[str, str]:
        values: dict[str, str] = {}
        if not self.env_file.is_file():
            return values
        for raw in self.env_file.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
        return values

    def save(self, updates: dict[str, str]) -> None:
        original = self.env_file.read_text(encoding="utf-8") if self.env_file.exists() else ""
        lines = original.splitlines()
        updated: set[str] = set()

        for index, raw in enumerate(lines):
            stripped = raw.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key = stripped.split("=", 1)[0].strip()
            if key in updates:
                lines[index] = f"{key}={updates[key]}"
                updated.add(key)

        missing = [key for key, value in updates.items() if key not in updated and value != ""]
        if missing:
            if lines and lines[-1].strip():
                lines.append("")
            lines.extend(f"{key}={updates[key]}" for key in missing)

        self.env_file.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
        if os.name == "posix":
            self.env_file.chmod(0o600)
        self.values = self._read()


def bundle_root() -> Path:
    """Return application resources in source and PyInstaller modes."""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    return Path(__file__).resolve().parents[1]


def user_data_dir() -> Path:
    """Persistent per-user storage; never write mutable data into the bundle.
    Kompatibel dengan standar Linux (XDG) dan Windows fallback.
    """
    if sys.platform.startswith("linux"):
        # Standar Linux: ~/.local/share/DigitalFootprintAuditor
        root = Path(os.getenv("XDG_DATA_HOME") or Path.home() / ".local" / "share") / APP_NAME
    else:
        # Fallback untuk Windows
        root = Path(os.getenv("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / APP_NAME

    root.mkdir(parents=True, exist_ok=True)
    # The launcher stores API keys and a Gmail App Password here. On POSIX,
    # the default umask can leave this directory traversable by other users.
    if os.name == "posix":
        root.chmod(0o700)
    return root

#def user_data_dir() -> Path:
#    """Persistent per-user storage; never write mutable data into the bundle."""
#    root = Path(os.getenv("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / APP_NAME
#    root.mkdir(parents=True, exist_ok=True)
#    return root


def _ensure_pepper(env_file: Path) -> None:
    text = env_file.read_text(encoding="utf-8") if env_file.exists() else ""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip().startswith("PII_PEPPER_KEY="):
            if len(line.split("=", 1)[1].strip()) >= 32:
                return
            lines[index] = f"PII_PEPPER_KEY={secrets.token_urlsafe(48)}"
            env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return
    env_file.write_text(text.rstrip() + f"\nPII_PEPPER_KEY={secrets.token_urlsafe(48)}\n", encoding="utf-8")


def prepare_environment() -> tuple[Path, bool]:
    """Create first-run config and move mutable paths outside the bundled application."""
    data_dir = user_data_dir()
    env_file = data_dir / ".env"
    first_run = not env_file.exists()
    example = bundle_root() / ".env.example"

    if first_run and example.is_file():
        env_file.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")

    _ensure_pepper(env_file)
    if os.name == "posix":
        env_file.chmod(0o600)
    load_dotenv(env_file, override=False)

    cache_dir = data_dir / "cache"
    (cache_dir / "breach").mkdir(parents=True, exist_ok=True)

    # Packaged mode keeps mutable/configurable data in user storage, not under _internal.
    os.environ.update({
        "CACHE_KEY_FILE": str(data_dir / ".cache_key"),
        "AI_CACHE_DIR": str(cache_dir),
        "BREACH_CACHE_DIR": str(cache_dir / "breach"),
        "IGNORED_DOMAINS_FILE": str(data_dir / "ignored_domains.txt"),
    })
    return data_dir, first_run


def configure_file_logging(data_dir: Path) -> logging.Handler:
    """Install file logging before application imports its logging setup."""
    log_file = data_dir / LOG_NAME
    root = logging.getLogger()
    target = log_file.resolve()
    for handler in root.handlers:
        if isinstance(handler, logging.FileHandler) and Path(handler.baseFilename).resolve() == target:
            return handler

    handler = logging.FileHandler(log_file, encoding="utf-8")
    handler.setLevel(logging.INFO)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"))
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    return handler


def choose_port(start: int = DEFAULT_PORT, count: int = PORT_RANGE) -> int:
    """Find a free localhost port, preferring Streamlit's normal 8501."""
    for port in range(start, start + count):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            if sock.connect_ex((HOST, port)) != 0:
                return port
    raise RuntimeError(f"Tidak ada port localhost yang tersedia pada {start}-{start + count - 1}.")


def app_path() -> Path:
    path = bundle_root() / "app.py"
    if not path.is_file():
        raise FileNotFoundError(f"Bundled app.py tidak ditemukan: {path}")
    return path


def _serve(port: int, data_dir: Path) -> None:
    """Run Streamlit's real CLI entry point in packaged production mode."""
    os.environ.update({
        "STREAMLIT_GLOBAL_DEVELOPMENT_MODE": "false",
        "STREAMLIT_SERVER_ADDRESS": HOST,
        "STREAMLIT_SERVER_PORT": str(port),
        "STREAMLIT_SERVER_HEADLESS": "true",
        "STREAMLIT_BROWSER_GATHER_USAGE_STATS": "false",
        "STREAMLIT_SERVER_FILE_WATCHER_TYPE": "none",
    })
    os.chdir(data_dir)
    logging.getLogger("PrivacyAuditorLauncher").info("Starting Streamlit child: %s:%s", HOST, port)

    from streamlit.web.cli import main as streamlit_main

    args = [
        "run",
        str(app_path()),
        f"--server.address={HOST}",
        f"--server.port={port}",
        "--server.headless=true",
    ]
    streamlit_main(args=args, prog_name="streamlit", standalone_mode=False)


def _child_command(port: int) -> list[str]:
    """Launch this executable/script again in Streamlit child mode."""
    if getattr(sys, "frozen", False):
        return [sys.executable, SERVE_FLAG, str(port)]
    return [sys.executable, str(Path(__file__).resolve()), SERVE_FLAG, str(port)]


def _stop_process(process: subprocess.Popen | None) -> None:
    if not process or process.poll() is not None:
        return
    logging.getLogger("PrivacyAuditorLauncher").info("Stopping Streamlit child (pid=%s)", process.pid)
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def _wait_ready(process: subprocess.Popen, url: str, notify) -> None:
    """Open browser only after Streamlit health and root endpoints are ready."""
    deadline = time.monotonic() + 45
    health_url = f"{url}/_stcore/health"
    while time.monotonic() < deadline and process.poll() is None:
        try:
            with urlopen(health_url, timeout=1) as response:
                healthy = 200 <= response.status < 300
            if healthy:
                with urlopen(url, timeout=1) as response:
                    if 200 <= response.status < 300:
                        webbrowser.open(url)
                        notify("ready", url)
                        return
        except Exception:
            pass
        time.sleep(0.25)
    notify("failed", "Streamlit gagal start. Periksa log aplikasi.")


def _show_error(message: str) -> None:
    """Show a useful startup error when the executable has no console."""
    try:
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Privacy Auditor", message)
        root.destroy()
    except Exception:
        pass


def show_configuration(parent, data_dir: Path, on_saved, on_save_start=None) -> None:
    """Show the first-run/settings form and save values into the user's .env."""
    import tkinter as tk
    from tkinter import messagebox, ttk

    env_file = data_dir / ".env"
    config = LauncherConfig(env_file)
    dialog = tk.Toplevel(parent)
    dialog.title("Privacy Auditor — Configuration")
    dialog.geometry("1100x780")
    dialog.minsize(1111, 632)
    dialog.transient(parent)
    dialog.grab_set()

    outer = ttk.Frame(dialog, padding=12)
    outer.pack(fill="both", expand=True)

    if sys.platform.startswith("linux"):
        ttk.Label(outer, text="Configuration", font=("Helvetica", 14, "bold")).pack(anchor="w")
    else:
        ttk.Label(outer, text="Configuration", font=("Segoe UI", 15, "bold")).pack(anchor="w")
    ttk.Label(
        outer,
        text="API keys and settings are stored locally in your Windows user profile.",
    ).pack(anchor="w", pady=(2, 10))

    canvas = tk.Canvas(outer, highlightthickness=0)
    scrollbar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
    form = ttk.Frame(canvas)
    form.bind("<Configure>", lambda _event: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.create_window((0, 0), window=form, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    fields: dict[str, tk.StringVar] = {}
    secret_entries: list[ttk.Entry] = []

    for group, items in CONFIG_GROUPS.items():
        section = ttk.LabelFrame(form, text=group, padding=10)
        section.pack(fill="x", expand=True, pady=(0, 10))
        section.columnconfigure(1, weight=1)

        for row, (key, label, secret) in enumerate(items):
            ttk.Label(section, text=label, width=34).grid(row=row, column=0, sticky="w", padx=(0, 8), pady=4)
            variable = tk.StringVar(value=config.values.get(key, ""))
            fields[key] = variable
            entry = ttk.Entry(section, textvariable=variable, width=100, show="•" if secret else "")
            entry.grid(row=row, column=1, sticky="ew", pady=4)
            if secret:
                secret_entries.append(entry)

    visibility = tk.BooleanVar(value=False)

    def toggle_secrets() -> None:
        mask = "" if visibility.get() else "•"
        for entry in secret_entries:
            entry.config(show=mask)

    ttk.Checkbutton(
        outer,
        text="Show API keys / passwords",
        variable=visibility,
        command=toggle_secrets,
    ).pack(anchor="w", pady=(4, 8))

    ttk.Label(
        outer,
        text=f"Config file: {env_file}",
        foreground="#666666",
    ).pack(anchor="w")

    buttons = ttk.Frame(outer)
    buttons.pack(fill="x", pady=(10, 0))

    def save(start_after=False) -> None:
        updates = {key: variable.get().strip() for key, variable in fields.items()}
        # Never log the actual values because API keys/passwords may be present.
        config.save(updates)
        load_dotenv(env_file, override=True)
        if start_after and on_save_start:
            dialog.destroy()
            on_save_start()
            return
        messagebox.showinfo(
            "Privacy Auditor",
            "Configuration saved. Restart the application if it is already running.",
            parent=dialog,
        )
        on_saved()
        dialog.destroy()

    ttk.Button(buttons, text="Save", command=lambda: save(False)).pack(side="right", padx=(6, 0))
    ttk.Button(buttons, text="Save & Start", command=lambda: save(True)).pack(side="right")
    ttk.Button(buttons, text="Cancel", command=dialog.destroy).pack(side="right", padx=(0, 6))
    dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)


def run_gui(data_dir: Path, first_run: bool) -> None:
    import tkinter as tk
    from tkinter import ttk

    root = tk.Tk()
    root.title("Local Digital Footprint & Privacy Auditor")
    root.resizable(False, False)
    root.geometry("580x330")

    process: subprocess.Popen | None = None
    port = DEFAULT_PORT
    url = ""

    if sys.platform.startswith("linux"):
        ttk.Label(root, text="🛡️ Local Digital Footprint & Privacy Auditor", font=("Helvetica", 13, "bold")).pack(pady=(20, 12))
    else:
        ttk.Label(root, text="🛡️ Local Digital Footprint & Privacy Auditor", font=("Segoe UI", 14, "bold")).pack(pady=(20, 12))
    status = ttk.Label(root, text="Status: Ready")
    status.pack(pady=3)
    address = ttk.Label(root, text="")
    address.pack(pady=2)

    buttons = ttk.Frame(root)
    buttons.pack(pady=18)
    start_btn = ttk.Button(buttons, text="▶ Start", width=14)
    stop_btn = ttk.Button(buttons, text="■ Stop", width=14, state="disabled")
    open_btn = ttk.Button(buttons, text="🌐 Browser", width=14, state="disabled")
    start_btn.grid(row=0, column=0, padx=5)
    stop_btn.grid(row=0, column=1, padx=5)
    open_btn.grid(row=0, column=2, padx=5)

    config_btn = ttk.Button(root, text="⚙ Configuration", width=18)
    config_btn.pack(pady=(0, 12))
    ttk.Label(root, text=f"Config: {data_dir / '.env'}", foreground="#666666").pack()

    def set_status(text: str) -> None:
        status.config(text=f"Status: {text}")

    def notify(kind: str, value: str) -> None:
        def update() -> None:
            nonlocal url
            if kind == "ready":
                url = value
                set_status("Running")
                address.config(text=url)
                open_btn.config(state="normal")
                start_btn.config(state="disabled")
                stop_btn.config(state="normal")
                return
            set_status("Startup failed")
            address.config(text="")
            start_btn.config(state="normal")
            stop_btn.config(state="disabled")
            _show_error(value)
        root.after(0, update)

    def poll_process() -> None:
        if process is not None and process.poll() is not None:
            set_status("Stopped")
            address.config(text="")
            start_btn.config(state="normal")
            stop_btn.config(state="disabled")
            open_btn.config(state="disabled")
        root.after(500, poll_process)

    def start() -> None:
        nonlocal process, port, url
        if process and process.poll() is None:
            return
        try:
            port = choose_port()
            url = f"http://{HOST}:{port}"
            log_stream = (data_dir / LOG_NAME).open("a", encoding="utf-8")
            process = subprocess.Popen(
                _child_command(port),
                cwd=str(data_dir),
                env=os.environ.copy(),
                stdout=log_stream,
                stderr=subprocess.STDOUT,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            log_stream.close()
            set_status("Starting...")
            address.config(text=url)
            start_btn.config(state="disabled")
            stop_btn.config(state="normal")
            Thread(target=_wait_ready, args=(process, url, notify), daemon=True).start()
        except Exception as exc:
            logging.getLogger("PrivacyAuditorLauncher").exception("Application startup failed")
            _show_error(f"Privacy Auditor gagal dijalankan.\n\n{type(exc).__name__}: {exc}")
            set_status("Startup failed")

    def stop() -> None:
        nonlocal process
        _stop_process(process)
        process = None
        set_status("Stopped")
        address.config(text="")
        start_btn.config(state="normal")
        stop_btn.config(state="disabled")
        open_btn.config(state="disabled")

    def open_browser() -> None:
        if url:
            webbrowser.open(url)

    def open_config() -> None:
        show_configuration(
            root,
            data_dir,
            lambda: set_status("Configuration saved — restart required"),
            on_save_start=start,
        )

    start_btn.config(command=start)
    stop_btn.config(command=stop)
    open_btn.config(command=open_browser)
    config_btn.config(command=open_config)
    root.protocol("WM_DELETE_WINDOW", lambda: (stop(), root.destroy()))
    root.after(500, poll_process)

    if first_run:
        root.after(250, lambda: show_configuration(root, data_dir, lambda: None, on_save_start=start))

    root.mainloop()


def main() -> None:
    data_dir, first_run = prepare_environment()
    handler = configure_file_logging(data_dir)
    try:
        # Frozen EXE launches itself in --serve mode as the Streamlit child.
        if len(sys.argv) >= 3 and sys.argv[1] == SERVE_FLAG:
            _serve(int(sys.argv[2]), data_dir)
        else:
            run_gui(data_dir, first_run)
    except Exception as exc:
        logging.getLogger("PrivacyAuditorLauncher").exception("Application startup failed")
        _show_error(
            f"Privacy Auditor gagal dijalankan.\n\n"
            f"Detail: {type(exc).__name__}: {exc}\n\n"
            f"Log: {data_dir / LOG_NAME}"
        )
    finally:
        try:
            handler.flush()
        except Exception:
            pass


if __name__ == "__main__":
    main()
