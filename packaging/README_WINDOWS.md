# Windows End-User Packaging

This packaging stage targets the requested UX:

```text
Install → Desktop shortcut → Double-click → Browser opens
```

The application itself remains the existing Python/Streamlit project. PyInstaller bundles the Python runtime and dependencies so end users do not need to install Python separately. The main application is built as **one-folder** first for easier diagnosis and faster startup; Inno Setup turns that folder into a normal Windows installer.

## Architecture

```text
Installer
  ↓
%LOCALAPPDATA%\\DigitalFootprintAuditor
  ├── PrivacyAuditor.exe
  └── _internal\\...

Runtime data is kept separately:

%LOCALAPPDATA%\\DigitalFootprintAuditor\\
  ├── .env
  ├── .cache_key
  ├── ignored_domains.txt
  ├── privacy_auditor.log
  └── cache\\
      └── breach\\
```

The launcher moves mutable cache/config files out of the bundled runtime. Prompt files remain bundled under `_internal/prompts` because the existing prompt loader resolves them relative to the packaged project root.

## Build requirements

Use the project's existing Windows virtual environment with all application dependencies installed from `requirements.txt`. Then the build script installs PyInstaller 6.x.

Run:

```bat
packaging\\build_windows.bat
```

Expected output:

```text
dist\\PrivacyAuditor\\PrivacyAuditor.exe
dist\\PrivacyAuditor\\_internal\\*
```

## First test

Do not create the installer yet. First run:

```text
dist\\PrivacyAuditor\\PrivacyAuditor.exe
```

Verify:

1. No console window from the main application.
2. Browser opens automatically.
3. Dashboard renders.
4. `%LOCALAPPDATA%\\DigitalFootprintAuditor\\privacy_auditor.log` is created.
5. `.env` and `.cache_key` are created in the user data directory.
6. IMAP scan works.
7. OSINT use `holehe modules` inside `PrivacyAuditor.exe`.
8. Breach scanner and HIBP behave exactly as in the source environment.

## Installer

Install Inno Setup and compile:

```bat
ISCC.exe packaging\\installer\\PrivacyAuditor.iss
```

The installer output is written to:

```text
dist\\installer\\PrivacyAuditor-Setup-v1.0.0.exe
```

## Why one-folder first

PyInstaller's one-folder build is easier to diagnose because the bundled runtime is visible as a directory. Once this build passes clean-machine testing, the next step can evaluate one-file packaging, installer signing, update strategy, and antivirus reputation.

## Fix 1.1

PyInstaller 6.x uses `_internal` as the default contents directory for onedir builds. Application data destinations in `PrivacyAuditor.spec` therefore use `.` and `prompts`, not `_internal` and `_internal/prompts`. In the resulting bundle, these files are expected under `dist\PrivacyAuditor\_internal\`.
