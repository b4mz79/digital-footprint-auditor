# Docker Workflow for Contributors

This workflow builds a local development image and a separate disposable test image. It does not change the application's runtime logic or enable optional features.

## Requirements

- Docker Desktop (Windows/macOS) or Docker Engine with Docker Compose v2.24 or newer (Linux).
- Git.

## 1. Configure local settings

From the repository root, copy the example environment file:

```bash
cp .env.example .env
```

Set `PII_PEPPER_KEY` to a random secret of at least 32 characters. For example, on a machine with Python installed:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Configure only the providers you intend to use. The Docker image does not contain `.env`, API keys, Gmail credentials, the cache key, or local scan caches.

On Windows PowerShell, use `Copy-Item .env.example .env` instead of `cp` if preferred.

## 2. Build the runtime image

Linux/macOS:

```bash
./scripts/build-docker.sh
```

Windows:

```powershell
.\scripts\build-docker.bat
```

The default image tag is `privacy-auditor:dev`. To force a clean rebuild, append `--no-cache`. To choose a different image tag, use `--tag privacy-auditor:local`. If you want Compose to use that custom tag, set `DOCKER_IMAGE` to the same value when running Compose, for example `DOCKER_IMAGE=privacy-auditor:local docker compose up --build` (PowerShell: `$env:DOCKER_IMAGE='privacy-auditor:local'; docker compose up --build`).

## 3. Open the contributor development shell

Linux/macOS/WSL:

```bash
./scripts/build-docker.sh --shell
```

Windows PowerShell or Command Prompt:

```powershell
.\scripts\build-docker.bat --shell
```

The script builds the `devshell` image (including `requirements.txt` and `requirements-test.txt`) and opens an interactive Bash shell in `/app`. The repository is bind-mounted, so edits made in the container are saved to the host checkout. When finished, run `exit`; the temporary container is removed automatically.

Inside the shell, for example:

```bash
python --version
python -m pytest -q
python -m compileall -q .
```

Use the shell for contributor development, debugging, and tests without installing the project's Python dependencies directly into WSL. The shell uses a fixed test-only `PII_PEPPER_KEY`; **do not use this development shell for real scan data**. The shell does not automatically load the host `.env`.

To force a clean development-image rebuild, add `--no-cache`:

```bash
./scripts/build-docker.sh --shell --no-cache
```

## 4. Run the application


```bash
docker compose up --build
```

Open [http://localhost:8501](http://localhost:8501). Compose binds the port to localhost by default; it is not published to the LAN. The source directory is mounted into the container so contributors can edit code on the host. Restart the service after changes that require a process restart.

Stop the service with `Ctrl+C`, or run:

```bash
docker compose down
```

The named volume `privacy-auditor-data` stores cache files and the cache encryption key outside the source tree. `docker compose down -v` also deletes that volume and its contents; use it only when you intentionally want to remove the container's persisted cache data and key.

## 5. Run tests in Docker

Linux/macOS:

```bash
./scripts/build-docker.sh --test
```

Windows:

```powershell
.\scripts\build-docker.bat --test
```

The script builds the `test` target and runs `pytest -q` in a disposable container. The test target uses a fixed test-only `PII_PEPPER_KEY`; it must never be reused for real scan data. Test execution does not load your host `.env` file or require provider API keys.

## Local Ollama

When the application runs in Docker, `127.0.0.1` refers to the container itself. Compose defaults `OLLAMA_HOST` to `http://host.docker.internal:11434` so the container can reach an Ollama service running on the host. If you set `OLLAMA_HOST` explicitly in `.env`, use that hostname rather than the container's loopback address.

## Notes

- The runtime image runs as a non-root user.
- The image exposes Streamlit on container port 8501, while Compose publishes it only on host loopback.
- Optional scan providers still make external network requests when configured; Docker does not make those requests local.
- Only use the application on data you own or are authorized to audit.
- Do not commit `.env`, cache contents, or other private scan artifacts.
