#!/usr/bin/env bash
set -Eeuo pipefail

# Always run relative to this script, not the caller's working directory.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RESET_MODE=false
FULL_RESET_MODE=false
NO_RUN=false
DOCKER_MODE=""

usage() {
    cat <<'EOF'
Usage: ./run.sh [reset|full-reset|reset-only|full-reset-only|docker-build|docker-test|docker-dev]

  (no argument)    Run the Streamlit application
  docker-build     Build the Docker runtime image
  docker-test      Build the Docker test image and run pytest
  docker-dev       Build the contributor image and open its shell
  reset            Clear Python bytecode caches, remove log.txt, then run
  full-reset       Also clear project cache and known test/build artifacts, then run
  reset-only       Clear standard caches and stop; do not run the application
  full-reset-only  Full cleanup and stop; do not run the application
EOF
}

for arg in "$@"; do
    case "${arg,,}" in
        docker-build)
            DOCKER_MODE=build
            ;;
        docker-test)
            DOCKER_MODE=test
            ;;
        docker-dev)
            DOCKER_MODE=dev
            ;;
        reset)
            RESET_MODE=true
            ;;
        full-reset)
            RESET_MODE=true
            FULL_RESET_MODE=true
            ;;
        reset-only)
            RESET_MODE=true
            NO_RUN=true
            ;;
        full-reset-only)
            RESET_MODE=true
            FULL_RESET_MODE=true
            NO_RUN=true
            ;;
        -h|--help|help)
            usage
            exit 0
            ;;
        *)
            printf '[ERROR] Argumen tidak dikenal: %s\n' "$arg" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ -n "$DOCKER_MODE" ]]; then
    if [[ "$RESET_MODE" == true || "$NO_RUN" == true ]]; then
        echo "[ERROR] Mode Docker tidak dapat digabung dengan mode reset." >&2
        exit 2
    fi
    case "$DOCKER_MODE" in
        build) exec "$SCRIPT_DIR/scripts/build-docker.sh" ;;
        test)  exec "$SCRIPT_DIR/scripts/build-docker.sh" --test ;;
        dev)   exec "$SCRIPT_DIR/scripts/build-docker.sh" --shell ;;
    esac
fi

# Return PIDs listening on the exact TCP port 8501, one per line.
list_port_pids() {
    if command -v lsof >/dev/null 2>&1; then
        lsof -nP -t -iTCP:8501 -sTCP:LISTEN 2>/dev/null | sort -u || true
    elif command -v fuser >/dev/null 2>&1; then
        fuser -n tcp 8501 2>/dev/null | tr ' ' '\n' | sed '/^$/d' | sort -u || true
    elif command -v ss >/dev/null 2>&1; then
        ss -H -ltnp 'sport = :8501' 2>/dev/null \
            | grep -oE 'pid=[0-9]+' \
            | cut -d= -f2 \
            | sort -u || true
    else
        return 1
    fi
}

port_is_listening() {
    if command -v ss >/dev/null 2>&1; then
        ss -H -ltn 'sport = :8501' 2>/dev/null | grep -q .
    elif command -v lsof >/dev/null 2>&1; then
        lsof -nP -iTCP:8501 -sTCP:LISTEN >/dev/null 2>&1
    else
        # Successful bind means the port is free; a failed bind means it is occupied.
        if python3 -c 'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("0.0.0.0",8501)); s.close()' >/dev/null 2>&1; then
            return 1
        else
            return 0
        fi
    fi
}

if [[ "$RESET_MODE" == true ]]; then
    echo "[INFO] Membersihkan cache proyek..."

    if [[ -f log.txt ]]; then
        if rm -f -- log.txt; then
            echo "[OK] log.txt dihapus."
        else
            echo "[WARN] Tidak dapat menghapus log.txt."
        fi
    fi

    # Do not traverse virtual environments, Git metadata, or packaging output.
    while IFS= read -r -d '' path; do
        if ! rm -rf -- "$path"; then
            echo "[WARN] Gagal menghapus: $path" >&2
        fi
    done < <(
        find . \
            \( -type d \( -name .git -o -name venv -o -name .venv -o -name build -o -name dist \) -prune \) -o \
            \( -type d -name __pycache__ -prune -print0 \)
    )
    echo "[OK] Cache Python proyek dibersihkan."

    if [[ "$FULL_RESET_MODE" == true ]]; then
        for path in cache .pytest_cache build/PrivacyAuditor dist/PrivacyAuditor dist/installer; do
            if [[ -e "$path" ]]; then
                if rm -rf -- "$path"; then
                    printf '[OK] %s dihapus.\n' "$path"
                else
                    printf '[WARN] Tidak dapat menghapus %s.\n' "$path" >&2
                fi
            fi
        done
    fi

    # Stop listeners only when the user explicitly requested a reset.
    if pids="$(list_port_pids)"; then
        if [[ -n "$pids" ]]; then
            while IFS= read -r pid; do
                [[ -n "$pid" ]] || continue
                printf '[INFO] Menghentikan proses pada port 8501 (PID %s)...\n' "$pid"
                if kill -TERM "$pid" 2>/dev/null; then
                    for _ in {1..20}; do
                        kill -0 "$pid" 2>/dev/null || break
                        sleep 0.1
                    done
                    if kill -0 "$pid" 2>/dev/null; then
                        echo "[WARN] Proses belum berhenti; tidak melakukan SIGKILL otomatis."
                    fi
                else
                    printf '[WARN] Tidak dapat menghentikan PID %s (izin atau proses berubah).\n' "$pid" >&2
                fi
            done <<< "$pids"
        fi
    else
        echo "[WARN] lsof/fuser/ss tidak tersedia; tidak dapat mengambil PID listener port 8501 untuk reset."
    fi
fi

if [[ "$NO_RUN" == true ]]; then
    echo "[OK] Reset selesai; aplikasi tidak dijalankan."
    exit 0
fi

if [[ ! -f app.py ]]; then
    echo "[ERROR] app.py tidak ditemukan di direktori proyek." >&2
    exit 1
fi

if [[ ! -x venv/bin/python ]]; then
    echo "[ERROR] Python virtual environment tidak ditemukan atau tidak executable: venv/bin/python" >&2
    echo "Buat environment dan install dependensi terlebih dahulu." >&2
    exit 1
fi

if port_is_listening; then
    echo "[WARN] Port 8501 sudah digunakan."
    echo "Buka http://localhost:8501 atau hentikan proses tersebut secara manual."
    exit 0
fi

echo "[INFO] Menjalankan Privacy Auditor melalui Streamlit pada port 8501..."
exec venv/bin/python -m streamlit run app.py --server.address 127.0.0.1
