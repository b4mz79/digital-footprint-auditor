#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_TAG="${DOCKER_IMAGE:-privacy-auditor:dev}"
RUN_TESTS=false
RUN_SHELL=false
NO_CACHE=false

usage() {
    cat <<'EOF'
Usage: ./scripts/build-docker.sh [--test | --shell] [--no-cache] [--tag IMAGE:TAG]

  (default)   Build the runtime image
  --test      Build the disposable test image and run pytest inside it
  --shell     Build the contributor development image and open an interactive Bash shell
  --no-cache  Build without Docker layer cache
  --tag       Set the base image name/tag (default: privacy-auditor:dev)

Examples:
  ./scripts/build-docker.sh
  ./scripts/build-docker.sh --test
  ./scripts/build-docker.sh --shell
  ./scripts/build-docker.sh --shell --tag privacy-auditor:local
  ./scripts/build-docker.sh --no-cache --shell
EOF
}

while (($#)); do
    case "$1" in
        --test)
            if [[ "$RUN_SHELL" == true ]]; then
                echo "[ERROR] --test and --shell cannot be used together." >&2
                exit 2
            fi
            RUN_TESTS=true
            shift
            ;;
        --shell)
            if [[ "$RUN_TESTS" == true ]]; then
                echo "[ERROR] --test and --shell cannot be used together." >&2
                exit 2
            fi
            RUN_SHELL=true
            shift
            ;;
        --no-cache)
            NO_CACHE=true
            shift
            ;;
        --tag)
            if (($# < 2)) || [[ -z "$2" ]]; then
                echo "[ERROR] --tag requires an image name/tag." >&2
                usage >&2
                exit 2
            fi
            IMAGE_TAG="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf '[ERROR] Unknown argument: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if ! command -v docker >/dev/null 2>&1; then
    echo "[ERROR] Docker CLI not found. Install Docker Desktop or Docker Engine first." >&2
    exit 127
fi

BUILD_ARGS=(build --progress=plain)
if [[ "$NO_CACHE" == true ]]; then
    BUILD_ARGS+=(--no-cache)
fi

if [[ "$RUN_TESTS" == true ]]; then
    TEST_TAG="${IMAGE_TAG}-test"
    echo "[INFO] Building disposable test image: $TEST_TAG"
    docker "${BUILD_ARGS[@]}" --target test --tag "$TEST_TAG" "$ROOT_DIR"
    echo "[INFO] Running pytest in the test container..."
    docker run --rm "$TEST_TAG"
elif [[ "$RUN_SHELL" == true ]]; then
    SHELL_TAG="${IMAGE_TAG}-shell"
    echo "[INFO] Building contributor development image: $SHELL_TAG"
    docker "${BUILD_ARGS[@]}" --target devshell --tag "$SHELL_TAG" "$ROOT_DIR"
    echo "[INFO] Opening interactive development shell in /app."
    echo "[INFO] Source edits are made in the mounted host repository."
    echo "[WARN] This shell uses a test-only PII_PEPPER_KEY; do not use it for real scan data."
    docker run --rm -it \
        --user "$(id -u):$(id -g)" \
        --env HOME=/tmp \
        --volume "$ROOT_DIR:/app" \
        --workdir /app \
        "$SHELL_TAG" /bin/bash
else
    echo "[INFO] Building Privacy Auditor runtime image: $IMAGE_TAG"
    docker "${BUILD_ARGS[@]}" --target runtime --tag "$IMAGE_TAG" "$ROOT_DIR"
    echo "[OK] Image built: $IMAGE_TAG"
    echo "[INFO] Run with: docker compose up --build"
fi
