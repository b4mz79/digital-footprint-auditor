# syntax=docker/dockerfile:1

# Shared dependency layer: changing application code does not reinstall Python packages.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser

COPY requirements.txt /tmp/requirements.txt
RUN python -m pip install --no-cache-dir -r /tmp/requirements.txt

# Contributor/test image. This stage is intentionally disposable and uses a test-only key.
FROM base AS test

COPY requirements-test.txt /tmp/requirements-test.txt
RUN python -m pip install --no-cache-dir -r /tmp/requirements-test.txt
COPY . /app

ENV PII_PEPPER_KEY=docker-test-only-key-not-for-real-data-00000000000000000000

CMD ["python", "-m", "pytest", "-q"]

# Interactive contributor shell with application and test dependencies.
# The fixed key is for local development/tests only; never use this image for real scan data.
FROM base AS devshell
COPY requirements-test.txt /tmp/requirements-test.txt
RUN python -m pip install --no-cache-dir -r /tmp/requirements-test.txt
COPY . /app
ENV PII_PEPPER_KEY=docker-test-only-key-not-for-real-data-00000000000000000000
CMD ["/bin/bash"]

# Default image: non-root Streamlit runtime.
FROM base AS runtime

COPY --chown=10001:10001 . /app
RUN mkdir -p /data/cache/breach /data/cache/imap /data/cache/osint /data/cache/enrichment \
    && chown -R 10001:10001 /data

ENV CACHE_KEY_FILE=/data/.cache_key \
    AI_CACHE_DIR=/data/cache \
    BREACH_CACHE_DIR=/data/cache/breach \
    IMAP_CACHE_DIR=/data/cache/imap \
    OSINT_CACHE_DIR=/data/cache/osint \
    EVIDENCE_ENRICHMENT_CACHE_DIR=/data/cache/enrichment \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

USER 10001:10001

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=3)"

ENTRYPOINT ["python", "-m", "streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501", "--server.headless=true", "--browser.gatherUsageStats=false"]
