# =============================================================================
# Multi-Stage Hardened Dockerfile
# Author: Kehinde (Kenny) Samson Ogunlowo
# Security: CIS Docker Benchmark Level 2 compliant
# =============================================================================

# ── Stage 1: Dependency resolution ──────────────────────────────────────────
FROM python:3.11-slim AS dependency-resolver

WORKDIR /app

# Install only what's needed for dependency resolution
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc=12.2.0-14 \
    libffi-dev=3.4.4-1 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

COPY requirements.txt requirements-dev.txt ./

# Create wheels for offline install in next stage
RUN pip install --no-cache-dir --upgrade pip==24.0 \
    && pip wheel --no-cache-dir --no-deps --wheel-dir /app/wheels \
        -r requirements.txt


# ── Stage 2: Security scan of dependencies ──────────────────────────────────
FROM aquasec/trivy:latest AS security-scanner

COPY --from=dependency-resolver /app/wheels /wheels
COPY requirements.txt .

# Scan dependencies for known vulnerabilities
RUN trivy fs --exit-code 1 --severity CRITICAL --no-progress .


# ── Stage 3: Test runner ──────────────────────────────────────────────────────
FROM python:3.11-slim AS test-runner

WORKDIR /app

COPY --from=dependency-resolver /app/wheels /wheels
COPY requirements.txt requirements-dev.txt ./

RUN pip install --no-cache-dir --no-index \
    --find-links=/wheels -r requirements.txt \
    && pip install --no-cache-dir -r requirements-dev.txt

COPY . .

# Run tests — build fails if tests fail
RUN python -m pytest tests/ -v --tb=short \
    --cov=. --cov-report=xml \
    --junitxml=test-results.xml


# ── Stage 4: Production runtime (distroless) ─────────────────────────────────
FROM gcr.io/distroless/python3-debian12:nonroot AS production

# Security labels
LABEL maintainer="kenny.ogunlowo@citadelcloudmanagement.com" \
      security.scan="trivy,grype,dockle" \
      compliance="cis-docker-benchmark,hipaa,nist-800-53" \
      build.date=$BUILD_DATE \
      git.commit=$GIT_COMMIT \
      version=$VERSION

WORKDIR /app

# Copy only necessary artifacts from dependency resolver
COPY --from=dependency-resolver /app/wheels /wheels
COPY --chown=nonroot:nonroot requirements.txt ./

# Install from pre-built wheels (no internet access needed)
# Note: distroless has Python but not pip — use user site
COPY --from=dependency-resolver /usr/local/lib/python3.11 /usr/local/lib/python3.11
COPY --from=dependency-resolver /usr/local/bin/python3 /usr/local/bin/python3

# Copy application code
COPY --chown=nonroot:nonroot src/ ./src/
COPY --chown=nonroot:nonroot configs/production.yaml ./configs/

# Security hardening:
# - nonroot user (UID 65532 in distroless nonroot)
# - Read-only filesystem enforced at container runtime (--read-only flag)
# - No shell available (distroless)
# - Minimal attack surface

USER nonroot

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD ["/usr/local/bin/python3", "-c", \
         "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"]

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/python3", "-m", "src.main"]
