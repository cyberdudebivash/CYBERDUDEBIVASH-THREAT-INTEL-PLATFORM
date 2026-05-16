# ============================================================================
# CYBERDUDEBIVASH® SENTINEL APEX — Production Dockerfile
# v47.0 ENTERPRISE HARDENING (additive over v11.0)
#
# Changes (zero regression):
#   - Multi-stage build: builder → runtime (removes build toolchain from image)
#   - Non-root user: cdbuser (uid=1001) — CIS Docker Benchmark L1
#   - HEALTHCHECK: liveness probe wired to /api/v1/health
#   - Explicit EXPOSE 8080
#   - Deterministic pip install with --no-cache-dir --user
#   - Data/export dirs created before USER switch
#   - CMD switched to uvicorn (production ASGI) — CMD preserved as env override
#
# Rollback: git revert this file — original CMD ["python", "-m", "agent.sentinel_blogger"]
#   available via SENTINEL_MODE=blogger env var override.
# ============================================================================

# ── Stage 1: Dependency Builder ───────────────────────────────────────────────
FROM python:3.12-slim AS builder

LABEL stage="builder"

WORKDIR /build

# Install build dependencies only in builder stage (never shipped to runtime)
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Install to user site-packages (copied to runtime image)
RUN pip install --no-cache-dir --user --upgrade pip \
 && pip install --no-cache-dir --user -r requirements.txt


# ── Stage 2: Production Runtime ───────────────────────────────────────────────
FROM python:3.12-slim AS runtime

LABEL maintainer="CyberDudeBivash <bivash@cyberdudebivash.com>"
LABEL description="CDB-SENTINEL Threat Intelligence Platform — APEX ENTERPRISE"
LABEL version="47.0"
LABEL org.opencontainers.image.source="https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"
LABEL org.opencontainers.image.vendor="CyberDudeBivash Pvt. Ltd."

# Security: create non-root service account (CIS Docker Benchmark L1 compliance)
RUN groupadd -r cdbuser --gid=1001 \
 && useradd -r -g cdbuser --uid=1001 \
    --no-create-home \
    --shell=/sbin/nologin \
    --comment="CDB SENTINEL APEX Service Account" \
    cdbuser

WORKDIR /app

# Copy compiled dependencies from builder (no build toolchain in runtime)
COPY --from=builder /root/.local /home/cdbuser/.local

# Copy application code — chown to service account
COPY --chown=cdbuser:cdbuser agent/       ./agent/
COPY --chown=cdbuser:cdbuser requirements.txt .

# Create required runtime directories and set ownership
RUN mkdir -p \
    data/stix \
    data/whitepapers \
    data/archive \
    data/security \
    data/observability \
    data/tenants \
    data/orgs \
    exports \
    logs \
 && chown -R cdbuser:cdbuser \
    data/ \
    exports/ \
    logs/ \
 && chmod 750 data/ exports/ logs/

# Runtime environment
ENV PYTHONPATH=/app
ENV PATH="/home/cdbuser/.local/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# ── Health Check ──────────────────────────────────────────────────────────────
# Liveness probe: checks /api/v1/health endpoint
# - Interval: 30s (allows startup time)
# - Timeout: 5s (fail fast)
# - Start period: 20s (grace period during initial startup)
# - Retries: 3 (before marking unhealthy)
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "\
import urllib.request, sys; \
try: \
    r = urllib.request.urlopen('http://localhost:8080/api/v1/health', timeout=4); \
    sys.exit(0 if r.status in (200, 503) else 1) \
except Exception as e: \
    print(f'Health check failed: {e}', file=sys.stderr); sys.exit(1)"

# Drop privileges — run as non-root service account
USER cdbuser

EXPOSE 8080

# ── Startup Command ───────────────────────────────────────────────────────────
# Default: FastAPI/uvicorn production server
# Override with SENTINEL_MODE=blogger to run the intelligence pipeline
CMD ["sh", "-c", "\
  if [ \"${SENTINEL_MODE}\" = \"blogger\" ]; then \
    exec python -m agent.sentinel_blogger; \
  else \
    exec uvicorn agent.api.api_server:app \
      --host 0.0.0.0 \
      --port 8080 \
      --workers 2 \
      --access-log \
      --log-level info \
      --proxy-headers \
      --forwarded-allow-ips='*'; \
  fi"]
