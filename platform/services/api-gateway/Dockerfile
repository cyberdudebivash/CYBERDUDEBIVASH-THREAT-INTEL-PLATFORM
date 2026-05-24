# SENTINEL APEX — api-gateway Production Dockerfile
FROM python:3.11-slim-bookworm AS builder
WORKDIR /build
RUN pip install --no-cache-dir uv
COPY requirements.txt .
RUN uv pip install --system --no-cache -r requirements.txt

FROM python:3.11-slim-bookworm AS runtime
LABEL org.opencontainers.image.title="sentinel-apex-api-gateway" \
      org.opencontainers.image.vendor="CYBERDUDEBIVASH" \
      org.opencontainers.image.version="2.0.0"

# Security: non-root user
RUN groupadd -r sentinel && useradd -r -g sentinel -s /bin/false sentinel
WORKDIR /app
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY . .
RUN chown -R sentinel:sentinel /app

USER sentinel
EXPOSE 8000
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PORT=8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4", "--loop", "uvloop", "--http", "httptools"]
