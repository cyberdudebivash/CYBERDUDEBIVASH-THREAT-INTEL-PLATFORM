"""
SENTINEL APEX — Security Headers Middleware v143.0.0
=====================================================
Enforces ISO 27001 / SOC 2 / OWASP-hardened HTTP security headers
on every response served by the SENTINEL APEX API.

Headers injected:
  Strict-Transport-Security     — HSTS max-age 1yr + includeSubDomains + preload
  Content-Security-Policy       — Restrictive CSP; Swagger UI carve-out for /docs
  X-Frame-Options               — DENY (clickjacking guard)
  X-Content-Type-Options        — nosniff (MIME-type sniffing guard)
  X-XSS-Protection              — 1; mode=block (legacy browser XSS filter)
  Referrer-Policy               — strict-origin-when-cross-origin
  Permissions-Policy            — deny geolocation/camera/microphone/payment access
  Cross-Origin-Opener-Policy    — same-origin (Spectre mitigation)
  Cross-Origin-Resource-Policy  — cross-origin (required for public API CDN clients)
  Cross-Origin-Embedder-Policy  — unsafe-none (Swagger UI compatibility)
  Cache-Control                 — no-store for auth/payment endpoints

Exempt paths: /health, / (root)  — lightweight endpoints, no CSP overhead.
Docs path (/docs, /redoc)        — relaxed CSP to allow Swagger UI assets.

(c) 2026 CyberDudeBivash Pvt. Ltd.  GSTIN: 21ARKPN8270G1ZP
"""
from __future__ import annotations

import logging
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("sentinel.security")

# ── CSP Profiles ──────────────────────────────────────────────────────────────

# API endpoints — strict JSON-only policy
_CSP_API = (
    "default-src 'none'; "
    "script-src 'none'; "
    "style-src 'none'; "
    "img-src 'none'; "
    "connect-src 'none'; "
    "font-src 'none'; "
    "frame-src 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'none'; "
    "base-uri 'none'; "
    "object-src 'none'; "
    "upgrade-insecure-requests"
)

# Swagger UI / ReDoc — must allow CDN assets and inline scripts
_CSP_DOCS = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
    "img-src 'self' data: https://fastapi.tiangolo.com; "
    "connect-src 'self'; "
    "font-src 'self' https://fonts.gstatic.com; "
    "frame-src 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'self'; "
    "base-uri 'self'; "
    "object-src 'none'"
)

# ── Permanent headers (all responses) ────────────────────────────────────────

_PERMANENT_HEADERS: dict[str, str] = {
    # HSTS — 1 year, all subdomains, preload list eligible
    "Strict-Transport-Security":    "max-age=31536000; includeSubDomains; preload",
    # Clickjacking guard — API never framed
    "X-Frame-Options":              "DENY",
    # MIME sniffing guard
    "X-Content-Type-Options":       "nosniff",
    # Legacy XSS filter
    "X-XSS-Protection":             "1; mode=block",
    # Referrer control
    "Referrer-Policy":              "strict-origin-when-cross-origin",
    # Permissions — deny all browser feature APIs
    "Permissions-Policy": (
        "geolocation=(), "
        "camera=(), "
        "microphone=(), "
        "payment=(), "
        "usb=(), "
        "magnetometer=(), "
        "gyroscope=(), "
        "accelerometer=(), "
        "ambient-light-sensor=(), "
        "autoplay=()"
    ),
    # Spectre / cross-origin isolation
    "Cross-Origin-Opener-Policy":   "same-origin",
    # Public API: allow cross-origin resource fetching by CDN/proxy clients
    "Cross-Origin-Resource-Policy": "cross-origin",
    # Swagger UI compat (COEP 'require-corp' breaks CDN asset loading)
    "Cross-Origin-Embedder-Policy": "unsafe-none",
    # Remove server fingerprint
    "Server":                       "SENTINEL-APEX",
    # Vendor signature
    "X-Powered-By":                 "CYBERDUDEBIVASH-APEX/143.0.0",
}

# Endpoints that must not be cached under any circumstance
_NO_STORE_PREFIXES = (
    "/api/v1/auth/",
    "/api/payment/",
    "/api/v1/keys/",
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Injects production-hardened security headers on every HTTP response.

    Behaviour:
      - All responses receive the _PERMANENT_HEADERS set.
      - /docs, /redoc, /openapi.json receive the relaxed Swagger CSP.
      - All other paths receive the strict API-only CSP.
      - Auth, payment, and key management endpoints get Cache-Control: no-store.
      - OPTIONS preflight responses are NOT modified (CORS middleware owns those).
    """

    # Paths served by Swagger UI — need relaxed CSP
    _DOCS_PATHS = {"/docs", "/redoc", "/openapi.json"}

    async def dispatch(self, request: Request, call_next) -> Response:
        response: Response = await call_next(request)
        path: str = request.url.path

        # Skip OPTIONS — CORS middleware owns those headers
        if request.method == "OPTIONS":
            return response

        # ── Inject all permanent headers ─────────────────────────────────────
        for header, value in _PERMANENT_HEADERS.items():
            response.headers[header] = value

        # ── Content-Security-Policy: path-dependent profile ──────────────────
        if path in self._DOCS_PATHS:
            response.headers["Content-Security-Policy"] = _CSP_DOCS
        else:
            response.headers["Content-Security-Policy"] = _CSP_API

        # ── Cache-Control: no-store for sensitive endpoints ───────────────────
        if any(path.startswith(p) for p in _NO_STORE_PREFIXES):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"]        = "no-cache"
            response.headers["Expires"]       = "0"

        return response
