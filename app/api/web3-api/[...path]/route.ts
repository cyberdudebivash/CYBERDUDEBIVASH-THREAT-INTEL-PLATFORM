/**
 * NEXT.JS API PROXY — WEB3 MODULE
 * =================================
 * Place at: /app/api/web3-api/[...path]/route.ts
 *
 * PURPOSE:
 * ─────────
 * In production, the frontend calls /api/web3-api/* (same origin).
 * This route proxies those requests to the isolated Web3 API backend.
 *
 * BENEFITS:
 * ─────────
 * • Zero CORS issues in production
 * • Backend URL never exposed to browser
 * • API keys stay on the server
 * • Single entry point — easy to add auth middleware here
 * • Feature flag enforced at this layer too
 *
 * ZERO REGRESSION:
 * ─────────────────
 * • Only activates when WEB3_ENABLED=true
 * • Only handles /api/web3-api/* — no overlap with existing routes
 * • Any failure returns a safe error, never crashes other routes
 */

import { NextRequest, NextResponse } from 'next/server';

// ─── CONFIG ───────────────────────────────────────────────────────────────────
const WEB3_ENABLED     = process.env.NEXT_PUBLIC_WEB3_ENABLED === 'true';
const WEB3_BACKEND_URL = process.env.WEB3_BACKEND_URL || 'http://localhost:3001';
const PROXY_TIMEOUT_MS = 30_000;

// ─── ALLOWED METHODS ──────────────────────────────────────────────────────────
const ALLOWED_METHODS = new Set(['GET', 'POST']);

// ─── STRIP HEADERS THAT MUST NOT BE FORWARDED ─────────────────────────────────
const STRIP_REQUEST_HEADERS  = new Set(['host', 'connection', 'content-length']);
const STRIP_RESPONSE_HEADERS = new Set(['transfer-encoding', 'connection', 'keep-alive']);

// ─── PROXY HANDLER ────────────────────────────────────────────────────────────
async function handler(
  request: NextRequest,
  { params }: { params: { path: string[] } }
): Promise<NextResponse> {
  // Feature flag gate
  if (!WEB3_ENABLED) {
    return NextResponse.json(
      { success: false, error: 'Web3 module is disabled', timestamp: new Date().toISOString() },
      { status: 503 }
    );
  }

  // Method guard
  if (!ALLOWED_METHODS.has(request.method)) {
    return NextResponse.json(
      { success: false, error: 'Method not allowed', timestamp: new Date().toISOString() },
      { status: 405 }
    );
  }

  // Build upstream URL
  const pathSegments = params.path ?? [];
  const upstreamPath = '/web3-api/' + pathSegments.join('/');
  const upstreamUrl  = new URL(upstreamPath, WEB3_BACKEND_URL);

  // Forward query params
  request.nextUrl.searchParams.forEach((value, key) => {
    upstreamUrl.searchParams.set(key, value);
  });

  // Forward sanitised headers
  const forwardHeaders = new Headers();
  request.headers.forEach((value, key) => {
    if (!STRIP_REQUEST_HEADERS.has(key.toLowerCase())) {
      forwardHeaders.set(key, value);
    }
  });

  // Mark as proxied (useful for backend logging)
  forwardHeaders.set('X-Forwarded-By', 'sentinel-apex-proxy');
  forwardHeaders.set('X-Module', 'web3');

  // Body (POST only)
  let body: string | undefined;
  if (request.method === 'POST') {
    try {
      body = await request.text();
    } catch {
      return NextResponse.json(
        { success: false, error: 'Failed to read request body', timestamp: new Date().toISOString() },
        { status: 400 }
      );
    }
  }

  // Proxy with timeout
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PROXY_TIMEOUT_MS);

  try {
    const upstream = await fetch(upstreamUrl.toString(), {
      method:  request.method,
      headers: forwardHeaders,
      body,
      signal:  controller.signal,
    });

    clearTimeout(timer);

    // Build response — strip problematic headers
    const responseHeaders = new Headers();
    upstream.headers.forEach((value, key) => {
      if (!STRIP_RESPONSE_HEADERS.has(key.toLowerCase())) {
        responseHeaders.set(key, value);
      }
    });

    // Security headers on every proxied response
    responseHeaders.set('X-Content-Type-Options', 'nosniff');
    responseHeaders.set('X-Frame-Options', 'DENY');

    const responseBody = await upstream.text();

    return new NextResponse(responseBody, {
      status:  upstream.status,
      headers: responseHeaders,
    });

  } catch (err: unknown) {
    clearTimeout(timer);

    const isTimeout = err instanceof Error && err.name === 'AbortError';

    return NextResponse.json(
      {
        success:   false,
        error:     isTimeout
          ? 'Web3 API request timed out'
          : 'Web3 API backend unavailable',
        timestamp: new Date().toISOString(),
      },
      { status: isTimeout ? 504 : 502 }
    );
  }
}

// Export all allowed HTTP methods
export const GET  = handler;
export const POST = handler;
