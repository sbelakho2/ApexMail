/**
 * Rust Admin API Client
 *
 * Forwards control-plane requests to the Rust API server at :3001.
 * Authenticates via the CONTROL_PLANE_API_KEY static key, which the
 * Rust auth middleware validates without a DB lookup (constant-time HMAC).
 *
 * Only used by Next.js API route handlers (server-side).
 * Browser requests still go through the existing middleware chain.
 */

import { NextResponse } from 'next/server';

const RUST_API_URL = process.env.RUST_API_URL || 'http://localhost:3001';
const CONTROL_PLANE_API_KEY = process.env.CONTROL_PLANE_API_KEY;

const REQUEST_TIMEOUT_MS = 30_000;
const MAX_RETRIES = 2;
const RETRYABLE_STATUS_CODES = new Set([408, 429, 502, 503, 504]);

// ─── Core fetch with retry ────────────────────────────────────

async function rustFetch(
  path: string,
  init: RequestInit = {},
): Promise<Response> {
  const url = `${RUST_API_URL}${path}`;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(init.headers as Record<string, string> ?? {}),
  };

  if (CONTROL_PLANE_API_KEY) {
    headers['x-api-key'] = CONTROL_PLANE_API_KEY;
  }

  let lastError: Error | null = null;

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    try {
      const res = await fetch(url, {
        ...init,
        headers,
        signal: controller.signal,
      });

      if (res.ok || !RETRYABLE_STATUS_CODES.has(res.status)) {
        return res;
      }
      lastError = new Error(`Rust API returned ${res.status}`);
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
    } finally {
      clearTimeout(timeout);
    }

    // Exponential back-off before retry
    if (attempt < MAX_RETRIES) {
      await new Promise((r) => setTimeout(r, 200 * 2 ** attempt));
    }
  }

  throw lastError ?? new Error('Rust API request failed');
}

// ─── Generic proxy helper ─────────────────────────────────────

/**
 * Proxy a Next.js API request to the Rust admin API.
 *
 * Usage in a route handler:
 * ```ts
 * import { proxyToRust } from '@/lib/rust-api';
 * export async function GET(request: Request) {
 *   return proxyToRust(request, '/v1/admin/tenants');
 * }
 * ```
 */
export async function proxyToRust(
  request: Request,
  rustPath: string,
): Promise<NextResponse> {
  try {
    const url = new URL(request.url);
    const search = url.search; // preserve query string
    const fullPath = `${rustPath}${search}`;

    const init: RequestInit = {
      method: request.method,
    };

    // Forward body for non-GET/HEAD methods
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      try {
        const body = await request.text();
        if (body) init.body = body;
      } catch {
        // empty body is fine
      }
    }

    const res = await rustFetch(fullPath, init);
    const data = await res.text();

    return new NextResponse(data, {
      status: res.status,
      headers: { 'Content-Type': res.headers.get('Content-Type') || 'application/json' },
    });
  } catch (err) {
    console.error('[rust-api] proxy error:', err);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 502 },
    );
  }
}

/**
 * Typed JSON fetch from the Rust admin API.
 *
 * For route handlers that need to transform or enrich the response.
 */
export async function fetchRustJson<T = unknown>(
  path: string,
  init?: RequestInit,
): Promise<{ data: T; status: number }> {
  const res = await rustFetch(path, init);
  const data = (await res.json()) as T;
  return { data, status: res.status };
}

/**
 * POST/PATCH/PUT with JSON body.
 */
export async function mutateRust<T = unknown>(
  path: string,
  method: 'POST' | 'PATCH' | 'PUT' | 'DELETE',
  body?: unknown,
): Promise<{ data: T; status: number }> {
  const init: RequestInit = { method };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
  }
  const res = await rustFetch(path, init);
  const data = (await res.json()) as T;
  return { data, status: res.status };
}
