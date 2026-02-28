/**
 * API Versioning Strategy
 *
 * ApexMail uses a simple integer versioning scheme exposed over HTTP headers.
 *
 * ## Version negotiation rules
 *
 * 1. If the client sends `X-API-Version: N` and N matches a supported version,
 *    the request is accepted.
 * 2. If the client sends `X-API-Version: N` and N is higher than the current
 *    maximum supported version, the server responds with HTTP 422 and a
 *    `X-API-Supported-Versions` header listing what *is* available.
 * 3. If no `X-API-Version` header is present, the current default version
 *    (CURRENT_API_VERSION) is assumed — this is backward-compatible behaviour.
 * 4. Every API response from a versioned handler MUST carry the two headers:
 *      `X-API-Version: <resolved-version>`
 *      `X-API-Supported-Versions: <comma-separated list>`
 *
 * ## Adding a new version
 *
 * 1. Increment MAX_API_VERSION.
 * 2. Update SUPPORTED_API_VERSIONS.
 * 3. Create new route modules in the appropriate `app/api/v<N>/` directory.
 * 4. Keep the old route modules in place until the previous version is
 *    deprecated and the sunset date has passed.
 */

/** The oldest version still supported by this deployment. */
export const MIN_API_VERSION = 1;

/** The newest (current) version. */
export const MAX_API_VERSION = 1;

/** Default version assumed when the client sends no `X-API-Version` header. */
export const CURRENT_API_VERSION = MAX_API_VERSION;

/**
 * Complete list of supported version numbers. Update `MIN_API_VERSION` and
 * `MAX_API_VERSION` as new versions are introduced or old ones are sunset.
 */
export const SUPPORTED_API_VERSIONS: readonly number[] = Array.from(
  { length: MAX_API_VERSION - MIN_API_VERSION + 1 },
  (_, i) => MIN_API_VERSION + i,
);

const SUPPORTED_VERSIONS_HEADER_VALUE = SUPPORTED_API_VERSIONS.join(', ');

/** HTTP request header used by clients to nominate an API version. */
export const API_VERSION_REQUEST_HEADER = 'x-api-version';

/** HTTP response header echoing the version number that was used. */
export const API_VERSION_RESPONSE_HEADER = 'X-API-Version';

/** HTTP response header listing every version this server can serve. */
export const API_SUPPORTED_VERSIONS_HEADER = 'X-API-Supported-Versions';

// ─────────────────────────────────────────────────────────────────────────────
// Version parsing + resolution
// ─────────────────────────────────────────────────────────────────────────────

export type ResolveVersionResult =
  | { ok: true; version: number }
  | { ok: false; requestedVersion: number; error: string };

/**
 * Resolve the requested API version from a raw header value string.
 *
 * Returns `{ ok: true, version }` when the requested version is supported, or
 * `{ ok: false, requestedVersion, error }` when it is not.
 */
export function resolveApiVersion(
  headerValue: string | null | undefined,
): ResolveVersionResult {
  if (!headerValue) {
    return { ok: true, version: CURRENT_API_VERSION };
  }

  const parsed = parseInt(headerValue, 10);
  if (Number.isNaN(parsed) || parsed <= 0) {
    return {
      ok: false,
      requestedVersion: NaN,
      error: `Invalid ${API_VERSION_REQUEST_HEADER} value "${headerValue}" — must be a positive integer`,
    };
  }

  if (!SUPPORTED_API_VERSIONS.includes(parsed)) {
    return {
      ok: false,
      requestedVersion: parsed,
      error: `API version ${parsed} is not supported. Supported versions: ${SUPPORTED_VERSIONS_HEADER_VALUE}`,
    };
  }

  return { ok: true, version: parsed };
}

// ─────────────────────────────────────────────────────────────────────────────
// Next.js / Response helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Inject the two standard API-version response headers into an existing
 * `Headers` object.
 *
 * ```ts
 * const headers = new Headers();
 * injectVersionHeaders(headers, 1);
 * // headers now has X-API-Version: 1  and  X-API-Supported-Versions: 1
 * ```
 */
export function injectVersionHeaders(headers: Headers, version: number): void {
  headers.set(API_VERSION_RESPONSE_HEADER, String(version));
  headers.set(API_SUPPORTED_VERSIONS_HEADER, SUPPORTED_VERSIONS_HEADER_VALUE);
}

/**
 * Build a `Response` that rejects an unsupported version request with HTTP 422.
 *
 * The response body is a JSON object with `{ error, supported_versions }`.
 */
export function unsupportedVersionResponse(
  requestedVersion: number | typeof NaN,
  errorMessage: string,
): Response {
  const body = JSON.stringify({
    error: errorMessage,
    supported_versions: SUPPORTED_API_VERSIONS,
  });
  const headers = new Headers({ 'Content-Type': 'application/json' });
  injectVersionHeaders(headers, CURRENT_API_VERSION);
  return new Response(body, { status: 422, headers });
}

// ─────────────────────────────────────────────────────────────────────────────
// Higher-order route wrapper (Next.js App Router)
// ─────────────────────────────────────────────────────────────────────────────

type NextRouteHandler = (request: Request, ctx?: unknown) => Promise<Response> | Response;

/**
 * Wrap a Next.js App Router route handler with automatic API-version
 * negotiation.
 *
 * The wrapper:
 * 1. Reads the `X-API-Version` request header.
 * 2. Rejects unsupported versions with HTTP 422.
 * 3. Calls the underlying `handler` with the request.
 * 4. Injects `X-API-Version` and `X-API-Supported-Versions` into the response.
 *
 * @example
 * ```ts
 * // app/api/users/route.ts
 * import { withApiVersion } from '@apexmail/lib/api-version';
 *
 * export const GET = withApiVersion(async (req) => {
 *   return Response.json({ users: [] });
 * });
 * ```
 */
export function withApiVersion(handler: NextRouteHandler): NextRouteHandler {
  return async (request: Request, ctx?: unknown): Promise<Response> => {
    const headerValue = (request.headers as Headers).get(API_VERSION_REQUEST_HEADER);
    const resolved = resolveApiVersion(headerValue);

    if (!resolved.ok) {
      return unsupportedVersionResponse(resolved.requestedVersion, resolved.error);
    }

    const response = await handler(request, ctx);

    // Clone to make headers mutable (Response headers are immutable after creation).
    const mutableHeaders = new Headers(response.headers);
    injectVersionHeaders(mutableHeaders, resolved.version);

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: mutableHeaders,
    });
  };
}
