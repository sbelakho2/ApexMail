/**
 * Typed error hierarchy, mirroring sdk-python's exceptions.py and the
 * canonical API error envelope (docs/api/errors.md):
 *
 *   { "error": { "code": "...", "message": "...", "details": [...] } }
 *
 * Every error carries a machine-readable `code`, the HTTP `statusCode`
 * (null for client-side/transport failures) and — when the server sent one —
 * the `requestId` (`X-Request-Id` response header), so support can correlate
 * a failed call with server logs.
 */

export interface ApexMailErrorOptions {
  /** Machine-readable error code (defaults to "UNKNOWN"). */
  code?: string;
  /** HTTP status code, or null for client-side/transport errors. */
  statusCode?: number | null;
  /** The server's `X-Request-Id`, when the response carried one. */
  requestId?: string | null;
  /** Original error (transport failures keep their cause). */
  cause?: unknown;
}

export class ApexMailError extends Error {
  readonly code: string;
  readonly statusCode: number | null;
  readonly requestId: string | null;

  constructor(message: string, options: ApexMailErrorOptions = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "ApexMailError";
    this.code = options.code ?? "UNKNOWN";
    this.statusCode = options.statusCode ?? null;
    this.requestId = options.requestId ?? null;
  }

  override toString(): string {
    return this.code ? `[${this.code}] ${this.message}` : this.message;
  }
}

export interface ValidationErrorOptions extends ApexMailErrorOptions {
  /** Field-level details from the error envelope (`details`/`errors`). */
  errors?: unknown[];
}

/** Request validation failed (the server's 400/422). */
export class ValidationError extends ApexMailError {
  readonly errors: unknown[];

  constructor(message: string, options: ValidationErrorOptions = {}) {
    super(message, {
      ...options,
      code: options.code ?? "VALIDATION_ERROR",
      statusCode: options.statusCode ?? 400,
    });
    this.name = "ValidationError";
    this.errors = options.errors ?? [];
  }
}

/** Authentication failed (401). */
export class AuthenticationError extends ApexMailError {
  constructor(message = "Invalid API key", options: ApexMailErrorOptions = {}) {
    super(message, { ...options, code: options.code ?? "AUTHENTICATION_ERROR", statusCode: 401 });
    this.name = "AuthenticationError";
  }
}

/** Access forbidden (403). */
export class ForbiddenError extends ApexMailError {
  constructor(message = "Forbidden", options: ApexMailErrorOptions = {}) {
    super(message, { ...options, code: options.code ?? "FORBIDDEN", statusCode: 403 });
    this.name = "ForbiddenError";
  }
}

/** Resource not found (404). */
export class NotFoundError extends ApexMailError {
  constructor(message = "Resource not found", options: ApexMailErrorOptions = {}) {
    super(message, { ...options, code: options.code ?? "NOT_FOUND", statusCode: 404 });
    this.name = "NotFoundError";
  }
}

/** Resource conflict (409). */
export class ConflictError extends ApexMailError {
  constructor(message = "Conflict", options: ApexMailErrorOptions = {}) {
    super(message, { ...options, code: options.code ?? "CONFLICT", statusCode: 409 });
    this.name = "ConflictError";
  }
}

export interface RateLimitErrorOptions extends ApexMailErrorOptions {
  /** Seconds to wait before retrying, when the server sent Retry-After. */
  retryAfter?: number | null;
}

/** Rate limit exceeded (429). `retryAfter` is populated from Retry-After. */
export class RateLimitError extends ApexMailError {
  readonly retryAfter: number | null;

  constructor(message = "Rate limit exceeded", options: RateLimitErrorOptions = {}) {
    super(message, {
      ...options,
      code: options.code ?? "RATE_LIMIT_EXCEEDED",
      statusCode: 429,
    });
    this.name = "RateLimitError";
    this.retryAfter = options.retryAfter ?? null;
  }
}

/** The server failed (5xx). */
export class ServerError extends ApexMailError {
  constructor(message = "Internal server error", options: ApexMailErrorOptions = {}) {
    super(message, { ...options, code: options.code ?? "SERVER_ERROR", statusCode: 500 });
    this.name = "ServerError";
  }
}
