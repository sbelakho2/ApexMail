/**
 * E-149: Standardised API error codes.
 *
 * All error codes returned in API responses should reference this file so
 * that codes stay consistent across routes and can be documented for SDK
 * consumers.  The values are intentionally plain strings (not an enum) so
 * they serialise cleanly to JSON and can be compared on the client side
 * without importing this module.
 */

// ── Authentication / Authorisation ──────────────────────────────────────────
export const AUTH_REQUIRED       = 'AUTH_REQUIRED';
export const INVALID_API_KEY     = 'INVALID_API_KEY';
export const INVALID_TOKEN       = 'INVALID_TOKEN';
export const TOKEN_EXPIRED       = 'TOKEN_EXPIRED';
export const TOKEN_REVOKED       = 'TOKEN_REVOKED';
export const INSUFFICIENT_SCOPE  = 'INSUFFICIENT_SCOPE';
export const FORBIDDEN           = 'FORBIDDEN';

// ── Validation ──────────────────────────────────────────────────────────────
export const BAD_REQUEST         = 'BAD_REQUEST';
export const VALIDATION_ERROR    = 'VALIDATION_ERROR';
export const INVALID_INPUT       = 'INVALID_INPUT';
export const INVALID_ID          = 'INVALID_ID';
export const INVALID_EMAIL       = 'INVALID_EMAIL';

// ── Resource ────────────────────────────────────────────────────────────────
export const NOT_FOUND           = 'NOT_FOUND';
export const CONFLICT            = 'CONFLICT';
export const DUPLICATE_KEY       = 'DUPLICATE_KEY';
export const DOMAIN_EXISTS       = 'DOMAIN_EXISTS';
export const VERIFICATION_EXPIRED = 'VERIFICATION_EXPIRED';

// ── Rate Limiting ───────────────────────────────────────────────────────────
export const RATE_LIMITED        = 'RATE_LIMITED';
export const DAILY_LIMIT_REACHED = 'DAILY_LIMIT_REACHED';

// ── Server ──────────────────────────────────────────────────────────────────
export const INTERNAL_ERROR      = 'INTERNAL_ERROR';
export const SERVICE_UNAVAILABLE = 'SERVICE_UNAVAILABLE';

// ── CSRF ────────────────────────────────────────────────────────────────────
export const CSRF_ORIGIN_MISMATCH = 'CSRF_ORIGIN_MISMATCH';
export const CSRF_MISSING_HEADER  = 'CSRF_MISSING_HEADER';

// ── Idempotency ─────────────────────────────────────────────────────────────
export const IDEMPOTENCY_CONFLICT = 'IDEMPOTENCY_CONFLICT';

/**
 * Convenience lookup – the full set as a plain object so consumers can
 * iterate or validate against it:
 *
 *   if (!(code in ErrorCodes)) { … }
 */
export const ErrorCodes = {
  AUTH_REQUIRED,
  INVALID_API_KEY,
  INVALID_TOKEN,
  TOKEN_EXPIRED,
  TOKEN_REVOKED,
  INSUFFICIENT_SCOPE,
  FORBIDDEN,
  BAD_REQUEST,
  VALIDATION_ERROR,
  INVALID_INPUT,
  INVALID_ID,
  INVALID_EMAIL,
  NOT_FOUND,
  CONFLICT,
  DUPLICATE_KEY,
  DOMAIN_EXISTS,
  VERIFICATION_EXPIRED,
  RATE_LIMITED,
  DAILY_LIMIT_REACHED,
  INTERNAL_ERROR,
  SERVICE_UNAVAILABLE,
  CSRF_ORIGIN_MISMATCH,
  CSRF_MISSING_HEADER,
  IDEMPOTENCY_CONFLICT,
} as const;

export type ErrorCode = (typeof ErrorCodes)[keyof typeof ErrorCodes];
