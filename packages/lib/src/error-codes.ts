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

// ── Billing ─────────────────────────────────────────────────────────────────
// FIX-ERROR-CODES: Added centralized billing error codes
export const PLAN_NOT_FOUND         = 'PLAN_NOT_FOUND';
export const PLAN_FEATURES_INVALID  = 'PLAN_FEATURES_INVALID';
export const SUBSCRIPTION_INACTIVE  = 'SUBSCRIPTION_INACTIVE';
export const PRORATION_LIMIT_EXCEEDED = 'PRORATION_LIMIT_EXCEEDED';
export const PRORATION_RACE_CONDITION = 'PRORATION_RACE_CONDITION';
export const PAYMENT_FAILED         = 'PAYMENT_FAILED';
export const STRIPE_ERROR           = 'STRIPE_ERROR';
export const STRIPE_CIRCUIT_OPEN    = 'STRIPE_CIRCUIT_OPEN';
export const WALLET_INSUFFICIENT    = 'WALLET_INSUFFICIENT';
export const DUNNING_SUSPENDED      = 'DUNNING_SUSPENDED';
export const METERING_BACKPRESSURE  = 'METERING_BACKPRESSURE';

// ── Database ────────────────────────────────────────────────────────────────
export const DB_CONNECTION_FAILED   = 'DB_CONNECTION_FAILED';
export const DB_QUERY_FAILED        = 'DB_QUERY_FAILED';
export const DB_POOL_EXHAUSTED      = 'DB_POOL_EXHAUSTED';

// ── Configuration ───────────────────────────────────────────────────────────
export const CONFIG_INVALID         = 'CONFIG_INVALID';
export const CONFIG_MISSING_VAR     = 'CONFIG_MISSING_VAR';

// ── External Services ───────────────────────────────────────────────────────
export const DNS_TIMEOUT            = 'DNS_TIMEOUT';
export const EXTERNAL_SERVICE_DOWN  = 'EXTERNAL_SERVICE_DOWN';
export const WEBHOOK_REPLAY_ATTACK  = 'WEBHOOK_REPLAY_ATTACK';

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
  // Billing
  PLAN_NOT_FOUND,
  PLAN_FEATURES_INVALID,
  SUBSCRIPTION_INACTIVE,
  PRORATION_LIMIT_EXCEEDED,
  PRORATION_RACE_CONDITION,
  PAYMENT_FAILED,
  STRIPE_ERROR,
  STRIPE_CIRCUIT_OPEN,
  WALLET_INSUFFICIENT,
  DUNNING_SUSPENDED,
  METERING_BACKPRESSURE,
  // Database
  DB_CONNECTION_FAILED,
  DB_QUERY_FAILED,
  DB_POOL_EXHAUSTED,
  // Configuration
  CONFIG_INVALID,
  CONFIG_MISSING_VAR,
  // External services
  DNS_TIMEOUT,
  EXTERNAL_SERVICE_DOWN,
  WEBHOOK_REPLAY_ATTACK,
} as const;

export type ErrorCode = (typeof ErrorCodes)[keyof typeof ErrorCodes];
