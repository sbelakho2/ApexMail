/**
 * Billing service constants — named values for magic numbers.
 */

// ---------------------------------------------------------------------------
// Time conversions
// ---------------------------------------------------------------------------

/** Milliseconds in one second. */
export const MS_PER_SECOND = 1_000;

/** Milliseconds in one minute. */
export const MS_PER_MINUTE = 60_000;

/** Milliseconds in one hour. */
export const MS_PER_HOUR = 3_600_000;

/** Milliseconds in one day. */
export const MS_PER_DAY = 86_400_000;

/** Seconds in one minute. */
export const SECONDS_PER_MINUTE = 60;

/** Seconds in one hour. */
export const SECONDS_PER_HOUR = 3_600;

/** Seconds in one day. */
export const SECONDS_PER_DAY = 86_400;

// ---------------------------------------------------------------------------
// Redis TTLs (in seconds)
// ---------------------------------------------------------------------------

/** 1 hour — default cache & pending-event TTL. */
export const TTL_ONE_HOUR = 3_600;

/** 5 minutes — Shorter TTL for dunning status cache to reduce inconsistency */
export const TTL_FIVE_MINUTES = 300;

/** 1 day — dedup key expiry. */
export const TTL_ONE_DAY = 86_400;

// ---------------------------------------------------------------------------
// Rate Limiting
// ---------------------------------------------------------------------------

/** Default rate limit window in seconds */
export const DEFAULT_RATE_LIMIT_WINDOW_SECONDS = 60;

/** Default max requests per rate limit window */
export const DEFAULT_RATE_LIMIT_MAX_REQUESTS = 300;

/** 30 days in seconds. */
export const TTL_30_DAYS = 30 * SECONDS_PER_DAY;

/** 35 days in seconds — referral / counter expiry. */
export const TTL_35_DAYS = 35 * SECONDS_PER_DAY;

// ---------------------------------------------------------------------------
// Metering defaults
// ---------------------------------------------------------------------------

/** Default flush interval in milliseconds. */
export const DEFAULT_FLUSH_INTERVAL_MS = 10_000;

/** Default max buffer size before forced flush. */
export const DEFAULT_MAX_BUFFER_SIZE = 5_000;

/** Fallback email limit when plan lookup fails. */
export const DEFAULT_EMAIL_LIMIT = 10_000;

// ---------------------------------------------------------------------------
// Stripe
// ---------------------------------------------------------------------------

/** HTTP timeout for Stripe API calls (ms). */
export const STRIPE_TIMEOUT_MS = 30_000;

/** Webhook signature tolerance window (seconds). */
export const STRIPE_WEBHOOK_TOLERANCE_SECONDS = 300;

// ---------------------------------------------------------------------------
// Billing
// ---------------------------------------------------------------------------

/** Default invoice payment terms: Net 30 (days). */
export const DEFAULT_NET_DAYS = 30;

/** Dedicated IP monthly add-on price in cents. */
export const DEDICATED_IP_ADDON_PRICE_CENTS = 3_000;

/** Wallet balance cache TTL (seconds). */
export const WALLET_CACHE_TTL_SECONDS = 300;

/** Usage alert cooldown (minutes). */
export const DEFAULT_ALERT_COOLDOWN_MINUTES = 60;

/** Cost circuit breaker check interval (minutes). */
export const COST_CHECK_INTERVAL_MINUTES = 60;

/** Bytes per GiB. */
export const BYTES_PER_GIB = 1_073_741_824;
