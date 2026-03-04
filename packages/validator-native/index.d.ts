/// <reference types="node" />

/**
 * @module @apexmail/validator-native
 *
 * Native Node.js bindings for ApexMail email validation.
 * RFC 5321/6531 syntax validation, MX record resolution (via trust-dns-resolver),
 * and disposable domain detection all run off the JS event loop in Rust.
 */

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ValidationResult {
  valid: boolean
  email: string
  localPart: string
  domain: string
  isEai: boolean
  isDisposable: boolean
  hasMx: boolean | null
  errors: string[]
  warnings: string[]
}

export interface MxCheckResult {
  domain: string
  hasMx: boolean
  mxRecords: string[]
  hasAFallback: boolean
}

export interface BatchResult {
  results: ValidationResult[]
  validCount: number
  invalidCount: number
}

// ─── Synchronous validation ───────────────────────────────────────────────────

/**
 * Validate an email address synchronously (syntax + disposable check, no MX).
 *
 * Uses RFC 5321/6531 (EAI) compliant parsing with international character
 * support. Runs entirely in Rust off the JS thread via the libuv thread-pool.
 */
export declare function validateEmail(email: string): ValidationResult

/**
 * Check if a domain is in the disposable email list.
 */
export declare function isDisposableDomain(domain: string): boolean

/**
 * Normalize an email address (lowercase domain, trim whitespace).
 */
export declare function normalizeEmail(email: string): string

/**
 * Get the list of known disposable domains.
 */
export declare function getDisposableDomains(): string[]

/**
 * Replace or extend the disposable domain list at runtime.
 *
 * @param domains - Array of domain strings to add.
 * @param replace - If true, replaces the entire list; if false, merges.
 * @returns The new total count of disposable domains.
 */
export declare function setDisposableDomains(
  domains: string[],
  replace: boolean,
): number

// ─── Async validation (with DNS) ─────────────────────────────────────────────

/**
 * Validate an email address with MX record verification.
 *
 * Uses trust-dns-resolver for non-blocking async DNS lookups with
 * built-in caching (5 min TTL, 10K max entries).
 */
export declare function validateEmailWithMx(
  email: string,
): Promise<ValidationResult>

/**
 * Batch validate multiple emails asynchronously.
 *
 * Parallelizes across tokio blocking threads for maximum throughput.
 */
export declare function validateEmailsBatch(
  emails: string[],
): Promise<BatchResult>

/**
 * Check MX records for a domain.
 *
 * Returns both MX records and A-record fallback status.
 */
export declare function checkMx(domain: string): Promise<MxCheckResult>

/**
 * Initialize the DNS resolver. Call once at process startup.
 * Subsequent calls are no-ops.
 */
export declare function initializeDnsResolver(): void
