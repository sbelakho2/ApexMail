/**
 * Email Validation Service
 * 
 * Comprehensive email address validation including:
 * - Syntax validation (RFC 5322)
 * - MX record verification
 * - Disposable email detection
 * - Role-based email detection
 * - Common typo detection and suggestions
 * - Rate limiting to prevent enumeration attacks (SEC-013)
 */

import * as dns from 'dns';
import { promisify } from 'util';
import { createRequire } from 'node:module';
import { createLogger } from '../logger/index.js';
import type { Redis } from 'ioredis';

const logger = createLogger({ name: 'email-validation' });

const resolveMx = promisify(dns.resolveMx);

// ── Native addon acceleration ──────────────────────────────────────────────
// When @apexmail/validator-native is compiled, hot-path functions delegate to
// the Rust napi-rs addon (runs on the libuv thread-pool, off the main thread).
// Falls back transparently to Node.js validation when the native binary is absent.
interface NativeValidationResult {
  valid: boolean;
  email: string;
  localPart: string;
  domain: string;
  isEai: boolean;
  isDisposable: boolean;
  hasMx: boolean | null;
  errors: string[];
  warnings: string[];
}

interface NativeValidator {
  validateEmail(email: string): NativeValidationResult;
  validateEmailWithMx(email: string): Promise<NativeValidationResult>;
  isDisposableDomain(domain: string): boolean;
  checkMx(domain: string): Promise<{ domain: string; hasMx: boolean; mxRecords: string[]; hasAFallback: boolean }>;
  normalizeEmail(email: string): string;
  initializeDnsResolver(): void;
}

const _cjsRequire = createRequire(import.meta.url);
let _nativeValidator: NativeValidator | null = null;

/**
 * Export validation mode for monitoring/metrics.
 * Applications can check this and emit metrics for native vs JS mode.
 */
export let validationMode: 'native' | 'js' = 'js';

try {
  _nativeValidator = _cjsRequire('@apexmail/validator-native') as NativeValidator;
  // Initialize the DNS resolver on load so MX checks are ready
  _nativeValidator.initializeDnsResolver();
  validationMode = 'native';
  logger.info('Native validator addon loaded — using Rust RFC 5321/6531 validation', {
    validationMode: 'native',
  });
} catch (error) {
  validationMode = 'js';
  logger.warn('Native validator addon unavailable, falling back to JS validation', {
    error: error instanceof Error ? error.message : String(error),
    validationMode: 'js',
    // Actionable info for alerting
    alertLevel: 'warning',
    performanceImpact: 'high',
  });
}

// ============================================================================
// Types
// ============================================================================

export interface EmailValidationResult {
    valid: boolean;
    email: string;
    normalized: string;
    local: string;
    domain: string;
    checks: {
        syntax: boolean;
        mxRecord: boolean;
        notDisposable: boolean;
        notRoleBased: boolean;
    };
    mxRecords?: dns.MxRecord[];
    suggestions?: string[];
    warnings?: string[];
    errors?: string[];
}

export interface EmailValidationOptions {
    /** Check MX records (default: true) */
    checkMx?: boolean;
    /** Check for disposable email domains (default: true) */
    checkDisposable?: boolean;
    /** Check for role-based emails (default: false) */
    checkRoleBased?: boolean;
    /** Suggest corrections for typos (default: true) */
    suggestCorrections?: boolean;
    /** Timeout for DNS lookups in ms (default: 2000) - SEC-012 FIX: reduced from 5000 */
    timeout?: number;
    /** Allow subaddressing like user+tag@domain.com (default: true) */
    allowSubaddressing?: boolean;
    /** Enable provider-specific normalization (e.g., Gmail dot handling) */
    normalizeProviderSpecific?: boolean;
}

// ============================================================================
// Known Lists
// ============================================================================

// Common disposable email domains
const DISPOSABLE_DOMAINS = new Set([
    'mailinator.com',
    'guerrillamail.com',
    'guerrillamail.net',
    'guerrillamail.org',
    'sharklasers.com',
    'grr.la',
    'guerrillamailblock.com',
    'pokemail.net',
    'spam4.me',
    'tempmail.com',
    'temp-mail.org',
    'tempmail.net',
    'throwaway.email',
    'throwawaymail.com',
    '10minutemail.com',
    '10minutemail.net',
    'minutemail.com',
    'dispostable.com',
    'fakeinbox.com',
    'mailnesia.com',
    'maildrop.cc',
    'getnada.com',
    'yopmail.com',
    'yopmail.fr',
    'trashmail.com',
    'trashmail.net',
    'mailcatch.com',
    'tempr.email',
    'discard.email',
    'discardmail.com',
    'spamgourmet.com',
    'mytemp.email',
    'mohmal.com',
    'tempail.com',
    'emailondeck.com',
    'fakemailgenerator.com',
    'getairmail.com',
    'mailsac.com',
]);

const extraDisposableDomains = (process.env['APEXMAIL_DISPOSABLE_DOMAINS'] ?? '')
    .split(',')
    .map((domain) => domain.trim().toLowerCase())
    .filter((domain) => domain.length > 0);

for (const domain of extraDisposableDomains) {
    DISPOSABLE_DOMAINS.add(domain);
}

// Role-based email prefixes
const ROLE_BASED_PREFIXES = new Set([
    'admin',
    'administrator',
    'abuse',
    'billing',
    'compliance',
    'devnull',
    'dns',
    'ftp',
    'hostmaster',
    'info',
    'inoc',
    'ispfeedback',
    'ispsupport',
    'list-request',
    'list',
    'maildaemon',
    'marketing',
    'noc',
    'no-reply',
    'noreply',
    'null',
    'operations',
    'phishing',
    'postmaster',
    'privacy',
    'registrar',
    'root',
    'sales',
    'security',
    'spam',
    'support',
    'sysadmin',
    'tech',
    'undisclosed-recipients',
    'unsubscribe',
    'usenet',
    'uucp',
    'webmaster',
    'www',
]);

// Common typos in email domains
const DOMAIN_TYPOS: Record<string, string> = {
    'gmial.com': 'gmail.com',
    'gmai.com': 'gmail.com',
    'gmal.com': 'gmail.com',
    'gnail.com': 'gmail.com',
    'gmail.co': 'gmail.com',
    'gmail.cm': 'gmail.com',
    'gmail.om': 'gmail.com',
    'gamil.com': 'gmail.com',
    'gmil.com': 'gmail.com',
    'gmail.con': 'gmail.com',
    'gmail.comm': 'gmail.com',
    'yaho.com': 'yahoo.com',
    'yahooo.com': 'yahoo.com',
    'yahoo.co': 'yahoo.com',
    'yahoo.cm': 'yahoo.com',
    'yahoo.om': 'yahoo.com',
    'yhaoo.com': 'yahoo.com',
    'hotmal.com': 'hotmail.com',
    'hotmai.com': 'hotmail.com',
    'hotmial.com': 'hotmail.com',
    'hotmail.co': 'hotmail.com',
    'hotmail.cm': 'hotmail.com',
    'hotmail.om': 'hotmail.com',
    'outlok.com': 'outlook.com',
    'outloo.com': 'outlook.com',
    'outlook.co': 'outlook.com',
    'outlook.cm': 'outlook.com',
    'icloud.co': 'icloud.com',
    'icoud.com': 'icloud.com',
    'iclould.com': 'icloud.com',
    'protonmal.com': 'protonmail.com',
    'protonmai.com': 'protonmail.com',
    'portonmail.com': 'protonmail.com',
};

// ============================================================================
// Validation Functions
// ============================================================================

/**
 * Validate email syntax according to RFC 5322
 * Native fast-path: delegates to Rust RFC 5321/6531 parser when available.
 */
function validateSyntax(email: string): { valid: boolean; local: string; domain: string } {
    // ── Native fast-path ──────────────────────────────────────────────────
    if (_nativeValidator) {
        const result = _nativeValidator.validateEmail(email);
        return {
            valid: result.valid && !result.isDisposable, // disposable handled separately
            local: result.localPart,
            domain: result.domain,
        };
    }

    // ── JS fallback ── RFC 5322 regex validation ──────────────────────────
    // Basic regex for email validation
    // More permissive than RFC 5322 but catches most common issues
    const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    
    if (!emailRegex.test(email)) {
        return { valid: false, local: '', domain: '' };
    }
    
    const [local, domain] = email.split('@');
    
    if (!local || !domain) {
        return { valid: false, local: '', domain: '' };
    }
    
    // Local part validation
    if (local.length > 64) {
        return { valid: false, local, domain };
    }
    
    // Check for consecutive dots
    if (local.includes('..') || domain.includes('..')) {
        return { valid: false, local, domain };
    }
    
    // Check for leading/trailing dots
    if (local.startsWith('.') || local.endsWith('.')) {
        return { valid: false, local, domain };
    }
    
    // Domain validation
    if (domain.length > 253) {
        return { valid: false, local, domain };
    }
    
    // Check TLD exists (at least 2 chars)
    const tld = domain.split('.').pop();
    if (!tld || tld.length < 2) {
        return { valid: false, local, domain };
    }
    
    return { valid: true, local, domain };
}

/**
 * Check MX records for domain
 * Native fast-path: delegates to Rust trust-dns-resolver when available.
 */
async function checkMxRecords(domain: string, timeout: number): Promise<{ valid: boolean; records?: dns.MxRecord[] }> {
    // ── Native fast-path ──────────────────────────────────────────────────
    if (_nativeValidator) {
        try {
            const result = await _nativeValidator.checkMx(domain);
            if (result.hasMx) {
                const records: dns.MxRecord[] = result.mxRecords.map((r) => {
                    const parts = r.split(' ');
                    return {
                        priority: parseInt(parts[0] ?? '10', 10),
                        exchange: parts[1] ?? domain,
                    };
                });
                return { valid: true, records };
            }
            if (result.hasAFallback) {
                return { valid: true, records: [{ exchange: domain, priority: 10 }] };
            }
            return { valid: false };
        } catch {
            // Fall through to JS implementation on native failure
        }
    }

    // ── JS fallback ── Node.js dns.resolveMx ──────────────────────────────
    try {
        const records = await withTimeout(resolveMx(domain), timeout, 'DNS timeout');
        
        if (records && records.length > 0) {
            return { valid: true, records: records.sort((a, b) => a.priority - b.priority) };
        }
        
        return { valid: false };
    } catch (err) {
        // Try resolving A record as fallback (some domains accept mail without MX)
        try {
            const aRecords = await withTimeout(promisify(dns.resolve4)(domain), timeout, 'DNS timeout');
            if (aRecords && aRecords.length > 0) {
                return { valid: true, records: [{ exchange: domain, priority: 10 }] };
            }
        } catch {
            // Ignore A record errors
        }
        
        logger.debug('MX lookup failed', { domain, error: err instanceof Error ? err.message : 'Unknown error' });
        return { valid: false };
    }
}

async function withTimeout<T>(operation: Promise<T>, timeoutMs: number, timeoutMessage: string): Promise<T> {
    let timeoutId: ReturnType<typeof setTimeout> | null = null;
    try {
        const timeoutPromise = new Promise<never>((_, reject) => {
            timeoutId = setTimeout(() => reject(new Error(timeoutMessage)), timeoutMs);
            timeoutId.unref?.();
        });

        return await Promise.race([operation, timeoutPromise]);
    } finally {
        if (timeoutId) {
            clearTimeout(timeoutId);
        }
    }
}

/**
 * Check if domain is a disposable email provider
 * Native fast-path: uses compiled Rust HashSet when available.
 */
function checkDisposable(domain: string): boolean {
    if (_nativeValidator) {
        return _nativeValidator.isDisposableDomain(domain);
    }
    return DISPOSABLE_DOMAINS.has(domain.toLowerCase());
}

/**
 * Check if email is a role-based address
 */
function checkRoleBased(local: string): boolean {
    const normalizedLocal = local.toLowerCase().split('+')[0] || local.toLowerCase();
    return ROLE_BASED_PREFIXES.has(normalizedLocal);
}

/**
 * Suggest corrections for common typos
 */
function suggestCorrections(email: string, domain: string): string[] {
    const suggestions: string[] = [];
    const lowerDomain = domain.toLowerCase();
    
    // Check for known typos
    const correction = DOMAIN_TYPOS[lowerDomain];
    if (correction) {
        const local = email.split('@')[0];
        suggestions.push(`${local}@${correction}`);
    }
    
    // Check Levenshtein distance for common domains
    const commonDomains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'icloud.com', 'protonmail.com'];
    for (const commonDomain of commonDomains) {
        if (commonDomain !== lowerDomain && levenshteinDistance(lowerDomain, commonDomain) <= 2) {
            const local = email.split('@')[0];
            const suggestion = `${local}@${commonDomain}`;
            if (!suggestions.includes(suggestion)) {
                suggestions.push(suggestion);
            }
        }
    }
    
    return suggestions;
}

/**
 * Calculate Levenshtein distance between two strings
 * FIX-500-095: Uses two-row rolling array instead of full O(n×m) matrix,
 * reducing memory from O(n×m) to O(min(n,m)).
 * 
 * SEC-015: Removed early termination to prevent timing attacks that could
 * leak information about string similarity. The function now always completes
 * the full matrix calculation regardless of intermediate values.
 */
function levenshteinDistance(a: string, b: string): number {
    // Ensure a is the shorter string so we allocate fewer columns
    if (a.length > b.length) {
        [a, b] = [b, a];
    }

    const m = a.length;
    const n = b.length;

    // The max threshold used by callers is 2 — if the length difference
    // alone exceeds it, we can return immediately.
    // Note: This length check is safe as it only depends on string lengths,
    // not character values, so it doesn't leak timing information.
    const MAX_THRESHOLD = 2;
    if (n - m > MAX_THRESHOLD) return n - m;

    let prev = new Array<number>(m + 1);
    let curr = new Array<number>(m + 1);

    // Initialise first row
    for (let j = 0; j <= m; j++) {
        prev[j] = j;
    }

    for (let i = 1; i <= n; i++) {
        curr[0] = i;

        for (let j = 1; j <= m; j++) {
            const cost = a[j - 1] === b[i - 1] ? 0 : 1;
            const del = (prev[j] ?? 0) + 1;
            const ins = (curr[j - 1] ?? 0) + 1;
            const sub = (prev[j - 1] ?? 0) + cost;
            curr[j] = Math.min(del, ins, sub);
        }

        // Swap rows
        [prev, curr] = [curr, prev];
    }

    return prev[m] ?? 0;
}

/**
 * Normalize email address
 */
function normalizeEmail(email: string, allowSubaddressing: boolean, normalizeProviderSpecific: boolean): string {
    const [local, domain] = email.toLowerCase().split('@');
    if (!local || !domain) return email.toLowerCase();
    
    let normalizedLocal = local;
    
    // Remove subaddressing if not allowed
    if (!allowSubaddressing && local.includes('+')) {
        normalizedLocal = local.split('+')[0] || local;
    }
    
    // Provider-specific: remove dots (Gmail ignores dots in local part)
    if (normalizeProviderSpecific && (domain === 'gmail.com' || domain === 'googlemail.com')) {
        normalizedLocal = normalizedLocal.replace(/\./g, '');
    }
    
    return `${normalizedLocal}@${domain}`;
}

// ============================================================================
// Main Validation Function
// ============================================================================

/**
 * Validate an email address
 */
export async function validateEmail(
    email: string,
    options: EmailValidationOptions = {}
): Promise<EmailValidationResult> {
    const {
        checkMx = true,
        checkDisposable: checkDisp = true,
        checkRoleBased: checkRole = false,
        suggestCorrections: suggest = true,
        // SEC-012 FIX: Reduced from 5000ms to prevent DoS via slow DNS domains
        timeout = 2000,
        allowSubaddressing = true,
        normalizeProviderSpecific = true,
    } = options;
    
    const trimmedEmail = email.trim();
    const errors: string[] = [];
    const warnings: string[] = [];
    
    // Step 1: Syntax validation
    const syntaxResult = validateSyntax(trimmedEmail);
    
    if (!syntaxResult.valid) {
        return {
            valid: false,
            email: trimmedEmail,
            normalized: trimmedEmail.toLowerCase(),
            local: syntaxResult.local,
            domain: syntaxResult.domain,
            checks: {
                syntax: false,
                mxRecord: false,
                notDisposable: true,
                notRoleBased: true,
            },
            errors: ['Invalid email syntax'],
        };
    }
    
    const { local, domain } = syntaxResult;
    const normalized = normalizeEmail(trimmedEmail, allowSubaddressing, normalizeProviderSpecific);
    
    // Step 2: MX record check
    let mxValid = true;
    let mxRecords: dns.MxRecord[] | undefined;
    
    if (checkMx) {
        const mxResult = await checkMxRecords(domain, timeout);
        mxValid = mxResult.valid;
        mxRecords = mxResult.records;
        
        if (!mxValid) {
            errors.push(`No MX records found for domain: ${domain}`);
        }
    }
    
    // Step 3: Disposable email check
    let notDisposable = true;
    if (checkDisp) {
        notDisposable = !checkDisposable(domain);
        if (!notDisposable) {
            warnings.push('Disposable email address detected');
        }
    }
    
    // Step 4: Role-based email check
    let notRoleBased = true;
    if (checkRole) {
        notRoleBased = !checkRoleBased(local);
        if (!notRoleBased) {
            warnings.push('Role-based email address detected');
        }
    }
    
    // Step 5: Suggest corrections
    let suggestions: string[] | undefined;
    if (suggest) {
        suggestions = suggestCorrections(trimmedEmail, domain);
        if (suggestions.length > 0) {
            warnings.push(`Did you mean: ${suggestions[0]}?`);
        }
    }
    
    // Determine overall validity
    const valid = syntaxResult.valid && mxValid && notDisposable;
    
    return {
        valid,
        email: trimmedEmail,
        normalized,
        local,
        domain,
        checks: {
            syntax: syntaxResult.valid,
            mxRecord: mxValid,
            notDisposable,
            notRoleBased,
        },
        mxRecords,
        suggestions: suggestions && suggestions.length > 0 ? suggestions : undefined,
        warnings: warnings.length > 0 ? warnings : undefined,
        errors: errors.length > 0 ? errors : undefined,
    };
}

/**
 * Quick validation - syntax only, no DNS
 */
export function validateEmailSyntax(email: string): boolean {
    return validateSyntax(email.trim()).valid;
}

/**
 * Batch validate multiple emails
 */
export async function validateEmails(
    emails: string[],
    options: EmailValidationOptions = {}
): Promise<EmailValidationResult[]> {
    // Process in batches to avoid overwhelming DNS
    const batchSize = 10;
    const results: EmailValidationResult[] = [];
    
    for (let i = 0; i < emails.length; i += batchSize) {
        const batch = emails.slice(i, i + batchSize);
        const batchResults = await Promise.all(
            batch.map(email => validateEmail(email, options))
        );
        results.push(...batchResults);
    }
    
    return results;
}

/**
 * Check if domain accepts email (has MX records)
 * SEC-012 FIX: Reduced default timeout from 5000ms to 2000ms
 */
export async function domainAcceptsEmail(domain: string, timeout = 2000): Promise<boolean> {
    const result = await checkMxRecords(domain, timeout);
    return result.valid;
}

/**
 * Check if email is from a disposable provider
 */
export function isDisposableEmail(email: string): boolean {
    const domain = email.split('@')[1];
    return domain ? checkDisposable(domain) : false;
}

/**
 * Check if email is role-based
 */
export function isRoleBasedEmail(email: string): boolean {
    const local = email.split('@')[0];
    return local ? checkRoleBased(local) : false;
}

// ============================================================================
// Rate Limiter (SEC-013)
// ============================================================================

export interface RateLimitConfig {
    /** Maximum requests per window per identifier (default: 100) */
    maxRequests: number;
    /** Window size in milliseconds (default: 60000 = 1 minute) */
    windowMs: number;
    /** Redis client for distributed rate limiting (optional, falls back to in-memory) */
    redis?: Redis;
    /** Key prefix for Redis (default: 'emailval:ratelimit:') */
    keyPrefix?: string;
}

export interface RateLimitResult {
    allowed: boolean;
    remaining: number;
    resetAt: Date;
    retryAfterMs?: number;
}

/**
 * In-memory rate limiter fallback for single-instance deployments
 */
class InMemoryRateLimiter {
    private requests: Map<string, { count: number; resetAt: number }> = new Map();
    private cleanupTimer: ReturnType<typeof setInterval> | null = null;

    constructor(private config: RateLimitConfig) {
        // Cleanup expired entries every 30 seconds
        this.cleanupTimer = setInterval(() => this.cleanup(), 30000);
        if (this.cleanupTimer.unref) this.cleanupTimer.unref();
    }

    async check(identifier: string): Promise<RateLimitResult> {
        const now = Date.now();
        const key = `${this.config.keyPrefix ?? 'ratelimit:'}${identifier}`;
        const entry = this.requests.get(key);

        if (!entry || now > entry.resetAt) {
            // New window
            const resetAt = now + this.config.windowMs;
            this.requests.set(key, { count: 1, resetAt });
            return {
                allowed: true,
                remaining: this.config.maxRequests - 1,
                resetAt: new Date(resetAt),
            };
        }

        if (entry.count >= this.config.maxRequests) {
            return {
                allowed: false,
                remaining: 0,
                resetAt: new Date(entry.resetAt),
                retryAfterMs: entry.resetAt - now,
            };
        }

        entry.count += 1;
        return {
            allowed: true,
            remaining: this.config.maxRequests - entry.count,
            resetAt: new Date(entry.resetAt),
        };
    }

    private cleanup(): void {
        const now = Date.now();
        for (const [key, entry] of this.requests) {
            if (now > entry.resetAt) {
                this.requests.delete(key);
            }
        }
    }

    destroy(): void {
        if (this.cleanupTimer) {
            clearInterval(this.cleanupTimer);
            this.cleanupTimer = null;
        }
        this.requests.clear();
    }
}

/**
 * Redis-based distributed rate limiter
 */
class RedisRateLimiter {
    constructor(private config: RateLimitConfig) {}

    async check(identifier: string): Promise<RateLimitResult> {
        const redis = this.config.redis!;
        const key = `${this.config.keyPrefix ?? 'emailval:ratelimit:'}${identifier}`;
        const window = this.config.windowMs;
        const max = this.config.maxRequests;

        // Use Redis INCR with atomic expiry
        const current = await redis.incr(key);
        
        if (current === 1) {
            // First request in window - set expiry
            await redis.pexpire(key, window);
        }

        const ttl = await redis.pttl(key);
        const resetAt = new Date(Date.now() + (ttl > 0 ? ttl : window));
        const remaining = Math.max(0, max - current);

        if (current > max) {
            return {
                allowed: false,
                remaining: 0,
                resetAt,
                retryAfterMs: ttl > 0 ? ttl : window,
            };
        }

        return {
            allowed: true,
            remaining: remaining - 1,
            resetAt,
        };
    }
}

/**
 * Factory to create appropriate rate limiter
 */
function createRateLimiter(config: RateLimitConfig): { check: (id: string) => Promise<RateLimitResult>; destroy?: () => void } {
    if (config.redis) {
        return new RedisRateLimiter(config);
    }
    const inMemory = new InMemoryRateLimiter(config);
    return { check: (id) => inMemory.check(id), destroy: () => inMemory.destroy() };
}

// ============================================================================
// Email Validator Class
// ============================================================================

export interface EmailValidatorConfig {
    validationOptions?: EmailValidationOptions;
    cacheMaxAgeMs?: number;
    maxCacheSize?: number;
    /** Rate limit configuration (SEC-013). If provided, enables rate limiting */
    rateLimit?: RateLimitConfig;
}

export class EmailValidator {
    private options: EmailValidationOptions;
    private cache: Map<string, { result: EmailValidationResult; timestamp: number }>;
    private cacheMaxAge: number;
    private maxCacheSize: number;
    private cleanupTimer: ReturnType<typeof setInterval> | null = null;
    private rateLimiter?: { check: (id: string) => Promise<RateLimitResult>; destroy?: () => void };
    private rateLimitConfig?: RateLimitConfig;
    
    constructor(
        options: EmailValidationOptions = {},
        cacheMaxAgeMs = 3600000,
        maxCacheSize = 10000,
        rateLimitConfig?: RateLimitConfig
    ) {
        this.options = options;
        this.cache = new Map();
        this.cacheMaxAge = cacheMaxAgeMs;
        this.maxCacheSize = maxCacheSize;
        this.rateLimitConfig = rateLimitConfig;

        // SEC-013: Initialize rate limiter if configured
        if (rateLimitConfig) {
            this.rateLimiter = createRateLimiter(rateLimitConfig);
        }

        // FIX-064: Periodic cleanup of expired entries (every 5 minutes)
        this.cleanupTimer = setInterval(() => this.evictExpired(), 5 * 60 * 1000);
        if (this.cleanupTimer.unref) this.cleanupTimer.unref();
    }

    /**
     * Alternate constructor accepting full config object
     */
    static withConfig(config: EmailValidatorConfig): EmailValidator {
        return new EmailValidator(
            config.validationOptions,
            config.cacheMaxAgeMs,
            config.maxCacheSize,
            config.rateLimit
        );
    }

    /**
     * Check rate limit before validation (SEC-013)
     * @param identifier - IP address or tenant ID to rate limit on
     * @returns RateLimitResult indicating if request is allowed
     */
    async checkRateLimit(identifier: string): Promise<RateLimitResult> {
        if (!this.rateLimiter) {
            // No rate limiting configured - always allow
            return {
                allowed: true,
                remaining: Infinity,
                resetAt: new Date(Date.now() + 60000),
            };
        }
        return this.rateLimiter.check(identifier);
    }
    
    async validate(email: string, rateLimitIdentifier?: string): Promise<EmailValidationResult> {
        // SEC-013: Check rate limit if identifier provided
        if (rateLimitIdentifier && this.rateLimiter) {
            const rateResult = await this.rateLimiter.check(rateLimitIdentifier);
            if (!rateResult.allowed) {
                logger.warn('Email validation rate limited', {
                    identifier: rateLimitIdentifier,
                    retryAfterMs: rateResult.retryAfterMs,
                });
                return {
                    valid: false,
                    email: email.trim(),
                    normalized: email.trim().toLowerCase(),
                    local: '',
                    domain: '',
                    checks: {
                        syntax: false,
                        mxRecord: false,
                        notDisposable: true,
                        notRoleBased: true,
                    },
                    errors: ['Rate limit exceeded. Please try again later.'],
                };
            }
        }
        const normalizedEmail = email.toLowerCase().trim();
        
        // Check cache
        const cached = this.cache.get(normalizedEmail);
        if (cached && Date.now() - cached.timestamp < this.cacheMaxAge) {
            // Move to end for LRU ordering (Map preserves insertion order)
            this.cache.delete(normalizedEmail);
            this.cache.set(normalizedEmail, cached);
            return cached.result;
        }
        
        // Remove stale entry if it existed
        if (cached) {
            this.cache.delete(normalizedEmail);
        }
        
        // Validate
        const result = await validateEmail(email, this.options);
        
        // Check cache size and trigger immediate eviction if near capacity
        // This prevents unbounded growth during validation bursts
        if (this.cache.size >= this.maxCacheSize - 1) {
            this.evictExpired();
            // If still at capacity after evicting expired, remove oldest
            while (this.cache.size >= this.maxCacheSize) {
                const oldestKey = this.cache.keys().next().value;
                if (oldestKey !== undefined) this.cache.delete(oldestKey);
            }
        }
        
        // Cache result
        this.cache.set(normalizedEmail, { result, timestamp: Date.now() });
        
        return result;
    }
    
    async validateBatch(emails: string[]): Promise<EmailValidationResult[]> {
        return validateEmails(emails, this.options);
    }
    
    clearCache(): void {
        this.cache.clear();
    }
    
    getCacheSize(): number {
        return this.cache.size;
    }

    /** Remove all entries older than cacheMaxAge */
    private evictExpired(): void {
        const now = Date.now();
        for (const [key, entry] of this.cache) {
            if (now - entry.timestamp >= this.cacheMaxAge) {
                this.cache.delete(key);
            }
        }
    }

    /** Stop periodic cleanup (for graceful shutdown / tests) */
    destroy(): void {
        if (this.cleanupTimer) {
            clearInterval(this.cleanupTimer);
            this.cleanupTimer = null;
        }
        this.cache.clear();
    }
}

/**
 * Create a new email validator instance
 */
export function createEmailValidator(
    options: EmailValidationOptions = {},
    cacheMaxAgeMs = 3600000
): EmailValidator {
    return new EmailValidator(options, cacheMaxAgeMs);
}
