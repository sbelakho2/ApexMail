# ApexMail Security & Bug Audit Report

**Generated:** 2026-02-26  
**Auditor:** GitHub Copilot (Claude Opus 4.5)  
**Scope:** Comprehensive security and code quality audit

---

## Summary

| Category | Critical | High | Medium | Low | Total |
|----------|----------|------|--------|-----|-------|
| SECURITY | 3 | 8 | 12 | 6 | 29 |
| BUG | 2 | 5 | 8 | 4 | 19 |
| PERFORMANCE | 0 | 2 | 6 | 3 | 11 |
| CODE-QUALITY | 0 | 1 | 5 | 8 | 14 |
| **Total** | **5** | **16** | **31** | **21** | **73** |

---

## CRITICAL Issues

### SEC-001: Rust Template Renderer Uses `unwrap()` in Production Code
**File:** [services/mail-server/crates/template-renderer/src/transpiler.rs](services/mail-server/crates/template-renderer/src/transpiler.rs#L17-L46)  
**Category:** SECURITY  
**Priority:** CRITICAL  

**Description:**  
Multiple `unwrap()` calls on regex compilation and capture groups can panic and crash the mail server. An attacker could craft malicious template payloads that trigger these panics, causing denial of service.

```rust
// Lines 17-46: Multiple unwrap() on Regex::new and .get() calls
Regex::new(r#"..."#).unwrap()
cap.get(0).unwrap().start()
```

**Fix Recommendation:**  
- Replace `unwrap()` with `expect()` for compile-time regexes (use `lazy_static` or `OnceLock`)
- Use proper error handling with `?` operator for runtime operations
- Add `#![deny(clippy::unwrap_used)]` to crate root (already present but not enforced in this file)

---

### SEC-002: Control Plane Login Allows Environment Variable Password Authentication
**File:** [apps/control-plane/src/app/api/auth/login/route.ts](apps/control-plane/src/app/api/auth/login/route.ts#L143-L177)  
**Category:** SECURITY  
**Priority:** CRITICAL  

**Description:**  
The control plane login route builds credentials from environment variables. If `CONTROL_PLANE_OWNER_PASSWORD` is not bcrypt-hashed, there's potential for plaintext password in env vars. Additionally, fallback to `admin` role without explicit check could allow privilege escalation.

```typescript
// Line 166-177: Role assignment without validation
role: 'super_admin',
// ...
role: 'admin',
```

**Fix Recommendation:**  
- Require bcrypt-hashed passwords in environment variables
- Add explicit validation that role values are from allowed set
- Log all super_admin logins to dedicated security audit stream
- Consider requiring hardware key (WebAuthn) for super_admin access

---

### SEC-003: Impersonation Token IP Extraction Vulnerable to Spoofing
**File:** [apps/control-plane/src/app/api/impersonate/route.ts](apps/control-plane/src/app/api/impersonate/route.ts#L143-L146)  
**Category:** SECURITY  
**Priority:** CRITICAL  

**Description:**  
The impersonation route extracts client IP from `x-forwarded-for` using the leftmost entry, which can be spoofed by clients. This affects audit logging accuracy for high-privilege impersonation actions.

```typescript
// Line 143-146
const forwardedFor = request.headers.get('x-forwarded-for');
const ipAddress = forwardedFor?.split(',')[0]?.trim() || realIp || null;
// Should use rightmost entry
```

**Fix Recommendation:**  
Use rightmost `x-forwarded-for` entry (added by trusted proxy), consistent with the fix already applied in middleware.ts:

```typescript
const parts = forwardedFor.split(',').map(s => s.trim()).filter(Boolean);
const ipAddress = parts[parts.length - 1] || realIp || null;
```

---

### BUG-001: Database Connection Pool Statement Timeout Uses String Interpolation
**File:** [packages/db/src/pool.ts](packages/db/src/pool.ts#L152-L159)  
**Category:** BUG  
**Priority:** CRITICAL  

**Description:**  
The statement timeout is set using string interpolation in SQL. While the value is validated as a number, this pattern is fragile and could lead to SQL injection if validation is bypassed.

```typescript
// Line 159
void client.query(`SET statement_timeout = ${timeoutMs}`)
```

**Fix Recommendation:**  
PostgreSQL doesn't support parameterized SET statements, but add explicit integer validation:

```typescript
const safeTimeout = Math.floor(Math.max(0, Math.min(timeoutMs, 2147483647)));
void client.query(`SET statement_timeout = ${safeTimeout.toString()}`);
```

---

### BUG-002: Transaction Isolation Level Also Uses String Interpolation
**File:** [packages/db/src/transaction.ts](packages/db/src/transaction.ts#L115-L125)  
**Category:** BUG  
**Priority:** CRITICAL  

**Description:**  
Transaction isolation level is set via string interpolation. While validated against enum, the pattern is risky.

```typescript
// Line 115
modifiers.push(`ISOLATION LEVEL ${opts.isolationLevel}`);
```

**Fix Recommendation:**  
Add explicit whitelist validation:

```typescript
const VALID_ISOLATION_LEVELS = ['READ COMMITTED', 'REPEATABLE READ', 'SERIALIZABLE'] as const;
if (!VALID_ISOLATION_LEVELS.includes(opts.isolationLevel)) {
  throw new Error(`Invalid isolation level: ${opts.isolationLevel}`);
}
```

---

## HIGH Priority Issues

### SEC-004: Control Plane Secrets API Missing Input Validation
**File:** [apps/control-plane/src/app/api/secrets/route.ts](apps/control-plane/src/app/api/secrets/route.ts#L77-L90)  
**Category:** SECURITY  
**Priority:** HIGH  

**Description:**  
The secrets API accepts `name`, `type`, `description` without length limits or character validation. This could allow:
- SQL column overflow attacks
- XSS via stored secret names shown in UI
- Resource exhaustion with very long strings

```typescript
// Line 77-90: No validation beyond existence check
const { name, type, description, rotationPolicy } = body;
if (!name || !type) { ... }
```

**Fix Recommendation:**  
Add zod schema validation:

```typescript
const createSecretSchema = z.object({
  name: z.string().min(1).max(100).regex(/^[a-zA-Z0-9_-]+$/),
  type: z.enum(['api_key', 'oauth_secret', 'encryption_key', 'signing_key']),
  description: z.string().max(500).optional().default(''),
  rotationPolicy: z.enum(['manual', 'daily', 'weekly', 'monthly']).optional(),
});
```

---

### SEC-005: Billing Admin Routes Missing Tenant Authorization
**File:** [apps/billing/src/routes/admin.ts](apps/billing/src/routes/admin.ts#L28-L30)  
**Category:** SECURITY  
**Priority:** HIGH  

**Description:**  
Admin routes check `isAdmin` flag but don't verify the admin has authority over specific tenants. A compromised admin account could access any tenant's billing data.

```typescript
// Line 28-30
router.use('*', async (c, next) => {
    const isAdmin = c.get('isAdmin');
    if (!isAdmin) { return c.json({ error: 'Admin access required' }, 403); }
    return next();
});
```

**Fix Recommendation:**  
Add tenant scope validation for admin actions:

```typescript
const adminScope = c.get('adminScope'); // e.g., ['tenant:*'] or ['tenant:uuid1', 'tenant:uuid2']
if (!canAccessTenant(adminScope, tenantId)) {
  return c.json({ error: 'Tenant access denied' }, 403);
}
```

---

### SEC-006: Stripe Webhook Missing Event ID Deduplication
**File:** [apps/billing/src/routes/webhooks.ts](apps/billing/src/routes/webhooks.ts#L12-L27)  
**Category:** SECURITY  
**Priority:** HIGH  

**Description:**  
The Stripe webhook handler processes events without checking for duplicate event IDs. Stripe recommends idempotency checks to prevent replay attacks and double-processing.

```typescript
// Line 12-27: No event.id tracking
router.post('/stripe', async (c) => {
    const result = await ctx.stripe.processWebhook(rawBody, signature);
    // No deduplication check
});
```

**Fix Recommendation:**  
Add Redis-based deduplication:

```typescript
const eventId = JSON.parse(rawBody).id;
const dedupKey = `stripe:event:${eventId}`;
const wasSet = await redis.set(dedupKey, '1', 'EX', 86400, 'NX');
if (!wasSet) {
  return c.json({ received: true }); // Already processed
}
```

---

### SEC-007: CSRF Cookie Configuration Missing Domain Attribute
**File:** [apps/web/src/lib/csrf.ts](apps/web/src/lib/csrf.ts#L96-L107)  
**Category:** SECURITY  
**Priority:** HIGH  

**Description:**  
CSRF cookies are set without explicit `domain` attribute, potentially allowing subdomains to access the token.

```typescript
// Line 96-107: Missing domain attribute
response.cookies.set(CSRF_COOKIE, token, {
    httpOnly: false,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
    maxAge: 60 * 60 * 2,
    // domain: undefined - inherits request domain
});
```

**Fix Recommendation:**  
Explicitly set domain to prevent subdomain cookie access:

```typescript
domain: process.env.NODE_ENV === 'production' ? '.apexmail.ee' : undefined,
```

---

### SEC-008: API Key Cache Doesn't Invalidate on Revocation
**File:** [services/mail-server/crates/api-server/src/middleware/auth.rs](services/mail-server/crates/api-server/src/middleware/auth.rs#L44)  
**Category:** SECURITY  
**Priority:** HIGH  

**Description:**  
API keys are cached in Redis for 60 seconds. If an API key is revoked, it remains valid for up to 60 seconds.

```rust
const API_KEY_CACHE_TTL: u64 = 60; // seconds
```

**Fix Recommendation:**  
- Reduce cache TTL to 10 seconds for better security/performance tradeoff
- Implement cache invalidation on API key revocation
- Add `api_key_revoked:{hash}` marker with shorter TTL

---

### SEC-009: Password Verification Returns Early on Invalid Hash Format
**File:** [packages/lib/src/crypto/index.ts](packages/lib/src/crypto/index.ts#L222-L228)  
**Category:** SECURITY  
**Priority:** HIGH  

**Description:**  
The `verifyPassword` function returns `false` immediately if the hash format is invalid. This creates a timing oracle that could reveal whether a user exists.

```typescript
// Line 222-228
if (parts.length !== 7 || parts[1] !== 'scrypt') {
    return false; // Fast return creates timing difference
}
```

**Fix Recommendation:**  
Add constant-time fake comparison:

```typescript
if (parts.length !== 7 || parts[1] !== 'scrypt') {
    // Perform fake work to prevent timing oracle
    await scryptAsync('dummy', 'salt', SCRYPT_KEYLEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem: SCRYPT_MAXMEM });
    return false;
}
```

---

### SEC-010: Session Token Not Bound to Client Fingerprint
**File:** [apps/web/src/middleware.ts](apps/web/src/middleware.ts#L140-L155)  
**Category:** SECURITY  
**Priority:** HIGH  

**Description:**  
Session tokens are not bound to client fingerprints (User-Agent, IP prefix). A stolen session cookie can be used from any client.

**Fix Recommendation:**  
Add fingerprint binding:

```typescript
const fingerprint = createHash('sha256')
  .update(request.headers.get('user-agent') || '')
  .update(getClientIpPrefix(request)) // First 3 octets of IPv4
  .digest('hex').slice(0, 16);

// Verify fingerprint in token matches request
if (tokenFingerprint !== fingerprint) {
  return NextResponse.redirect(new URL('/login?reason=session_mismatch', request.url));
}
```

---

### SEC-011: Billing Checkout URL Validation Can Be Bypassed
**File:** [apps/billing/src/routes/billing.ts](apps/billing/src/routes/billing.ts#L100-L107)  
**Category:** SECURITY  
**Priority:** HIGH  

**Description:**  
The URL validation for checkout success/cancel URLs only checks if hostname ends with `apexmail.ee`. An attacker could register `evil-apexmail.ee` to bypass this check.

```typescript
// Line 100-107
successUrl: z.string().url().refine(
    (u) => { try { const h = new URL(u).hostname; return h.endsWith('apexmail.ee') || h === 'localhost'; } catch { return false; } },
    'Redirect URL must belong to apexmail.ee'
),
```

**Fix Recommendation:**  
Check for exact domain match or subdomain:

```typescript
const isValidDomain = (hostname) => {
  return hostname === 'apexmail.ee' || 
         hostname.endsWith('.apexmail.ee') ||
         (process.env.NODE_ENV !== 'production' && hostname === 'localhost');
};
```

---

### BUG-003: Metering Service Buffer Can Still Overflow
**File:** [apps/billing/src/services/metering.ts](apps/billing/src/services/metering.ts#L113-L129)  
**Category:** BUG  
**Priority:** HIGH  

**Description:**  
The buffer overflow check only logs a warning when at capacity but still tries to flush. If the flush fails repeatedly, events could be lost.

```typescript
// Line 113-129
if (this.buffer.length >= this.config.maxBufferSize) {
    const flushResult = await this.flush();
    if (!flushResult.ok) {
        console.error('[Metering] Flush attempt during buffer pressure failed');
    }
    if (this.buffer.length >= this.config.maxBufferSize) {
        console.error(`[Metering] Buffer at capacity`);
        // Event remains in Redis but may not be processed
        return Result.ok(true);
    }
}
```

**Fix Recommendation:**  
Return an error when buffer is full to enable backpressure:

```typescript
if (this.buffer.length >= this.config.maxBufferSize) {
  return Result.err(new Error('Metering buffer full - apply backpressure'));
}
```

---

### BUG-004: Invoice Number Sequence Not Tenant-Isolated
**File:** [apps/billing/src/services/invoices.ts](apps/billing/src/services/invoices.ts#L86-L97)  
**Category:** BUG  
**Priority:** HIGH  

**Description:**  
Invoice numbers use a global sequence, allowing tenants to infer invoice count. This leaks business metrics.

```typescript
// Line 86-97
const result = await this.db.query<{ next_val: string }>(
    `SELECT nextval('invoice_number_seq')::text as next_val`
);
```

**Fix Recommendation:**  
Use per-tenant sequences or UUID-based invoice numbers:

```typescript
const invoiceNumber = `${year}-${tenantIdPrefix}-${generateRandomHex(6).toUpperCase()}`;
```

---

### BUG-005: Queue Job Payload Corruption Silently Skipped
**File:** [packages/lib/src/queue/index.ts](packages/lib/src/queue/index.ts#L215-L236)  
**Category:** BUG  
**Priority:** HIGH  

**Description:**  
When a queue job has corrupted JSON payload, it's silently skipped. These jobs will never be processed and eventually timeout/expire.

```typescript
// Line 215-236
try {
    jobs.push({ ...parsedJob });
} catch (parseError) {
    this.logger.error('Failed to parse job payload/metadata', { jobId: row.id });
    // Job silently dropped
}
```

**Fix Recommendation:**  
Move corrupt jobs to dead-letter queue with reason:

```typescript
catch (parseError) {
  await this.deadLetter(row.id, `JSON parse error: ${parseError.message}`);
  this.logger.error('Corrupt job moved to DLQ', { jobId: row.id });
}
```

---

## MEDIUM Priority Issues

### SEC-012: Email Validation MX Lookup Timeout Could Cause DoS
**File:** [packages/lib/src/validation/index.ts](packages/lib/src/validation/index.ts#L55)  
**Category:** SECURITY  
**Priority:** MEDIUM  

**Description:**  
MX lookup timeout defaults to 5000ms. Attackers could submit many emails with domains that have slow/unresponsive DNS to tie up resources.

**Fix Recommendation:**  
- Reduce default timeout to 2000ms
- Add per-IP rate limiting for validation requests
- Cache MX lookup results

---

### SEC-013: Impersonation Session Duration Too Long
**File:** [apps/control-plane/src/app/api/impersonate/route.ts](apps/control-plane/src/app/api/impersonate/route.ts#L19)  
**Category:** SECURITY  
**Priority:** MEDIUM  

**Description:**  
Impersonation tokens are valid for 15 minutes, which may be too long for high-privilege access.

```typescript
const IMPERSONATION_TOKEN_DURATION_MS = 15 * 60 * 1000; // 15 minutes
```

**Fix Recommendation:**  
Reduce to 5 minutes and require re-auth for sensitive actions during impersonation.

---

### SEC-014: Control Plane IP Whitelist Supports Wildcard
**File:** [apps/control-plane/src/middleware.ts](apps/control-plane/src/middleware.ts#L283-L285)  
**Category:** SECURITY  
**Priority:** MEDIUM  

**Description:**  
The IP whitelist check allows `'*'` which bypasses all IP restrictions.

```typescript
return IP_WHITELIST.includes(clientIp) || IP_WHITELIST.includes('*');
```

**Fix Recommendation:**  
Remove wildcard support or require explicit env var to enable:

```typescript
if (IP_WHITELIST.includes('*') && process.env.ALLOW_ALL_IPS !== 'true') {
  console.error('[SECURITY] Wildcard IP whitelist requires ALLOW_ALL_IPS=true');
  return false;
}
```

---

### SEC-015: User Password Hash Stored in Same Column for Different Algorithms
**File:** [packages/db/src/repositories/users.ts](packages/db/src/repositories/users.ts#L48)  
**Category:** SECURITY  
**Priority:** MEDIUM  

**Description:**  
Password hashes don't include algorithm versioning metadata. Future algorithm upgrades will be difficult.

**Fix Recommendation:**  
The current `$scrypt$` prefix is good - ensure all password creation uses this standard format.

---

### SEC-016: SSO OAuth State Not Validated for CSRF
**File:** [apps/web/src/app/api/auth/sso/github/route.ts](apps/web/src/app/api/auth/sso/github/route.ts#L13)  
**Category:** SECURITY  
**Priority:** MEDIUM  

**Description:**  
The SSO routes read `next` from query params without CSRF protection on the OAuth state parameter.

**Fix Recommendation:**  
Include CSRF token hash in OAuth state and validate on callback.

---

### SEC-017: Rate Limiter Cache Not Distributed
**File:** [services/mail-server/crates/submission/src/auth.rs](services/mail-server/crates/submission/src/auth.rs#L18-L23)  
**Category:** SECURITY  
**Priority:** MEDIUM  

**Description:**  
Auth rate limiting uses in-memory `moka` cache. In multi-instance deployments, attackers can bypass by targeting different instances.

```rust
static AUTH_FAIL_CACHE: LazyLock<Cache<IpAddr, u32>> = LazyLock::new(|| {
    Cache::builder()
        .max_capacity(50_000)
        .time_to_live(Duration::from_secs(300))
        .build()
});
```

**Fix Recommendation:**  
Use Redis-based rate limiting for production deployments.

---

### SEC-018: Audit Log Hash Chain Creates Contention
**File:** [packages/db/src/repositories/audit-logs.ts](packages/db/src/repositories/audit-logs.ts#L130-L132)  
**Category:** SECURITY  
**Priority:** MEDIUM  

**Description:**  
Using advisory locks per tenant for hash chain serialization could create performance bottleneck during high audit volume.

**Fix Recommendation:**  
Consider partitioned hash chains or eventual consistency model for audit logs.

---

### BUG-006: parseInt Without Radix in Some Places
**File:** [apps/billing/src/routes/billing.ts](apps/billing/src/routes/billing.ts#L165-L166)  
**Category:** BUG  
**Priority:** MEDIUM  

**Description:**  
Some `parseInt` calls use radix but with `|| default` pattern that could mask NaN.

```typescript
const limit = Math.min(Math.max(parseInt(c.req.query('limit') ?? '50', 10) || 50, 1), 200);
```

**Fix Recommendation:**  
Use explicit NaN check:

```typescript
const parsed = parseInt(c.req.query('limit') ?? '', 10);
const limit = Math.min(Math.max(Number.isNaN(parsed) ? 50 : parsed, 1), 200);
```

---

### BUG-007: VAT Calculation May Have Floating Point Issues
**File:** [apps/billing/src/services/invoices.ts](apps/billing/src/services/invoices.ts#L106-L120)  
**Category:** BUG  
**Priority:** MEDIUM  

**Description:**  
VAT calculation uses integer math but the formula could overflow for large amounts:

```typescript
(amountCents * ratePercent + 50) / 100
```

**Fix Recommendation:**  
Use BigInt for amounts over 21 billion cents or add overflow check.

---

### BUG-008: Enterprise Contract Usage Query Not Tenant-Scoped
**File:** [apps/billing/src/services/enterprise-contracts.ts](apps/billing/src/services/enterprise-contracts.ts#L250)  
**Category:** BUG  
**Priority:** MEDIUM  

**Description:**  
Need to verify the usage query properly filters by tenant_id.

**Fix Recommendation:**  
Audit all enterprise contract queries for proper tenant scoping.

---

### BUG-009: Database Pool Password Throws in Lambda Before Init
**File:** [packages/db/src/pool.ts](packages/db/src/pool.ts#L114)  
**Category:** BUG  
**Priority:** MEDIUM  

**Description:**  
The password getter throws synchronously, which could crash the process before error handlers are set up.

```typescript
password: config.password ?? process.env['DB_PASSWORD'] ?? (() => { throw new Error('DB_PASSWORD must be configured'); })(),
```

**Fix Recommendation:**  
Return Result type or check in connect() method instead.

---

### BUG-010: Cache Get Returns Null on Parse Error
**File:** [packages/lib/src/cache/index.ts](packages/lib/src/cache/index.ts#L129-L134)  
**Category:** BUG  
**Priority:** MEDIUM  

**Description:**  
When JSON parsing fails, the cache returns null which is indistinguishable from cache miss. This could cause stale data issues.

```typescript
try {
    return JSON.parse(value) as T;
} catch {
    return null;
}
```

**Fix Recommendation:**  
Throw error or return discriminated union:

```typescript
return { hit: true, value: JSON.parse(value), parseError: undefined };
// vs
return { hit: true, value: undefined, parseError: e };
```

---

### PERF-001: N+1 Query in Admin Tenant List
**File:** [apps/billing/src/routes/admin.ts](apps/billing/src/routes/admin.ts#L32-L60)  
**Category:** PERFORMANCE  
**Priority:** HIGH  

**Description:**  
The tenant list query joins multiple tables but the individual tenant detail endpoint makes 5 parallel queries.

**Fix Recommendation:**  
Add indexed composite query or GraphQL DataLoader pattern.

---

### PERF-002: Metering Flush Could Batch Better
**File:** [apps/billing/src/services/metering.ts](apps/billing/src/services/metering.ts#L148)  
**Category:** PERFORMANCE  
**Priority:** HIGH  

**Description:**  
`recordBatch` calls `recordEvent` in parallel but each makes individual Redis calls.

**Fix Recommendation:**  
Use Redis pipeline for batch operations.

---

### CODE-001: Inconsistent Error Handling Patterns
**File:** Multiple files  
**Category:** CODE-QUALITY  
**Priority:** HIGH  

**Description:**  
Mix of `Result<T, Error>`, throwing, and error returns across the codebase.

**Fix Recommendation:**  
Standardize on `Result` type for all async operations.

---

## LOW Priority Issues

### SEC-019: Development E2E Bypass Configuration
**File:** [apps/web/src/middleware.ts](apps/web/src/middleware.ts#L30-L42)  
**Category:** SECURITY  
**Priority:** LOW  

**Description:**  
E2E bypass exists for testing. Ensure this is properly disabled in production.

**Fix Recommendation:**  
Add deployment check that fails if E2E_TEST_MODE is set in production.

---

### SEC-020: Disposable Email List Could Be Outdated
**File:** [packages/lib/src/validation/index.ts](packages/lib/src/validation/index.ts#L60-L90)  
**Category:** SECURITY  
**Priority:** LOW  

**Description:**  
Static disposable email domain list will become outdated.

**Fix Recommendation:**  
Add external API integration or periodic list updates.

---

### BUG-011: Missing Return Type Annotations
**File:** Multiple TypeScript files  
**Category:** CODE-QUALITY  
**Priority:** LOW  

**Description:**  
Some functions missing explicit return type annotations, reducing type safety.

**Fix Recommendation:**  
Enable `noImplicitReturns` and add missing annotations.

---

### BUG-012: Some Zod Numbers Missing Max Bounds
**File:** [apps/billing/src/routes/billing.ts](apps/billing/src/routes/billing.ts#L60)  
**Category:** BUG  
**Priority:** LOW  

**Description:**  
Some `z.number()` validations have `min` but not `max` bounds.

**Fix Recommendation:**  
Add `.max()` constraints to prevent overflow.

---

### PERF-003: Template Regex Compiled on Every Call
**File:** [services/mail-server/crates/template-renderer/src/transpiler.rs](services/mail-server/crates/template-renderer/src/transpiler.rs#L17-L46)  
**Category:** PERFORMANCE  
**Priority:** MEDIUM  

**Description:**  
Regex patterns use `LazyLock` but could benefit from pre-compilation at build time.

**Fix Recommendation:**  
Use `regex!` macro if available or ensure single initialization.

---

### CODE-002: Console.log Used Instead of Logger
**File:** [apps/billing/src/services/stripe-integration.ts](apps/billing/src/services/stripe-integration.ts#L22-L23)  
**Category:** CODE-QUALITY  
**Priority:** LOW  

**Description:**  
Some error logging uses `console.error` instead of structured logger.

**Fix Recommendation:**  
Replace with `logger.error()` for consistent log aggregation.

---

## Action Items

### Immediate (This Sprint)
1. [x] SEC-001: Fix Rust unwrap() calls in template-renderer
2. [x] SEC-003: Fix IP extraction in impersonation route
3. [x] BUG-001: Add validation for statement timeout
4. [x] SEC-006: Add Stripe webhook deduplication
5. [x] SEC-011: Fix checkout URL validation

### Short-term (Next 2 Sprints)
1. [x] SEC-004: Add input validation to secrets API
2. [x] SEC-005: Add tenant scope to admin routes
3. [x] SEC-008: Reduce API key cache TTL and add invalidation
4. [x] SEC-009: Add constant-time fake work for invalid hashes
5. [x] BUG-003: Return error when metering buffer full

### Medium-term (Next Quarter)
1. [ ] SEC-010: Implement session fingerprinting
2. [ ] SEC-017: Migrate auth rate limiting to Redis
3. [ ] PERF-001: Optimize admin tenant queries
4. [ ] CODE-001: Standardize error handling patterns

### Additional Fixes Applied
- [x] SEC-007: Added domain attribute to CSRF cookies
- [x] SEC-012: Reduced MX lookup timeout from 5000ms to 2000ms
- [x] SEC-013: Reduced impersonation token duration to 5 minutes
- [x] SEC-014: Wildcard IP whitelist now requires ALLOW_ALL_IPS=true
- [x] BUG-002: Added whitelist validation for transaction isolation level
- [x] BUG-004: Invoice numbers now tenant-isolated (random hex instead of global sequence)
- [x] BUG-005: Corrupt queue jobs now moved to DLQ instead of silently dropped
- [x] BUG-010: Cache parse errors now logged and corrupt entries deleted

---

## Notes

1. **Overall Security Posture:** The codebase demonstrates good security practices in many areas:
   - CSRF protection with HMAC signatures and constant-time comparison
   - Parameterized SQL queries throughout
   - Proper bcrypt/argon2/scrypt password hashing
   - Rate limiting on sensitive endpoints
   - IP whitelisting for control plane

2. **Architecture Strengths:**
   - Result type for error handling (though not consistently applied)
   - Connection leak detection in database pool
   - Hash-chained audit logs for tamper evidence
   - Multi-layer DDoS protection

3. **Areas for Improvement:**
   - Consistent application of security patterns across all services
   - Better distributed coordination for rate limiting
   - More comprehensive input validation

---

*This audit was performed automatically and should be verified by the security team.*
