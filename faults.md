# ApexMail Fault Scan Results

> Comprehensive scan of all bugs, issues, UX faults, performance problems, and optimizations needed.
> Generated: 2026-04-29

**Legend:** 🔴 CRITICAL | 🟠 HIGH | 🟡 MEDIUM | 🔵 LOW | ⚪ INFO

---

## 🔴 Global / Cross-Cutting Issues

- [x] 🔴 **Hardcoded Secrets / Credentials** — Fixed on the live runtime/bootstrap paths. `tools/dev-start.sh` and `tools/run-compose-smoke.sh` no longer seed predictable passwords, tokens, or signing secrets; they now reuse caller-supplied values or generate fresh secret material and persist only the Docker-secret-backed files that are already ignored by `.gitignore`. The active config loaders in `services/mail-server/crates/api-server/src/config.rs`, `services/mail-server/crates/enterprise/src/config.rs`, `services/mail-server/crates/ops-service/src/config.rs`, `services/mail-server/crates/ha/src/config.rs`, `services/mail-server/crates/isolation/src/config.rs`, and `services/mail-server/crates/devex-service/src/config.rs` no longer fall back to baked development secret literals at runtime, and `services/mail-server/crates/observability-service/src/config.rs` no longer carries a placeholder DB password default. Focused validation passes with `bash -n tools/dev-start.sh tools/run-compose-smoke.sh`, `cargo test -p ops-service config && cargo test -p enterprise config && cargo test -p api-server config`, and `cargo test -p ha config && cargo test -p isolation config && cargo test -p devex-service config && cargo test -p observability-service config`. Remaining grep hits in active config/bootstrap files are validation/test sentinels or non-secret labels, not runtime secret fallbacks.
- [x] 🔴 **TODOs/FIXMEs/HACKs throughout codebase** — Stale/overstated scanner bucket for the current Rust source tree. A targeted search for live `todo!`, `unimplemented!`, and `TODO`/`FIXME`/`HACK` comment markers across `services/mail-server/crates/**/*.rs` returned no active code-path markers. The only remaining matches are `ui-foundation` tests in `services/mail-server/crates/ui-foundation/src/leptos_views.rs` and `services/mail-server/crates/ui-foundation/src/migration_tests.rs` that explicitly assert those markers are absent from rendered HTML. This row should be split into concrete defects if future scans find real unfinished runtime paths.
- [ ] 🟠 **Missing `deny_unknown_fields` on request structs** — Many API request deserialization structs lack `#[serde(deny_unknown_fields)]`, allowing silent ignore of misspelled fields that should be errors.
- [x] 🟠 **No global timeout on HTTP clients** — Stale claim. `services/mail-server/crates/apexmail-lib/src/http_client.rs` already configures both request timeout and connect timeout in the shared `reqwest::Client` builder.
- [x] 🟠 **Unsafe code audit needed** — Stale as a current fault item. A workspace-wide Rust search for `unsafe {`, `unsafe fn`, and `unsafe impl` returned no live `unsafe` blocks in `services/mail-server/crates`, so there is no current unsafe surface to audit.
- [x] 🟡 **Error response format standardized** — Fixed in `services/mail-server/crates/api-server/src/middleware/request_logger.rs`. JSON error responses are now normalized at the middleware boundary into a consistent `{"error":{"code","message","details?","requestId"}}` envelope, which also covers legacy ad hoc error bodies returned directly by handlers such as the billing routes. Revalidated with `cargo test -p api-server`.
- [x] 🟡 **Request IDs included in error responses** — Fixed in `services/mail-server/crates/api-server/src/middleware/request_logger.rs`. JSON error bodies now carry `error.requestId` in addition to the existing `X-Request-ID` response header, so support can correlate client-visible failures with server logs. Revalidated with `cargo test -p api-server`.

---

## 🏗️ Mail Server (Rust Crates)

### 🔴 CRITICAL: Crash / Panic Bugs

- [x] 🔴 **UTF-8 char boundary panic** — Fixed in `services/mail-server/crates/compliance/src/content_scanner.rs`. The scanner now truncates the blocked-pattern scan text via a UTF-8-safe helper instead of raw byte slicing, and `cargo test -p compliance test_utf8_prefix_truncates_on_char_boundary` passes.
- [x] 🔴 **Unbounded String allocation in WAF** — Stale claim as written. The current decoder in `services/mail-server/crates/waf-engine/src/decoder.rs` allocates per layer at most the current input length, and the request body path in `services/mail-server/crates/waf-engine/src/engine.rs` is already truncated to `max_body_size` before canonicalization, so the cited `%25%32%35...` expansion/OOM scenario is not reproducible from the current code.
- [x] 🔴 **Unwrap on poisoned Mutex** — Stale claim. The current `services/mail-server/crates/api-server/src/middleware/rate_limiter.rs` no longer uses a local `Mutex` at all; it is Redis-backed middleware and contains no `lock().unwrap()` path.
- [x] 🔴 **Unwrap on Redis connection failure** — Stale path. The current outbound queue crate no longer has `services/mail-server/crates/outbound-queue/src/lib.rs`, and the shipped startup path in `services/mail-server/crates/outbound-queue/src/main.rs` initializes fallibly through `Result` without the cited `RedisClient::connect().unwrap()` crash site.
- [x] 🔴 **`expect()` in hot path of MTA** — Stale path. The current `services/mail-server/crates/mta` crate no longer has `src/delivery.rs`, and the live SMTP server write paths in `src/servers/*.rs` use fallible `write_all(...).await?` instead of the cited `expect("Failed to write to TCP stream")` panic.
- [x] 🟡 **Dynamic SQL with parameterized placeholders** — Fixed in `services/mail-server/crates/apexmail-db/src/repos/messages.rs`. `MessagesRepo::batch_create()` now uses `sqlx::QueryBuilder` instead of manual placeholder assembly, and `cargo test -p apexmail-db` passes.
- [x] 🔴 **Integer overflow in billing calculations** — Stale path. The current billing-service crate no longer has `src/calculator.rs`, and the live pricing/proration arithmetic that remains in `config.rs`, `plans.rs`, and `routes.rs` already uses checked or saturating arithmetic instead of the cited raw `credits * 1000` multiplication site.

### 🟠 HIGH: Logic / Race Condition Bugs

- [x] 🟠 **TOCTOU race condition on wallet balance** — Stale claim. The cited `available_balance = row.1 - row.2` code in `services/mail-server/crates/api-server/src/routes/billing.rs` only materializes a read-only DTO from the current wallet row; it is not a spend/authorization path and cannot by itself overdraw the wallet.
- [x] 🟠 **Race condition on credit changes** — Stale path. The current credit mutation route is `admin_apply_credit()` in `services/mail-server/crates/api-server/src/routes/billing.rs`, and it updates wallet balance with a single SQL CTE (`SET balance = balance + $1` plus transaction insert) rather than the old read-then-write flow described here.
- [x] 🟠 **Advisory lock hash collision** — Fixed in `services/mail-server/crates/isolation/src/encryption.rs`. The advisory lock id is now derived from a domain-separated SHA-256 digest truncated to 63 bits instead of FNV-1a, and focused `cargo test -p isolation test_hash_code_` coverage passes.
- [x] 🟠 **Billing audit trail missing for failed transactions** — Fixed at the current control point in `services/mail-server/crates/billing-service/src/stripe_webhooks.rs`. Stripe `invoice.payment_failed` handling now appends an `audit_logs` entry in the same transaction as the dunning-state update instead of only recording dunning/notification state. Focused `cargo test -p billing-service classify_webhook_claim_` validation passes.
- [x] 🟠 **Missing `SELECT FOR UPDATE` on credit deductions** — Stale path/claim. The cited `services/mail-server/crates/billing-service/src/operations.rs` no longer exists, and the live wallet credit mutation path is `admin_apply_credit()` in `services/mail-server/crates/api-server/src/routes/billing.rs`, which applies the balance change via a single SQL CTE update instead of a split read-then-write deduction flow.
- [x] 🟠 **Suppression list not checked in batch send** — Fixed in `services/mail-server/crates/api-server/src/routes/messages.rs`. Shared message validation now performs a batched suppression lookup before queueing, so both single-send and batch-send reject suppressed recipients. Focused `cargo test -p api-server api_messages_` coverage passes.
- [x] 🟠 **No CSRF token validation** — Stale claim. The current auth middleware in `services/mail-server/crates/api-server/src/middleware/auth.rs` enforces CSRF for unsafe session-cookie requests, and `services/mail-server/crates/api-server/src/app.rs` includes route-level tests that reject logout, refresh, and change-password requests without a valid CSRF token.
- [x] 🟠 **IDOR in analytics export** — Fixed in `services/mail-server/crates/api-server/src/routes/admin/analytics_export.rs`. Non-system callers now bind `auth.tenant_id` into the export query, while the sentinel `system` tenant keeps the global admin view; focused `cargo test -p api-server build_export_query_` coverage passes.
- [x] 🟠 **Inbox route missing tenant isolation** — Fixed in `services/mail-server/crates/api-server/src/routes/admin/inbox.rs`. Non-system callers now scope inbox list/update queries by `auth.tenant_id`, while the sentinel `system` tenant keeps the global admin view. Focused admin-inbox SQL builder tests pass.

### 🟡 MEDIUM: SMTP / Protocol / Compliance

- [x] 🟡 **No HELO/EHLO validation** — Fixed in `services/mail-server/crates/mta/src/servers/inbound.rs`. The inbound SMTP parser now requires exactly one valid HELO/EHLO hostname or address literal and rejects malformed/multi-token values. Focused `cargo test -p mta parse_helo_hostname` coverage passes.
- [x] 🟡 **Missing STARTTLS support in submission port** — Stale claim. The current submission server in `services/mail-server/crates/submission/src/main.rs` and `services/mail-server/crates/submission/src/session.rs` advertises and handles `STARTTLS` when enabled.
- [x] 🟡 **PIPELINING not advertised but implemented** — Stale path/claim. The cited `services/mail-server/crates/mta/src/smtp.rs` no longer exists, and the current inbound server in `services/mail-server/crates/mta/src/servers/inbound.rs` reads commands from the buffered stream and processes them in-order, which is compatible with pipelined command delivery rather than out-of-order execution.
- [x] 🟡 **Inbound SMTP enforces PTR/FCrDNS before accepting senders** — Fixed in `services/mail-server/crates/mta/src/servers/inbound.rs`. The live inbound SMTP path now performs cached reverse DNS plus forward-confirmed reverse DNS verification for public client IPs before accepting `MAIL FROM`, and rejects sources without a confirmed PTR mapping. Local/private/link-local sources are exempt so development and internal traffic do not regress. Focused `cargo test -p mta ptr_verification` validation passes.
- [x] 🟡 **DKIM signature missing from forwarded mail** — Stale path. The current `services/mail-server/crates/mta` crate no longer contains `src/outbound.rs`, and this scanner entry does not point to a live forwarding implementation in the current MTA server surface.
- [x] 🟡 **DMARC policy not enforced** — Stale path/claim. The current enforcement path lives in `services/mail-server/crates/mta/src/auth/email_authentication.rs`, where DMARC failures map to reject/quarantine dispositions when DMARC enforcement is enabled.
- [x] 🟡 **Missing MTA-STS support** — Stale claim. The current MTA crate implements MTA-STS discovery and policy fetching in `services/mail-server/crates/mta/src/auth/mta_sts.rs`.

### 🟡 MEDIUM: Performance

- [x] 🟡 **O(n²) suppression list matching** — Fixed in `services/mail-server/crates/api-server/src/routes/messages.rs`. Suppression validation now canonicalizes recipients, batches the database lookup with `ANY($2)`, and deduplicates matches via a `HashSet` instead of linear list scanning.
- [x] 🟡 **Unbounded memory in outbound queue** — Stale claim. The current `services/mail-server/crates/outbound-queue/src/queue.rs` is database-backed, initializes a persisted `email_queue` table, and processes bounded batches via `fetch_pending(self.config.batch_size as i64)` instead of accumulating an in-memory unbounded queue.
- [x] 🟡 **Template rendering without cache** — Stale claim. The current `services/mail-server/crates/template-renderer/src/renderer.rs` already maintains a `TemplateCache` and serves cached `render_template()` results keyed by template id plus canonicalized props.
- [x] 🟡 **Serial webhook delivery** — Fixed in `services/mail-server/crates/worker-processors/src/webhook/processor.rs`. The poll loop now drives fetched webhook jobs through bounded concurrent processing instead of awaiting each delivery serially, while continuing to use the shared `reqwest::Client`. Focused `cargo test -p worker-processors ssrf` validation passes.
- [x] 🟡 **Missing connection pooling in HTTP client** — Stale claim. `services/mail-server/crates/apexmail-lib/src/http_client.rs` builds a shared `reqwest::Client` with `pool_max_idle_per_host(20)`, so keep-alive pooling is already configured.

### 🟡 MEDIUM: Code Quality / Maintainability

- [ ] 🟡 **Duplicate payment logic** — `services/mail-server/crates/billing-service/src/`: Payment processing logic duplicated in 3+ files. Extract into shared module.
- [x] 🟡 **Dead code: unused route files** — Stale claim for the current admin route surface. A current registration audit shows every `services/mail-server/crates/api-server/src/routes/admin/*.rs` route module is declared and nested from `services/mail-server/crates/api-server/src/app.rs`; no unregistered admin route files remain.
- [ ] 🟡 **Magic numbers throughout** — Hardcoded constants (e.g., `50_000` byte limit, 60-second timeouts, retry counts) not defined as named constants.
- [ ] 🟡 **Error types not implementing `std::error::Error`** — Some custom error types lack `source()` implementation, losing error chain context.
- [ ] 🟡 **Massive files exceeding 1000 lines** — Several route handler files >1500 lines. Should be split.

---

## 🔐 Security / RBAC / Auth

- [x] 🔴 **No rate limiting on login endpoint** — Stale claim. The public auth surface is wrapped by `public_rate_limit_middleware` in `services/mail-server/crates/api-server/src/app.rs`, and that middleware is explicitly documented and wired for login/register/SSO endpoints.
- [x] 🔴 **Session tokens in URL** — Fixed for the live auth-bearing URL path in `services/mail-server/crates/tracking-service/src/routes/sse.rs`. The SSE stream endpoint no longer accepts `?token=` query authentication and now requires `Authorization: Bearer <token>`. Matching issuer docs in `services/mail-server/crates/api-server/src/routes/stream_tokens.rs` were updated, and focused `cargo test -p tracking-service bearer_token && cargo test -p api-server ttl_clamping` validation passes.
- [ ] 🟠 **RBAC enforcement not centralized** — Permission checks scattered across route handlers with inconsistent patterns. Missing a `require_permission!()` macro or middleware.
- [x] 🟠 **Password strength not enforced** — Stale claim. The current auth flow in `services/mail-server/crates/api-server/src/routes/auth.rs` already enforces 12-128 characters plus uppercase, lowercase, digit, and punctuation via `validate_password_strength()`, and that helper is exercised by focused auth unit tests.
- [x] 🟠 **API key rotation not enforced** — Fixed in `services/mail-server/crates/api-server/src/routes/auth.rs`. New API keys now default to a bounded expiry window instead of being indefinite when `expires_in_days` is omitted, out-of-range lifetimes are rejected, and the auth API surfaces `expires_at`. Focused `cargo test -p api-server api_key_` coverage passes.
- [x] 🟠 **No account lockout after failed attempts** — Stale claim. `services/mail-server/crates/api-server/src/routes/auth.rs` now implements failure counting, escalating lockout durations, and lock clearing on successful authentication.
- [x] 🟠 **Session fixation vulnerability** — Stale claim. The current auth flow in `services/mail-server/crates/api-server/src/routes/auth.rs` mints a fresh JWT on login and refresh, blacklists the old token on refresh, and overwrites the `am_session` cookie instead of reusing an existing session identifier.
- [x] 🟠 **Missing Content-Security-Policy headers on API responses** — Stale claim. `services/mail-server/crates/api-server/src/app.rs` already injects a default locked-down CSP (`default-src 'none'; frame-ancestors 'none'`) for API responses in `security_headers()`, and the current app test suite includes a passing `api_json_routes_keep_the_default_locked_down_csp` regression test.
- [x] 🟠 **JWT secret may be weak/default** — Stale as written. `services/mail-server/crates/api-server/src/config.rs` requires RSA JWT key material from `JWT_PRIVATE_KEY_PEM` and `JWT_PUBLIC_KEY_PEM` instead of using a fallback shared-secret JWT default.
- [x] 🟡 **No MFA enforcement for admin accounts** — Fixed in `services/mail-server/crates/api-server/src/routes/auth.rs`. Admin and owner logins now require MFA: accounts with configured MFA must supply a valid TOTP code, and accounts without configured MFA are forced through first-time TOTP enrollment via a short-lived MFA challenge before a session is issued. Focused `cargo test -p api-server mfa` validation passes.
- [x] 🟡 **Logout does not invalidate all sessions** — Fixed in `services/mail-server/crates/api-server/src/routes/auth.rs` and `services/mail-server/crates/api-server/src/middleware/auth.rs`. Logout now records a tenant/user-scoped session revocation cutoff in Redis, and JWT auth rejects tokens whose `iat` is at or before that cutoff, so existing sessions for that user are invalidated instead of only blacklisting the current token. Focused `cargo test -p api-server revocation` validation passes.
- [x] 🟡 **No API key scope/restrictions** — Stale claim. `services/mail-server/crates/api-server/src/routes/auth.rs` accepts and persists per-key scope lists through `CreateApiKeyRequest { scopes: Vec<String> }`, so scoped/read-only API keys are supported in the current implementation.

---

## 💰 Billing

- [x] 🔴 **Integer overflow in credit math** — Stale path/claim. The cited `billing-service/src/calculator.rs` is not part of the current crate, and the live billing math already uses checked multiplication in `services/mail-server/crates/billing-service/src/config.rs` plus widened/checked proration arithmetic in `services/mail-server/crates/billing-service/src/routes.rs`.
- [x] 🔴 **No idempotency on payment processing** — Stale path/claim. The current Stripe webhook path in `services/mail-server/crates/billing-service/src/stripe_webhooks.rs` claims each `stripe_event_id` before handling and returns early for `AlreadyProcessed` / `AlreadyPending`, so duplicate Stripe deliveries are deduplicated before billing side effects run.
- [ ] 🔴 **Race condition in plan downgrade** — `billing-service/src/operations.rs:300-350`: Plan downgrade checks current usage at time of request, but usage can increase before downgrade takes effect — customer gets features cut but still charged.
- [x] 🟠 **PAYG credit calculation off by factor** — Stale path/claim. The current PAYG calculation lives in `services/mail-server/crates/billing-service/src/config.rs`, where email pricing is expressed in millicents and converted back to cents deliberately, with focused tests covering free-tier API rounding and combined totals.
- [x] 🟠 **Billing alerts for approaching limits** — Stale claim. `services/mail-server/crates/billing-service/src/maintenance.rs` already schedules `process_usage_alerts()`, reads tenant `usage_alert_configs`, evaluates threshold percentages against current usage, enforces cooldowns, and sends webhook/email notifications when customers approach configured limits.
- [x] 🟠 **Invoice generation skips zero-amount items** — Stale path/claim. The current invoice builder in `services/mail-server/crates/billing-service/src/invoices.rs` iterates every supplied line item and appends it to the stored invoice payload without any `amount == 0` skip branch, so free-tier/zero-amount items are not dropped by the live implementation.
- [x] 🟠 **Enterprise contract billing prorates partial periods** — Fixed in `services/mail-server/crates/enterprise/src/contracts.rs`. The contract usage/billing path no longer assumes synthetic 30-day months; it now builds calendar month billing periods anchored to the contract start date, clips the final partial period to the contract end date, and prorates committed volume for that clipped period instead of charging it like a full month. Focused `cargo test -p enterprise contract_billing` and `cargo test -p enterprise prorates_partial` validation passes.
- [x] 🟡 **Usage metering audit trail added** — Fixed in `services/mail-server/crates/billing-service/src/usage.rs` and `services/mail-server/crates/billing-service/src/maintenance.rs`. Metering inserts now append hash-chained audit records in the same DB transaction as the `metering_events` write, rollback deletes emit compensating audit entries, and recovered pending metering events are audited during maintenance replay, preserving a dispute trail even when the metering row is later rolled back. Revalidated with `cargo test -p billing-service`.
- [x] 🟡 **Plan-aware API rate limits enforced** — Fixed in `services/mail-server/crates/api-server/src/middleware/rate_limiter.rs`. Authenticated rate limits now resolve the tenant’s billing quota via `billing-service::plans::get_quota_for_tenant()` and derive the fixed-window cap from the existing `RateLimitTier` mapping instead of applying one global static limit to every tenant; unresolved/system tenants still fall back to the config default. Focused `cargo test -p api-server rate_limiter` validation passes.
- [x] 🟡 **Billing webhook signature verification missing** — Stale claim. `services/mail-server/crates/billing-service/src/stripe_webhooks.rs` requires the `stripe-signature` header, parses the Stripe timestamp/signature envelope, enforces a tolerance window, and verifies the HMAC-SHA256 signature before processing. The existing focused route test `stripe_webhook_route_rejects_invalid_signature_before_processing` in `services/mail-server/crates/billing-service/src/routes.rs` covers the rejection path.

---

## 🖥️ Control Plane & Admin Console

- [ ] 🟠 **Admin dashboard shows stale data** — `admin/dashboard.rs`: Uses un-cached DB queries. For orgs with 1M+ emails, dashboard load >5s.
- [x] 🟠 **No pagination on admin user listing** — Stale path/claim. `services/mail-server/crates/api-server/src/routes/admin/features.rs` serves feature flags and overrides, not an admin user-listing endpoint, so this scanner row does not map to the cited file.
- [x] 🟠 **Audit log query without date range limits** — Fixed in `services/mail-server/crates/api-server/src/routes/admin/audit.rs`. Audit log queries now always apply a bounded timestamp window, defaulting to the last 30 days and rejecting windows wider than 90 days or inverted ranges. Focused `cargo test -p api-server audit_window` validation passes.
- [x] **Admin operations audit-logged** — `routes/admin/{features,inbox,risk,gdpr,support,autopilot,sales,proxy}.rs` now emit audit records on successful mutations, matching the already-audited `secrets`, `tenants`, and `warmup` handlers. Revalidated with `cargo test -p api-server`.
- [ ] 🟡 **No confirmation on destructive admin actions** — Delete org/user actions don't require secondary confirmation (e.g., typing "DELETE").
- [x] 🟡 **Calendar route: potential XSS** — Stale as written. `services/mail-server/crates/api-server/src/routes/admin/calendar.rs` returns calendar data as JSON; it does not render HTML in the API layer, so title escaping is a frontend rendering concern rather than an XSS flaw in this route itself.
- [ ] 🟡 **GDPR export missing data categories** — `admin/gdpr.rs`: Export doesn't include all PII categories required by GDPR (e.g., IP logs, email content).

---

## 👤 User Console / UX

- [ ] 🟠 **Error messages expose internal details** — Error responses include file paths, SQL queries, and stack traces in some error modes — information disclosure risk.
- [ ] 🟠 **No loading states on data tables** — UI doesn't show skeleton loaders or progress indicators during API calls.
- [ ] 🟠 **Form validation is client-side only** — Forms validate input only in browser — bypass curl can submit invalid data.
- [ ] 🟠 **No confirmation on irreversible actions** — Delete campaign/contact list actions lack "Are you sure?" confirmation.
- [ ] 🟠 **Pagination state lost on navigation** — Current page resets to 1 when navigating away and back.
- [x] 🟡 **Password change requires current password** — Stale claim. `services/mail-server/crates/api-server/src/routes/auth.rs` verifies `current_password` against the stored hash before updating the password and rejects invalid current passwords.
- [ ] 🟡 **Session timeout not configurable** — Session expiry is hardcoded (likely 24h). No "remember me" option.
- [ ] 🟡 **No bulk select operations on contact lists** — Can't select multiple contacts for batch operations.
- [ ] 🟡 **Search/filter debounce missing** — No debounce on search inputs, causing API call on every keystroke.
- [ ] 🟡 **No keyboard shortcuts** — Power users cannot navigate via keyboard (common in email platforms).
- [ ] 🟡 **Campaign builder missing auto-save** — Unsaved work lost on accidental navigation.
- [ ] 🟡 **No dark mode** — Missing theme toggle.
- [ ] 🟡 **Mobile responsive issues** — Check if tables/forms render properly on mobile viewports.
- [ ] 🟡 **Focus trap in modals** — Tab navigation in modals may not properly trap focus for accessibility.

---

## 🌐 Web (Marketing / Zola Site)

- [ ] 🟠 **Pricing page mismatch with code** — `apps/marketing-zola/content/pricing.md`: Listed prices may not match configured rates in billing-service.
- [ ] 🟠 **No canonical URLs** — SEO issue: pages accessible via multiple URLs without canonical tags.
- [ ] 🟠 **Missing meta descriptions** — Several pages lack meta description tags, hurting SEO.
- [ ] 🟠 **No schema.org markup** — Missing structured data (Product, SoftwareApplication, Organization schemas).
- [ ] 🟡 **Broken links check needed** — Verify all internal and external links resolve correctly.
- [ ] 🟡 **Missing 404 page** — No custom 404 page.
- [ ] 🟡 **No sitemap.xml** — Missing XML sitemap for search engines.
- [ ] 🟡 **CTA buttons lack urgency** — Marketing copy CTAs ("Sign Up", "Get Started") lack compelling language.
- [ ] 🟡 **No social sharing meta tags** — Missing Open Graph and Twitter Card meta tags.
- [ ] 🟡 **Accessibility: missing alt text on images** — Check all images for descriptive alt text.
- [ ] 🟡 **Color contrast issues** — Verify WCAG AA compliance for text/background contrast.
- [ ] 🟡 **No cookie consent banner** — GDPR cookie consent notice missing.
- [ ] 🟡 **Font loading blocks rendering** — Custom fonts may cause FOUT/FOIT.

---

## 🤖 AI Pipeline

- [ ] 🟠 **Training data leakage between tenants** — `ai-service/src/training.rs:50`: Training data loader doesn't filter by tenant_id — cross-tenant data contamination.
- [ ] 🟠 **Inference endpoint not rate-limited** — `ai-service/src/routes.rs:30`: AI inference endpoint accessible without rate limiting — allow abuse.
- [ ] 🟠 **Model poisoning possible via training endpoint** — No validation on submitted training data quality.
- [ ] 🟡 **Embeddings stored without tenant isolation** — `ai-embeddings/src/vector_store.rs:45`: Vector DB queries not filtered by tenant — one org can search another's embeddings.
- [ ] 🟡 **AI service config hardcoded** — `ai-service/src/config.rs`: Model paths, API endpoints hardcoded instead of configurable.
- [ ] 🟡 **Training data format validation missing** — JSONL data files not validated before ingestion — malformed records crash pipeline.
- [ ] 🟡 **Chunker splits mid-word for non-English** — `ai-embeddings/src/chunker.rs:30`: Tokenizer splits at byte boundary, breaking CJK/emoji text.
- [ ] 🟡 **No model versioning in storage** — AI models stored without version metadata — rollback impossible.
- [ ] 🟡 **Bandit algorithm not persisted** — `ai-service/src/bandits.rs`: Contextual bandit state in memory only — lost on restart.

---

## 📦 SDKs

- [ ] 🟡 **SDK retry logic missing exponential backoff** — `packages/sdk-python/apexmail/client.py`: Retries use fixed delay, causing thundering herd on recovery.
- [ ] 🟡 **SDK timeout too short/long** — Verify SDK timeout values are appropriate for email API latency.
- [ ] 🟡 **Missing user-agent header in SDK HTTP clients** — API cannot identify SDK callers for analytics.
- [ ] 🔵 **Java SDK uses deprecated HTTP client** — `packages/sdk-java/`: Uses `HttpURLConnection` instead of `HttpClient` (Java 11+).
- [ ] 🔵 **PHP SDK no type hints** — Missing PHP type declarations for IDE autocomplete.
- [ ] 🔵 **Ruby SDK missing gem specification** — `packages/sdk-ruby/`: Missing `gemspec` file or incomplete `Gemfile`.
- [ ] 🔵 **Go SDK context not propagated** — `packages/sdk-go/client.go`: HTTP calls don't accept `context.Context` for cancellation/timeouts.
- [ ] 🔵 **SDK READMEs inconsistent** — Installation and usage instructions differ across SDK packages.

---

## 🦞 Lobster (Game Engine)

- [ ] 🟡 **FIXME: type coercion bug** — `Lobster/modules/gui.lobster:317`: Force-casts "selected" to int because enum assign fails — type system issue.
- [ ] 🟡 **FIXME: texture placement** — `Lobster/modules/texture.lobster:37`: "put this in a place and know it'll be drawn last" — drawing order issue.
- [ ] 🟡 **TODO: navigation mesh performance** — `Lobster/modules/navmap.lobster:12`: Blocked Q could be more efficient.
- [ ] 🟡 **FIXME: GUI cleanup** — `Lobster/modules/gui.lobster:205`: Cleanup needed on position(size) function.
- [ ] 🔵 **Calc game minor: no input validation** — `Lobster/main.lob`: Doesn't validate all edge cases on button input.

---

## 🚀 Deployment & DevOps

### NGINX (deploy/nginx/nginx.conf)

- [ ] 🔴 **Missing ssl_dhparam** — Line 48: No DH params file configured, weakening forward secrecy to 1024-bit default.
- [ ] 🟠 **No HSTS on HTTP redirect** — Port 80 doesn't send `Strict-Transport-Security`, vulnerable to SSL-strip on first visit.
- [ ] 🟠 **Restrictive CSP on tracking server breaks functionality** — Lines 226-274: CSP `default-src 'none'` blocks tracking pixel images/redirects.
- [ ] 🟠 **Missing X-Content-Type-Options: nosniff** — MIME-sniffing prevention header missing on some blocks.
- [ ] 🟠 **No Referrer-Policy header** — Information leakage via referrer header on outbound links.
- [ ] 🟠 **Missing Permissions-Policy header** — No browser feature restrictions.
- [ ] 🟠 **TLS versions not restricted** — No `ssl_protocols TLSv1.2 TLSv1.3` — may accept older insecure versions.
- [ ] 🟠 **No ciphersuite restriction** — Missing `ssl_ciphers` directive — uses OpenSSL defaults which may include weak ciphers.
- [ ] 🟡 **Proxy buffer sizes too small** — May truncate large API responses or headers.
- [ ] 🟡 **Missing rate limiting on API routes** — No `limit_req` zones configured for API paths.
- [ ] 🟡 **Missing upstream health checks** — No active health checks on upstream servers.
- [ ] 🟡 **Large client_body_size may allow abuse** — No limit or very large limit on request body size.

### Docker & Compose

- [ ] 🟠 **No resource limits in docker-compose.yml** — Containers lack memory/cpu limits, one service can starve others.
- [ ] 🟠 **No restart policies** — Missing `restart: always`/`unless-stopped` on critical services.
- [ ] 🟠 **ClickHouse exposed to host** — No port binding restriction (binds to 0.0.0.0:8123).
- [ ] 🟠 **Redis without password** — Default Redis config with no `requirepass`, accessible from any container.
- [ ] 🟡 **No healthchecks in docker-compose** — Missing `healthcheck` blocks for service dependency ordering.
- [ ] 🟡 **Secrets exposed via environment variables** — `docker-compose.yml` may pass secrets via env vars (visible in `docker inspect`).
- [ ] 🟡 **No network isolation** — All services on same Docker network, no segmentation between public and internal services.

### Kubernetes (deploy/k8s/)

- [ ] 🟠 **Pods running as root** — Check `securityContext: runAsNonRoot: true` — missing on all pods.
- [ ] 🟠 **No resource requests/limits** — Missing `resources.requests` and `resources.limits` on all containers.
- [ ] 🟠 **Readiness/liveness probes missing** — No startup, liveness, or readiness probes on any deployment.
- [ ] 🟠 **No PodDisruptionBudget** — Critical services lack PDB, can all go down during node maintenance.
- [ ] 🟠 **Secrets in template not encrypted** — `secrets.template.yaml`: Contains placeholder values but no encryption (should use SealedSecrets or External Secrets Operator).
- [ ] 🟠 **No NetworkPolicies** — No network policy to restrict pod-to-pod traffic.
- [ ] 🟠 **No PodSecurityPolicy/PSA** — No pod security admission controls.
- [ ] 🟡 **No HorizontalPodAutoscaler** — Services lack autoscaling configuration.
- [ ] 🟡 **No affinity/anti-affinity rules** — Pods can all be scheduled on same node — single point of failure.
- [ ] 🟡 **ConfigMap may contain secrets** — Plaintext config values in ConfigMap instead of using Secrets.
- [ ] 🟡 **No topology spread constraints** — Pods not distributed across zones.

### Monitoring & Observability

- [ ] 🟠 **No alert on mail queue backlog** — `deploy/alerting-rules.yml`: Missing alert for outbound queue depth > threshold.
- [ ] 🟠 **No alert on billing failures** — Missing alert for payment processing errors.
- [ ] 🟠 **Prometheus retention not configured** — Default retention (15d) may be insufficient for compliance.
- [ ] 🟠 **No dashboard configs provided** — No Grafana dashboard JSON definitions in repo.
- [ ] 🟠 **Alertmanager not configured for production PagerDuty/OpsGenie** — Only email notifications configured.
- [ ] 🟡 **Blackbox exporter missing TLS checks** — SSL certificate expiry monitoring not configured.
- [ ] 🟡 **No synthetic transaction monitoring** — No browser-level health check for user-facing endpoints.
- [ ] 🟡 **Distributed tracing not integrated** — No Jaeger/Zipkin config — can't trace requests across services.
- [ ] 🟡 **Log aggregation not configured** — No centralized log shipping (e.g., Loki, ELK).

---

## 📄 Documentation & API Specs

### OpenAPI Spec (docs/api/openapi.yaml)

- [ ] 🔴 **Missing `DELETE /v1/webhooks/{id}`** — Documented in webhooks.md but not in OpenAPI spec (line ~700).
- [ ] 🟠 **Inconsistent error codes** — `RATE_LIMIT_EXCEEDED` in spec vs `TOO_MANY_REQUESTS` in errors.md (line ~560).
- [ ] 🟠 **Batch message schema allows contradictory fields** — `template_id` and `inline_only` both accepted when they should be mutually exclusive (`oneOf`).
- [ ] 🟠 **Missing 429 response on many endpoints** — Most endpoints lack documented rate limit error response.
- [ ] 🟠 **Missing 401/403 responses** — Many endpoints don't document auth failure responses.
- [ ] 🟠 **Webhook signatures not documented** — How to verify webhook signatures missing from spec and webhooks.md.
- [ ] 🟠 **Pagination parameters not standardized** — Some endpoints use `?page=1&per_page=50`, others use `?offset=0&limit=50`.
- [ ] 🟡 **Missing `PATCH` operations** — Some resources have `PUT` but missing `PATCH` for partial updates.
- [ ] 🟡 **Rate limit headers documented differently than implemented** — Spec says `X-RateLimit-Remaining` but actual implementation may differ.

### Architecture Docs

- [ ] 🟠 **Data-flow.md: Outdated diagram** — Architecture diagram doesn't include tracking service or AI pipeline.
- [ ] 🟠 **Hybrid infrastructure docs contradict code** — Docs describe SES-primary delivery but code shows alternate providers.
- [ ] 🟠 **ADR 0001 (Database choice) possibly outdated** — Mentions PostgreSQL but code uses ClickHouse for analytics — inconsistency.
- [ ] 🟠 **Pricing.md: Math errors or stale prices** — Verify all listed prices match billing-service configuration.
- [ ] 🟡 **Missing SSO documentation** — Enterprise SSO setup not documented despite being implemented.
- [ ] 🟡 **API route audit report incomplete** — `api-route-audit-report.md`: Missing several recently added routes.

---

## 🛠️ Tools / Scripts

- [ ] 🔴 **`bootstrap.sh`: Hardcoded credentials** — `tools/bootstrap.sh`: May contain hardcoded test credentials or API keys.
- [ ] 🟠 **`fix_*.py` scripts may have side effects** — Multiple fix scripts (`fix_all_errors.py`, `fix_v4.py`, etc.) modify source code programmatically. Non-idempotent — running twice may corrupt files.
- [x] 🟠 **`dev-start.sh` hardened for shell failures** — Fixed in `tools/dev-start.sh`. The script now runs with `set -euo pipefail`, so failed commands, unset variables, and pipeline failures stop startup instead of leaving partial local state. Syntax revalidated with `bash -n tools/dev-start.sh tools/poll_instance.sh`.
- [x] 🟠 **`poll_instance.sh` infinite loop risk** — Stale claim. `tools/poll_instance.sh` already bounds polling with `VAST_MAX_POLL_ATTEMPTS` (default `60`) and exits non-zero once the maximum attempts are exhausted instead of looping forever.
- [ ] 🟠 **Python audit scripts use `eval()`** — `tools/audit_features.py:155`: `eval()` on user-influenced input — code injection risk.
- [ ] 🟠 **Migration scripts not in transactions** — `tools/migrations/`: SQL migration files may not be wrapped in transactions — partial migration breaks DB state.
- [ ] 🟠 **`load-secret-env.sh` exposes secrets** — `deploy/load-secret-env.sh`: Sources env file that may contain secrets — visible in `ps aux`.
- [ ] 🟡 **`check-forbidden-patterns.sh` too restrictive** — May flag legitimate patterns, causing developer frustration.
- [ ] 🟡 **`run-mail-server-tests.sh` no test selection** — Runs full suite, no option for targeted test execution.
- [ ] 🟡 **`checksums.sha256` may be stale** — SHA256 checksums may not match current files.
- [ ] 🟡 **`browser_smoke.py` no retries** — Single attempt fails flaky test — should retry.
- [ ] 🟡 **Python scripts use `print()` instead of logging** — No proper logging configuration — output goes to stderr/stdout without levels.
- [ ] 🟡 **`generate_bigfix.py`: Generated code quality** — Auto-generated fix code may not follow project conventions.

---

## 🧪 Testing

- [ ] 🟠 **No tests for billing race conditions** — Critical concurrent billing scenarios untested.
- [ ] 🟠 **MTA integration tests mock external services** — Tests mock remote MTAs — don't verify actual SMTP protocol compliance.
- [ ] 🟠 **Load tests not representative** — `load-tests/`: May not simulate realistic email workload patterns.
- [ ] 🟠 **Fuzz tests limited coverage** — `fuzz-tests/`: Only test specific paths, not the full request lifecycle.
- [ ] 🟠 **Smoke tests don't verify cleanup** — `smoke-tests/`: Test data may persist after test run, polluting DB.
- [ ] 🟠 **Schema contract tests incomplete** — `integration-tests/tests/schema_contract_tests.rs`: Missing tests for newly added endpoints.
- [ ] 🟡 **No property-based testing** — Critical business logic (billing, rate limiting) not tested with property-based frameworks like `proptest`.
- [ ] 🟡 **No mutation testing integration** — Despite `mutants.toml` config, no CI step for mutation testing.
- [ ] 🟡 **Functional tests duplicated** — `functional-tests/` and `integration-tests/` may overlap in coverage.
- [ ] 🟡 **Test flakiness from shared state** — Tests may share DB state, causing order-dependent failures.
- [ ] 🟡 **No performance regression benchmarks** — No benchmark comparisons in CI to detect performance regressions.

---

## 📊 Data / Migrations / SQL

- [ ] 🟠 **Migration 001 creates tables without IF NOT EXISTS** — `migrations/001_initial_schema.sql`: May fail on re-run.
- [ ] 🟠 **Missing down migrations** — No rollback/reverse migrations defined.
- [ ] 🟠 **Golden QA data may contain PII** — `data/golden_qa.jsonl`: Check for real user data in test fixtures.
- [ ] 🟠 **Training data not sanitized** — `data/train.jsonl`: May contain real emails with PII — compliance risk.
- [ ] 🟡 **No FOREIGN KEY on some tables** — Referential integrity not enforced in schema.
- [ ] 🟡 **Missing indexes on high-query columns** — Check `EXPLAIN ANALYZE` for missing indexes on `tenant_id`, `created_at`, `email`.
- [ ] 🟡 **No created_at/updated_at on some tables** — Audit trail incomplete — some tables missing timestamp columns.
- [ ] 🟡 **Migration scripts not ordered chronologically** — Gap: no migration 004-019 after 003.

---

## 🎯 Performance Optimization Opportunities

- [ ] 🟠 **Database connection pool too small** — Check `pool.rs` for pool size — may be too small for concurrent request volume.
- [ ] 🟠 **No response compression** — API responses not gzip/brotli compressed — increases bandwidth.
- [ ] 🟠 **No CDN for static assets** — Marketing site and console assets served directly, no CDN.
- [ ] 🟠 **Session store in DB** — Sessions stored in PostgreSQL — should use Redis for speed.
- [ ] 🟡 **No database query caching** — Frequent read queries (templates, domains) not cached.
- [ ] 🟡 **N+1 query patterns** — Check for loops making individual DB queries instead of batched queries.
- [ ] 🟡 **Missing Redis pipeline for batch operations** — Redis operations done individually, not pipelined.
- [ ] 🟡 **No prepared statement caching** — SQL queries reparsed on every execution.
- [ ] 🟡 **Serial processing in worker-processors** — Event processing should be parallelized per shard/partition.
- [ ] 🟡 **Large JSON payloads parsed repeatedly** — Email content parsed multiple times through different processors.

---

## ⚪ INFO / Recommendations

- [ ] ⚪ **Add contribution guidelines (CONTRIBUTING.md)** — Missing developer contribution guide.
- [ ] ⚪ **Add CHANGELOG.md** — No changelog file for release tracking.
- [ ] ⚪ **Add CODEOWNERS file** — PR review assignment via GitHub CODEOWNERS missing.
- [ ] ⚪ **Add Dependabot/config for dependency updates** — No automated dependency update configuration.
- [ ] ⚪ **Add editorconfig for consistent formatting** — Missing `.editorconfig`.
- [ ] ⚪ **Add pre-commit hooks** — No git hooks for linting/formatting before commit.
- [ ] ⚪ **Snyk/Dependabot alerts not configured** — No vulnerability scanning on dependencies.
- [ ] ⚪ **Semantic versioning not applied** — No version file or release strategy documented.

---

> **Note:** This fault list was generated by automated analysis of the codebase. Each item should be manually verified and prioritized. Items marked 🔴 CRITICAL could cause crashes, data loss, security vulnerabilities, or financial errors and should be addressed immediately.
