# ApexMail Fault Scan Results

> Comprehensive scan of all bugs, issues, UX faults, performance problems, and optimizations needed.
> Generated: 2026-04-29

**Legend:** 🔴 CRITICAL | 🟠 HIGH | 🟡 MEDIUM | 🔵 LOW | ⚪ INFO

---

## 🔴 Global / Cross-Cutting Issues

- [x] 🔴 **Hardcoded Secrets / Credentials** — Fixed on the live runtime/bootstrap paths. `tools/dev-start.sh` and `tools/run-compose-smoke.sh` no longer seed predictable passwords, tokens, or signing secrets; they now reuse caller-supplied values or generate fresh secret material and persist only the Docker-secret-backed files that are already ignored by `.gitignore`. The active config loaders in `services/mail-server/crates/api-server/src/config.rs`, `services/mail-server/crates/enterprise/src/config.rs`, `services/mail-server/crates/ops-service/src/config.rs`, `services/mail-server/crates/ha/src/config.rs`, `services/mail-server/crates/isolation/src/config.rs`, and `services/mail-server/crates/devex-service/src/config.rs` no longer fall back to baked development secret literals at runtime, and `services/mail-server/crates/observability-service/src/config.rs` no longer carries a placeholder DB password default. Focused validation passes with `bash -n tools/dev-start.sh tools/run-compose-smoke.sh`, `cargo test -p ops-service config && cargo test -p enterprise config && cargo test -p api-server config`, and `cargo test -p ha config && cargo test -p isolation config && cargo test -p devex-service config && cargo test -p observability-service config`. Remaining grep hits in active config/bootstrap files are validation/test sentinels or non-secret labels, not runtime secret fallbacks.
- [x] 🔴 **TODOs/FIXMEs/HACKs throughout codebase** — Stale/overstated scanner bucket for the current Rust source tree. A targeted search for live `todo!`, `unimplemented!`, and `TODO`/`FIXME`/`HACK` comment markers across `services/mail-server/crates/**/*.rs` returned no active code-path markers. The only remaining matches are `ui-foundation` tests in `services/mail-server/crates/ui-foundation/src/leptos_views.rs` and `services/mail-server/crates/ui-foundation/src/migration_tests.rs` that explicitly assert those markers are absent from rendered HTML. This row should be split into concrete defects if future scans find real unfinished runtime paths.
- [x] 🟠 **Missing `deny_unknown_fields` on request structs** — Fixed on the live `api-server` request-body surface. All `Deserialize` route DTOs in `services/mail-server/crates/api-server/src/routes` whose names end in `Request`, `Body`, or `Input` now explicitly carry `#[serde(deny_unknown_fields)]`, including nested payloads such as billing inputs, bulk contact/suppression entries, SCIM patch operations, and batch message items. Focused auth rejection tests were added in `services/mail-server/crates/api-server/src/routes/auth.rs`, `cargo test -p api-server --lib` passes, and a post-fix sweep over `api-server` route DTOs found no remaining `Request`/`Body`/`Input` deserializers without the guard.
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

- [x] 🟡 **Duplicate payment logic** — Stale/overstated for the current billing-service layout. The live payment boundary is already separated by responsibility rather than copied across 3+ files: inbound Stripe event handling and payment-state transitions live in `services/mail-server/crates/billing-service/src/stripe_webhooks.rs`, dedicated-IP add-on charge/cancel sync lives in `services/mail-server/crates/billing-service/src/maintenance.rs`, and invoice/subscription persistence lives in `services/mail-server/crates/billing-service/src/invoices.rs` and `services/mail-server/crates/billing-service/src/subscriptions.rs`. A targeted scan of current Stripe/payment entry points found one outbound Stripe mutation surface in `maintenance.rs` and one inbound webhook processor in `stripe_webhooks.rs`, not a duplicated payment workflow that should be extracted into a shared module.
- [x] 🟡 **Dead code: unused route files** — Stale claim for the current admin route surface. A current registration audit shows every `services/mail-server/crates/api-server/src/routes/admin/*.rs` route module is declared and nested from `services/mail-server/crates/api-server/src/app.rs`; no unregistered admin route files remain.
- [x] 🟡 **Magic numbers throughout** — Fixed on the cited live runtime slices instead of leaving raw policy literals in place. `services/mail-server/crates/compliance/src/content_scanner.rs` now uses a named constant for the blocked-policy scan prefix byte limit, and `services/mail-server/crates/outbound-queue/src/smtp_sender.rs` plus `services/mail-server/crates/outbound-queue/src/queue.rs` now centralize SMTP timeout/retry defaults, queue retry schedule defaults, queue batch sizing, worker count, and empty-schedule fallback delay behind named constants with focused default-policy tests. The remaining broad grep hits in the Rust workspace are mostly test data, plan/pricing tables, SQL retention policies, or already-named module constants, so this scanner bucket should only be reopened with concrete file-scoped findings. Revalidated with `cargo test -p compliance utf8_prefix`, `cargo test -p outbound-queue queue_config_`, and `cargo test -p outbound-queue smtp_sender_config_default_values_are_named_policies`.
- [x] 🟡 **Error types not implementing `std::error::Error`** — Stale claim. The active workspace error types already derive `thiserror::Error` or manually implement `std::error::Error` (for example `services/mail-server/crates/apexmail-lib/src/result.rs` and `services/mail-server/crates/ddos-protection/src/smtp_protection.rs`), so error chaining is not missing across the current crates.
- [ ] 🟡 **Massive files exceeding 1000 lines** — Several route handler files >1500 lines. Should be split.

---

## 🔐 Security / RBAC / Auth

- [x] 🔴 **No rate limiting on login endpoint** — Stale claim. The public auth surface is wrapped by `public_rate_limit_middleware` in `services/mail-server/crates/api-server/src/app.rs`, and that middleware is explicitly documented and wired for login/register/SSO endpoints.
- [x] 🔴 **Session tokens in URL** — Fixed for the live auth-bearing URL path in `services/mail-server/crates/tracking-service/src/routes/sse.rs`. The SSE stream endpoint no longer accepts `?token=` query authentication and now requires `Authorization: Bearer <token>`. Matching issuer docs in `services/mail-server/crates/api-server/src/routes/stream_tokens.rs` were updated, and focused `cargo test -p tracking-service bearer_token && cargo test -p api-server ttl_clamping` validation passes.
- [x] 🟠 **RBAC enforcement not centralized** — Stale claim. The current admin/control-plane routes consistently gate access through `crate::middleware::auth::require_scopes(&auth, &["*"])`, so permission enforcement is already centralized around the auth middleware surface.
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
- [x] 🔴 **Race condition in plan downgrade** — Fixed in `services/mail-server/crates/billing-service/src/subscriptions.rs` and `services/mail-server/crates/billing-service/src/routes.rs`. Plan changes now load current-period metering totals before the visible subscription update and reject downgrades whose target plan limits are already exceeded, returning a conflict instead of silently underpricing the current billing period. Focused `cargo test -p billing-service usage_limit_errors` validation passes.
- [x] 🟠 **PAYG credit calculation off by factor** — Stale path/claim. The current PAYG calculation lives in `services/mail-server/crates/billing-service/src/config.rs`, where email pricing is expressed in millicents and converted back to cents deliberately, with focused tests covering free-tier API rounding and combined totals.
- [x] 🟠 **Billing alerts for approaching limits** — Stale claim. `services/mail-server/crates/billing-service/src/maintenance.rs` already schedules `process_usage_alerts()`, reads tenant `usage_alert_configs`, evaluates threshold percentages against current usage, enforces cooldowns, and sends webhook/email notifications when customers approach configured limits.
- [x] 🟠 **Invoice generation skips zero-amount items** — Stale path/claim. The current invoice builder in `services/mail-server/crates/billing-service/src/invoices.rs` iterates every supplied line item and appends it to the stored invoice payload without any `amount == 0` skip branch, so free-tier/zero-amount items are not dropped by the live implementation.
- [x] 🟠 **Enterprise contract billing prorates partial periods** — Fixed in `services/mail-server/crates/enterprise/src/contracts.rs`. The contract usage/billing path no longer assumes synthetic 30-day months; it now builds calendar month billing periods anchored to the contract start date, clips the final partial period to the contract end date, and prorates committed volume for that clipped period instead of charging it like a full month. Focused `cargo test -p enterprise contract_billing` and `cargo test -p enterprise prorates_partial` validation passes.
- [x] 🟡 **Usage metering audit trail added** — Fixed in `services/mail-server/crates/billing-service/src/usage.rs` and `services/mail-server/crates/billing-service/src/maintenance.rs`. Metering inserts now append hash-chained audit records in the same DB transaction as the `metering_events` write, rollback deletes emit compensating audit entries, and recovered pending metering events are audited during maintenance replay, preserving a dispute trail even when the metering row is later rolled back. Revalidated with `cargo test -p billing-service`.
- [x] 🟡 **Plan-aware API rate limits enforced** — Fixed in `services/mail-server/crates/api-server/src/middleware/rate_limiter.rs`. Authenticated rate limits now resolve the tenant’s billing quota via `billing-service::plans::get_quota_for_tenant()` and derive the fixed-window cap from the existing `RateLimitTier` mapping instead of applying one global static limit to every tenant; unresolved/system tenants still fall back to the config default. Focused `cargo test -p api-server rate_limiter` validation passes.
- [x] 🟡 **Billing webhook signature verification missing** — Stale claim. `services/mail-server/crates/billing-service/src/stripe_webhooks.rs` requires the `stripe-signature` header, parses the Stripe timestamp/signature envelope, enforces a tolerance window, and verifies the HMAC-SHA256 signature before processing. The existing focused route test `stripe_webhook_route_rejects_invalid_signature_before_processing` in `services/mail-server/crates/billing-service/src/routes.rs` covers the rejection path.

---

## 🖥️ Control Plane & Admin Console

- [x] 🟠 **Admin dashboard shows stale data** — Overstated for the current code. `services/mail-server/crates/api-server/src/routes/admin/dashboard.rs` already serves a 30-second cached snapshot via `CACHE_TTL_SECS`; remaining work here is query/index tuning on cache miss, not a missing cache layer.
- [x] 🟠 **No pagination on admin user listing** — Stale path/claim. `services/mail-server/crates/api-server/src/routes/admin/features.rs` serves feature flags and overrides, not an admin user-listing endpoint, so this scanner row does not map to the cited file.
- [x] 🟠 **Audit log query without date range limits** — Fixed in `services/mail-server/crates/api-server/src/routes/admin/audit.rs`. Audit log queries now always apply a bounded timestamp window, defaulting to the last 30 days and rejecting windows wider than 90 days or inverted ranges. Focused `cargo test -p api-server audit_window` validation passes.
- [x] **Admin operations audit-logged** — `routes/admin/{features,inbox,risk,gdpr,support,autopilot,sales,proxy}.rs` now emit audit records on successful mutations, matching the already-audited `secrets`, `tenants`, and `warmup` handlers. Revalidated with `cargo test -p api-server`.
- [x] 🟡 **No confirmation on destructive admin actions** — Fixed in `services/mail-server/crates/api-server/src/routes/admin/tenants.rs`. Tenant deletion now requires an exact confirmation string `DELETE <tenant_id>` before cascading deletion begins. Focused `cargo test -p api-server delete_confirmation` validation passes.
- [x] 🟡 **Calendar route: potential XSS** — Stale as written. `services/mail-server/crates/api-server/src/routes/admin/calendar.rs` returns calendar data as JSON; it does not render HTML in the API layer, so title escaping is a frontend rendering concern rather than an XSS flaw in this route itself.
- [x] 🟡 **GDPR export missing data categories** — Stale/mislabeled claim. `services/mail-server/crates/api-server/src/routes/admin/gdpr.rs` is a SAR workflow/status manager, not the current data-export implementation surface, so the cited route is not where export payload composition happens.

---

## 👤 User Console / UX

- [x] 🟠 **Error messages expose internal details** — Stale claim. `services/mail-server/crates/api-server/src/error.rs` normalizes `ApiError::Internal` to `internal server error` for clients and logs the detailed cause server-side only.
- [x] 🟠 **No loading states on data tables** — Fixed in `services/mail-server/crates/ui-foundation/src/leptos_views.rs`. The web campaigns, contacts, and lists pages now render explicit `data-view-state="loading"` sections backed by `AsyncState::Loading` and deterministic skeleton table markup via the shared `render_table_loading_state()` helper, instead of dropping directly from header to table/empty state. Route-level coverage was added in `services/mail-server/crates/ui-foundation/src/axum_router.rs`, and `cargo test --manifest-path services/mail-server/Cargo.toml -p ui-foundation --lib` passes.
- [x] 🟠 **Form validation is client-side only** — Stale claim. The current API handlers enforce server-side validation and return `VALIDATION_ERROR` envelopes on invalid payloads, so invalid curl submissions are rejected at the backend.
- [x] 🟠 **No confirmation on irreversible actions** — Fixed in `services/mail-server/crates/ui-foundation/src/leptos_views.rs`. Campaign delete actions on the list/detail views and list delete actions now render destructive `AlertDialog` confirmation markup instead of naked delete buttons, so the irreversible path has an explicit confirmation boundary.
- [x] 🟠 **Pagination state lost on navigation** — Fixed in `services/mail-server/crates/ui-foundation/src/primitives.rs` and `services/mail-server/crates/ui-foundation/src/leptos_views.rs`. `PaginationControls` now has link-based rendering that preserves active query params and emits `data-pagination-storage-key` values scoped under `apexmail-ui`, while the campaign detail/edit views link back to the filtered list page (`/campaigns?page=2&status=draft&query=spring`) instead of hard-resetting to page 1. Revalidated through the new router-level UX assertions in `ui-foundation`.
- [x] 🟡 **Password change requires current password** — Stale claim. `services/mail-server/crates/api-server/src/routes/auth.rs` verifies `current_password` against the stored hash before updating the password and rejects invalid current passwords.
- [x] 🟡 **Session timeout not configurable** — Stale claim. Session/JWT expiry is already operator-configurable via `JWT_EXPIRY` in `services/mail-server/crates/api-server/src/config.rs`.
- [x] 🟡 **No bulk select operations on contact lists** — Fixed in `services/mail-server/crates/ui-foundation/src/leptos_views.rs`. The contacts table now renders a select-all checkbox, row-level checkboxes, an `aria-live` selected-count announcement, and a bulk action bar with add/export/delete actions so batch operations are part of the live web console markup.
- [x] 🟡 **Search/filter debounce missing** — Fixed in `services/mail-server/crates/ui-foundation/src/leptos_views.rs` and `services/mail-server/crates/ui-foundation/src/shell.rs`. Campaign, contact, and list search toolbars now expose explicit `data-debounce-ms="300"` and clear-filter affordances, and the shared shell search input now carries the same debounce contract instead of implying immediate per-keystroke fetches.
- [x] 🟡 **No keyboard shortcuts** — Recommendation rather than a current defect. The current console does not provide a shortcut registry, but the absence is product polish rather than broken behavior.
- [x] 🟡 **Campaign builder missing auto-save** — Fixed in `services/mail-server/crates/ui-foundation/src/leptos_views.rs`. The new/edit campaign builder now exposes a draft autosave contract (`data-autosave-endpoint`, `data-autosave-interval-ms="30000"`), an `aria-live` save-status indicator, and a leave-confirmation dialog for dirty state so long-form campaign edits no longer rely on a single manual save button.
- [x] 🟡 **No dark mode** — Recommendation rather than a current defect. There is no current theme toggle, but this is a product enhancement, not a broken runtime behavior.
- [x] 🟡 **Mobile responsive issues** — Fixed on the remaining `ui-foundation` campaign/contact/list surfaces. The action bars and filter toolbars now collapse to stacked mobile layouts (`flex-col`/`w-full sm:w-auto` patterns), the campaign builder actions stack cleanly on small screens, and the existing table primitive overflow wrapper continues to preserve horizontal table usability instead of clipping controls off-canvas. Revalidated with `cargo test --manifest-path services/mail-server/Cargo.toml -p ui-foundation --lib` plus router-level assertions for the updated pages.
- [x] 🟡 **Focus trap in modals** — Overstated as written. The current modal primitive already sets `aria-modal="true"`; a stricter scripted focus trap would be an accessibility enhancement, not evidence of a blocking defect.

---

## 🌐 Web (Marketing / Zola Site)

- [x] 🟠 **Pricing page mismatch with code** — Stale claim. `apps/marketing-zola/templates/partials/pricing/plans.html` currently matches `services/mail-server/crates/billing-service/src/plans.rs` for the published Free/Starter/Pro/Growth/Scale pricing and limits.
- [x] 🟠 **No canonical URLs** — Fixed already. `apps/marketing-zola/templates/base.html` emits a canonical link using `current_url` with `config.base_url` fallback.
- [x] 🟠 **Missing meta descriptions** — Fixed already. `apps/marketing-zola/templates/base.html` provides a default description block that pages can override.
- [x] 🟠 **No schema.org markup** — Fixed already. `apps/marketing-zola/templates/base.html` includes Organization JSON-LD.
- [x] 🟡 **Broken links check needed** — Stale claim for the cited compare CTA surface. The linked comparison pages already exist under `apps/marketing-zola/content/compare/{sendgrid,resend,postmark}/index.md`.
- [x] 🟡 **Missing 404 page** — Fixed in `apps/marketing-zola/templates/404.html`. The site now has a branded fallback page instead of relying on the default Zola stub.
- [x] 🟡 **No sitemap.xml** — Stale claim. The current marketing build already emits `apps/marketing-zola/public/sitemap.xml`, and `apps/marketing-zola/static/robots.txt` advertises it.
- [x] 🟡 **CTA buttons lack urgency** — Recommendation rather than a correctness defect. CTA copy is a conversion optimization topic, not a broken implementation.
- [x] 🟡 **No social sharing meta tags** — Fixed already. `apps/marketing-zola/templates/base.html` includes Open Graph and Twitter Card metadata.
- [ ] 🟡 **Accessibility: missing alt text on images** — Check all images for descriptive alt text.
- [ ] 🟡 **Color contrast issues** — Verify WCAG AA compliance for text/background contrast.
- [x] 🟡 **No cookie consent banner** — Fixed already. `apps/marketing-zola/templates/base.html` includes the cookie consent island/banner.
- [x] 🟡 **Font loading blocks rendering** — Fixed already. `apps/marketing-zola/templates/base.html` preloads the font assets.

---

## 🤖 AI Pipeline

- [x] 🟠 **Training data leakage between tenants** — Stale/mislabeled claim for the current `ai-service` training surface. `services/mail-server/crates/ai-service/src/training.rs` is an in-memory training job manager; it does not load training corpora or join tenant-scoped data at all, so the cited file is not a live cross-tenant data-loader path.
- [x] 🟠 **Inference endpoint not rate-limited** — Fixed in `services/mail-server/crates/ai-service/src/routes.rs` and `services/mail-server/crates/ai-service/src/config.rs`. The `/predict` handler now enforces a configurable local request limit (`AI_INFERENCE_RATE_LIMIT`, `AI_INFERENCE_RATE_LIMIT_WINDOW_SECS`) and returns HTTP 429 once the inference window is exhausted instead of allowing unbounded prediction traffic behind the shared service token. Focused validation passes with `cargo test --manifest-path services/mail-server/Cargo.toml -p ai-service --lib`.
- [x] 🟠 **Model poisoning possible via training endpoint** — Stale claim for the current endpoint shape. `services/mail-server/crates/ai-service/src/routes.rs` exposes `/train` as a job-start endpoint that only accepts `model_id` plus `TrainingConfig`; it does not ingest raw user-provided training examples, corpora, or labels, so the cited training endpoint is not presently a model-poisoning surface.
- [x] 🟡 **Embeddings stored without tenant isolation** — Fixed in `services/mail-server/crates/ai-embeddings/src/vector_store.rs`, `services/mail-server/crates/ai-embeddings/src/search.rs`, and `services/mail-server/crates/ai-embeddings/src/routes.rs`. Embeddings now require `tenant_id` metadata at write time, vector searches require a tenant scope, and the store filters similarity results by `tenant_id` instead of searching across the entire in-memory corpus. Focused validation passes with `cargo test --manifest-path services/mail-server/Cargo.toml -p ai-embeddings --lib`.
- [x] 🟡 **AI service config hardcoded** — Stale claim. `services/mail-server/crates/ai-service/src/config.rs` already loads its settings from environment variables with validation.
- [x] 🟡 **Training data format validation missing** — Stale/mislabeled claim for the current AI service crates. A targeted search over `services/mail-server/crates/ai-*` found no live JSONL training-data ingestion path; the current `/train` route only starts an in-memory job with `model_id` plus `TrainingConfig`, so there is no runtime JSONL parser here to crash on malformed records.
- [x] 🟡 **Chunker splits mid-word for non-English** — Fixed in `services/mail-server/crates/ai-embeddings/src/chunker.rs`. Overlap slicing and post-overlap truncation now snap to UTF-8 character boundaries instead of raw byte offsets, and a new regression test covers non-ASCII overlap with CJK text. Focused validation passes with `cargo test --manifest-path services/mail-server/Cargo.toml -p ai-embeddings chunker`.
- [ ] 🟡 **No model versioning in storage** — AI models stored without version metadata — rollback impossible.
- [ ] 🟡 **Bandit algorithm not persisted** — `ai-service/src/bandits.rs`: Contextual bandit state in memory only — lost on restart.

---

## 📦 SDKs

- [x] 🟡 **SDK retry logic missing exponential backoff** — Stale claim. The current SDKs already implement exponential backoff; for example `packages/sdk-python/src/apexmail/client.py` uses `_calculate_backoff()`.
- [x] 🟡 **SDK timeout too short/long** — Stale claim. The maintained SDKs use reasonable defaults and expose them for override.
- [x] 🟡 **Missing user-agent header in SDK HTTP clients** — Stale claim. The current SDK HTTP clients already send versioned `User-Agent` headers.
- [x] 🔵 **Java SDK uses deprecated HTTP client** — Stale claim. `packages/sdk-java/src/main/java/ee/apexmail/ApexMailClient.java` already uses `java.net.http.HttpClient`.
- [x] 🔵 **PHP SDK no type hints** — Stale claim. `packages/sdk-php/src/Client.php` enables `strict_types` and uses typed method signatures.
- [x] 🔵 **Ruby SDK missing gem specification** — Stale claim. `packages/sdk-ruby/apexmail.gemspec` is present and populated.
- [x] 🔵 **Go SDK context not propagated** — Stale claim. The current Go SDK threads `context.Context` through its public request methods.
- [x] 🔵 **SDK READMEs inconsistent** — Stale claim. The current SDK READMEs follow the same installation, quick-start, feature, and API reference structure.

---

## 🦞 Lobster (Game Engine)

- [ ] 🟡 **FIXME: type coercion bug** — `Lobster/modules/gui.lobster:317`: Force-casts "selected" to int because enum assign fails — type system issue.
- [ ] 🟡 **FIXME: texture placement** — `Lobster/modules/texture.lobster:37`: "put this in a place and know it'll be drawn last" — drawing order issue.
- [ ] 🟡 **TODO: navigation mesh performance** — `Lobster/modules/navmap.lobster:12`: Blocked Q could be more efficient.
- [ ] 🟡 **FIXME: GUI cleanup** — `Lobster/modules/gui.lobster:205`: Cleanup needed on position(size) function.
- [x] 🔵 **Calc game minor: no input validation** — Stale claim. The calculator input handlers in `Lobster/main.lob` already guard decimal, operator, and divide-by-zero edge cases.

---

## 🚀 Deployment & DevOps

### NGINX (deploy/nginx/nginx.conf)

- [x] 🔴 **Missing ssl_dhparam** — Stale/intentional config. `deploy/nginx/nginx.conf` explicitly documents DH params as optional unless a provisioned file exists, while the live TLS config already restricts protocols and ciphers to modern suites.
- [x] 🟠 **No HSTS on HTTP redirect** — Overstated fix surface. HSTS is already emitted on the HTTPS API/tracking server blocks with `preload`; adding it to the port-80 redirect would not be the missing fix for first-visit bootstrap behavior.
- [x] 🟠 **Restrictive CSP on tracking server breaks functionality** — Stale claim. The tracking service serves `image/gif` pixels and redirect responses rather than a rendered HTML app, so the locked-down CSP in `deploy/nginx/nginx.conf` does not break the live tracking flow.
- [x] 🟠 **Missing X-Content-Type-Options: nosniff** — Fixed already. `deploy/nginx/nginx.conf` adds `X-Content-Type-Options nosniff` on the HTTPS server blocks.
- [x] 🟠 **No Referrer-Policy header** — Fixed already. `deploy/nginx/nginx.conf` adds `Referrer-Policy strict-origin-when-cross-origin` on the HTTPS server blocks.
- [x] 🟠 **Missing Permissions-Policy header** — Fixed already. `deploy/nginx/nginx.conf` sets a restrictive `Permissions-Policy` on the HTTPS server blocks.
- [x] 🟠 **TLS versions not restricted** — Fixed already. `deploy/nginx/nginx.conf` restricts TLS to `TLSv1.2 TLSv1.3`.
- [x] 🟠 **No ciphersuite restriction** — Fixed already. `deploy/nginx/nginx.conf` pins modern ECDHE cipher suites.
- [x] 🟡 **Proxy buffer sizes too small** — Stale claim. The current nginx proxy buffer sizes are already sized for the API/tracking responses they serve.
- [x] 🟡 **Missing rate limiting on API routes** — Fixed already. `deploy/nginx/nginx.conf` defines and applies `limit_req` zones for auth, general API, and tracking routes.
- [x] 🟡 **Missing upstream health checks** — Overstated claim. The current nginx upstreams already define passive failure handling via `max_fails` and `fail_timeout`.
- [x] 🟡 **Large client_body_size may allow abuse** — Fixed already. The API block is capped at `1m` and the tracking block at `1k` in `deploy/nginx/nginx.conf`.

### Docker & Compose

- [x] 🟠 **No resource limits in docker-compose.yml** — Fixed already. `docker-compose.yml` defines resource limits/reservations on the maintained services.
- [x] 🟠 **No restart policies** — Fixed already. Critical services in `docker-compose.yml` use `restart: unless-stopped`.
- [x] 🟠 **ClickHouse exposed to host** — Fixed already. The Compose port mapping binds ClickHouse to loopback by default.
- [x] 🟠 **Redis without password** — Fixed already. Redis loads its password from Docker secrets in the current Compose setup.
- [x] 🟡 **No healthchecks in docker-compose** — Fixed already. Health checks are defined for the core services in `docker-compose.yml`.
- [x] 🟡 **Secrets exposed via environment variables** — Fixed already. The maintained Compose config uses Docker secret files and `_FILE`-style inputs instead of plain secret env vars.
- [x] 🟡 **No network isolation** — Fixed already. `docker-compose.yml` separates frontend, backend, data, and monitoring traffic across distinct networks.

### Kubernetes (deploy/k8s/)

- [x] 🟠 **Pods running as root** — Fixed already. The maintained Kubernetes deployments set `runAsNonRoot`, `runAsUser`, and related security context fields.
- [x] 🟠 **No resource requests/limits** — Fixed already. The maintained Kubernetes deployments define requests and limits.
- [x] 🟠 **Readiness/liveness probes missing** — Fixed already. The maintained Kubernetes deployments include readiness, liveness, and startup probes.
- [x] 🟠 **No PodDisruptionBudget** — Fixed already. PDB manifests exist for the maintained deployments.
- [ ] 🟠 **Secrets in template not encrypted** — `secrets.template.yaml`: Contains placeholder values but no encryption (should use SealedSecrets or External Secrets Operator).
- [x] 🟠 **No NetworkPolicies** — Fixed already. NetworkPolicy manifests are present for the maintained deployments.
- [x] 🟠 **No PodSecurityPolicy/PSA** — Overstated for the maintained manifests. The current deployments already enforce the important equivalent runtime hardening (`RuntimeDefault`, dropped capabilities, no privilege escalation, read-only root filesystem).
- [x] 🟡 **No HorizontalPodAutoscaler** — Fixed already. HPA manifests exist for the maintained deployments.
- [ ] 🟡 **No affinity/anti-affinity rules** — Pods can all be scheduled on same node — single point of failure.
- [x] 🟡 **ConfigMap may contain secrets** — Stale claim. The current ConfigMap contains non-sensitive configuration while actual secrets are sourced from Secret objects.
- [x] 🟡 **No topology spread constraints** — Fixed already. The maintained deployments include topology spread constraints.

### Monitoring & Observability

- [x] 🟠 **No alert on mail queue backlog** — Fixed already. `deploy/alerting-rules.yml` defines queue backlog alerts.
- [x] 🟠 **No alert on billing failures** — Fixed already. `deploy/alerting-rules.yml` defines Stripe/billing failure alerts.
- [x] 🟠 **Prometheus retention not configured** — Fixed in `docker-compose.yml`. Prometheus retention now reads `${PROMETHEUS_RETENTION:-15d}` instead of hardcoding `15d`.
- [ ] 🟠 **No dashboard configs provided** — No Grafana dashboard JSON definitions in repo.
- [ ] 🟠 **Alertmanager not configured for production PagerDuty/OpsGenie** — Only email notifications configured.
- [x] 🟡 **Blackbox exporter missing TLS checks** — Fixed already. The current blackbox config and alert rules include TLS probe coverage and certificate-expiry alerting.
- [x] 🟡 **No synthetic transaction monitoring** — Overstated as written. The current monitoring stack already performs synthetic blackbox probing of the live health endpoints.
- [ ] 🟡 **Distributed tracing not integrated** — No Jaeger/Zipkin config — can't trace requests across services.
- [ ] 🟡 **Log aggregation not configured** — No centralized log shipping (e.g., Loki, ELK).

---

## 📄 Documentation & API Specs

### OpenAPI Spec (docs/api/openapi.yaml)

- [x] 🔴 **Missing `DELETE /v1/webhooks/{id}`** — Stale claim. The current OpenAPI spec already documents `DELETE /v1/webhooks/{id}`.
- [x] 🟠 **Inconsistent error codes** — Stale claim. The current OpenAPI spec consistently documents `RATE_LIMIT_EXCEEDED` for 429 responses.
- [x] 🟠 **Batch message schema allows contradictory fields** — Stale claim. The current `BatchMessageSendRequest` in `docs/api/openapi.yaml` only wraps `messages: [MessageSendRequest]` and does not expose the cited mutually-exclusive `template_id` / `inline_only` combination.
- [x] 🟠 **Missing 429 response on many endpoints** — Stale claim. The current OpenAPI spec documents 429 responses across the maintained endpoint set.
- [x] 🟠 **Missing 401/403 responses** — Stale claim. The current OpenAPI spec documents auth/authorization failure responses across the maintained endpoint set.
- [x] 🟠 **Webhook signatures not documented** — Stale claim. `docs/api/webhooks.md` already documents signature verification.
- [x] 🟠 **Pagination parameters not standardized** — Documentation consistency recommendation rather than a verified runtime defect. The live issue here is spec style drift, not broken request handling.
- [x] 🟡 **Missing `PATCH` operations** — Stale claim. The current OpenAPI spec already includes PATCH operations for maintained partial-update resources.
- [x] 🟡 **Rate limit headers documented differently than implemented** — Stale claim. The current OpenAPI spec documents the `X-RateLimit-*` headers consistently.

### Architecture Docs

- [x] 🟠 **Data-flow.md: Outdated diagram** — Stale path/claim. The cited `docs/architecture/data-flow.md` is no longer the maintained architecture document surface.
- [x] 🟠 **Hybrid infrastructure docs contradict code** — Stale claim. The maintained ADR and migration documentation already describe the SES-primary / hybrid-delivery arrangement used by the current code.
- [x] 🟠 **ADR 0001 (Database choice) possibly outdated** — Stale claim. The current ADR already documents the PostgreSQL + ClickHouse split.
- [x] 🟠 **Pricing.md: Math errors or stale prices** — Stale claim. `docs/pricing.md` currently matches the live pricing in `services/mail-server/crates/billing-service/src/plans.rs`.
- [x] 🟡 **Missing SSO documentation** — Stale claim. SSO/SCIM surfaces are already documented in the current docs/OpenAPI set.
- [x] 🟡 **API route audit report incomplete** — Static-report drift rather than a source-of-truth defect. `docs/api/openapi.yaml` is the maintained API contract surface.

---

## 🛠️ Tools / Scripts

- [x] 🔴 **`bootstrap.sh`: Hardcoded credentials** — Stale claim. The current bootstrap script does not embed hardcoded credentials.
- [x] 🟠 **`fix_*.py` scripts may have side effects** — Tooling/process recommendation rather than a product defect. These one-off maintainer utilities are not part of the runtime surface.
- [x] 🟠 **`dev-start.sh` hardened for shell failures** — Fixed in `tools/dev-start.sh`. The script now runs with `set -euo pipefail`, so failed commands, unset variables, and pipeline failures stop startup instead of leaving partial local state. Syntax revalidated with `bash -n tools/dev-start.sh tools/poll_instance.sh`.
- [x] 🟠 **`poll_instance.sh` infinite loop risk** — Stale claim. `tools/poll_instance.sh` already bounds polling with `VAST_MAX_POLL_ATTEMPTS` (default `60`) and exits non-zero once the maximum attempts are exhausted instead of looping forever.
- [x] 🟠 **Python audit scripts use `eval()`** — Stale claim. The current audit scripts do not use `eval()` on user-controlled input.
- [x] 🟠 **Migration scripts not in transactions** — Stale claim for the maintained migration set. The current SQL migrations are wrapped in transactions where needed.
- [x] 🟠 **`load-secret-env.sh` exposes secrets** — Fixed in `deploy/load-secret-env.sh`. The loader no longer uses `eval` for indirect expansion and now resolves only validated env var names plus secret-file contents before `exec`-ing the target command.
- [x] 🟡 **`check-forbidden-patterns.sh` too restrictive** — Recommendation rather than a current defect. There is no current evidence that this script is blocking legitimate work in the maintained repo state.
- [x] 🟡 **`run-mail-server-tests.sh` no test selection** — Stale claim. The script already forwards arbitrary cargo selection arguments, and the current VS Code tasks use it for targeted package/test subsets.
- [x] 🟡 **`checksums.sha256` may be stale** — Build-hygiene recommendation rather than a verified defect. No current mismatch evidence was found in this pass.
- [x] 🟡 **`browser_smoke.py` no retries** — Fixed in `tools/browser_smoke.py`. The smoke runner now supports configurable `--retries` with bounded backoff for flaky browser operations. CLI validation passes.
- [x] 🟡 **Python scripts use `print()` instead of logging** — Recommendation rather than a correctness defect. These operator-run utility scripts intentionally emit plain stdout/stderr summaries and are not part of the production request path.
- [x] 🟡 **`generate_bigfix.py`: Generated code quality** — Recommendation rather than a current defect. This is a tooling/process concern, not a verified runtime bug.

---

## 🧪 Testing

- [x] 🟠 **No tests for billing race conditions** — Duplicate follow-up item rather than a separate defect. The real remaining issue is the live plan-downgrade race above; the missing regression test belongs with that fix.
- [x] 🟠 **MTA integration tests mock external services** — Test-strategy recommendation rather than a verified product defect.
- [x] 🟠 **Load tests not representative** — Performance-testing recommendation rather than a verified runtime defect.
- [x] 🟠 **Fuzz tests limited coverage** — Coverage recommendation rather than a verified runtime defect.
- [x] 🟠 **Smoke tests don't verify cleanup** — Test-hygiene recommendation rather than a verified current defect.
- [x] 🟠 **Schema contract tests incomplete** — Coverage recommendation rather than a verified runtime defect.
- [x] 🟡 **No property-based testing** — Testing-depth recommendation rather than a verified runtime defect.
- [x] 🟡 **No mutation testing integration** — CI/process recommendation rather than a verified runtime defect.
- [x] 🟡 **Functional tests duplicated** — Test-suite organization recommendation rather than a verified runtime defect.
- [x] 🟡 **Test flakiness from shared state** — Unverified testing recommendation rather than a confirmed current defect.
- [x] 🟡 **No performance regression benchmarks** — Performance-testing recommendation rather than a verified runtime defect.

---

## 📊 Data / Migrations / SQL

- [x] 🟠 **Migration 001 creates tables without IF NOT EXISTS** — Stale claim for the maintained migration surface. The current migrations consistently use modern guarded creation patterns where required.
- [x] 🟠 **Missing down migrations** — Migration-policy recommendation rather than a verified current defect. The maintained migration flow is forward-only in practice.
- [x] 🟠 **Golden QA data may contain PII** — Stale claim. The current golden QA fixtures contain test/support content rather than live user PII.
- [x] 🟠 **Training data not sanitized** — Stale claim. The maintained training fixtures contain synthetic/product content rather than live customer data.
- [x] 🟡 **No FOREIGN KEY on some tables** — Overstated for the maintained schema. The current migrations already include foreign keys on the cited modern tables.
- [x] 🟡 **Missing indexes on high-query columns** — Performance audit recommendation rather than a verified defect. This row needs concrete `EXPLAIN` evidence before it should be tracked as a live fault.
- [x] 🟡 **No created_at/updated_at on some tables** — Overstated claim. The maintained migrations already include timestamp columns across the modern schema additions.
- [x] 🟡 **Migration scripts not ordered chronologically** — Repository-history/documentation issue rather than a runtime defect.

---

## 🎯 Performance Optimization Opportunities

- [x] 🟠 **Database connection pool too small** — Unverified performance recommendation rather than a current defect. The maintained services already expose pool sizing via configuration.
- [x] 🟠 **No response compression** — Stale claim. The current deployment/static site setup already enables compression on the served assets.
- [x] 🟠 **No CDN for static assets** — Stale claim. The current marketing/static asset setup already references CDN-backed delivery.
- [x] 🟠 **Session store in DB** — Stale claim. The current auth flow uses JWT session tokens rather than a PostgreSQL-backed server-side session store.
- [x] 🟡 **No database query caching** — Optimization recommendation rather than a verified defect.
- [x] 🟡 **N+1 query patterns** — Audit recommendation rather than a verified current defect. This row needs a concrete endpoint/query trace before it should be tracked as a live fault.
- [x] 🟡 **Missing Redis pipeline for batch operations** — Optimization recommendation rather than a verified defect.
- [x] 🟡 **No prepared statement caching** — Overstated claim. The maintained SQLx query paths already use prepared statements by default, so this is not a live defect as written.
- [x] 🟡 **Serial processing in worker-processors** — Overstated broad claim. The maintained webhook worker path already uses bounded concurrency; any remaining worker parallelism work needs a file-scoped finding instead of a generic scanner bucket.
- [x] 🟡 **Large JSON payloads parsed repeatedly** — Optimization recommendation rather than a verified defect.

---

## ⚪ INFO / Recommendations

- [x] ⚪ **Add contribution guidelines (CONTRIBUTING.md)** — Recommendation rather than a fault. This is a workflow/documentation improvement, not a runtime defect.
- [x] ⚪ **Add CHANGELOG.md** — Recommendation rather than a fault. Release-note process is not a code defect.
- [x] ⚪ **Add CODEOWNERS file** — Recommendation rather than a fault. Review assignment policy is an organizational workflow choice.
- [x] ⚪ **Add Dependabot/config for dependency updates** — Recommendation rather than a fault. Dependency update automation is process tooling, not a broken implementation.
- [x] ⚪ **Add editorconfig for consistent formatting** — Recommendation rather than a fault. Formatting is already handled by language-specific tooling.
- [x] ⚪ **Add pre-commit hooks** — Recommendation rather than a fault. This is a workflow enhancement.
- [x] ⚪ **Snyk/Dependabot alerts not configured** — Recommendation rather than a fault. Dependency scanning integration is operational tooling.
- [x] ⚪ **Semantic versioning not applied** — Recommendation rather than a fault. Versioning policy is a release-management concern, not a current code bug.


---

## 🛒 Sales-Autopilot System (services/mail-server/crates/sales-autopilot/)

> Analysis of the automated sales system — lead scoring, enrichment, campaigns, calendar, inbox, web scraper, autopilot state machine, and admin API integration.

### 🔴 CRITICAL: Data Loss / Wrong Implementation

- [ ] 🔴 **In-memory CRM used in production binary instead of PostgreSQL** — `services/mail-server/crates/sales-autopilot/src/bin/server.rs:43` uses `CrmService::new()` (in-memory `Arc<RwLock<Vec<Lead>>>`), which loses all leads on process restart. The PostgreSQL-backed `SqlxCrmService` (366 lines, fully implemented in `services/mail-server/crates/sales-autopilot/src/crm_pg.rs`) is never instantiated. Fix: change `AppState` to hold `SqlxCrmService` and wire it in `bin/server.rs`. Leads, campaigns, calendar events, and inbox messages all vanish on restart.
- [ ] 🔴 **Enrichment service returns hardcoded fake data** — `services/mail-server/crates/sales-autopilot/src/enrichment.rs:46-77`: The `enrich_company()` method uses a `match` statement with exactly 3 hardcoded domains (`acme.com`, `beta.io`, `gamma.dev`). Everything else gets `"Unknown (unknown)"` with industry/size/revenue all set to `"Unknown"`. The `api_url` config value is stored in the constructor but **never used for any HTTP call** — the code logs `"using mock enrichment backend"` then proceeds to the hardcoded match. Data is persisted to `enriched_companies` with a hardcoded confidence of `0.85`.
- [ ] 🔴 **Autopilot state machine has no automation** — `services/mail-server/crates/api-server/src/routes/admin/autopilot.rs`: The autopilot supports `start`, `stop`, `approve`, `reject`, `approve-all`, `exit-safe-mode` actions stored in `sales_autopilot_state`. However, there is **no background worker, no scheduler, no cron job, no scoring loop, no action loop** that runs when status is `'running'`. The `PENDING_APPROVAL_SCORE` constant is declared but **never referenced in any comparison or filter**. The `rules` JSONB column is stored but **never read or interpreted by any code**. The autopilot is a manual approval queue with start/stop buttons that do nothing.
- [ ] 🔴 **Campaign system never sends emails** — `services/mail-server/crates/sales-autopilot/src/campaigns.rs`: Campaigns support Draft→Active→Paused→Completed lifecycle with recipient management. However, **no code sends the actual emails**. No scheduler, no cron, no background task, no SMTP call. The `sent`, `opened`, `clicked` counters initialize to `0` and have **no event source or write path**. Recipients enrolled via `add_recipients()` are stored in memory and vanish on restart.
- [ ] 🔴 **Web scraper doesn't fetch the web** — `services/mail-server/crates/sales-autopilot/src/scrapers.rs:44-57`: `extract_company_info(domain)` returns URL strings like `{"homepage": "https://{domain}/about"}` without making any HTTP requests. The `reqwest` crate is in Cargo.toml dependencies but is **not used by this module**. The robots.txt parser (`is_allowed_by_robots()`) is correct but receives zero inputs because nothing downloads robots.txt. The `scraper_rpm` config (default 30) is stored but never enforced.

### 🟠 HIGH: Missing Functionality / Integration

- [ ] 🟠 **Lead discovery is circular with no external data source** — `services/mail-server/crates/api-server/src/routes/admin/sales.rs:run_discovery()`: Reads `enriched_companies` table and inserts new rows into `sales_leads`. However, the only way companies get into `enriched_companies` is through the enrichment endpoint, which returns fake data. No integration with Clearbit, Apollo, LinkedIn, Hunter.io, or any external lead/prospecting API.
- [ ] 🟠 **Thompson sampling engine completely disconnected from campaigns** — `services/mail-server/crates/analytics/src/campaign_autopilot.rs`: This 424-line module implements a production-quality Beta-Bernoulli multi-armed bandit with Marsaglia-Tsang Gamma sampling, Box-Muller normal transform, 10K Monte Carlo selection probabilities via `spawn_blocking`, 95% credible intervals, expected regret, and convergence detection. **But it lives in the `analytics` crate, not `sales-autopilot`.** The `campaign_arms` table and `drip_campaigns` table coexist in PostgreSQL but `select_arm()` is never called by any route handler, scheduler, or background task. This is the highest-quality code in the entire sales system and it does nothing.
- [ ] 🟠 **No pagination on any list endpoint** — `services/mail-server/crates/sales-autopilot/src/routes.rs`: All list endpoints (`/leads`, `/campaigns`, `/calendar`, `/inbox`, `/companies`) return unbounded result sets. A tenant with 100K leads must fetch them all in a single response. No `LIMIT/OFFSET`, no cursor, no page size parameter.
- [ ] 🟠 **Inbox classifier uses 20 hardcoded keywords with no ML** — `services/mail-server/crates/sales-autopilot/src/inbox.rs:49-81`: Classification is a `match` on `subject.to_lowercase().contains()` with exactly 20 keywords (unsubscribe, viagra, lottery, support, help, ticket, issue, invoice, payment, subscription, renewal, demo, pricing, interested, trial, plus noreply from-address). No ML, no NLP, no training data. Messages have **no integration with the actual email pipeline** — there is no ingress source that feeds real emails into this classifier.
- [ ] 🟠 **Calendar has no external provider integration** — `services/mail-server/crates/sales-autopilot/src/calendar.rs`: The slot scheduling logic (working hours 09:00-17:00 UTC, Mon-Fri, 30-min slots, overlap detection) is correct. But there is no integration with Google Calendar, Calendly, Outlook, or any iCal provider. No email notifications when events are created. `find_available_slots()` does not check for weekends — it will return Saturday slots despite `is_within_working_hours()` only being used during event creation.

### 🟡 MEDIUM: Code Quality / Edge Cases

- [ ] 🟡 **Lead score field allows values above semantic range** — `services/mail-server/crates/sales-autopilot/src/types.rs:76`: `score: u8` has a documented semantic range of 0-100 but can physically store values up to 255. `crm_pg.rs:256` has `s.clamp(0, 100) as u8` but the `crm.rs` in-memory version and `types.rs` struct do not enforce this constraint.
- [ ] 🟡 **No rate limiting on enrichment endpoint** — `services/mail-server/crates/sales-autopilot/src/routes.rs:291-335`: The `POST /enrich` endpoint has no request rate limiting. An attacker could flood it with enrichment requests, potentially exhausting external API quota (when a real enrichment API is connected) or database connections.
- [ ] 🟡 **Auth silently disabled if INTERNAL_SERVICE_TOKEN is empty** — `services/mail-server/crates/sales-autopilot/src/bin/server.rs:49-53`: When `INTERNAL_SERVICE_TOKEN` env var is unset, the binary logs `"INTERNAL_SERVICE_TOKEN is not set — internal auth is effectively disabled"` as a warning but **continues to start without authentication**. Any request without a token passes the emptiness check at `routes.rs:128-130`.
- [ ] 🟡 **`LOWER() LIKE` search is O(n) without pg_trgm index** — `services/mail-server/crates/sales-autopilot/src/crm_pg.rs:185-201`: The `search_leads()` method uses `LOWER(name) LIKE $1 OR LOWER(email) LIKE $1 OR LOWER(company) LIKE $1` with a leading `%` wildcard, which cannot use a standard B-tree index. For large lead tables (>100K rows), this will be a sequential scan. Should add a `pg_trgm` GIN index or use PostgreSQL full-text search.
- [ ] 🟡 **No deduplication in campaign `add_recipients()`** — `services/mail-server/crates/sales-autopilot/src/campaigns.rs:144-149`: `add_recipients()` uses `list.extend(emails)` which appends all provided emails to the recipient list without checking for duplicates. The same email can be added to a campaign 100 times. This applies to the in-memory version; the admin API layer's `run_outreach()` at `services/mail-server/crates/api-server/src/routes/admin/sales.rs` writes to the `campaign_recipients` table with the same potential issue.
- [ ] 🟡 **Health endpoint returns 200 even when Postgres is down** — `services/mail-server/crates/sales-autopilot/src/bin/server.rs:59-65` + `routes.rs:115-117`: `/health` returns `{"status":"healthy"}` without checking if the PostgreSQL connection pool is alive. Kubernetes readiness/liveness probes would think the service is healthy when all database-dependent operations would fail.
- [ ] 🟡 **Campaign stats counters have no write path** — `services/mail-server/crates/sales-autopilot/src/campaigns.rs:108-127`: The `sent`, `opened`, `clicked` fields on `Campaign` are initialized to `0` and **never updated by any code path**. No event ingestion, no callback, no webhook processing. The `get_stats()` method returns them as-is.
- [ ] 🟡 **No pagination on companies list** — `services/mail-server/crates/sales-autopilot/src/routes.rs:238-279`: `GET /companies` has `limit` (default 100, max 500) and `offset` parameters but the admin dashboard's list endpoints do not surface these. The default of 100 rows may miss data, and the 500-max cap prevents exporting the full dataset.
- [ ] 🟡 **SQL injection risk in dynamic list_leads query** — `services/mail-server/crates/sales-autopilot/src/crm_pg.rs:120-162`: The `list_leads()` method builds SQL dynamically with `format!(" AND source = {}", param)` using string formatting instead of bind parameters. While `param` is derived from `Option<&str>` which limits the attack surface, this should use `sqlx::QueryBuilder` or bind parameters for correctness.
- [ ] 🟡 **Enriched companies cache silently fails** — `services/mail-server/crates/sales-autopilot/src/routes.rs:304-332`: The `enrich` handler attempts to persist results to `enriched_companies` with an `INSERT ... ON CONFLICT DO UPDATE` but wraps the entire operation in `if let Err(error) = ...` that only logs a warning. Failures to persist enrichment results are invisible to the caller, who receives a successful response with the company data regardless.
- [ ] 🟡 **`escape_like_pattern()` function duplicates std functionality** — `services/mail-server/crates/sales-autopilot/src/routes.rs:496-501`: The `escape_like_pattern()` helper manually escapes `\`, `%`, and `_` characters for `ILIKE` queries. This is correct but duplicates functionality that could be provided by PostgreSQL's `pg_trgm` or a shared utility crate. Minor maintenance burden.
- [ ] 🟡 **No cross-tenant validation on /companies endpoint** — `services/mail-server/crates/sales-autopilot/src/routes.rs:238-279`: The `GET /companies` endpoint queries `enriched_companies` table without filtering by tenant. If multiple tenants' data exists, the response leaks company records across tenants. The `sales_leads` queries are properly tenant-scoped in the admin API layer but this endpoint is not.

---

---

## 🔧 Control-Plane Admin API (`services/mail-server/crates/api-server/src/routes/admin/`)

> Deep analysis of the 24-module (45+ endpoint) control-plane admin REST API — tenant management, feature flags, GDPR, secrets, audit, dashboard, compliance, risk, revenue, sales/CRM, campaigns, autopilot, calendar, inbox, warmup, content, support, analytics, proxy, and system health.

### Infrastructure & Middleware (app.rs)

The Axum application stack in `services/mail-server/crates/api-server/src/app.rs` assembles these layers:

- **DDoS protection** (`ddos_protection::evaluate_request`) on public and authenticated routes — evaluates IP, path, method, user-agent, body size, tenant context; returns Allow/Challenge (429)/RateLimit (429)/Block (403)
- **Auth** (`require_auth`) — API key (SHA-256 HMAC + Redis cache/10s TTL + control-plane static key), JWT (RS256 + Redis blacklist), session cookie
- **Idempotency** — `Idempotency-Key` header deduplication
- **Rate limiting** — public routes (specific per-endpoint), authenticated routes (global, configurable)
- **Load shedding** — `LoadShedLayer` + `GlobalConcurrencyLimitLayer` (default 80 concurrent)
- **Security headers** — HSTS 1yr, X-Frame-Options DENY, X-Content-Type-Options nosniff, CSP `default-src 'none'; frame-ancestors 'none'`, Permissions-Policy
- **Null byte check** — rejects `\0` in paths and query params
- **30s timeout**, **10MB body limit**, **compression**, **OpenTelemetry tracing**

### 24 Admin Route Modules — Complete Inventory

| # | Module | Lines | Endpoints | Auth | Audit |
|---|--------|-------|-----------|------|-------|
| 1 | `tenants.rs` | 297 | GET/PATCH/DELETE /v1/admin/tenants | `["*"]` | Yes |
| 2 | `features.rs` | 190 | GET/POST/PATCH /v1/admin/features | `["*"]` | Yes |
| 3 | `gdpr.rs` | 176 | GET/PATCH /v1/admin/gdpr | `["*"]` | Yes |
| 4 | `secrets.rs` | 293 | GET/POST/PATCH/DELETE /v1/admin/secrets | `["*"]` | Yes |
| 5 | `audit.rs` | 249 | GET /v1/admin/audit | `["*"]` | N/A (reads audit) |
| 6 | `dashboard.rs` | 284 | GET /v1/admin/dashboard/stats | `["*"]` | No |
| 7 | `compliance_overview.rs` | 231 | GET /v1/admin/compliance | `["*"]` | No |
| 8 | `risk.rs` | 415 | GET/PATCH /v1/admin/risk | `["*"]` | Yes |
| 9 | `revenue.rs` | 218 | GET /v1/admin/revenue | `["*"]` | No |
| 10 | `inbox.rs` | 297 | GET/PATCH /v1/admin/inbox | `["*"]` | Yes |
| 11 | `calendar.rs` | 99 | GET /v1/admin/calendar | `["*"]` | No |
| 12 | `warmup.rs` | 214 | GET/POST /v1/admin/warmup | `["*"]` | Yes |
| 13 | `content.rs` | 95 | GET /v1/admin/content | `["*"]` | No |
| 14 | `autopilot.rs` | 645 | GET/POST /v1/admin/autopilot | `["*"]` | Yes |
| 15 | `proxy.rs` | 234 | POST /v1/admin/proxy | `["*"]` | Yes |
| 16 | `sales.rs` | 1074 | 8 endpoints under /v1/admin/sales | `["*"]` | Yes |
| 17 | `analytics.rs` | 193 | GET /v1/admin/analytics | `["*"]` | No |
| 18 | `analytics_export.rs` | TBD | GET /v1/admin/analytics/export | `["*"]` | No |
| 19 | `campaigns.rs` | 92 | GET /v1/admin/campaigns | `["*"]` | No |
| 20 | `crm_leads.rs` | 95 | GET /v1/admin/crm/leads | `["*"]` | No |
| 21 | `leads_discovery.rs` | 124 | GET /v1/admin/leads/discovery | `["*"]` | No |
| 22 | `support.rs` | 317 | GET/POST/PUT /v1/admin/support | `["*"]` | Yes |
| 23 | `support_analytics.rs` | TBD | GET /v1/admin/support/analytics | `["*"]` | No |
| 24 | `system_health.rs` | 195 | GET /v1/admin/system/health | `["*"]` | No |

### ✅ Strengths

1. **Universal auth coverage** — Every single handler calls `require_scopes(&auth, &["*"])`. Confirmed by test (`admin_route_files_enforce_wildcard_scope`) that scans all .rs files for the pattern. Zero missing auth checks.
2. **Universal audit logging** — Every mutation (tenant update, secret rotation, GDPR status change, feature toggle, risk limit set, autopilot action, proxy request, support ticket update, inbox update, campaign update, lead update) writes to `audit_logs` table with action, resource type, resource ID, tenant ID, timestamp, metadata.
3. **Graceful degradation** — Optional table checks (`table_exists()`) throughout. Dashboard, compliance, risk, autopilot, system_health all handle missing tables without crashing.
4. **Dynamic SQL safety** — `sales.rs` uses `sqlx::QueryBuilder` for lead queries (parameterized binds). `audit.rs` uses parameterized dynamic SQL (numbered $N params with bind values).
5. **SSRF-safe proxy** — Full IP/hostname blocklist: localhost, RFC1918, link-local, cloud metadata, carrier-grade NAT, IPv6 ULA/link-local, decimal IP tricks. Header allowlist. HTTPS enforce in production. Configurable domain allowlist (`CONTROL_PLANE_PROXY_ALLOWLIST`).
6. **Tenant deletion safety** — `tenants.rs:delete_tenant_records()` iteratively discovers FK dependencies, retries blocked tables, uses a transaction. Requires explicit confirmation phrase (`DELETE {tenant_id}`).
7. **Risk scoring formula** — `risk.rs:251` weights: critical=35pts, high=12pts, bounce_rate*200, complaint_rate*2000, clamped to 0-100. Sensible weights.
8. **Revenue MRR calculation** — Properly normalizes yearly subscriptions to monthly (`amount / 12.0`), excludes canceled subscriptions. Revenue by plan breakdown with percentages.
9. **Analytics dynamic column detection** — Handles both `event_type`/`type` and `created_at`/`timestamp` naming conventions.
10. **Rate-limited outreach** — In-memory rate limiter: 5 outreach actions per 10-minute window.
11. **Dashboard pipeline mapping** — Maps 9+ raw status values to 5 pipeline stages (prospect/outreach/engaged/demo/closed).

### 🔴 CRITICAL Issues

- [ ] 🔴 **Risk thresholds and tenant limits live in memory, lost on restart** — `risk.rs:105-106`: `static THRESHOLDS: Mutex<Option<Thresholds>>` and `static TENANT_LIMITS: Mutex<Option<HashMap<String, TenantLimits>>>` are process-level statics. `SetLimit` best-effort persists to DB but does not reload on startup. `SaveThresholds` only writes to memory. On any process restart, all thresholds and limits vanish. No initialization code loads persisted values from DB.
- [ ] 🔴 **RunAssessment is a no-op** — `risk.rs:379-383`: `RiskMutation::RunAssessment` inserts an audit log entry and returns a timestamp. No actual risk computation, no bounce rate recalculation, no reputation analysis, no alert generation. The `risk_score` field on `RiskTenant` is computed from raw DB counts at read time, not stored.
- [ ] 🔴 **Revenue LTV, CAC, expansion revenue, upgrades, downgrades are hardcoded to zero** — `revenue.rs:206-213`: `ltv: 0.0, cac: 0.0, expansion_revenue: 0.0, upgrades: 0, downgrades: 0`. These are essential SaaS metrics and there is no calculation logic behind them.
- [ ] 🔴 **Monthly revenue data only uses total invoice amounts, displays zero for new/expansion/churned** — `revenue.rs:171-175`: `new_mrr: 0.0, expansion_mrr: 0.0, churned_mrr: 0.0`. The `MonthlyData` struct defines breakouts but they are never computed.
- [ ] 🔴 **Autopilot "start" does not start any background process** — `autopilot.rs:456-484`: Setting status to `"running"` in PostgreSQL does not spawn any worker, scheduler, or loop. No cron, no tokio task, no message queue consumer. The autopilot is a status flag that does nothing.

### 🟠 HIGH Issues

- [ ] 🟠 **Risk threshold values never actually used** — `risk.rs:94-103` defines `Thresholds` with `bounce_rate_warn: 5.0`, `bounce_rate_critical: 10.0`, `complaint_rate_warn: 1.0`, `complaint_rate_critical: 3.0`. These values are stored in a `Mutex<Option<Thresholds>>` but are **never referenced in any comparison, alert trigger, or scoring formula**. The risk score at line 251 uses a hardcoded formula with no threshold comparison.
- [ ] 🟠 **No pagination on list_secrets, list_gdpr_requests, list_features, list_content** — `secrets.rs:87-103`: `list_secrets()` returns ALL secrets without limit/offset. `gdpr.rs:81-136`: `list_gdpr_requests()` has `limit` and `offset` parameters but the underlying query has no pagination in the SQL — the `LIMIT`/`OFFSET` values from the query struct are not used in the SQL query. Audit: `audit.rs:171` does use `LIMIT ${param_idx} OFFSET ${}`.
- [ ] 🟠 **support_ticket creation is missing** — `support.rs`: Only list tickets, add replies, and update ticket. No POST to create a new ticket. Tickets must be created externally or via some other endpoint.
- [ ] 🟠 **Dashboard cache (30s TTL) can serve stale mutation data** — `dashboard.rs:20-21`: `static CACHE: Mutex<Option<(Instant, DashboardStats)>>`. When an admin mutates data (updates lead status, creates campaign), the dashboard won't reflect changes for up to 30 seconds. No invalidation mechanism exists.
- [ ] 🟠 **Warmup action response says "success" even when pool_id is invalid** — `warmup.rs:148-213`: `warmup_action()` runs `UPDATE ip_pools SET status = $1 ... WHERE id = $2` but never checks `result.rows_affected()`. If the pool_id doesn't exist, the response still says `{"success": true}`.
- [ ] 🟠 **Revenue metrics use VARCHAR counters via ::text casts** — Throughout `revenue.rs`, `COUNT(*)::text` is used and then parsed with `.parse::<f64>().ok()`. This pattern is repeated in `dashboard.rs`, `compliance_overview.rs`, `risk.rs`. This fragility could silently return 0 on type mismatches.
- [ ] 🟠 **Autopilot candidates query doesn't filter by tenant** — `autopilot.rs:159-165`: `pending_candidates()` queries `sales_leads` without a `tenant_id` WHERE clause. For a multi-tenant control plane, this leaks candidates across tenants.
- [ ] 🟠 **calendar events and inbox messages list has no tenant filter in SQL** — `calendar.rs:54-63`: Fetches all `calendar_events` without tenant_id filter. `inbox.rs:77-86` does support tenant scoping but only when `auth.tenant_id != "system"`. When a system admin views the calendar, they see all tenants' events.

### 🟡 MEDIUM Issues

- [ ] 🟡 **`risk.rs` TenantLimits uses in-memory Mutex with no DB persistence guarantee** — `risk.rs:314-342`: `SetLimit` writes to `TENANT_LIMITS` Mutex, then best-effort persists to tenants.metadata JSONB. The DB write failure is silently swallowed (only logged). Limits are not reloaded from DB on startup.
- [ ] 🟡 **`analytics.rs` dynamically builds SQL with format!()** — `analytics.rs:87-103`: Column names are introspected from `information_schema.columns` (safe), but the SQL is assembled with `format!()`. If `type_col` or `time_col` somehow contain malicious values (e.g., from a compromised information_schema), SQL injection is possible.
- [ ] 🟡 **`compliance_overview.rs` GDPR overdue count is always 0** — `gdpr_requests.overdue` at line 130: The `"overdue"` status is in the match arm but `UpdateGdprRequest` doesn't support setting a status of "overdue". No overdue detection logic exists.
- [ ] 🟡 **`system_health.rs` workers derived from queue_jobs, not actual worker registry** — `system_health.rs:113-137`: Worker IDs are extracted from `queue_jobs.worker_id` (jobs table), implying a worker only exists if it has processed a job. No heartbeat table, no worker registration, no health check endpoint for workers.
- [ ] 🟡 **`secrets.rs` stores metadata only, not the actual secret value** — The secrets table has `name`, `type`, `description`, `rotation_policy`, `status`, `access_count`. No encrypted value column. This means secrets must be managed externally or the feature is incomplete.
- [ ] 🟡 **No batch update support for feature flags** — `features.rs:153-189`: Each `update_feature` call handles a single flag. Updating 100 flags requires 100 HTTP requests.
- [ ] 🟡 **`content.rs` has no author field filter or content_type filter** — Simply returns all content ordered by published_at/created_at. No way to filter by type (blog, help, legal, changelog).
- [ ] 🟡 **`calendar.rs` has no POST endpoint** — Read-only view of calendar events. No create/update/delete for events through the admin API. Events must be created through the sales-autopilot microservice.
- [ ] 🟡 **`leads_discovery.rs` `icon_for()` function uses emoji strings** — Returns hardcoded emoji per source name. This is a UI concern leaking into the API layer. Not a bug, but a design smell.
- [ ] 🟡 **`sales.rs` outreach rate limiter is process-local, not shared** — `sales.rs:825-827`: `static OUTREACH_LIMITER: Mutex<Option<(Instant, u32)>>` — in a multi-instance deployment, each node has its own counter. A coordinated client could send 5 requests per node per window.
- [ ] 🟡 **`gdpr.rs` doesn't enforce GDPR deletion/completion** — `update_gdpr_request()` sets status to "completed" but performs no actual data deletion or export. It's a status change only.
- [ ] 🟡 **`secrets.rs` doesn't enforce rotation schedules** — Rotation policy can be set to "daily", "weekly", "monthly" but no background task checks or enforces these schedules. The `rotate` action must be called manually.

---

## 📊 Analytics Crate — Disconnected ML Engine (`services/mail-server/crates/analytics/`)

> The analytics crate contains ~4,000+ lines of genuine production-quality machine learning code that is completely disconnected from any consumer. No route handler, scheduler, or background task consumes its outputs.

### 🔴 CRITICAL: Dead Computation

- [ ] 🔴 **Thompson sampling multi-armed bandit completely disconnected** — `services/mail-server/crates/analytics/src/campaign_autopilot.rs`: 424 lines implementing a Beta-Bernoulli MAB with Marsaglia-Tsang Gamma sampling, Box-Muller normal transform, 10K Monte Carlo selection probabilities, 95% credible intervals, expected regret, and convergence detection. Talks to `campaign_arms` and `drip_campaigns` PostgreSQL tables. **However, `select_arm()` is never called by any route, scheduler, or background worker.** The `TemplateArm` struct supports variants (A-F) with arm-level statistics but no send path uses these selections.
- [ ] 🔴 **Churn prediction engine computes scores for no one** — `services/mail-server/crates/analytics/src/churn_prediction.rs`: Multi-factor signal computation (engagement decay, velocity), sigmoid scoring, risk tier classification, Redis caching. `predict()` is never called by any billing alerting, customer health dashboard, or notification system.
- [ ] 🔴 **Send time optimizer determines optimal windows that no scheduler honors** — `services/mail-server/crates/analytics/src/send_time_optimizer.rs`: Bayesian-smoothed optimal send time per recipient with cold-start hour/day priors, Redis cached. `get_optimal_window()` and `get_bulk_optimization()` are never called by any queuing or batch send path.
- [ ] 🔴 **Engagement trust scoring influences no sending decisions** — `services/mail-server/crates/analytics/src/engagement_trust.rs`: Trust scoring (credibility/reliability/intimacy/self-orientation), letter grading A-F, risk level classification. `calculate_trust()` and `campaign_trust()` are never used to throttle, prioritize, or block sends.
- [ ] 🔴 **Subject line analyzer runs on no subject lines** — `services/mail-server/crates/analytics/src/subject_line_analyzer.rs`: Tokenization, length scoring, personalization detection, spam-word checking, urgency/benefit classification. `analyze()` is never called before campaigns are created or activated.
- [ ] 🔴 **Bot detection and reply tracking duplicated and disconnected** — `services/mail-server/crates/analytics/src/bot_detection.rs` and `reply_tracking.rs`: Overlap with `tracking-service/src/bot.rs`. The analytics versions are never called. The tracking-service version runs on real events but has no integration back to the analytics crate.
- [ ] 🔴 **Inbox placement service makes recommendations no one sees** — `services/mail-server/crates/analytics/src/inbox_placement.rs`: Provider classification, placement trends, deliverability recommendations. No dashboard surfaces these metrics.

### 🟡 MEDIUM: Design / Implementation

- [ ] 🟡 **clickhouse_engine uses primitive HTTP client, no connection pooling** — `services/mail-server/crates/analytics/src/clickhouse_engine.rs`: Uses `reqwest::Client` directly with no connection pooling for ClickHouse native protocol. Every query creates a new TCP connection. Should use `clickhouse-rs` crate for native protocol and connection management.
- [ ] 🟡 **Compaction worker uses filesystem for cold storage, not S3-compatible** — `services/mail-server/crates/analytics/src/compaction.rs`: Writes JSONL batches to filesystem path. The `cold_storage_path` config supports a prefix but S3 upload code (`cleanup_cold_storage`) relies on `aws-sdk-s3` which may not be configured. Cold storage is essentially local filesystem writes.
- [ ] 🟡 **Reconciliation worker doesn't reconcile** — `services/mail-server/crates/analytics/src/reconciliation.rs`: `find_discrepancies()` logic is defined but the `run()` function returns a `ReconciliationResult { total_checked: 0, discrepancies: 0, alerts_sent: 0 }` with no actual reconciliation loop implemented.
- [ ] 🟡 **No integration tests for any analytics module** — All analytics tests are unit tests with mocked/stub data. No ClickHouse, no Redis, no PostgreSQL-backed integration tests exist.

---

## 💰 Billing Service — Additional Issues (`services/mail-server/crates/billing-service/`)

### 🟠 HIGH

- [ ] 🟠 **No webhook replay mechanism** — `stripe_webhooks.rs`: When a Stripe webhook fails processing (e.g., subscription_event parsing error), the deadletter entry is logged but there is no UI or API to replay deadlettered webhooks. Recovery requires direct database manipulation.
- [ ] 🟠 **Invoice PDF generation falls back silently** — `invoices.rs:generate_invoice_pdf()`: If S3 credentials are missing or upload fails, the function logs an error but returns Ok. Callers don't know the PDF wasn't generated.
- [ ] 🟠 **Usage metering has no late-arriving data handling** — `usage.rs`: Usage is credited to the billing period of the `timestamp` field. If a metering event arrives 5 minutes after period close, it credits the wrong period. No late-arriving data window or re-billing mechanism exists.
- [ ] 🟠 **Dunning configuration stored in-memory with no persistence** — `stripe_webhooks.rs:get_dunning_config_for_tenant()`: Reads from `dunning_config` table. If the table doesn't exist (first deploy), `ensure_dunning_config_table()` creates it with minimal defaults but the admin API has no endpoint to configure dunning schedules per tenant.
- [ ] 🟠 **No proration preview for annual→monthly downgrades** — `routes.rs:preview_plan_proration()`: Handles monthly→annual and monthly→monthly correctly. But annual→any downgrade computes proration based on remaining days in a 365-day period, which may not match Stripe's actual proration logic. No validation against Stripe's preview API.

### 🟡 MEDIUM

- [ ] 🟡 **No idempotency-key support on billing mutation endpoints** — `routes.rs`: `switch_plan`, `cancel_subscription_request`, `record_usage` endpoints lack `Idempotency-Key` header support. Duplicate requests could cause double billing.
- [ ] 🟡 **PAYG pricing test coverage missing edge cases** — `config.rs`: Tests cover zero usage, first tier only, combined usage, and contract rounding. Missing: max u64 boundary, multi-year cumulative overflow, negative pricing injection (if config ever allows negative), mixed currency configurations.
- [ ] 🟡 **Maintenance jobs run inline, not as separate workers** — `maintenance.rs`: All 12 job types run sequentially in `start_periodic_jobs()`. A slow job (e.g., SLA credit sweep with many tenants) blocks grace period processing, metering draining, etc.
- [ ] 🟡 **SLA credit calculation uses hardcoded percentages** — `maintenance.rs:sla_credit_percentage_for_breach()`: 99.9%→10%, 99.0%→25%, 95.0%→50%, <95%→100%. These should be configurable per-plan in the PlanFeatures or a dedicated SLA config table.
- [ ] 🟡 **Stripe API calls use reqwest directly, not SDK** — `maintenance.rs:stripe_get_json/stripe_post_json()`: Raw HTTP calls to Stripe API with manual signature handling. Should use `stripe-rust` crate for type safety, webhook event deserialization, and automatic signature verification.
- [ ] 🟡 **No usage rollback for failed sends** — `routes.rs:record_usage_checked()` increments counters before the send completes. If the SMTP send fails, usage is still charged. No compensating rollback or credit mechanism exists.

---

## 📬 Tracking Service — Missing Features (`services/mail-server/crates/tracking-service/`)

### 🟠 HIGH

- [ ] 🟠 **No A/B testing or variant tracking** — `processor.rs`: Tracks opens, clicks, unsubscribes per campaign+recipient. Doesn't track which template variant was shown, so A/B test results cannot be measured at the tracking level.
- [ ] 🟠 **No spam complaint tracking** — No processing pipeline for feedback loop (FBL) complaints from ISPs. Without FBL ingestion, reputation management is incomplete.
- [ ] 🟠 **No bounce classification** — `processor.rs`: Records opens/clicks/unsubscribes but has no hard bounce, soft bounce, or out-of-office event handling. These are tracked downstream in the queue system but not correlated with tracking events.

### 🟡 MEDIUM

- [ ] 🟡 **Unsubscribe preferences page is XSS-vulnerable by design** — `templates.rs:render_preferences_page()`: Renders `email` and `token` directly in HTML via `format!()`. While token is AES-GCM encrypted (non-malleable), email address appears in the page. If the unsubscribe link is intercepted, recipient sees their email in the page title. Mitigation: apply `escape_html()` to all user-data in template strings.
- [ ] 🟡 **Tracking pixel URL query parameters not sanitized** — The pixel endpoint (`/_/o/<token>.png`) ignores query parameters but the redirect endpoint (`/_/c/<token>`) may pass unrecognized query params through to the target URL. Audit for open redirect risk.
- [ ] 🟡 **Event processor doesn't prioritize real-time events over historical** — `processor.rs`: All events queue through the same WAL channel. A burst of historical data (e.g., batch import) could delay real-time open tracking updates.
- [ ] 🟡 **No metrics for deduplication rate** — `processor.rs`: `try_set_dedup()` silently skips duplicates. There's no metric for dedup hit rate, making it impossible to detect if legitimate opens are being filtered.

---

## 📨 Outbound Queue — Improvements Needed (`services/mail-server/crates/outbound-queue/`)

### 🟠 HIGH

- [ ] 🟠 **No TLS certificate verification override for MX servers** — `smtp_sender.rs`: Uses rustls with default certificate verification. Some internal/exchange servers use self-signed certs. No config option to disable verification per domain.
- [ ] 🟠 **No DSN (Delivery Status Notification) support** — `smtp_sender.rs`: The SMTP conversation doesn't request DSN via `RCPT TO ... NOTIFY=SUCCESS,FAILURE,DELAY`. If a downstream server bounces after accepting the message, there's no way to correlate the bounce back to the original send.
- [ ] 🟠 **No delivery time optimization (send window scheduling)** — `smtp_sender.rs`: Sends are attempted as soon as they're dequeued. No per-recipient timezone awareness, no quiet hours, no scheduled delivery window. The analytics send_time_optimizer computes all this data for free but the queue has no integration.
- [ ] 🟠 **Connection pool per-MX has no upper bound** — `smtp_sender.rs:take_pooled_connection()`: The `pooled_connections: Arc<Mutex<Vec<(SocketAddr, PooledStream)>>>` has no size cap. For a popular MX (e.g., Google, Microsoft), hundreds of connections could accumulate.

### 🟡 MEDIUM

- [ ] 🟡 **No pipelining support** — `smtp_sender.rs`: MAIL/RCPT/DATA commands are sent sequentially with individual response waits. Pipelining (RFC 2920) could batch these and significantly improve throughput.
- [ ] 🟡 **No SMTPUTF8 (international email) support** — `smtp_sender.rs`: MAIL FROM/RCPT TO sends bare addresses without SMTPUTF8. Non-ASCII email addresses will fail.
- [ ] 🟡 **No exponential backoff on MX lookup failures** — `smtp_sender.rs:lookup_mx()`: Caches successful lookups for 300s but DNS failures are not cached. A temporary DNS outage causes repeated lookups on every retry.
- [ ] 🟡 **DKIM signing happens before queue, key rotation impossible without restart** — `smtp_sender.rs:build_message()` signs at send time with a static `DkimSigner`. Key rotation requires restarting the service. No support for multiple DKIM selectors or key rollover.

---

## 🔧 Workspace-Level Issues

### 🔴 CRITICAL

- [ ] 🔴 **Analytics ↔ Sales-autopilot disconnect is the single largest inefficiency in the codebase** — `crates/analytics/` has ~4,000+ lines of genuine ML/AI code doing nothing because nothing calls it. `crates/sales-autopilot/` has status tracking (campaign status, autopilot state, lead scores) with no integration to the analytics engine. The fix requires wiring: analytics autopilot → campaign send scheduler; send time optimizer → outbound queue; churn prediction → billing alerting; engagement trust → sending throttling; subject line analyzer → campaign validation. Estimate: 2-3 months engineering effort.
- [ ] 🔴 **Three separate MTA/outbound implementations exist** — `crates/outbound-queue/` (main SMTP sender), `crates/mta/` (separate SMTP server implementation), `crates/smtp-edge/` (third SMTP implementation). These duplicate MX resolution, SMTP conversation logic, and connection management. Risk of behavior divergence.

### 🟠 HIGH

- [ ] 🟠 **No centralized feature flag system** — Feature flags exist ad-hoc: in `PlanFeatures` (billing-plan gated), in `enterprise/src/contracts.rs` (contract-level flags), in `autopilot.rs` (stored in JSONB). No centralized toggle mechanism, no gradual rollout, no kill switch.
- [ ] 🟠 **No health check or dependency graph** — `crates/system_health.rs`: Infers worker existence from `queue_jobs` table. No service registry, no dependency-aware startup ordering, no circuit breakers, no health endpoint that checks all dependencies.
- [ ] 🟠 **No metrics for control-plane health** — No Prometheus metrics for admin API request latency, audit log write rate, sales-autopilot processing rate, enrichment requests, campaign starts. Only the main API surface has metrics.
- [ ] 🟠 **No dark launch / canary infrastructure** — No configuration or code to run shadow mode, compare new vs old code paths, or gradually roll out new features to a subset of tenants.

### 🟡 MEDIUM

- [ ] 🟡 **Config structs are duplicated across many crates** — Every crate has its own `Config` struct with its own `from_env()` parsing. `DATABASE_URL`, `REDIS_URL`, `LOG_LEVEL` are parsed independently in 15+ crates. A shared config crate would reduce duplication.
- [ ] 🟡 **Test utilities scattered across crates** — No shared test utility crate. Each crate re-implements `test_app()`, `test_config()`, `make_test_email()`, etc. Inconsistent test infrastructure.
- [ ] 🟡 **No cargo workspace artifacts caching** — CI builds all 40+ crates from scratch. No `sccache` or `mold` linker configuration in workspace config.
- [ ] 🟡 **More than 100 unchecked `unwrap()` calls across workspace** — Running `grep -rn "\.unwrap()" services/mail-server/crates/**/*.rs` reveals 100+ unwrap calls that could panic on unexpected database states or edge cases.
- [ ] 🟡 **No SQL migration validation** — No check that `crates/apexmail-db/migrations/` migrations are consistent across environments, no guard against running out-of-order migrations, no migration dry-run mode.

---

## 🏗️ Cross-Cutting Architectural Issues

- [ ] 🟠 **Control plane has no SLA/SLO tracking** — No uptime tracking, no latency SLO enforcement, no error budget tracking. The billing system *computes* SLA credits for customers but the platform doesn't track its own SLO achievement.
- [ ] 🟠 **No tenant-level circuit breaker** — If one tenant creates excessive load (spam run, API abuse), there's no circuit breaker per tenant. The DDoS protection is IP-based, not tenant-based. A compromised tenant account could degrade service for all.
- [ ] 🟠 **No data retention policies enforced** — PostgreSQL tables (`audit_logs`, `metering_events`, `tracking_events`, `queue_jobs`) grow unbounded. The compaction worker handles analytics events but audit_logs, metering_events, and queue_jobs have no cleanup policy.
- [ ] 🟡 **CSP headers differ between nginx and application layer** — `deploy/nginx/nginx.conf` sets CSP on the upstream response, but `api-server/src/app.rs` also injects CSP headers. These could conflict or duplicate. Should consolidate at one layer.
- [ ] 🟡 **`faults.md` is becoming a multipurpose audit document** — Mixes original bug tracking, fixed-stale markers, and new deep-analysis inventory sections. Consider splitting: bugs vs feature gaps vs architecture recommendations.

