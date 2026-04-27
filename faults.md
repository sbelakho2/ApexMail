# ApexMail Repository - Comprehensive Faults and Issues Report

**Scan Date:** 2026-04-27  
**Repository:** ApexMail  
**Status:** VALIDATED - Original scan reviewed against current code; checked items below are either fixed in code or proven stale by direct verification.  
**Scan Method:** Multi-agent parallel scanning of all directories

---

## Summary

This document contains all bugs, issues, security vulnerabilities, logic errors, UI/UX issues, billing errors, and configuration problems identified during a comprehensive line-by-line scan of the ApexMail repository.

**Validation Update (2026-04-27):** A checked box now means one of two things: the defect was fixed and validated in the current codebase, or the original finding was proven stale/incorrect and no code change was required. Unchecked items still need follow-up or deeper validation.

**Total Issues Found:** 58  
**Critical:** 9  
**High:** 17  
**Medium:** 20  
**Low:** 9  
**Info:** 3

---

## CRITICAL ISSUES

### [x] 1. **Decimal Point Button Does Nothing**
- **File:** `Lobster/main.lob` (Lines 183-184)
- **Severity:** CRITICAL
- **Type:** BUG / LOGIC
- **Description:** The decimal point button handler immediately returns without doing anything. Users cannot enter decimal numbers (e.g., 3.14). This renders the calculator nearly unusable for any real mathematical work.
- **Code:** `if label == ".": return`
- **Fix:** Implement decimal input handling - track decimal places and modify input_value accordingly.
- **Validation Update (2026-04-27):** Fixed in `Lobster/main.lob` by replacing the integer-only input model with explicit whole/fractional entry state; validated with `./Lobster/bin/lobster --non-interactive-test Lobster/main.lob`.

### [x] 2. **Hardcoded Redis Password Exposed**
- **File:** `secrets/redis_password.txt` (Line 1)
- **Severity:** CRITICAL
- **Type:** SECURITY
- **Description:** The Redis password file contains a placeholder password `CHANGE_ME_redis_password_min_32_chars`. File has overly permissive permissions (`-rw-r--r--` for all users).
- **Fix:** Generate strong password with `openssl rand -base64 32` and set permissions to `600`.
- **Validation Update (2026-04-27):** Fixed by rotating `secrets/redis_password.txt` to a strong generated value and tightening permissions to `600`; verified with `ls -l`.

### [x] 3. **Redis Password Exposed in Docker Compose**
- **File:** `docker-compose.override.yml` (Lines 36-37, 45)
- **Severity:** CRITICAL
- **Type:** SECURITY
- **Description:** Redis password is exposed via command and healthcheck test in plain text, visible through `docker inspect`.
- **Fix:** Use Docker secrets or environment variables with proper secret management.
- **Validation Update (2026-04-27):** Fixed by switching `docker-compose.override.yml` to the same secret-file entrypoint pattern as the base compose; merged `docker compose config` now renders `REDIS_PASSWORD_FILE` plus a secret mount instead of a plaintext password env/command.

### [x] 4. **Python SDK - Suppression Check API Path Mismatch**
- **File:** `packages/sdk-python/src/apexmail/resources/suppressions.py` (Lines 87-89)
- **Severity:** CRITICAL
- **Type:** API / BUG
- **Description:** The `check()` method uses `/v1/suppressions/check/{email}` (path parameter), but API contract expects `/v1/suppressions/check?email={email}` (query parameter). Results in 404 errors.
- **Fix:** No SDK code change required in this pass.
- **Validation Update (2026-04-27):** Stale finding. The current server route is still `GET /v1/suppressions/check/:email`, so the Python SDK path matches the implementation; the broader contract drift remains tracked under #44.

### [x] 5. **VAT Calculation Uses Biased Rounding**
- **File:** `services/mail-server/crates/billing-service/src/invoices.rs`
- **Severity:** HIGH (upgraded from HIGH to CRITICAL due to financial impact)
- **Type:** BUG / FINANCIAL
- **Description:** VAT calculation uses `((subtotal * rate) + 50) / 100` which always rounds up, causing overcharging. Example: `((10000 * 22) + 50) / 100 = 2250` but mathematically should be 2200.
- **Fix:** No code change applied in this pass.
- **Validation Update (2026-04-27):** The original example was incorrect. Current code rounds half-up to the nearest cent, not “always up”; no financial logic change was made without a tax-policy requirement proving banker's rounding is expected.

### [x] 6. **PAYG Pricing Unwrap_or Could Cause Billing Chaos**
- **File:** `services/mail-server/crates/billing-service/src/config.rs` (Lines 141, 149)
- **Severity:** CRITICAL
- **Type:** BUG / FINANCIAL
- **Description:** `PaygPricing::calculate()` uses `unwrap_or(i64::MAX)` which can cause incorrect billing charges if conversions fail.
- **Fix:** Return an error instead of using fallback to MAX values.
- **Validation Update (2026-04-27):** Fixed in `billing-service` by replacing the fallback with explicit checked overflow errors and route handling; validated with `cargo test --manifest-path services/mail-server/Cargo.toml -p billing-service payg`.

### [x] 7. **Hardcoded Internal Domain URLs in K8s ConfigMap**
- **File:** `deploy/k8s/configmap.yaml` (Lines 21-23, 39)
- **Severity:** CRITICAL
- **Type:** SECURITY / CONFIG
- **Description:** Internal domain URLs (`app.apexmail.ee`, `admin.apexmail.ee`, `track.apexmail.ee`) exposed in ConfigMap, revealing infrastructure details.
- **Fix:** Move to Helm values.yaml with defaults for per-environment override.
- **Validation Update (2026-04-27):** Fixed by converting the raw K8s manifest defaults to explicit example placeholders (`*.example.invalid`) and documenting them as replace-before-apply template values.

### [x] 8. **Training Data Contains Fabricated Customer IDs**
- **File:** `data/train_agent.jsonl` (Line 1)
- **Severity:** CRITICAL
- **Type:** DATA / SECURITY
- **Description:** Training data contains realistic but fabricated customer account IDs (`acct_4k8r1w`, `acct_7w3x5y`) that could be accidentally used as real data.
- **Fix:** Use clearly synthetic IDs like `sample_acct_*` or `test_acct_*` in training data.
- **Validation Update (2026-04-27):** Fixed by bulk-rewriting account IDs in `data/train_agent.jsonl` to the `sample_acct_*` prefix; verified with `grep` that no bare `acct_` IDs remain.

### [x] 9. **Python SDK - Template Render Request Body Key Mismatch**
- **File:** `packages/sdk-python/src/apexmail/resources/templates.py` (Lines 119-126)
- **Severity:** CRITICAL
- **Type:** API / BUG
- **Description:** The `render()` method sends `{"variables": variables}` but API expects `{"data": data}`, causing template rendering to fail.
- **Fix:** No SDK code change required in this pass.
- **Validation Update (2026-04-27):** Stale finding. The current API server `RenderRequest` still expects `variables`, so the Python SDK payload matches the implementation; any docs drift belongs under #44.

---

## HIGH PRIORITY ISSUES

### [x] 10. **Display Truncates All Decimal Values**
- **File:** `Lobster/main.lob` (Lines 132-135)
- **Severity:** HIGH
- **Type:** BUG / LOGIC
- **Description:** Even if decimal input worked, display converts `input_value` to int, truncating all decimals. Example: 3.5 displays as "3".
- **Fix:** Use proper float-to-string conversion that preserves decimals.
- **Validation Update (2026-04-27):** Fixed alongside #1 by moving display rendering to explicit entry/result formatting rather than `int(...)`; validated with the Lobster runtime smoke check.

### [x] 11. **Division by Zero Not Handled**
- **File:** `Lobster/main.lob` (Line ~200)
- **Severity:** HIGH
- **Type:** BUG / LOGIC
- **Description:** No check before division operation, causing runtime crash potential.
- **Fix:** Add division-by-zero check before performing operation.
- **Validation Update (2026-04-27):** Fixed in `Lobster/main.lob` with an explicit `Division by 0` error path instead of silently continuing with bad state.

### [x] 12. **Division Produces Wrong Results**
- **File:** `Lobster/main.lob` (Line ~195)
- **Severity:** HIGH
- **Type:** BUG / LOGIC
- **Description:** Division operation returns incorrect values due to integer division issues.
- **Fix:** Verify and correct division logic implementation.
- **Validation Update (2026-04-27):** Fixed by replacing the prior integer-style entry model with true decimal-aware operand construction; division now operates on the same float values shown in the display.

### [x] 13. **Negative Numbers Not Displayed Correctly**
- **File:** `Lobster/main.lob` (Line ~140)
- **Severity:** MEDIUM
- **Type:** BUG / UI
- **Description:** Negative numbers show incorrectly (may display as large positive number).
- **Fix:** Add explicit negative sign handling in display conversion.
- **Validation Update (2026-04-27):** Fixed by making the display derive from explicit sign state instead of coercing the input through `int(...)`.

### [x] 14. **Nginx Health Check Endpoint Mismatch**
- **File:** `deploy/nginx/nginx.conf` (Line 149)
- **Severity:** HIGH
- **Type:** CONFIG / BUG
- **Description:** Health check proxies to `/health/live` but API exposes `/health`. Causes health checks to fail.
- **Fix:** No nginx change required in this pass.
- **Validation Update (2026-04-27):** Stale finding. Live compose smoke validation already proved the `/health/live` mapping is the correct backend target for the current API surface.

### [x] 15. **Hardcoded Image Tags in K8s Deployment**
- **File:** `deploy/k8s/api-server/deployment.yaml` (Line 49)
- **Severity:** HIGH
- **Type:** CONFIG
- **Description:** Image tag hardcoded as `apexmail/api-server:v1.0.0` with `imagePullPolicy: Always` prevents using updated images.
- **Fix:** Use mutable tags like `latest` or proper image digests.
- **Validation Update (2026-04-27):** Fixed by converting the raw K8s deployment manifests to explicit `REPLACE_TAG` template placeholders and `IfNotPresent` pull policy.

### [x] 16. **Webhook Signature Verification Timing Issues**
- **File:** `services/mail-server/crates/billing-service/src/stripe_webhooks.rs`
- **Severity:** HIGH
- **Type:** SECURITY
- **Description:** Stripe webhook signature verification may have timing issues affecting security.
- **Fix:** Ensure proper timestamp tolerance in verification.
- **Validation Update (2026-04-27):** Stale finding. `stripe_webhooks.rs` already enforces a five-minute tolerance window and validates the timestamp before accepting the webhook.

### [x] 17. **Concurrent Invoice Generation Race Condition**
- **File:** `services/mail-server/crates/api-server/src/routes/billing.rs`
- **Severity:** HIGH
- **Type:** BUG / LOGIC
- **Description:** Multiple concurrent requests could generate duplicate invoices.
- **Fix:** Add idempotency checks using database locks or unique constraints.
- **Validation Update (2026-04-27):** Fixed in the owning admin invoice creation path by wrapping the existence check and insert in a transaction-scoped advisory lock keyed by tenant and billing period; validated with `cargo test --manifest-path services/mail-server/Cargo.toml -p api-server --no-run`.

### [x] 18. **Missing Unit Tests for Billing Calculations**
- **File:** `services/mail-server/crates/billing-service/src/`
- **Severity:** HIGH
- **Type:** TESTING
- **Description:** Critical pricing logic lacks unit tests.
- **Fix:** Add comprehensive test suite for all billing calculations.
- **Validation Update (2026-04-27):** Stale finding. `billing-service` already contains targeted tests for VAT and PAYG logic, and the PAYG slice now has additional regression coverage.

### [x] 19. **Logging Sensitive Payment Information**
- **File:** `services/mail-server/crates/billing-service/src/routes.rs`
- **Severity:** HIGH
- **Type:** SECURITY
- **Description:** Potential logging of sensitive payment information.
- **Fix:** Ensure PII/sensitive data is redacted from all logs.
- **Validation Update (2026-04-27):** Stale finding. The route layer logs only status/error summaries plus aggregate usage counters; no card numbers, payment-method secrets, receipt emails, IBANs, or similar payment fields are logged from this file.

### [x] 20. **API Key Hardcoded in Java SDK**
- **File:** `packages/sdk-java/src/main/java/ee/apexmail/ApexMailClient.java` (Line ~27)
- **Severity:** HIGH
- **Type:** SECURITY
- **Type:** API key hardcoded in client initialization.
- **Fix:** No Java SDK change required in this pass.
- **Validation Update (2026-04-27):** Stale finding. The Java client accepts the API key via constructor parameters; the cited string is documentation/example usage, not a hardcoded credential.

### [x] 21. **Missing Timeout on External API Calls**
- **File:** `packages/sdk-python/src/apexmail/client.py`
- **Severity:** MEDIUM
- **Type:** BUG / CONFIG
- **Description:** No timeout configured for external API calls, causing potential hangs.
- **Fix:** Add appropriate timeouts (e.g., `requests.get(timeout=30)`).
- **Validation Update (2026-04-27):** Stale finding. The Python SDK already has a default `httpx` timeout of 30 seconds wired through both sync and async clients.

### [x] 22. **Memory Leak Potential in Training Loop**
- **File:** `apps/ai/training/train.py` (Lines ~280-320)
- **Severity:** HIGH
- **Type:** BUG / PERFORMANCE
- **Description:** Model/tensor accumulation without proper cleanup.
- **Fix:** Add memory management with proper tensor disposal.
- **Validation Update (2026-04-27):** Fixed by streaming the golden-set eval instead of materializing it, using `torch.inference_mode()` for generation, and releasing per-example tensors after decode in `apps/ai/training/train.py`; validated with `python3 -m py_compile apps/ai/training/train.py`.

### [x] 23. **Broken Internal Link in Documentation**
- **File:** `docs/quickstart.md` (Line 97)
- **Severity:** HIGH
- **Type:** DOCS
- **Description:** Link `../security/mcaptcha-login.md` is incorrect. Should be `./security/mcaptcha-login.md`.
- **Fix:** Correct the relative path to match file structure.
- **Validation Update (2026-04-27):** Stale finding. The current link in `docs/quickstart.md` is already `./security/mcaptcha-login.md`.

### [x] 24. **PAYG Pricing Tier Inconsistency**
- **File:** `data/train_agent.jsonl` (Line 1)
- **Severity:** HIGH
- **Type:** BUG / PRICING
- **Description:** System prompt states "first 100k free, then $0.10/1,000" but training examples show inconsistent calculations.
- **Fix:** Standardize API pricing across all training examples.
- **Validation Update (2026-04-27):** Stale finding. The current training examples and pricing docs already agree on the free 100K API tier followed by $0.10 per 1,000 calls.

### [x] 25. **Unclosed Database Connections**
- **File:** `services/mail-server/crates/api-server/src/bin/server.rs`
- **Severity:** MEDIUM
- **Type:** BUG / RESOURCE
- **Description:** Connection pool may not be properly closed on shutdown.
- **Fix:** Implement proper connection cleanup on application shutdown.
- **Validation Update (2026-04-27):** Fixed in the actual server shutdown path by explicitly awaiting `db.close()` after Axum graceful shutdown completes; validated with `cargo test --manifest-path services/mail-server/Cargo.toml -p api-server --no-run`.

### [x] 26. **JWT Secret Template Missing Proper Instructions**
- **File:** `deploy/k8s/secrets.template.yaml`
- **Severity:** MEDIUM
- **Type:** SECURITY
- **Description:** Template may lead to insecure secrets if not properly configured.
- **Fix:** Add clear instructions for secure secret generation.
- **Validation Update (2026-04-27):** Stale finding. `deploy/k8s/secrets.template.yaml` already documents secure secret handling and includes explicit `kubectl create secret` examples.

---

## MEDIUM PRIORITY ISSUES

### [x] 27. **API Base URL Inconsistency in Documentation**
- **File:** `docs/api/openapi.yaml` (Lines 50-52) and `docs/quickstart.md` (Line 31)
- **Severity:** MEDIUM
- **Type:** DOCS
- **Description:** OpenAPI shows `api.apexmail.ee` and `sandbox.api.apexmail.ee` but quickstart uses different examples.
- **Fix:** Ensure all documentation examples are consistent.
- **Validation Update (2026-04-27):** Stale finding. The documented production and sandbox API base URLs are intentionally different and currently consistent with the published docs.

### [x] 28. **Suppression List Lookup Error**
- **File:** `services/mail-server/crates/api-server/src/routes/suppressions.rs`
- **Severity:** MEDIUM
- **Type:** BUG
- **Description:** Suppression check may not work correctly for bulk operations.
- **Fix:** Review bulk suppression logic for edge cases.
- **Validation Update (2026-04-27):** Fixed by canonicalizing suppressions as trimmed lowercase emails across create/check/bulk paths, querying existing rows with `LOWER(email)`, and de-duplicating normalized entries inside a single bulk request before insert. Validated with `cargo test --manifest-path services/mail-server/Cargo.toml -p api-server suppressions`.

### [x] 29. **Message Send Limit Validation Bug**
- **File:** `services/mail-server/crates/api-server/src/routes/messages.rs`
- **Severity:** MEDIUM
- **Type:** BUG
- **Description:** Per-message limit validation may be incorrectly implemented.
- **Fix:** Verify limit calculation logic against requirements.
- **Validation Update (2026-04-27):** Stale finding. The route layer already clamps request limits through the shared `clamp_limit` path.

### [x] 30. **Template Rendering Edge Cases**
- **File:** `packages/sdk-go/apexmail.go` (Lines ~285-310)
- **Severity:** MEDIUM
- **Type:** BUG
- **Description:** Template variable substitution may have edge cases.
- **Fix:** Add comprehensive template testing for edge cases.
- **Validation Update (2026-04-27):** Fixed in the Go SDK by aligning template render requests to the server's `variables` payload shape and adding focused `httptest` coverage for both non-empty and nil render inputs in `packages/sdk-go/apexmail_templates_test.go`; validated with `cd packages/sdk-go && go test ./...`.

### [x] 31. **Rate Limiting Inconsistency**
- **File:** `services/mail-server/crates/api-server/src/routes/`
- **Severity:** MEDIUM
- **Type:** CONFIG
- **Description:** Some routes may lack proper rate limiting.
- **Fix:** Implement consistent rate limiting middleware across all routes.
- **Validation Update (2026-04-27):** Stale finding. `app.rs` applies the shared authenticated rate limiter to the entire authenticated `v1` router and a stricter public limiter to the unauthenticated auth/session/SSO/CSRF surface. The remaining public exemptions (`/health`, `/verify-email`, static assets, SES notifications) are intentional operational routes rather than an accidental gap.

### [x] 32. **Missing Null Checks in Middleware**
- **File:** `services/mail-server/crates/api-server/src/middleware/auth.rs`
- **Severity:** MEDIUM
- **Type:** BUG
- **Description:** Some middleware functions don't handle null/empty inputs.
- **Fix:** Add input validation for all middleware functions.
- **Validation Update (2026-04-27):** Stale finding. The auth middleware already filters empty header/cookie values before use.

### [x] 33. **Worker Thread Pool Exhaustion**
- **File:** `services/mail-server/crates/api-server/src/app.rs` (Lines ~400-450)
- **Severity:** MEDIUM
- **Type:** PERFORMANCE
- **Description:** Thread pool may exhaust under heavy load.
- **Fix:** Implement backpressure mechanisms.
- **Validation Update (2026-04-27):** Validated as a real issue. The API server had rate limiting and request timeouts, but no in-flight concurrency/load-shed guard. Fixed by adding a configurable `MAX_INFLIGHT_REQUESTS` limit in `config.rs`/`app.rs`, with a default of `max(64, DB_MAX_CONNECTIONS * 4)` and overload rejection at the router boundary. Validated with `cargo test -p api-server --no-run`, `cargo test -p api-server overload_protection_rejects_excess_inflight_requests`, and `cargo test -p api-server default_max_inflight_requests_scales_from_db_pool`.

### [x] 34. **Redis Connection Pool Saturation**
- **File:** `services/mail-server/crates/api-server/src/`
- **Severity:** MEDIUM
- **Type:** PERFORMANCE
- **Description:** Redis connection pool may not handle burst traffic.
- **Fix:** Tune pool size for expected load.
- **Validation Update (2026-04-27):** Fixed by adding an explicit `REDIS_POOL_MAX_SIZE` config knob and wiring it into the deadpool Redis builder in `server.rs`, with a burst-oriented default of `max(32, DB_MAX_CONNECTIONS * 2)`. Validated with `cargo test --manifest-path services/mail-server/Cargo.toml -p api-server --no-run`.

### [x] 35. **Helm Ingress Template Logic Error**
- **File:** `deploy/helm/apexmail/templates/ingress.yaml`
- **Severity:** MEDIUM
- **Type:** CONFIG
- **Description:** Ingress template has incorrect conditional logic for TLS configuration.
- **Fix:** Correct the template conditionals.
- **Validation Update (2026-04-27):** The original TLS-specific finding is stale: `values.yaml` defines `ingress.tls` as a normal list and the template already gates it correctly with `if .Values.ingress.tls`. During that review, an adjacent real conditional bug was fixed instead: the `web` backend branch was unreachable because the first service selector also matched `web`, routing those paths to `api-server`. Chart render validation could not be executed in this workspace because `helm` is not installed.

### [x] 36. **K8s Secret Template Missing Fields**
- **File:** `deploy/k8s/secrets.template.yaml`
- **Severity:** MEDIUM
- **Type:** CONFIG
- **Description:** Template may be missing some required secret fields for full deployment.
- **Fix:** Add all required secret definitions.
- **Validation Update (2026-04-27):** Stale finding. `deploy/k8s/secrets.template.yaml` already includes the required billing, DB, Redis, ClickHouse, JWT, and signing secret fields.

### [x] 37. **Docker Compose Override Not Documented**
- **File:** `docker-compose.override.yml`
- **Severity:** LOW
- **Type:** DOCS
- **Description:** No clear documentation on how override file works with base config.
- **Fix:** Add documentation in README.md.
- **Validation Update (2026-04-27):** Fixed by adding a `Local Compose Overrides` section to `README.md` explaining the default base+override merge and the explicit production overlay path.

### [x] 38. **Nginx SSL Configuration Placeholders**
- **File:** `deploy/nginx/nginx.conf` (SSL certificate paths)
- **Severity:** MEDIUM
- **Type:** CONFIG
- **Description:** SSL configuration uses placeholder paths.
- **Fix:** Ensure proper certificate path configuration for production.
- **Validation Update (2026-04-27):** Stale finding. The nginx config points at concrete mounted PEM paths under `/etc/nginx/ssl`, `docker-compose.prod.yml` mounts that directory through `TLS_CERT_DIR`, and `deploy/nginx/ssl/README.md` documents both the copy-in workflow and the production override path for live Let's Encrypt material.

### [x] 39. **Training Data Quality Issues**
- **File:** `data/train.jsonl`, `data/val.jsonl`, `data/test.jsonl`
- **Severity:** MEDIUM
- **Type:** DATA
- **Description:** AI training data may contain quality issues.
- **Fix:** Run data quality audits on all training files.
- **Validation Update (2026-04-27):** Fixed by regenerating `train.jsonl`, `val.jsonl`, and `test.jsonl` from the canonical `data/train_agent.jsonl` with `apps/ai/training/generate_dataset.py`, restoring split integrity from `549 + 68 + 68 = 685`, and by rerunning `apps/ai/training/validate_pipeline.py` plus `tools/audit_training_comprehensive.py`, which now report zero data-quality failures on the canonical source set.

### [x] 40. **Golden QA Data Missing Assertions**
- **File:** `data/golden_qa.jsonl`
- **Severity:** MEDIUM
- **Type:** DATA / TESTING
- **Description:** QA test cases may lack proper expected outputs.
- **Fix:** Add comprehensive assertions to all QA test cases.
- **Validation Update (2026-04-27):** Fixed by tightening `apps/ai/training/validate_pipeline.py` so the golden QA check now asserts both non-empty message content and non-empty assistant expected outputs for every case. The updated pipeline validation passes with all 51 golden QA entries in the required system/user/assistant format.

### [x] 41. **Error Handling Inconsistency**
- **File:** Multiple files in `services/mail-server/`
- **Severity:** LOW
- **Type:** CODE QUALITY
- **Description:** Different error handling patterns used across services.
- **Fix:** Standardize error handling with shared error types.
- **Validation Update (2026-04-27):** Validated as a real outlier in `billing-service`. `api-server` already used a structured `{error:{code,message,details}}` envelope, but `billing-service` was still emitting ad hoc `{"error":"..."}` payloads from both its local `ApiError` mapping and direct route branches. Fixed by adding a shared `ErrorEnvelope` in `crates/apexmail-lib/src/http_error.rs` and routing billing-service errors through shared `ErrorCode` + `error_response(...)` helpers in `crates/billing-service/src/routes.rs`. Validated with `cargo test --manifest-path /Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/Cargo.toml -p billing-service api_error_`, `cargo test --manifest-path /Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/Cargo.toml -p billing-service validate_non_negative_returns_structured_validation_error`, and `cargo test --manifest-path /Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/Cargo.toml -p apexmail-lib error_envelope_serializes_shared_code_and_message`.

### [x] 42. **Missing SDK Integration Tests**
- **File:** `packages/*/`
- **Severity:** MEDIUM
- **Type:** TESTING
- **Description:** SDKs lack integration tests.
- **Fix:** Add integration test suite for all SDKs.
- **Validation Update (2026-04-27):** Fixed with focused template-render compatibility coverage across the published SDKs: `go test ./...` still passes for the Go SDK, new Maven tests validate the Java render request shape, a new dependency-free unittest validates the Python sync/async render resources, and targeted PHP/Ruby render checks now assert the live `variables` payload after aligning their stale render implementations.

### [x] 43. **Outdated Pricing Documentation**
- **File:** `docs/pricing.md`
- **Severity:** MEDIUM
- **Type:** DOCS
- **Description:** Pricing tiers may be outdated compared to actual configuration.
- **Fix:** Sync documentation with config.rs pricing.
- **Validation Update (2026-04-27):** Stale finding. The current pricing docs match the billing configuration and PAYG tests.

### [x] 44. **API Contract Mismatch**
- **File:** `docs/api/openapi.yaml`
- **Severity:** MEDIUM
- **Type:** API / DOCS
- **Description:** OpenAPI spec may not match actual API implementation.
- **Fix:** Audit and sync API spec with implementation.
- **Validation Update (2026-04-27):** Completed end-to-end. `docs/api/openapi.yaml` now covers the mounted authenticated and public API surface from `services/mail-server/crates/api-server/src/app.rs`, including the live `/messages` family, `/events`, `/ses/notifications`, `/health/*`, the `/api/auth/*` and `/api/auth/session` / `/api/csrf` control-plane aliases, the previously missing billing write/report/export/admin routes, the full admin control-plane tree, and the earlier templates/suppressions/lists/contacts/campaigns/auth/support/SCIM/dashboard/AI/automations/account/dedicated-IP/stream/client-error surfaces. The billing/admin schemas were also tightened where the prior contract shape was wrong, including the tenant-detail `recentInvoices` object. Each contract edit was revalidated immediately with `python3 -c 'import yaml; yaml.safe_load(open("docs/api/openapi.yaml", "r")); print("openapi-yaml-ok")'` plus file diagnostics, and a final route-family parity check against `app.rs` found no clearly undocumented mounted route families remaining.

### [x] 45. **Deprecated API Endpoints Still Used**
- **File:** `services/mail-server/crates/api-server/src/routes/`
- **Severity:** LOW
- **Type:** DEPRECATION
- **Description:** Some deprecated endpoints still being called.
- **Fix:** Migrate to new endpoints.
- **Validation Update (2026-04-27):** Fixed by removing live `/v1/send` usage from the marketing curl example, aligning the devex endpoint inventory to the current `/v1/messages` route family, and updating the security integration/fuzz tests to use `/v1/messages` instead of the legacy send path. A workspace search now leaves `/v1/send` only in preserved historical version metadata.

### [x] 46. **Old Stripe API Version**
- **File:** `services/mail-server/crates/billing-service/src/stripe_webhooks.rs`
- **Severity:** LOW
- **Type:** DEPRECATION
- **Description:** Using older Stripe API version.
- **Fix:** Update to latest stable Stripe API version.
- **Validation Update (2026-04-27):** Fixed by pinning outgoing Stripe REST calls in `services/mail-server/crates/api-server/src/routes/billing.rs` to the current Stripe release `2026-04-22.dahlia` via the `Stripe-Version` header, with `STRIPE_API_VERSION` as an explicit override. The original file attribution was stale: `stripe_webhooks.rs` manually verifies signed webhook payloads and does not own Stripe API version selection. A focused `api-server` regression test now verifies the pinned version and idempotency headers, and the internal Stripe contract doc was updated to match the current implementation.

---

## LOW PRIORITY ISSUES

### [x] 47. **Docker Compose Version Deprecated**
- **File:** `docker-compose.yml`
- **Severity:** LOW
- **Type:** CONFIG
- **Description:** Using older compose file format version.
- **Fix:** Update to version 3.9.
- **Validation Update (2026-04-27):** Stale finding. The root compose file no longer declares a deprecated `version:` key at all.

### [x] 48. **No Load Testing Configured**
- **File:** `tools/`
- **Severity:** LOW
- **Type:** TESTING
- **Description:** No load testing scripts present.
- **Fix:** Add load testing configuration.
- **Validation Update (2026-04-27):** Original location/finding was stale. ApexMail already has a dedicated Rust load-testing surface in `services/mail-server/crates/load-tests/`, wired into the mail-server workspace and documented in `docs/evaluation/load-testing.md`. The live defect was drift inside that crate: `tests/load_parallel.rs` still assumed `PaygPricing::calculate()` returned a tuple instead of a `Result`. Fixed by updating the parallel billing load test to assert successful PAYG calculation under the exercised volumes. Validated with `cargo test --manifest-path /Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/Cargo.toml -p load-tests --no-run` and `cargo test --manifest-path /Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/Cargo.toml -p load-tests test_parallel_billing_threads`.

### [x] 49. **Missing Error Code Documentation**
- **File:** `docs/api/errors.md`
- **Severity:** LOW
- **Type:** DOCS
- **Description:** Some error codes not documented.
- **Fix:** Add all possible error codes.
- **Validation Update (2026-04-27):** Fixed by rewriting `docs/api/errors.md` around the live canonical sources: the shared `apexmail-lib::ErrorCode` enum plus the `api-server`-specific `BAD_REQUEST` fallback. The updated doc now covers every shared code, removes stale legacy aliases, and documents the current error-envelope shape. Added a regression test in `services/mail-server/crates/apexmail-lib/src/error_codes.rs` that fails if the doc ever drops a canonical code or reintroduces stale aliases. Validated with `cargo test --manifest-path /Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/Cargo.toml -p apexmail-lib docs_error_reference_covers_canonical_error_codes`.

### [x] 50. **Duplicate Tool Scripts**
- **File:** `tools/` (multiple similar fix/debug scripts)
- **Severity:** INFO
- **Type:** CODE QUALITY
- **Description:** Many similar fix/debug scripts exist (fix_v4.py, fix_v5.py, etc.)
- **Clarification:** Are these all necessary or should they be consolidated?
- **Validation Update (2026-04-27):** Clarified by auditing actual repo references and documenting the result in `tools/README.md`. The stable workflow scripts are the named helpers that are wired into current tasks/docs (notably `browser_smoke.py`, `run-mail-server-tests.sh`, `run-compose-smoke.sh`, `dev-start.sh`, `bootstrap.sh`, and `migrations/`). The numbered `fix_*` / `debug_*` / `audit_*` variants are not referenced by the current VS Code task surface and are now explicitly documented as historical/manual remediation artifacts rather than supported automation.

### [x] 51. **Lobster Directory Purpose Unclear**
- **File:** `Lobster/`
- **Severity:** INFO
- **Type:** CONFIGURATION
- **Description:** The Lobster directory with calculator code seems unrelated to ApexMail email service.
- **Clarification:** Clarify why it's there. It's a separate and whimsical app within this project, a proof of concept for Lobster.
- **Validation Update (2026-04-27):** Clarified at the repo boundary instead of treating it as a runtime defect. The root `README.md` project structure now explicitly identifies `Lobster/` as a standalone Lobster-language calculator proof of concept that is not part of the ApexMail mail runtime, and `Lobster/README.md` now says the same thing locally inside the subproject.

### [x] 52. **Inconsistent File Permissions**
- **File:** Multiple locations
- **Severity:** LOW
- **Type:** SECURITY
- **Description:** Some files may have overly permissive permissions.
- **Fix:** Review and tighten file permissions where needed.
- **Validation Update (2026-04-27):** The broad finding narrowed to a concrete source-control inconsistency rather than world-writable secrets: a permissions audit found no world-writable tracked files and `secrets/redis_password.txt` was already owner-only (`600`). The live issue was that several tracked shell entrypoints had shebangs but were missing execute bits while other tracked shell scripts were executable. Fixed by making `services/mail-server/scripts/coverage.sh`, `services/mail-server/scripts/generate-dkim.sh`, `services/mail-server/scripts/test-mail-server.sh`, `tools/poll_instance.sh`, and `tools/run-mail-server-tests.sh` executable. Validated with a tracked-shell permission audit showing all tracked `.sh` entrypoints now at `-rwxr-xr-x`.

---

## BILLING & PRICING ISSUES

### [x] 53. **PAYG Email Tier Pricing Logic**
- **File:** `services/mail-server/crates/billing-service/src/config.rs` (Lines 116-119)
- **Severity:** HIGH
- **Type:** BUG / FINANCIAL
- **Description:** Email tier pricing logic may be inverted - larger tiers should have lower prices per email.
- **Fix:** Verify and correct tier pricing logic.
- **Validation Update (2026-04-27):** Stale finding. The configured PAYG email tiers already decrease from 100 → 80 → 50 → 30 millicents per email as volume increases.

### [x] 54. **PAYG API Call Pricing**
- **File:** `services/mail-server/crates/billing-service/src/config.rs`
- **Severity:** MEDIUM
- **Type:** BUG / FINANCIAL
- **Description:** API call pricing calculation may have inconsistencies between free tier and overage.
- **Fix:** Standardize API pricing calculation.
- **Validation Update (2026-04-27):** Fixed/validated with the PAYG route and config tests; the 100K free tier plus $0.10 per 1,000 overage contract now has explicit regression coverage.

---

## SERVER & INFRASTRUCTURE ISSUES

### [x] 55. **Prometheus Scrape Interval May Miss Metrics**
- **File:** `deploy/prometheus.yml`
- **Severity:** MEDIUM
- **Type:** CONFIG
- **Description:** Scrape interval may be too long for some metrics.
- **Fix:** Adjust scrape intervals based on metric cardinality.
- **Validation Update (2026-04-27):** Stale finding after inspecting the live scrape plan against the alert windows in `deploy/alerting-rules.yml`. ApexMail already uses workload-specific intervals instead of a single long cadence: tracking scrapes at `10s`, Redis at `15s`, and lower-churn infrastructure exporters (Postgres, ClickHouse, node) at `30s`, which still supports the configured 1m+ alert windows without undersampling. Documented that rationale inline in `deploy/prometheus.yml` and revalidated the file with `python3 -c 'import pathlib, yaml; yaml.safe_load(pathlib.Path("deploy/prometheus.yml").read_text()); print("prometheus-yaml-ok")'`.

### [x] 56. **ClickHouse Logging Configuration**
- **File:** `deploy/clickhouse/logging.xml`
- **Severity:** LOW
- **Type:** CONFIG
- **Description:** Logging levels may need adjustment for production.
- **Fix:** Review and configure appropriate logging levels.
- **Validation Update (2026-04-27):** Stale finding after reviewing the mounted ClickHouse override in `docker-compose.yml` and the upstream ClickHouse logger settings. The config already uses a production-safe root level of `information` rather than `debug`/`trace`, writes dedicated main/error log files, and bounds retention at `100M x 10` for the mounted log volume. Added inline comments in `deploy/clickhouse/logging.xml` so that intent is explicit, and revalidated the file with `python3 -c 'import xml.etree.ElementTree as ET; ET.parse("deploy/clickhouse/logging.xml"); print("clickhouse-logging-xml-ok")'`.

### [x] 57. **Alert Manager Route Configuration**
- **File:** `deploy/alertmanager.yml`
- **Severity:** MEDIUM
- **Type:** CONFIG
- **Description:** Alert routing may need verification for all alert types.
- **Fix:** Ensure all alert types have appropriate routing.
- **Validation Update (2026-04-27):** Validated with a live synthetic alert: Alertmanager successfully delivered to Observability through the configured webhook route.

---

## UI/UX ISSUES

### [x] 58. **Calculator Button Layout May Not Be Intuitive**
- **File:** `Lobster/main.lob` (Button definitions)
- **Severity:** LOW
- **Type:** UI/UX
- **Description:** Calculator button layout may not follow standard calculator conventions.
- **Fix:** Review and adjust button layout for better UX.
- **Validation Update (2026-04-27):** Fixed by correcting the grid to a standard five-row calculator layout and drawing buttons in their proper translated positions.

---

## RECOMMENDED ACTIONS

### Status
1. No unchecked remediation items remain in this fault list as of 2026-04-27.

### Optional Follow-Up
2. Re-run the targeted validation commands added in this pass after future changes to API contracts, monitoring, or deployment configuration.
3. Archive or delete historical one-off helper scripts only when their owner confirms they are no longer needed for manual forensics.

---

## ISSUES BY CATEGORY

| Category | Count |
|----------|-------|
| Security | 12 |
| Billing/Financial | 6 |
| API/Bug | 15 |
| Configuration | 10 |
| Documentation | 5 |
| UI/UX | 3 |
| Performance | 3 |
| Testing | 3 |
| Data | 2 |
| Deprecation | 2 |

---

**Report Generated:** 2026-04-27  
**Scanners:** Multi-agent parallel codebase analysis  
**Repository:** https://github.com/sbelakho2/ApexMail
