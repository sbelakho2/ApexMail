# Current Application Route Inventory

Validated: April 14, 2026

## Scope

This document captures the current Rust application route inventory for the UI and backend only.

Included:
- services/mail-server/crates/api-server
- services/mail-server/crates/ui-foundation
- docs/development/ui-baseline-manifest.json

Excluded:
- product SDKs
- billing service route inventory

## Validation Status

The current backend inventory was validated with the full api-server crate test sweep against a disposable local Postgres instance:

```sh
cd services/mail-server
DATABASE_URL=postgres://apexmail:apexmail@127.0.0.1:5435/apexmail \
TEST_DATABASE_URL=postgres://apexmail:apexmail@127.0.0.1:5435/apexmail \
cargo test -p api-server
```

Result on April 14, 2026:
- 114 tests passed
- 0 tests failed

The app-level router contract tests that directly cover the migrated UI and auth surface are in services/mail-server/crates/api-server/src/app.rs and verify:
- migrated UI route rendering
- auth session and CSRF aliases
- invalid-input auth behavior
- browser /verify-email rendering
- logout wiring and POST-only auth aliases
- fallback and null-byte behavior

## Backend Route Inventory

### Public exact routes in app.rs

| Method | Path | Notes |
|---|---|---|
| GET | /verify-email | Browser verify-email page rendered by the Rust UI router |

### Public mounted prefixes in app.rs

| Prefix | Source |
|---|---|
| /health | services/mail-server/crates/api-server/src/routes/health.rs |
| /v1/ses | services/mail-server/crates/api-server/src/routes/ses_notifications.rs |
| /v1/auth | services/mail-server/crates/api-server/src/routes/auth.rs |
| /v1/auth/session | services/mail-server/crates/api-server/src/routes/session.rs |
| /v1/auth/forgot-password | services/mail-server/crates/api-server/src/routes/forgot_password.rs |
| /v1/auth/sso | services/mail-server/crates/api-server/src/routes/sso.rs |
| /v1/auth/csrf | services/mail-server/crates/api-server/src/routes/csrf.rs |
| /api/auth | services/mail-server/crates/api-server/src/routes/auth.rs control-plane alias router |
| /api/auth/session | services/mail-server/crates/api-server/src/routes/session.rs |
| /api/csrf | services/mail-server/crates/api-server/src/routes/csrf.rs |

### Expanded public auth and browser routes

Routes mounted under /v1/auth are public at the router boundary for login, registration, refresh, browser verification, and alias compatibility. Some endpoints under the same prefix enforce an authenticated user inside the handler.

| Method | Path | Source |
|---|---|---|
| POST | /v1/auth/login | auth.rs |
| POST | /v1/auth/register | auth.rs |
| POST | /v1/auth/signup | auth.rs |
| GET | /v1/auth/verify-email | auth.rs |
| POST | /v1/auth/reset-password | auth.rs |
| POST | /v1/auth/api-keys | auth.rs |
| GET | /v1/auth/api-keys | auth.rs |
| DELETE | /v1/auth/api-keys/:id | auth.rs |
| POST | /v1/auth/logout | auth.rs |
| POST | /v1/auth/refresh | auth.rs |
| POST | /v1/auth/change-password | auth.rs |
| POST | /v1/auth/sessions/revoke | auth.rs |
| GET | /v1/auth/session/ | session.rs |
| POST | /v1/auth/forgot-password/ | forgot_password.rs |
| GET | /v1/auth/csrf/ | csrf.rs |
| GET | /v1/auth/sso/google | sso.rs |
| GET | /v1/auth/sso/github | sso.rs |
| GET | /v1/auth/sso/google/callback | sso.rs |
| GET | /v1/auth/sso/github/callback | sso.rs |
| POST | /api/auth/login | auth.rs control-plane alias router |
| POST | /api/auth/logout | auth.rs control-plane alias router |
| POST | /api/auth/refresh | auth.rs control-plane alias router |
| GET | /api/auth/session/ | session.rs |
| GET | /api/csrf/ | csrf.rs |

### Authenticated application mounts in app.rs

| Prefix | Source |
|---|---|
| /v1/messages | routes::messages |
| /v1/domains | routes::domains |
| /v1/templates | routes::templates |
| /v1/suppressions | routes::suppressions |
| /v1/events | routes::events |
| /v1/webhooks | routes::webhooks |
| /v1/analytics | routes::analytics |
| /v1/support | routes::support |
| /v1/scim | routes::scim |
| /v1/campaigns | routes::campaigns |
| /v1/contacts | routes::contacts |
| /v1/lists | routes::lists |
| /v1/dashboard | routes::dashboard |
| /v1/client-errors | routes::client_errors |
| /v1/automations | routes::automations |
| /v1/ai | routes::ai_insights |
| /v1/dedicated-ips | routes::dedicated_ips |
| /v1/account | routes::account |
| /v1/stream | routes::stream_tokens |
| /v1/auth/impersonate | routes::impersonate |
| /v1/auth/telemetry | routes::telemetry |
| /v1/admin/tenants | routes::admin::tenants |
| /v1/admin/features | routes::admin::features |
| /v1/admin/gdpr | routes::admin::gdpr |
| /v1/admin/secrets | routes::admin::secrets |
| /v1/admin/audit | routes::admin::audit |
| /v1/admin/dashboard | routes::admin::dashboard |
| /v1/admin/compliance | routes::admin::compliance_overview |
| /v1/admin/risk | routes::admin::risk |
| /v1/admin/revenue | routes::admin::revenue |
| /v1/admin/inbox | routes::admin::inbox |
| /v1/admin/calendar | routes::admin::calendar |
| /v1/admin/warmup | routes::admin::warmup |
| /v1/admin/content | routes::admin::content |
| /v1/admin/autopilot | routes::admin::autopilot |
| /v1/admin/proxy | routes::admin::proxy |
| /v1/admin/sales | routes::admin::sales |
| /v1/admin/analytics | routes::admin::analytics |
| /v1/admin/analytics/export | routes::admin::analytics_export |
| /v1/admin/campaigns | routes::admin::campaigns |
| /v1/admin/crm/leads | routes::admin::crm_leads |
| /v1/admin/leads/discovery | routes::admin::leads_discovery |
| /v1/admin/support | routes::admin::support |
| /v1/admin/support/reply | routes::admin::support |
| /v1/admin/support/analytics | routes::admin::support_analytics |
| /v1/admin/system/health | routes::admin::system_health |

## Rust UI Surface Inventory

Source of truth: docs/development/ui-baseline-manifest.json and services/mail-server/crates/ui-foundation/src/routing.rs

Total manifest-backed Rust UI routes: 92

### Web surface

Public routes:
- /
- /login
- /signup
- /forgot-password
- /reset-password
- /verify-email

Authenticated routes:
- /dashboard
- /campaigns
- /campaigns/new
- /campaigns/c_1
- /campaigns/c_1/edit
- /contacts
- /contacts/new
- /lists
- /lists/new
- /templates
- /templates/new
- /reports
- /reports/deliverability
- /analytics
- /events
- /domains
- /domains/new
- /settings
- /settings/api-keys
- /settings/team
- /settings/billing
- /settings/dedicated-ips
- /settings/webhooks
- /settings/profile

### Control-plane surface

Public routes:
- /login

Authenticated routes:
- /
- /dashboard
- /tenants
- /tenants/new
- /audit
- /analytics
- /operators
- /operators/new
- /discovery
- /jobs
- /infrastructure
- /infrastructure/nodes
- /infrastructure/queues
- /domains
- /billing
- /billing/plans
- /compliance
- /compliance/gdpr
- /alerts
- /alerts/rules
- /settings
- /settings/security

### Marketing surface

All routes are public:
- /
- /pricing
- /pricing/calculator
- /features
- /compliance
- /private-cloud
- /api-console
- /case-studies
- /forensic
- /status
- /compare/postmark
- /compare/resend
- /compare/sendgrid
- /terms
- /privacy
- /cookies
- /acceptable-use
- /dpa
- /sla

### Marketing-zola surface

All routes are public:
- /
- /pricing
- /pricing/calculator
- /features
- /compliance
- /private-cloud
- /api-console
- /case-studies
- /forensic
- /status
- /compare
- /compare/postmark
- /compare/resend
- /compare/sendgrid
- /terms
- /privacy
- /cookies
- /acceptable-use
- /dpa
- /sla

## Source Files

Current route ownership is anchored in:
- services/mail-server/crates/api-server/src/app.rs
- services/mail-server/crates/api-server/src/routes/auth.rs
- services/mail-server/crates/api-server/src/routes/session.rs
- services/mail-server/crates/api-server/src/routes/forgot_password.rs
- services/mail-server/crates/api-server/src/routes/csrf.rs
- services/mail-server/crates/api-server/src/routes/sso.rs
- services/mail-server/crates/ui-foundation/src/routing.rs
- docs/development/ui-baseline-manifest.json
