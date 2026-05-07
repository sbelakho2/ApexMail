# ApexMail API Route Audit Report

**Generated:** May 1, 2026  
**Purpose:** Current route and UI-surface readiness check

## Current Source Of Truth

ApexMail no longer uses the historical `apps/web`, `apps/control-plane`, or `apps/user-console` React/Next.js frontends. Browser surfaces are represented by the Rust UI migration in `services/mail-server/crates/ui-foundation/` and are mounted through the API server's Axum router.

The current source-of-truth files are:

- `services/mail-server/crates/api-server/src/app.rs` for API route mounting.
- `services/mail-server/crates/api-server/src/routes/` for route modules and handlers.
- `services/mail-server/crates/ui-foundation/src/routing.rs` for migrated browser route declarations.
- `services/mail-server/crates/ui-foundation/src/ssr.rs` and `src/axum_router.rs` for Rust SSR route coverage.
- `docs/development/ui-baseline-manifest.json` for the browser route contract.

## Browser Surface Migration Status

The former frontend apps have been replaced by the Rust SSR migration contract rather than restored as separate app directories.

| Surface | Current implementation | Verification |
|---------|------------------------|--------------|
| Web dashboard | `ui-foundation` web surface routes | `migration_all_93_routes_have_view_functions` |
| Control plane | `ui-foundation` control-plane surface routes | `migration_all_93_routes_have_view_functions` |
| Marketing | Zola templates plus Rust route manifest coverage | `migration_all_93_routes_have_view_functions` |
| Marketing Zola output | `apps/marketing-zola` templates and generated public output | visual parity task artifacts under `reports/visual-parity/` |

The route manifest currently declares 93 browser routes across `web`, `control-plane`, `marketing`, and `marketing-zola`; the migration tests assert that every declared route has a renderer.

## API Server Mounted Routes

The API server mounts these authenticated route families under `/v1`:

| Resource | Prefix | Module |
|----------|--------|--------|
| Messages | `/v1/messages` | `routes::messages` |
| Domains | `/v1/domains` | `routes::domains` |
| Templates | `/v1/templates` | `routes::templates` |
| Suppressions | `/v1/suppressions` | `routes::suppressions` |
| Events | `/v1/events` | `routes::events` |
| Webhooks | `/v1/webhooks` | `routes::webhooks` |
| Analytics | `/v1/analytics` | `routes::analytics` |
| Support | `/v1/support` | `routes::support` |
| SCIM | `/v1/scim` | `routes::scim` |
| Billing | `/v1/billing` | `routes::billing` |
| Campaigns | `/v1/campaigns` | `routes::campaigns` |
| Contacts | `/v1/contacts` | `routes::contacts` |
| Lists | `/v1/lists` | `routes::lists` |
| Dashboard | `/v1/dashboard` | `routes::dashboard` |
| Client errors | `/v1/client-errors` | `routes::client_errors` |
| Automations | `/v1/automations` | `routes::automations` |
| AI insights | `/v1/ai` | `routes::ai_insights` |
| Dedicated IPs | `/v1/dedicated-ips` | `routes::dedicated_ips` |
| Account | `/v1/account` | `routes::account` |
| Stream tokens | `/v1/stream` | `routes::stream_tokens` |

Public and auth-related route families are mounted separately under `/health`, `/v1/auth`, `/v1/auth/session`, `/v1/auth/forgot-password`, `/v1/auth/sso`, `/v1/auth/csrf`, `/api/auth`, `/api/auth/session`, `/api/csrf`, and `/v1/ses`.

## Enterprise Service Routes

The Enterprise service is built from `services/mail-server/crates/enterprise/src/routes.rs`. Private deployment and BYOIP lifecycle routes are documented in `docs/api/openapi.yaml` under `/enterprise/v1/*` and in `docs/enterprise/private-cloud.md` for operator/customer workflows.

| Resource | Prefix | Backing service |
|----------|--------|-----------------|
| Private deployments | `/enterprise/v1/deployments` | `PrivateDeployService::create` |
| Private deployment detail | `/enterprise/v1/deployments/:id` | `PrivateDeployService::get` |
| Tenant deployment list | `/enterprise/v1/deployments/tenant/:tenant_id` | `PrivateDeployService::list` |
| Provisioning lifecycle | `/enterprise/v1/deployments/:id/provision` | `PrivateDeployService::provision` |
| Deployment health | `/enterprise/v1/deployments/:id/health` | `PrivateDeployService::health_check` |
| Enterprise dedicated IP allocation | `/enterprise/v1/ips/allocate` | `PrivateDeployService::allocate_dedicated_ip` |
| Enterprise dedicated IP detail | `/enterprise/v1/ips/:id` | `PrivateDeployService::get_dedicated_ip` |
| Tenant dedicated IP list | `/enterprise/v1/ips/tenant/:tenant_id` | `PrivateDeployService::list_dedicated_ips` |
| Dedicated IP reputation | `/enterprise/v1/ips/reputation/:ip_address` | `PrivateDeployService::get_ip_reputation` |
| BYOIP registration | `/enterprise/v1/ips/byoip` | `PrivateDeployService::register_byoip` |
| BYOIP verification | `/enterprise/v1/ips/byoip/:id/verify` | `PrivateDeployService::verify_byoip` |

## Admin And Control-Plane Routes

The control-plane API surface is implemented as authenticated admin route modules under `/v1/admin`:

| Prefix | Module |
|--------|--------|
| `/v1/admin/tenants` | `routes::admin::tenants` |
| `/v1/admin/features` | `routes::admin::features` |
| `/v1/admin/gdpr` | `routes::admin::gdpr` |
| `/v1/admin/secrets` | `routes::admin::secrets` |
| `/v1/admin/audit` | `routes::admin::audit` |
| `/v1/admin/dashboard` | `routes::admin::dashboard` |
| `/v1/admin/compliance` | `routes::admin::compliance_overview` |
| `/v1/admin/risk` | `routes::admin::risk` |
| `/v1/admin/revenue` | `routes::admin::revenue` |
| `/v1/admin/inbox` | `routes::admin::inbox` |
| `/v1/admin/calendar` | `routes::admin::calendar` |
| `/v1/admin/warmup` | `routes::admin::warmup` |
| `/v1/admin/content` | `routes::admin::content` |
| `/v1/admin/autopilot` | `routes::admin::autopilot` |
| `/v1/admin/proxy` | `routes::admin::proxy` |
| `/v1/admin/sales` | `routes::admin::sales` |
| `/v1/admin/analytics` | `routes::admin::analytics` |
| `/v1/admin/analytics/export` | `routes::admin::analytics_export` |
| `/v1/admin/campaigns` | `routes::admin::campaigns` |
| `/v1/admin/crm/leads` | `routes::admin::crm_leads` |
| `/v1/admin/leads/discovery` | `routes::admin::leads_discovery` |
| `/v1/admin/support` | `routes::admin::support` |
| `/v1/admin/support/analytics` | `routes::admin::support_analytics` |
| `/v1/admin/system/health` | `routes::admin::system_health` |

## Retired Audit Findings

Older audit rows that referenced TypeScript files under `apps/web/src/` or `apps/control-plane/src/` are retired because those files are not part of the current product surface. The replacement verification is the Rust SSR route manifest and migration test suite.

The route families called out by the retired audit are now either mounted directly or represented by the current Rust modules:

- `/v1/lists/*` is mounted through `routes::lists`.
- `/v1/dashboard/*` is mounted through `routes::dashboard` for user dashboard data and `/v1/admin/dashboard/*` for control-plane data.
- `/v1/ai/*` is mounted through `routes::ai_insights`.
- Contact, template, domain, campaign, and support route coverage is owned by the corresponding Rust route modules listed above.

## Verification Commands

Use these checks when route wiring changes:

```bash
cargo test --manifest-path services/mail-server/Cargo.toml -p ui-foundation migration_all_93_routes_have_view_functions
cargo test --manifest-path services/mail-server/Cargo.toml -p api-server --lib routes
```

The `api-server` route check may require local PostgreSQL/Redis fixtures for DB-backed handlers; the UI route coverage test is pure Rust and should remain fast.