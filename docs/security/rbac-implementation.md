# RBAC Implementation Analysis — ApexMail

**Generated:** February 27, 2026
**Scope:** Backend API Server, Web App, Control Plane

---

## 1. Overview

ApexMail implements Role-Based Access Control (RBAC) through a **scope-based permission system** combined with **role-based scope assignment**. The system has two parallel RBAC implementations:

1. **Customer API** (Rust backend) — Scope-based authorization
2. **Control Plane** (Admin dashboard) — Role-level authorization

---

## 2. User Roles & Scope Assignments

### 2.1 Customer Dashboard Roles (`web` Surface)

| Role | Assigned Scopes | Description |
|------|----------------|-------------|
| **owner** | `*` (wildcard) | Full access to all operations |
| **admin** | `*` (wildcard) | Full access to all operations |
| **developer** | `messages:send`, `messages:read`, `domains:read`, `templates:read`, `templates:write`, `events:read`, `analytics:read`, `contacts:read`, `contacts:write` | Can send/read messages, manage templates and contacts |
| **viewer** | `messages:read`, `domains:read`, `templates:read`, `events:read`, `analytics:read`, `contacts:read` | Read-only access |
| **member** (default) | `messages:read` | Minimal read access |

**Source:** [auth.rs](../services/mail-server/crates/api-server/src/routes/auth.rs#L130-L159)

```rust
// Fix #24: Assign scopes based on user role instead of blanket wildcard.
let scopes = match user.role.as_str() {
    "admin" | "owner" => vec!["*".into()],
    "developer" => vec![
        "messages:send", "messages:read", "domains:read", "templates:read",
        "templates:write", "events:read", "analytics:read", "contacts:read", "contacts:write"
    ],
    "viewer" => vec![
        "messages:read", "domains:read", "templates:read", "events:read",
        "analytics:read", "contacts:read"
    ],
    _ => vec!["messages:read".into()],
};
```

### 2.2 Current Role Profiles

The Rust auth layer maps user roles to scopes rather than applying a separate rank-based control-plane middleware.

| Role | Effective Access |
|------|------------------|
| **viewer** | Read-only scopes for messages, domains, templates, events, analytics, and contacts |
| **developer** | Viewer scopes plus send/write access for messages, templates, and contacts |
| **admin** | Wildcard access via `*` |
| **owner** | Wildcard access via `*` |
| **fallback/member** | Minimal access via `messages:read` |

**Source:** [routes/auth.rs](../services/mail-server/crates/api-server/src/routes/auth.rs#L37-L56)

---

## 3. API Scopes Reference

### 3.1 Complete Scope Matrix

| Scope | Read Operations | Write Operations |
|-------|-----------------|------------------|
| `messages:send` | — | Send single/batch messages, cancel scheduled messages |
| `messages:read` | List messages, get message details | — |
| `domains:read` | List domains, get domain, get DNS records | — |
| `domains:write` | — | Create domain, delete domain, verify domain |
| `templates:read` | List templates, get template, render preview | — |
| `templates:write` | — | Create template, update template, delete template |
| `contacts:read` | List contacts, get contact | — |
| `contacts:write` | — | Create contact, update contact, delete contact, bulk import |
| `events:read` | List events, get event, stats, timeseries | — |
| `analytics:read` | Dashboard stats, campaign analytics, bounce insights, delivery trends, geographic distribution, provider breakdown | — |
| `webhooks:read` | List webhooks, get webhook | — |
| `webhooks:write` | — | Create webhook, update webhook, delete webhook, rotate secret |
| `suppressions:read` | List suppressions, export suppressions | — |
| `suppressions:write` | — | Add suppression, remove suppression, bulk import |
| `campaigns:read` | List campaigns, get campaign | — |
| `campaigns:write` | — | Create campaign, delete campaign, pause/resume campaign |
| `automations:read` | List automations, get automation | — |
| `automations:write` | — | Create, update, delete, enable/disable automation |
| `support:read` | List tickets, get ticket | — |
| `support:write` | — | Create ticket, reply to ticket |
| `dedicated_ips:read` | List IPs | — |
| `dedicated_ips:write` | — | Provision IP, release IP, configure warmup |
| `scim:read` | SCIM user/group discovery | — |
| `scim:write` | — | SCIM provisioning operations |
| `ai:read` | AI insights, predictions, recommendations, anomaly detection | — |
| `*` | All read operations | All write operations (wildcard) |

---

## 4. Protected Routes & Scope Requirements

### 4.1 Messages (`/v1/messages`)

| Endpoint | Method | Required Scope | Handler |
|----------|--------|----------------|---------|
| `/` | POST | `messages:send` | `send_message` |
| `/batch` | POST | `messages:send` | `send_batch` |
| `/` | GET | `messages:read` | `list_messages` |
| `/:id` | GET | `messages:read` | `get_message` |
| `/:id/cancel` | POST | `messages:send` | `cancel_message` |

### 4.2 Domains (`/v1/domains`)

| Endpoint | Method | Required Scope | Handler |
|----------|--------|----------------|---------|
| `/` | POST | `domains:write` | `create_domain` |
| `/` | GET | `domains:read` | `list_domains` |
| `/:id` | GET | `domains:read` | `get_domain` |
| `/:id` | DELETE | `domains:write` | `delete_domain` |
| `/:id/verify` | POST | `domains:write` | `verify_domain` |
| `/:id/dns-records` | GET | `domains:read` | `get_dns_records` |

### 4.3 Templates (`/v1/templates`)

| Endpoint | Method | Required Scope | Handler |
|----------|--------|----------------|---------|
| `/` | POST | `templates:write` | `create_template` |
| `/` | GET | `templates:read` | `list_templates` |
| `/:id` | GET | `templates:read` | `get_template` |
| `/:id` | PUT | `templates:write` | `update_template` |
| `/:id` | DELETE | `templates:write` | `delete_template` |
| `/:id/render` | POST | `templates:read` | `render_preview` |

### 4.4 Contacts (`/v1/contacts`)

| Endpoint | Method | Required Scope | Handler |
|----------|--------|----------------|---------|
| `/` | POST | `contacts:write` | `create_contact` |
| `/` | GET | `contacts:read` | `list_contacts` |
| `/:id` | GET | `contacts:read` | `get_contact` |
| `/:id` | PUT | `contacts:write` | `update_contact` |
| `/:id` | DELETE | `contacts:write` | `delete_contact` |
| `/import` | POST | `contacts:write` | `bulk_import` |

### 4.5 Events (`/v1/events`)

| Endpoint | Method | Required Scope | Handler |
|----------|--------|----------------|---------|
| `/` | GET | `events:read` | `list_events` |
| `/:id` | GET | `events:read` | `get_event` |
| `/stats` | GET | `events:read` | `event_stats` |
| `/timeseries` | GET | `events:read` | `event_timeseries` |

### 4.6 Analytics (`/v1/analytics`)

| Endpoint | Method | Required Scope | Handler |
|----------|--------|----------------|---------|
| `/dashboard` | GET | `analytics:read` | `dashboard_stats` |
| `/campaigns/:id` | GET | `analytics:read` | `campaign_analytics` |
| `/bounce-insights` | GET | `analytics:read` | `bounce_insights` |
| `/delivery-trends` | GET | `analytics:read` | `delivery_trends` |
| `/geographic` | GET | `analytics:read` | `geographic_distribution` |
| `/providers` | GET | `analytics:read` | `provider_breakdown` |

### 4.7 Webhooks (`/v1/webhooks`)

| Endpoint | Method | Required Scope | Handler |
|----------|--------|----------------|---------|
| `/` | POST | `webhooks:write` | `create_webhook` |
| `/` | GET | `webhooks:read` | `list_webhooks` |
| `/:id` | GET | `webhooks:read` | `get_webhook` |
| `/:id` | PUT | `webhooks:write` | `update_webhook` |
| `/:id` | DELETE | `webhooks:write` | `delete_webhook` |
| `/:id/rotate-secret` | POST | `webhooks:write` | `rotate_secret` |

### 4.8 Suppressions (`/v1/suppressions`)

| Endpoint | Method | Required Scope | Handler |
|----------|--------|----------------|---------|
| `/` | POST | `suppressions:write` | `add_suppression` |
| `/` | GET | `suppressions:read` | `list_suppressions` |
| `/:email` | DELETE | `suppressions:write` | `remove_suppression` |
| `/export` | GET | `suppressions:read` | `export_suppressions` |
| `/import` | POST | `suppressions:write` | `bulk_import` |

### 4.9 Campaigns (`/v1/campaigns`)

| Endpoint | Method | Required Scope | Handler |
|----------|--------|----------------|---------|
| `/` | POST | `campaigns:write` | `create_campaign` |
| `/` | GET | `campaigns:read` | `list_campaigns` |
| `/:id` | GET | `campaigns:read` | `get_campaign` |
| `/:id` | DELETE | `campaigns:write` | `delete_campaign` |
| `/:id/pause` | POST | `campaigns:write` | `pause_campaign` |
| `/:id/resume` | POST | `campaigns:write` | `resume_campaign` |

### 4.10 Automations (`/v1/automations`)

| Endpoint | Method | Required Scope | Handler |
|----------|--------|----------------|---------|
| `/` | POST | `automations:write` | `create_automation` |
| `/` | GET | `automations:read` | `list_automations` |
| `/:id` | GET | `automations:read` | `get_automation` |
| `/:id` | PUT | `automations:write` | `update_automation` |
| `/:id` | DELETE | `automations:write` | `delete_automation` |
| `/:id/enable` | POST | `automations:write` | `enable_automation` |
| `/:id/disable` | POST | `automations:write` | `disable_automation` |

### 4.11 AI Insights (`/v1/ai`)

| Endpoint | Method | Required Scope | Handler |
|----------|--------|----------------|---------|
| `/insights` | GET | `ai:read` | `get_insights` |
| `/predictions` | GET | `ai:read` | `get_predictions` |
| `/recommendations` | GET | `ai:read` | `get_recommendations` |
| `/anomalies` | GET | `ai:read` | `detect_anomalies` |

### 4.12 Support (`/v1/support`)

| Endpoint | Method | Required Scope | Handler |
|----------|--------|----------------|---------|
| `/tickets` | POST | `support:write` | `create_ticket` |
| `/tickets` | GET | `support:read` | `list_tickets` |
| `/tickets/:id` | GET | `support:read` | `get_ticket` |
| `/tickets/:id/reply` | POST | `support:write` | `reply_to_ticket` |

### 4.13 Dedicated IPs (`/v1/dedicated-ips`)

| Endpoint | Method | Required Scope | Handler |
|----------|--------|----------------|---------|
| `/` | POST | `dedicated_ips:write` | `provision_ip` |
| `/` | GET | `dedicated_ips:read` | `list_ips` |
| `/:id` | DELETE | `dedicated_ips:write` | `release_ip` |
| `/:id/warmup` | PUT | `dedicated_ips:write` | `configure_warmup` |

### 4.14 SCIM (`/v1/scim`)

| Endpoint | Method | Required Scope | Handler |
|----------|--------|----------------|---------|
| `/Users` | GET | `scim:read` | `list_users` |
| `/Users` | POST | `scim:write` | `create_user` |
| `/Users/:id` | GET | `scim:read` | `get_user` |
| `/Users/:id` | PUT | `scim:write` | `replace_user` |
| `/Users/:id` | PATCH | `scim:write` | `patch_user` |
| `/Groups` | GET | `scim:read` | `list_groups` |
| `/Groups` | POST | `scim:write` | `create_group` |
| `/Groups/:id` | GET | `scim:read` | `get_group` |
| `/Groups/:id` | PUT | `scim:write` | `replace_group` |
| `/Groups/:id` | PATCH | `scim:write` | `patch_group` |
| `/Groups/:id` | DELETE | `scim:write` | `delete_group` |

---

## 5. Authentication & Authorization Flow

### 5.1 Backend (Rust API Server)

```
┌─────────────────────────────────────────────────────────────────┐
│                    Request Flow                                  │
├─────────────────────────────────────────────────────────────────┤
│  1. Request arrives at public or authenticated route            │
│                                                                 │
│  2. For authenticated routes:                                   │
│     ├─ auth::require_auth middleware runs                       │
│     ├─ Extracts AuthUser via FromRequestParts                   │
│     └─ Sets Authorization: Bearer <JWT> or X-API-Key            │
│                                                                 │
│  3. AuthUser extraction:                                        │
│     ├─ If X-API-Key: hash key, lookup in DB (Redis-cached 10s)  │
│     │   └─ Returns: tenant_id, api_key_id, scopes[]             │
│     └─ If Bearer JWT: validate RS256 signature, check blacklist │
│         └─ Returns: tenant_id, user_id, scopes[]                │
│                                                                 │
│  4. Handler invokes require_scopes(&auth, &["scope:action"])    │
│     ├─ If scopes contains "*", allow (wildcard)                 │
│     └─ Else, check for exact scope match                        │
│                                                                 │
│  5. If scope missing → ApiError::Forbidden("missing scope")     │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 Browser Surfaces (`web` and `control-plane`)

```
┌─────────────────────────────────────────────────────────────────┐
│                 Browser Surface Request Flow                     │
├─────────────────────────────────────────────────────────────────┤
│  1. Request arrives at nginx / api-server                       │
│                                                                 │
│  2. Host/surface routing resolves `web` vs `control-plane`      │
│                                                                 │
│  3. `ui-foundation` SSR applies browser auth/CSRF equivalents   │
│                                                                 │
│  4. Protected data/API requests extract `AuthUser`              │
│     └─ Returns tenant_id, user_id, api_key_id, scopes[]         │
│                                                                 │
│  5. Handlers call `require_scopes(&auth, &[..])`                │
│     └─ Missing scope → ApiError::Forbidden                      │
└─────────────────────────────────────────────────────────────────┘
```

### 5.3 Control Plane (Admin Surface)

```
┌─────────────────────────────────────────────────────────────────┐
│               Control Plane Security Layers                      │
├─────────────────────────────────────────────────────────────────┤
│  Layer 1: Surface routing                                       │
│     └─ Host mapping resolves the `control-plane` browser surface│
│                                                                 │
│  Layer 2: Authentication extraction                             │
│     └─ JWT / API key auth produces `AuthUser` + scopes          │
│                                                                 │
│  Layer 3: Scope enforcement                                     │
│     └─ Handlers enforce exact scopes or wildcard access         │
│                                                                 │
│  Layer 4: Browser auth / CSRF equivalents                       │
│     └─ Implemented in `ui-foundation` SSR wiring                │
│                                                                 │
│  Layer 5: Security Headers                                      │
│     └─ Response hardening and no-store handling stay server-side│
└─────────────────────────────────────────────────────────────────┘
```

---

## 6. RBAC Guards Implementation

### 6.1 Scope Guard (`require_scopes`)

**Location:** [middleware/auth.rs](../services/mail-server/crates/api-server/src/middleware/auth.rs#L288-L300)

```rust
pub fn require_scopes(user: &AuthUser, required: &[&str]) -> Result<(), ApiError> {
    // Wildcard scope grants all access
    if user.scopes.iter().any(|s| s == "*") {
        return Ok(());
    }
    // Check each required scope
    for scope in required {
        if !user.scopes.iter().any(|s| s == scope) {
            return Err(ApiError::Forbidden(format!(
                "missing required scope: {scope}"
            )));
        }
    }
    Ok(())
}
```

### 6.2 Authentication Extractor (`AuthUser`)

**Location:** [middleware/auth.rs](../services/mail-server/crates/api-server/src/middleware/auth.rs#L20-L27)

```rust
pub struct AuthUser {
    pub tenant_id: String,
    pub user_id: Option<String>,
    pub api_key_id: Option<String>,
    pub scopes: Vec<String>,
}
```

### 6.3 Scope Guard (`require_scopes`)

**Location:** [middleware/auth.rs](../services/mail-server/crates/api-server/src/middleware/auth.rs#L453-L465)

```rust
pub fn require_scopes(user: &AuthUser, required: &[&str]) -> Result<(), ApiError> {
    if user.scopes.iter().any(|s| s == "*") {
        return Ok(());
    }
    for scope in required {
        if !user.scopes.iter().any(|s| s == scope) {
            return Err(ApiError::Forbidden(format!("missing required scope: {scope}")));
        }
    }
    Ok(())
}
```

---

## 7. Public (Unauthenticated) Routes

These routes **do not require authentication**:

| Route Group | Endpoints | Purpose |
|-------------|-----------|---------|
| Health | `/health/live`, `/health/ready`, `/health/deep` | Infrastructure probes |
| Auth | `/v1/auth/login`, `/v1/auth/logout`, `/v1/auth/refresh` | Authentication flows |
| SES Notifications | `/v1/ses/notifications` | AWS SES webhook (validated via SNS signature) |

**Source:** [app.rs](../services/mail-server/crates/api-server/src/app.rs#L53-L56)

---

## 8. Security Analysis: Potential Issues

### 8.1 ✅ Properly Protected Routes

All authenticated routes in the following modules correctly call `require_scopes`:

- `messages.rs` ✓
- `domains.rs` ✓
- `templates.rs` ✓
- `contacts.rs` ✓
- `events.rs` ✓
- `analytics.rs` ✓
- `webhooks.rs` ✓
- `suppressions.rs` ✓
- `campaigns.rs` ✓
- `automations.rs` ✓
- `ai_insights.rs` ✓
- `support.rs` ✓
- `dedicated_ips.rs` ✓
- `scim.rs` ✓

### 8.2 ⚠️ Routes Without Scope Checks

The following auth-related routes use `AuthUser` but don't enforce scopes:

| Route | File | Risk Level | Recommendation |
|-------|------|------------|----------------|
| `POST /api-keys` | auth.rs | **Low** | Inherently privileged operation — tenant-scoped |
| `GET /api-keys` | auth.rs | **Low** | Users should see their own API keys |
| `DELETE /api-keys/:id` | auth.rs | **Low** | Tenant-scoped deletion |

**Rationale:** These operations are inherently scoped to the authenticated tenant and don't expose cross-tenant data. However, consider adding an `api_keys:write` scope for principle of least privilege.

### 8.3 ⚠️ Missing Scopes in Role Assignments

| Role | Missing from Default | Impact |
|------|---------------------|--------|
| `developer` | `webhooks:read`, `webhooks:write`, `automations:*`, `campaigns:*`, `suppressions:*`, `dedicated_ips:*`, `support:*`, `scim:*`, `ai:read` | Developers cannot manage webhooks, automations, campaigns |
| `viewer` | `webhooks:read`, `automations:read`, `campaigns:read`, `suppressions:read`, `support:read`, `ai:read` | Viewers cannot see webhooks, automations |

**Recommendation:** Either expand role scopes or document that additional API key scopes must be manually assigned.

### 8.4 ✅ Security Best Practices Implemented

1. **Wildcard scope restricted to admin/owner** — Prevents privilege escalation
2. **API key hash uses HMAC-SHA256** — Prevents offline brute-force if DB compromised
3. **Token blacklist check before JWT validation** — Enables revocation
4. **User status verification on each request** — Detects disabled/deleted users
5. **Short API key cache TTL (10s)** — Limits window for revoked key abuse
6. **CSRF protection on control plane mutations** — Prevents cross-site attacks
7. **IP whitelist on control plane** — Limits admin access surface

---

## 9. Role-Permission Matrix Summary

### 9.1 Customer Roles → Scopes

| Operation | Owner | Admin | Developer | Viewer | Member |
|-----------|:-----:|:-----:|:---------:|:------:|:------:|
| Send messages | ✓ | ✓ | ✓ | ✗ | ✗ |
| Read messages | ✓ | ✓ | ✓ | ✓ | ✓ |
| Manage domains | ✓ | ✓ | ✗ | ✗ | ✗ |
| Read domains | ✓ | ✓ | ✓ | ✓ | ✗ |
| Manage templates | ✓ | ✓ | ✓ | ✗ | ✗ |
| Read templates | ✓ | ✓ | ✓ | ✓ | ✗ |
| Manage contacts | ✓ | ✓ | ✓ | ✗ | ✗ |
| Read contacts | ✓ | ✓ | ✓ | ✓ | ✗ |
| Read events | ✓ | ✓ | ✓ | ✓ | ✗ |
| Read analytics | ✓ | ✓ | ✓ | ✓ | ✗ |
| Manage webhooks | ✓ | ✓ | ✗ | ✗ | ✗ |
| Manage campaigns | ✓ | ✓ | ✗ | ✗ | ✗ |
| Manage automations | ✓ | ✓ | ✗ | ✗ | ✗ |
| Manage suppressions | ✓ | ✓ | ✗ | ✗ | ✗ |
| SCIM provisioning | ✓ | ✓ | ✗ | ✗ | ✗ |
| AI insights | ✓ | ✓ | ✗ | ✗ | ✗ |
| Support tickets | ✓ | ✓ | ✗ | ✗ | ✗ |
| Dedicated IPs | ✓ | ✓ | ✗ | ✗ | ✗ |

### 9.2 Current Role Profiles → Actions

| Operation | Owner | Admin | Developer | Viewer | Fallback/Member |
|-----------|:-----:|:-----:|:---------:|:------:|:---------------:|
| View dashboard | ✓ | ✓ | ✓ | ✓ | ✗ |
| View messages/domains/templates/events | ✓ | ✓ | ✓ | ✓ | ✓ |
| Send messages | ✓ | ✓ | ✓ | ✗ | ✗ |
| Edit templates | ✓ | ✓ | ✓ | ✗ | ✗ |
| Edit contacts | ✓ | ✓ | ✓ | ✗ | ✗ |
| Wildcard/admin operations | ✓ | ✓ | ✗ | ✗ | ✗ |

---

## 10. Recommendations

### 10.1 High Priority

1. **Add `api_keys:write` scope** for API key management operations
2. **Expand developer role** to include commonly needed scopes (webhooks, campaigns)
3. **Add `billing:read` and `billing:write` scopes** for billing operations (if not already separate)

### 10.2 Medium Priority

1. **Audit logging** — Log all scope check failures for security monitoring
2. **Scope inheritance** — Consider hierarchical scopes (e.g., `messages:*` expands to both read/write)
3. **Custom roles** — Allow tenants to define custom role→scope mappings

### 10.3 Low Priority

1. **Scope documentation in OpenAPI** — Add `x-required-scopes` extension to API spec
2. **Scope UI in dashboard** — Show users which scopes their API keys have

---

## 11. References

- [middleware/auth.rs](../services/mail-server/crates/api-server/src/middleware/auth.rs) — Authentication extractors and scope guards
- [routes/auth.rs](../services/mail-server/crates/api-server/src/routes/auth.rs) — Role→scope assignment logic
- [app.rs](../services/mail-server/crates/api-server/src/app.rs) — Route organization and middleware stacking
- [ssr.rs](../services/mail-server/crates/ui-foundation/src/ssr.rs) — Browser-surface auth and CSRF middleware equivalents
- [dashboard.rs](../services/mail-server/crates/api-server/src/routes/dashboard.rs) — Dashboard route scope enforcement
- [docs/adr/0010-security-architecture.md](../docs/adr/0010-security-architecture.md) — Security design decisions
