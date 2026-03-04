# Frontend vs Backend API Route Audit Report

**Generated:** March 3, 2026  
**Purpose:** Production Readiness Check  

---

## Summary

| Category | Count |
|----------|-------|
| Missing Frontend Routes (will 404) | **19** |
| Missing Control Plane Routes | **8** |
| Billing Route Mismatches | **1** |
| Webhook Path Issues | **0** |

---

## 1. ACTUAL BACKEND API ROUTES

### 1.1 Rust API Server (services/mail-server/crates/api-server)

#### Public Routes (No Auth)
| Method | Path | Handler |
|--------|------|---------|
| GET | `/health` | health check |
| POST | `/v1/auth/login` | login |
| POST | `/v1/auth/register` | register |
| GET | `/v1/auth/verify-email` | verify_email |
| POST | `/v1/auth/logout` | logout |
| POST | `/v1/auth/refresh` | refresh_token |
| POST | `/v1/auth/forgot-password` | forgot_password |
| GET | `/v1/auth/session` | get_session |
| GET | `/v1/auth/csrf` | get_csrf_token |
| GET/POST | `/v1/auth/sso/google` | SSO flow |
| GET/POST | `/v1/auth/sso/github` | SSO flow |
| POST | `/v1/ses/notifications` | SNS webhook |

#### Authenticated Routes
| Resource | Method | Path |
|----------|--------|------|
| **Messages** | POST | `/v1/messages` |
| | GET | `/v1/messages` |
| | POST | `/v1/messages/batch` |
| | GET | `/v1/messages/:id` |
| | POST | `/v1/messages/:id/cancel` |
| **Domains** | POST | `/v1/domains` |
| | GET | `/v1/domains` |
| | GET | `/v1/domains/:id` |
| | DELETE | `/v1/domains/:id` |
| | POST | `/v1/domains/:id/verify` |
| | GET | `/v1/domains/:id/dns-records` |
| **Templates** | POST | `/v1/templates` |
| | GET | `/v1/templates` |
| | GET | `/v1/templates/:id` |
| | PUT | `/v1/templates/:id` |
| | DELETE | `/v1/templates/:id` |
| | POST | `/v1/templates/:id/render` |
| **Contacts** | POST | `/v1/contacts` |
| | GET | `/v1/contacts` |
| | GET | `/v1/contacts/:id` |
| | PUT | `/v1/contacts/:id` |
| | DELETE | `/v1/contacts/:id` |
| | POST | `/v1/contacts/bulk` |
| **Campaigns** | POST | `/v1/campaigns` |
| | GET | `/v1/campaigns` |
| | GET | `/v1/campaigns/:id` |
| | DELETE | `/v1/campaigns/:id` |
| | POST | `/v1/campaigns/:id/resume` |
| | POST | `/v1/campaigns/:id/pause` |
| **Suppressions** | POST | `/v1/suppressions` |
| | GET | `/v1/suppressions` |
| | DELETE | `/v1/suppressions/:id` |
| | GET | `/v1/suppressions/check/:email` |
| | POST | `/v1/suppressions/bulk` |
| **Events** | GET | `/v1/events` |
| | GET | `/v1/events/stats` |
| | GET | `/v1/events/timeseries` |
| | GET | `/v1/events/:id` |
| **Webhooks** | POST | `/v1/webhooks` |
| | GET | `/v1/webhooks` |
| | GET | `/v1/webhooks/:id` |
| | PUT | `/v1/webhooks/:id` |
| | DELETE | `/v1/webhooks/:id` |
| | POST | `/v1/webhooks/:id/test` |
| **Analytics** | GET | `/v1/analytics/dashboard` |
| | GET | `/v1/analytics/volume` |
| | GET | `/v1/analytics/engagement` |
| | GET | `/v1/analytics/deliverability` |
| | GET | `/v1/analytics/export` |
| | GET | `/v1/analytics/export/:job_id` |
| **Support** | POST | `/v1/support/tickets` |
| | GET | `/v1/support/tickets` |
| | GET | `/v1/support/tickets/:id` |
| | PUT | `/v1/support/tickets/:id` |
| **Dedicated IPs** | POST | `/v1/dedicated-ips` |
| | GET | `/v1/dedicated-ips` |
| | DELETE | `/v1/dedicated-ips/:id` |
| | POST | `/v1/dedicated-ips/:id/warmup` |
| **Account** | GET | `/v1/account/profile` |
| | DELETE | `/v1/account` |
| **Automations** | Full CRUD | `/v1/automations/*` |
| **AI Insights** | GET | `/v1/ai/send-time` |
| | GET | `/v1/ai/subject-analysis` |
| | GET | `/v1/ai/churn-prediction` |
| | GET | `/v1/ai/bot-detection` |
| **Auth (keys)** | POST | `/v1/auth/api-keys` |
| | GET | `/v1/auth/api-keys` |
| | DELETE | `/v1/auth/api-keys/:id` |
| **SCIM** | All | `/v1/scim/*` |
| **Impersonate** | POST | `/v1/auth/impersonate` |
| | POST | `/v1/auth/impersonate/end` |
| **Telemetry** | POST | `/v1/auth/telemetry` |

#### Admin Routes (Control Plane)
| Path | Methods |
|------|---------|
| `/v1/admin/tenants` | GET, PATCH, DELETE |
| `/v1/admin/features` | GET, POST, PATCH |
| `/v1/admin/gdpr` | GET, PATCH |
| `/v1/admin/secrets` | GET, POST, PATCH, DELETE |
| `/v1/admin/audit` | GET |
| `/v1/admin/dashboard/stats` | GET |
| `/v1/admin/compliance` | GET |
| `/v1/admin/risk` | GET, PATCH |
| `/v1/admin/revenue` | GET |
| `/v1/admin/inbox` | GET, PATCH |
| `/v1/admin/calendar` | GET |
| `/v1/admin/warmup` | GET, POST |
| `/v1/admin/content` | GET |
| `/v1/admin/autopilot` | GET, POST |
| `/v1/admin/proxy` | POST, GET |
| `/v1/admin/sales/leads` | GET |
| `/v1/admin/sales/leads/update` | PATCH |
| `/v1/admin/sales/leads/enrich` | POST |
| `/v1/admin/sales/campaigns` | GET, PATCH |
| `/v1/admin/sales/discovery/run` | POST |
| `/v1/admin/sales/outreach/start` | POST |
| `/v1/admin/analytics` | GET |
| `/v1/admin/analytics/export` | GET |
| `/v1/admin/campaigns` | GET |
| `/v1/admin/crm/leads` | GET |
| `/v1/admin/leads/discovery` | GET |
| `/v1/admin/support` | GET, POST, PUT |
| `/v1/admin/support/analytics` | GET |
| `/v1/admin/system/health` | GET |

### 1.2 Billing Service (apps/billing)

| Path | Methods | Description |
|------|---------|-------------|
| `/webhooks/stripe` | POST | Stripe webhook |
| `/api/billing/usage` | GET | Get usage |
| `/api/billing/usage/realtime/:metric` | GET | Realtime metric |
| `/api/billing/alerts` | POST | Create alert |
| `/api/billing/subscription` | GET | Get subscription |
| `/api/billing/checkout` | POST | Create checkout |
| `/api/billing/portal` | POST | Create portal |
| `/api/billing/proration/:planName` | GET | Proration preview |
| `/api/billing/invoices` | GET | List invoices |
| `/api/billing/invoices/:id` | GET | Get invoice |
| `/api/billing/invoices/:id/pdf` | GET | Download PDF |
| `/api/billing/invoices/:id/xml` | GET | Download XML |
| `/api/billing/wallet` | GET | Get wallet |
| `/api/billing/wallet/transactions` | GET | List transactions |
| `/api/billing/credits` | GET | Get credits |
| `/api/billing/dunning` | GET | Get dunning status |
| `/api/billing/costs` | GET | Get costs |
| `/api/billing/viral/stats` | GET | Viral stats |
| `/api/billing/payg/pricing` | GET | PAYG pricing |
| `/api/billing/payg/estimate` | POST | PAYG estimate |
| `/api/billing/overage/estimate` | POST | Overage estimate |
| `/api/billing/payg/usage` | GET | PAYG usage |
| `/api/billing/switch-plan` | POST | Switch plan |
| `/api/billing/cancel` | POST | Cancel subscription |
| `/api/plans` | GET | List plans |
| `/api/plans/:planId` | GET | Get plan |
| `/api/plans/tenant/current` | GET | Current tenant plan |
| `/api/plans/features/:feature` | GET | Check feature |
| `/api/plans/tenant/features` | GET | Tenant features |
| `/api/plans/tenant/limits` | GET | Tenant limits |
| `/api/plans/compare/:planId1/:planId2` | GET | Compare plans |
| `/api/plans` | POST | Create plan (admin) |
| `/api/plans/:planId` | PATCH | Update plan (admin) |
| `/api/plans/seed` | POST | Seed plans (admin) |
| `/api/enterprise/contracts*` | All | Enterprise contracts |
| `/api/admin/tenants*` | All | Admin tenant management |
| `/api/admin/reports/*` | GET | Reports |

---

## 2. FRONTEND CALLS THAT WILL 404 (MISSING BACKEND ROUTES)

### 2.1 Web Frontend (apps/web/src/)

| Frontend Call | File | Issue |
|---------------|------|-------|
| `GET /v1/lists` | [use-api.ts](apps/web/src/hooks/use-api.ts#L400) | **NO BACKEND ROUTE EXISTS** |
| `POST /v1/lists` | [use-api.ts](apps/web/src/hooks/use-api.ts#L404) | **NO BACKEND ROUTE EXISTS** |
| `GET /v1/lists/:id` | [use-api.ts](apps/web/src/hooks/use-api.ts#L412) | **NO BACKEND ROUTE EXISTS** |
| `PUT /v1/lists/:id` | [lists/page.tsx](apps/web/src/app/(dashboard)/lists/page.tsx#L101) | **NO BACKEND ROUTE EXISTS** |
| `DELETE /v1/lists/:id` | [lists/page.tsx](apps/web/src/app/(dashboard)/lists/page.tsx#L121) | **NO BACKEND ROUTE EXISTS** |
| `POST /v1/lists/:id/import` | [lists/page.tsx](apps/web/src/app/(dashboard)/lists/page.tsx#L153) | **NO BACKEND ROUTE EXISTS** |
| `GET /v1/dashboard/stats` | [use-api.ts](apps/web/src/hooks/use-api.ts#L426) | **NO BACKEND ROUTE EXISTS** (exists at `/v1/admin/dashboard/stats` for admin only) |
| `GET /v1/analytics/ai/insights` | [ai-insights/page.tsx](apps/web/src/app/(dashboard)/ai-insights/page.tsx#L45) | **NO BACKEND ROUTE EXISTS** (backend has `/v1/ai/*`) |
| `POST /v1/contacts/bulk/tag` | [use-contacts-controller.ts](apps/web/src/app/(dashboard)/contacts/use-contacts-controller.ts#L121) | **NO BACKEND ROUTE EXISTS** (only `/v1/contacts/bulk` for import) |
| `POST /v1/contacts/bulk/delete` | [use-contacts-controller.ts](apps/web/src/app/(dashboard)/contacts/use-contacts-controller.ts#L122) | **NO BACKEND ROUTE EXISTS** |
| `POST /v1/contacts/bulk/restore` | [use-contacts-controller.ts](apps/web/src/app/(dashboard)/contacts/use-contacts-controller.ts#L123) | **NO BACKEND ROUTE EXISTS** |
| `POST /v1/contacts/bulk/resolve-duplicates` | [use-contacts-controller.ts](apps/web/src/app/(dashboard)/contacts/use-contacts-controller.ts#L124) | **NO BACKEND ROUTE EXISTS** |
| `GET /v1/contacts/counts` | [use-contacts-controller.ts](apps/web/src/app/(dashboard)/contacts/use-contacts-controller.ts#L159) | **NO BACKEND ROUTE EXISTS** |
| `POST /v1/contacts/import` | [use-contacts-controller.ts](apps/web/src/app/(dashboard)/contacts/use-contacts-controller.ts#L491) | Backend has `/v1/contacts/bulk` instead |
| `GET /v1/domains/:id/auth-status` | [domains/page.tsx](apps/web/src/app/(dashboard)/domains/page.tsx#L197) | **NO BACKEND ROUTE EXISTS** (only dns-records) |
| `POST /v1/templates/:id/duplicate` | [templates/page.tsx](apps/web/src/app/(dashboard)/templates/page.tsx#L87) | **NO BACKEND ROUTE EXISTS** |
| `POST /v1/templates/:id/rollback` | [templates/page.tsx](apps/web/src/app/(dashboard)/templates/page.tsx#L175) | **NO BACKEND ROUTE EXISTS** |
| `POST /v1/campaigns/resend` | [campaigns/[id]/page.tsx](apps/web/src/app/(dashboard)/campaigns/[id]/page.tsx#L45) | **NO BACKEND ROUTE EXISTS** |
| `POST /v1/support/tickets/:id/messages` | [use-api.ts](apps/web/src/hooks/use-api.ts#L455) | **NO BACKEND ROUTE EXISTS** (backend only has ticket CRUD, no nested messages route) |

### 2.2 Billing Route Mismatch

| Frontend Call | Expected | Actual Backend |
|---------------|----------|----------------|
| `POST /api/checkout/create` | [register/route.ts](apps/web/src/app/api/auth/register/route.ts#L158) | `/api/billing/checkout` |

---

## 3. CONTROL PLANE CALLS THAT WILL 404 (MISSING BACKEND ROUTES)

| Frontend Call | File | Issue |
|---------------|------|-------|
| `GET /api/audit/export` | [audit/page.tsx](apps/control-plane/src/app/audit/page.tsx#L100) | No separate export endpoint |
| `GET /api/audit/export/:id` | [audit/page.tsx](apps/control-plane/src/app/audit/page.tsx#L115) | No async job status |
| `POST /api/audit/alerts` | [audit/page.tsx](apps/control-plane/src/app/audit/page.tsx#L488) | No alerts endpoint |
| `DELETE /api/integrations/:id` | [settings/page.tsx](apps/control-plane/src/app/settings/page.tsx#L585) | No integrations CRUD |
| `POST /api/settings/backup/run` | [settings/page.tsx](apps/control-plane/src/app/settings/page.tsx#L1123) | No backup endpoints |
| `POST /api/settings/backup/dr-test` | [settings/page.tsx](apps/control-plane/src/app/settings/page.tsx#L1147) | No DR test endpoint |
| `PATCH /api/calendar/availability/:id` | [calendar/page.tsx](apps/control-plane/src/app/calendar/page.tsx#L101) | Backend only has GET `/v1/admin/calendar` |
| `PATCH /api/calendar/events/:id/status` | [calendar/page.tsx](apps/control-plane/src/app/calendar/page.tsx#L129) | No events CRUD |
| `POST /api/calendar/availability` | [calendar/page.tsx](apps/control-plane/src/app/calendar/page.tsx#L484) | No availability creation |

---

## 4. WEBHOOK PATH VERIFICATION

| Expected Path | Actual Backend | Status |
|---------------|----------------|--------|
| `/webhooks/stripe` | `/webhooks/stripe` (billing service) | ✅ OK |
| `/v1/ses/notifications` | `/v1/ses/notifications` (Rust API) | ✅ OK |

---

## 5. CRITICAL MISSING ROUTES - ACTION REQUIRED

### Priority 1 (BLOCKING - User Features Broken)

1. **`/v1/lists/*` - ENTIRE RESOURCE MISSING**
   - Frontend has full Lists CRUD UI
   - Backend has NO lists routes
   - **ACTION:** Create `services/mail-server/crates/api-server/src/routes/lists.rs`

2. **`/v1/dashboard/stats` - Non-admin dashboard broken**
   - Only exists at `/v1/admin/dashboard/stats` (admin-only)
   - Regular users can't see dashboard
   - **ACTION:** Add tenant-scoped `/v1/dashboard/stats` route

3. **`/v1/analytics/ai/insights`**
   - Frontend calls this specific path
   - Backend has `/v1/ai/*` with different structure
   - **ACTION:** Add alias or update frontend to use `/v1/ai/*`

### Priority 2 (User Experience Degraded)

4. **Contact Bulk Operations Missing:**
   - `/v1/contacts/bulk/tag`
   - `/v1/contacts/bulk/delete`
   - `/v1/contacts/bulk/restore`
   - `/v1/contacts/bulk/resolve-duplicates`
   - `/v1/contacts/counts`
   - **ACTION:** Expand contacts router

5. **Template Operations Missing:**
   - `/v1/templates/:id/duplicate`
   - `/v1/templates/:id/rollback`
   - **ACTION:** Add template operations

6. **Domain Auth Status Missing:**
   - `/v1/domains/:id/auth-status`
   - **ACTION:** Add auth-status endpoint

7. **Campaign Resend Missing:**
   - `/v1/campaigns/resend`
   - **ACTION:** Add resend functionality

8. **Support Ticket Messages Missing:**
   - `/v1/support/tickets/:id/messages`
   - Backend only has ticket CRUD, no nested messages route
   - **ACTION:** Add messages sub-route to support tickets

### Priority 3 (Admin/Ops Features)

9. **Billing Checkout Path Mismatch:**
   - Frontend: `/api/checkout/create`
   - Backend: `/api/billing/checkout`
   - **ACTION:** Either add `/api/checkout/create` route OR update frontend

10. **Control Plane Admin Features:**
   - Audit export/alerts
   - Backup/DR testing
   - Calendar CRUD
   - Integrations CRUD
   - **ACTION:** Implement or remove from UI

---

## 6. RECOMMENDATIONS

### Short-term Fixes (Before Deploy)
1. Create `/v1/lists` CRUD routes (Priority 1)
2. Add `/v1/dashboard/stats` for regular users (Priority 1)
3. Fix billing checkout path mismatch (Priority 3)
4. Add `/v1/support/tickets/:id/messages` route (Priority 2 - support broken)

### Medium-term Fixes (Week 1 Post-Deploy)
1. Add all contact bulk operations (Priority 2)
2. Add template duplicate/rollback (Priority 2)
3. Add domain auth-status endpoint (Priority 2)
4. Add campaign resend (Priority 2)

### Long-term (Backlog)
1. Complete control plane admin features
2. Add API versioning strategy
3. Generate OpenAPI spec from route definitions

---

## Appendix: Route Counts

| Service | Route Count |
|---------|-------------|
| Rust API Server (public) | 12 |
| Rust API Server (authenticated) | 58 |
| Rust API Server (admin) | 32 |
| Billing Service | 35 |
| **Total Backend Routes** | **137** |
| Frontend API Calls | ~85 |
| Control Plane API Calls | ~45 |
| **Missing Routes** | **28** |
