# Control Plane Exhaustive Audit Report

Generated: 2025-01-XX  
Scope: `apps/control-plane/src/` — 23 pages, 46 API routes, 11 library files, middleware, components

---

## Table of Contents

1. [CRITICAL — Missing or Broken API Routes](#1-critical--missing-or-broken-api-routes)
2. [HIGH — HTTP Method Mismatches](#2-high--http-method-mismatches)
3. [MEDIUM — Missing Optimistic Rollback / Fire-and-Forget Mutations](#3-medium--missing-optimistic-rollback--fire-and-forget-mutations)
4. [LOW — DOM Anti-Patterns](#4-low--dom-anti-patterns)
5. [Security Audit](#5-security-audit)
6. [Integration Audit (proxyToRust, Env Vars)](#6-integration-audit)
7. [Route ↔ Frontend Coverage Matrix](#7-route--frontend-coverage-matrix)
8. [Summary by Severity](#8-summary-by-severity)

---

## 1. CRITICAL — Missing or Broken API Routes

These are frontend calls to API routes that do **not exist at all** in `src/app/api/`. They will 404 at runtime.

### 1.1 Settings page → `/api/v1/operator/settings` (DOES NOT EXIST)

| | |
|---|---|
| **File** | `src/app/settings/page.tsx` |
| **Lines** | 164 (GET), 306 (PUT) |
| **Severity** | 🔴 CRITICAL |

```tsx
// Line 164 — loadSettings()
const response = await fetch('/api/v1/operator/settings', { cache: 'no-store' });

// Line 306 — save()
const response = await fetch('/api/v1/operator/settings', {
    method: 'PUT',
    ...
});
```

**Problem:** The settings page fetches from `/api/v1/operator/settings` (GET) and saves to the same path (PUT). This path does **not** exist as a Next.js route. There is no `src/app/api/v1/` directory at all. The only settings-related routes are under `/api/settings/backup/`.

**Fix:** Create `src/app/api/v1/operator/settings/route.ts` proxying to Rust, or change the frontend to call an existing route. If the intent is to consolidate all settings via Rust:

```ts
// src/app/api/v1/operator/settings/route.ts
import { proxyToRust } from '@/lib/rust-api';
export const GET = (r: Request) => proxyToRust(r, '/v1/operator/settings');
export const PUT = (r: Request) => proxyToRust(r, '/v1/operator/settings');
```

---

### 1.2 IP Warmer page → 6 missing warmup sub-routes

| | |
|---|---|
| **File** | `src/app/ip-warmer/page.tsx` |
| **Lines** | 130, 163, 190, 225, 276, 321 |
| **Severity** | 🔴 CRITICAL |

```tsx
// Line 130
await executeWarmupAction(`/api/warmup/ip/${ip.ipAddress}/start`);
// Line 163
await executeWarmupAction(`/api/warmup/ip/${ip.ipAddress}/pause`);
// Line 190
await executeWarmupAction(`/api/warmup/ip/${ip.ipAddress}/resume`);
// Line 225
await executeWarmupAction(`/api/warmup/ip/${ip.ipAddress}/reset`);
// Line 276
await executeWarmupAction(`/api/warmup/ip/${selectedIP.ipAddress}/day`, { day: newWarmupDay });
// Line 321
await executeWarmupAction('/api/warmup/advance');
```

**Problem:** The only warmup route is `src/app/api/warmup/route.ts` which handles GET and POST to `/api/warmup`. There are **no** routes for:
- `/api/warmup/ip/[ipAddress]/start/`
- `/api/warmup/ip/[ipAddress]/pause/`
- `/api/warmup/ip/[ipAddress]/resume/`
- `/api/warmup/ip/[ipAddress]/reset/`
- `/api/warmup/ip/[ipAddress]/day/`
- `/api/warmup/advance/`

All 6 calls will 404 at runtime. Every per-IP action and the daily advancement button are dead.

**Fix:** Create route files for each, or consolidate into a single dynamic route:

```
src/app/api/warmup/ip/[ipAddress]/[action]/route.ts  → proxyToRust
src/app/api/warmup/advance/route.ts                   → proxyToRust
```

---

### 1.3 Campaigns page → `/api/campaigns/${campaignId}` (DOES NOT EXIST)

| | |
|---|---|
| **File** | `src/app/campaigns/page.tsx` |
| **Lines** | 68, 92 |
| **Severity** | 🔴 CRITICAL |

```tsx
// Line 68 — toggleCampaignStatus()
const res = await fetch(`/api/campaigns/${campaignId}`, {
    method: 'PATCH',
    ...
});

// Line 92 — startCampaign()
const res = await fetch(`/api/campaigns/${campaignId}`, {
    method: 'PATCH',
    ...
});
```

**Problem:** The campaigns route (`src/app/api/campaigns/route.ts`) only exports `GET` and handles the path `/api/campaigns`. There is no `src/app/api/campaigns/[id]/route.ts`. Calls to `/api/campaigns/abc123` will 404.

**Fix:** Create `src/app/api/campaigns/[id]/route.ts`:

```ts
import { proxyToRust } from '@/lib/rust-api';
export const PATCH = (r: Request, { params }: { params: { id: string } }) =>
    proxyToRust(r, `/v1/admin/campaigns/${params.id}`);
```

---

### 1.4 Calendar page → `/api/calendar/events/${eventId}/status` (DOES NOT EXIST)

| | |
|---|---|
| **File** | `src/app/calendar/page.tsx` |
| **Line** | 129 |
| **Severity** | 🔴 CRITICAL |

```tsx
// Line 129 — updateEventStatus()
const response = await fetch(`/api/calendar/events/${eventId}/status`, {
    method: 'PATCH',
    ...
});
```

**Problem:** No `src/app/api/calendar/events/` directory exists. The only calendar routes are `/api/calendar` (GET) and `/api/calendar/availability` (GET/POST). Event status updates will 404.

**Fix:** Create `src/app/api/calendar/events/[eventId]/status/route.ts`:

```ts
import { proxyToRust } from '@/lib/rust-api';
export const PATCH = (r: Request, { params }: { params: { eventId: string } }) =>
    proxyToRust(r, `/v1/admin/calendar/events/${params.eventId}/status`);
```

---

### 1.5 Calendar page → `/api/calendar/availability/${slotId}` (DOES NOT EXIST)

| | |
|---|---|
| **File** | `src/app/calendar/page.tsx` |
| **Line** | 103 |
| **Severity** | 🔴 CRITICAL |

```tsx
// Line 103 — toggleAvailability()
const response = await fetch(`/api/calendar/availability/${slotId}`, {
    method: 'PATCH',
    ...
});
```

**Problem:** The only availability route is `src/app/api/calendar/availability/route.ts` (GET/POST). There is no `src/app/api/calendar/availability/[slotId]/route.ts`, so calls to `/api/calendar/availability/slot123` will 404.

**Fix:** Create `src/app/api/calendar/availability/[slotId]/route.ts`:

```ts
import { proxyToRust } from '@/lib/rust-api';
export const PATCH = (r: Request, { params }: { params: { slotId: string } }) =>
    proxyToRust(r, `/v1/admin/calendar/availability/${params.slotId}`);
```

---

### 1.6 System page → `/api/system/workers/${workerId}/restart` (DOES NOT EXIST)

| | |
|---|---|
| **File** | `src/app/system/page.tsx` |
| **Line** | 158 |
| **Severity** | 🔴 CRITICAL |

```tsx
// Line 158 — restartWorker()
const response = await fetch(`/api/system/workers/${workerId}/restart`, {
    method: 'POST',
    ...
});
```

**Problem:** No `src/app/api/system/workers/` directory exists. The worker restart button is completely dead.

**Fix:** Create `src/app/api/system/workers/[workerId]/restart/route.ts`:

```ts
import { proxyToRust } from '@/lib/rust-api';
export const POST = (r: Request, { params }: { params: { workerId: string } }) =>
    proxyToRust(r, `/v1/admin/system/workers/${params.workerId}/restart`);
```

---

## 2. HIGH — HTTP Method Mismatches

These are calls where the route file exists, but the exported HTTP method does not match the method used by the frontend.

### 2.1 System `acknowledgeAlert` sends POST, route exports PATCH

| | |
|---|---|
| **File** | `src/app/system/page.tsx` |
| **Line** | 138 |
| **Route** | `src/app/api/system/alerts/[alertId]/acknowledge/route.ts` |
| **Severity** | 🟠 HIGH |

```tsx
// system/page.tsx line 138
fetch(`/api/system/alerts/${alertId}/acknowledge`, {
    method: 'POST',    // ← sends POST
    ...
```

```ts
// api/system/alerts/[alertId]/acknowledge/route.ts
export const PATCH = (r: Request, { params }) =>   // ← exports PATCH only
    proxyToRust(r, `/v1/admin/system/alerts/${params.alertId}/acknowledge`);
```

**Result:** Alert acknowledgment will return 405 Method Not Allowed.

**Fix:** Either change the frontend to `method: 'PATCH'`, or add `export const POST` to the route.

---

### 2.2 Features `deleteOverride` sends DELETE, route has no DELETE export

| | |
|---|---|
| **File** | `src/app/features/page.tsx` |
| **Line** | 153 |
| **Route** | `src/app/api/features/route.ts` |
| **Severity** | 🟠 HIGH |

```tsx
// features/page.tsx line 153
const res = await fetch('/api/features', {
    method: 'DELETE',   // ← sends DELETE
    ...
```

```ts
// api/features/route.ts — only exports GET, POST, PATCH. No DELETE.
export const GET = (r: Request) => proxyToRust(r, '/v1/admin/features');
export const POST = (r: Request) => proxyToRust(r, '/v1/admin/features');
export const PATCH = (r: Request) => proxyToRust(r, '/v1/admin/features');
```

**Result:** Override deletion will return 405 Method Not Allowed. The optimistic UI update happens, but the rollback fires immediately.

**Fix:** Add `export const DELETE` to the route:

```ts
export const DELETE = (r: Request) => proxyToRust(r, '/v1/admin/features');
```

---

### 2.3 CRM page sends PATCH/DELETE/POST, route only exports GET

| | |
|---|---|
| **File** | `src/app/crm/page.tsx` |
| **Lines** | 190 (PATCH—drag-drop), 230 (DELETE), 268 (PATCH—edit), 285 (POST—add) |
| **Route** | `src/app/api/crm/leads/route.ts` |
| **Severity** | 🟠 HIGH |

```ts
// api/crm/leads/route.ts — only exports GET
export const GET = (r: Request) => proxyToRust(r, '/v1/admin/crm/leads');
```

The CRM page calls:
- `PATCH /api/crm/leads` — drag-drop stage change (line ~190) and edit save (line ~268)
- `DELETE /api/crm/leads` — delete lead (line ~230)
- `POST /api/crm/leads` — add lead (line ~285)

All three mutation methods will return 405.

**Fix:** Add the missing method exports:

```ts
export const PATCH = (r: Request) => proxyToRust(r, '/v1/admin/crm/leads');
export const DELETE = (r: Request) => proxyToRust(r, '/v1/admin/crm/leads');
export const POST = (r: Request) => proxyToRust(r, '/v1/admin/crm/leads');
```

---

## 3. MEDIUM — Missing Optimistic Rollback / Fire-and-Forget Mutations

These mutations update the UI optimistically but do **not** roll back on failure.

### 3.1 Inbox — `toggleStar`, `markAsRead`, `reclassify` are fire-and-forget

| | |
|---|---|
| **File** | `src/app/inbox/page.tsx` |
| **Lines** | 62–68 (toggleStar), 70–79 (markAsRead), 81–96 (reclassify) |
| **Severity** | 🟡 MEDIUM |

```tsx
// Line 62 — toggleStar()
setMessages(prev => prev.map(...));
getCsrfToken().then(csrfToken => {
    fetch('/api/inbox', { method: 'PATCH', ... })
        .catch(err => console.error('Failed to persist star toggle:', err));
        // ← No rollback on failure
});
```

The same fire-and-forget pattern applies to `markAsRead` (line 70) and `reclassify` (line 81). If the API call fails, the UI remains in the updated state with no user notification.

**Fix:** Capture previous state before mutation and restore if the PATCH fails. Add a toast or inline error on failure.

---

### 3.2 Content — `publishItem`, `archiveItem`, `duplicateItem` are fire-and-forget

| | |
|---|---|
| **File** | `src/app/content/page.tsx` |
| **Lines** | 96–110 (publish), 112–125 (archive), 127–146 (duplicate) |
| **Severity** | 🟡 MEDIUM |

```tsx
// Line 96 — publishItem()
setContent(prev => prev.map(item => ...));
getCsrfToken().then(csrfToken => {
    fetch('/api/content', { method: 'PATCH', ... })
        .catch(err => console.error('Failed to persist publish:', err));
        // ← No rollback
});
```

Same pattern for `archiveItem` and `duplicateItem`.

**Fix:** Store previous state and rollback + toast on failure.

---

### 3.3 Campaigns — `toggleCampaignStatus`, `startCampaign` — no rollback

| | |
|---|---|
| **File** | `src/app/campaigns/page.tsx` |
| **Lines** | 66–82 (toggleCampaignStatus), 84–103 (startCampaign) |
| **Severity** | 🟡 MEDIUM |

```tsx
// Line 66 — toggleCampaignStatus()
// Updates UI only on success (res.ok), but has no error toast or user feedback on failure:
try {
    const res = await fetch(...);
    if (res.ok) {
        setCampaigns(prev => prev.map(...));
    }
    // ← else: silent failure — no user feedback
} catch (err) {
    console.error('Failed to toggle campaign status:', err);
    // ← No toast, no UI indication
}
```

**Fix:** Add error toast on failure (`!res.ok` and `catch`).

---

### 3.4 System — `acknowledgeAlert` is fire-and-forget

| | |
|---|---|
| **File** | `src/app/system/page.tsx` |
| **Lines** | 135–143 |
| **Severity** | 🟡 MEDIUM |

```tsx
// Line 135
setAlerts(prev => prev.map(a => 
    a.id === alertId ? { ...a, acknowledged: true } : a
));
getCsrfToken().then(csrfToken => {
    fetch(`/api/system/alerts/${alertId}/acknowledge`, {
        method: 'POST',
        ...
    }).catch(err => console.error('Failed to persist alert acknowledgment:', err));
    // ← No rollback
});
```

**Fix:** Rollback `acknowledged` to `false` on failure, or at minimum show a toast. (Also fix the POST → PATCH method mismatch per §2.1.)

---

### 3.5 Sales — `updateLeadNotes` is fire-and-forget

| | |
|---|---|
| **File** | `src/app/sales/page.tsx` |
| **Lines** | 412–425 |
| **Severity** | 🟡 MEDIUM |

```tsx
// Line 412
setLeads(prev => prev.map(l => l.id === leadId ? { ...l, notes } : l));
try {
    const csrfToken = await getCsrfToken();
    await fetch('/api/sales/leads/update', { method: 'PATCH', ... });
} catch (err) {
    console.error('Failed to persist notes:', err);
    // ← No rollback, no toast
}
```

**Fix:** Store previous notes and rollback on failure + toast.

---

## 4. LOW — DOM Anti-Patterns

### 4.1 `document.createElement('a')` for CSV download

| | |
|---|---|
| **Files** | `analytics/page.tsx` L154, `sales/page.tsx` L616, `crm/page.tsx` L315 |
| **Severity** | 🔵 LOW |

```tsx
// analytics/page.tsx line 154
const link = document.createElement('a');
link.href = url;
link.download = `analytics-export-${timeRange}.csv`;
document.body.appendChild(link);
link.click();
document.body.removeChild(link);
```

Similarly in `sales/page.tsx` (line 616) and `crm/page.tsx` (line 315).

**Problem:** Direct DOM manipulation bypasses React's rendering model and can cause issues in SSR contexts.

**Fix:** Use a reusable `downloadFile(url, filename)` utility that creates and removes the anchor element safely, or use the [download attribute pattern](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/a#download) on a rendered `<a>` element.

---

### 4.2 `document.createElement('form')` for impersonation POST

| | |
|---|---|
| **File** | `src/app/tenants/page.tsx` |
| **Lines** | 408–424 |
| **Severity** | 🔵 LOW |

```tsx
const form = document.createElement('form');
form.method = 'POST';
form.action = data.postTarget;
form.target = '_blank';
const input = document.createElement('input');
...
form.submit();
form.remove();
```

**Problem:** Creates a hidden form in the DOM for cross-origin POST impersonation. This is a deliberate pattern for token-based impersonation that requires a form POST, so it's acceptable as-is, but should be documented.

**Fix (optional):** Extract into a shared `submitImpersonationForm(postTarget, token)` utility for reusability and testability.

---

### 4.3 `document.getElementById` in mCaptcha widget

| | |
|---|---|
| **File** | `src/components/security/mcaptcha-widget.tsx` |
| **Line** | 28 |
| **Severity** | 🔵 LOW |

```tsx
const input = document.getElementById(tokenInputId) as HTMLInputElement | null;
```

**Problem:** This is a bridge to the third-party mCaptcha glue script which injects a hidden input by ID. Using `document.getElementById` is the only viable approach here since the input is created by an external script. **Acceptable.**

---

## 5. Security Audit

### 5.1 Middleware — Overall Assessment: ✅ STRONG

The middleware (`src/middleware.ts`, 452 lines) implements a 4-layer security model:

| Layer | Mechanism | Status |
|-------|-----------|--------|
| 1. IP Whitelist | `CONTROL_PLANE_IP_WHITELIST` env var, CIDR-aware, fail-secure | ✅ |
| 2. API Key | `x-control-plane-key` header, constant-time comparison | ✅ |
| 3. Session Auth | HMAC-SHA256 signed tokens, sliding refresh at half-life | ✅ |
| 3.5. CSRF | Double-submit cookie + HMAC signature, session-bound | ✅ |
| 4. Security Headers | X-Frame-Options, CSP, HSTS, no-cache, nosniff | ✅ |

Verified specifics:
- **Session tokens**: Custom HMAC-SHA256 signed (not JWT library). Edge-compatible via Web Crypto API.
- **CSRF**: Double-submit cookie pattern with HMAC signature binding cookie to session token. Enforced on all non-GET API requests except `/api/auth/login` and `/api/csrf`.
- **IP extraction**: Uses rightmost `x-forwarded-for` entry (FIX-500-304), which is correct for reverse-proxy deployments.
- **Wildcard IP whitelist**: Requires explicit `ALLOW_ALL_IPS=true` env var — good defense-in-depth.
- **Constant-time comparison**: Used for session signatures, API keys, and CSRF.
- **E2E bypass**: Only in non-production (`NODE_ENV !== 'production'`), requires secret.

### 5.2 RBAC — Assessment: ✅ GOOD (one gap)

Roles: `viewer` < `operator` < `admin` < `owner`/`super_admin`

Admin-only restrictions:
- **Pages**: `/secrets` requires admin+
- **API mutations**: `/api/tenants`, `/api/secrets`, `/api/features`, `/api/impersonate` require admin+ for non-GET

**Gap:** The `/secrets` page is admin-restricted, but the settings page at `/settings` (which can modify IP whitelist, MFA, session timeouts) has **no role restriction** in middleware. Any authenticated operator can access and modify platform settings.

**Fix:** Add `/settings` to `ADMIN_PAGE_PREFIXES` and `/api/v1/operator/settings` to `ADMIN_MUTATION_API_PREFIXES` (once the route exists).

### 5.3 Login Security — Assessment: ✅ STRONG

- DB-backed rate limiting per IP (5 attempts, 15-minute lockout)
- bcrypt password verification with constant-time dummy hash on miss (prevents email enumeration)
- mCaptcha CAPTCHA integration (configurable via env)
- Credentials exclusively from environment variables (no hardcoded passwords)
- CSRF validated on login (separate from middleware CSRF)

### 5.4 Session Management — Assessment: ✅ GOOD

- 8-hour session duration
- 24-hour absolute maximum age
- Sliding refresh at 4-hour mark (half-life)
- Cookie attributes: `httpOnly`, `secure` (prod), `sameSite: strict`, scoped to `/`
- Invalid sessions are cleared on detection

### 5.5 CSP Note

The Content-Security-Policy in middleware is:
```
default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'
```

The mCaptcha widget loads an external script from `unpkg.com`. If mCaptcha is enabled, this CSP will **block** the glue script unless `NEXT_PUBLIC_MCAPTCHA_GLUE_SCRIPT_URL` is added to the `script-src` directive.

**Fix:** If mCaptcha is used, add the script domain to CSP:
```
script-src 'self' https://unpkg.com;
```

---

## 6. Integration Audit

### 6.1 `proxyToRust` Pattern — Assessment: ✅ GOOD

Defined in `src/lib/rust-api.ts`. Forwards requests to `RUST_ADMIN_API_URL` (default `http://localhost:3001`) with `x-api-key` header from `RUST_ADMIN_API_KEY` env var. Includes:
- Original request body and method forwarding
- Query string forwarding
- `Content-Type: application/json` header
- `x-forwarded-for` header preservation
- Session cookie forwarding
- Timeout: 30 seconds
- Error wrapping with original status code

37 of 46 API routes use this pattern. The 9 that don't:
- `auth/login` (direct DB queries + bcrypt)
- `auth/session` (direct HMAC verification)
- `auth/logout` (cookie clearing only)
- `autopilot` (custom fetch to `AUTOPILOT_API_URL` port 3010)
- 5 remaining are likely direct DB or thin wrappers

### 6.2 Hardcoded URLs — Assessment: ✅ CLEAN

No hardcoded production URLs found in source. All external URLs use environment variables:
- `RUST_ADMIN_API_URL` → Rust admin API
- `AUTOPILOT_API_URL` → Autopilot service
- `NEXT_PUBLIC_MCAPTCHA_WIDGET_URL` → mCaptcha widget
- `NEXT_PUBLIC_MCAPTCHA_GLUE_SCRIPT_URL` → mCaptcha JS (defaults to unpkg.com)

### 6.3 Required Environment Variables

| Variable | Used In | Required |
|----------|---------|----------|
| `CONTROL_PLANE_JWT_SECRET` | middleware.ts | ✅ CRITICAL |
| `CSRF_SECRET` | middleware.ts | ✅ CRITICAL |
| `CONTROL_PLANE_IP_WHITELIST` | middleware.ts | ✅ PRODUCTION |
| `CONTROL_PLANE_API_KEY` | middleware.ts | Optional (API key auth) |
| `RUST_ADMIN_API_URL` | rust-api.ts | Defaults to localhost:3001 |
| `RUST_ADMIN_API_KEY` | rust-api.ts | ✅ REQUIRED for Rust proxy |
| `CEO_EMAIL` / `CEO_PASSWORD_HASH` | login route | ✅ At least one credential pair |
| `DATABASE_URL` | db.ts | ✅ REQUIRED for login |
| `AUTOPILOT_API_URL` | autopilot route | Defaults to localhost:3010 |

---

## 7. Route ↔ Frontend Coverage Matrix

### Pages with ALL routes verified working:
| Page | API Routes | Status |
|------|-----------|--------|
| Dashboard `/` | `GET /api/dashboard/stats` | ✅ |
| Analytics `/analytics` | `GET /api/analytics`, `/api/analytics/platform`, `/api/analytics/export` | ✅ |
| Sales `/sales` | `GET /api/sales/leads`, `campaigns`, `settings`; `PATCH leads/update`; `POST discovery/run`, `outreach/start` | ✅ |
| Secrets `/secrets` | `GET/POST/PATCH/DELETE /api/secrets` | ✅ |
| Compliance `/compliance` | `GET /api/compliance/overview` | ✅ |
| Leads `/leads` | `GET /api/leads/discovery`, `GET /api/crm/leads`, `POST /api/sales/discovery/run` | ✅ |
| Autopilot `/autopilot` | `GET/POST /api/autopilot` | ✅ |
| Revenue `/revenue` | `GET /api/revenue` | ✅ |
| Support `/support` | `GET/POST/PUT /api/support`, `GET /api/support/analytics` | ✅ |
| GDPR `/gdpr` | `GET/PATCH /api/gdpr` | ✅ |
| Inbox `/inbox` | `GET/PATCH /api/inbox`, `GET/PUT /api/inbox/config` | ✅ |
| Risk `/risk` | `GET/PATCH /api/risk`, `PATCH /api/tenants` | ✅ |
| Login `/login` | `GET /api/csrf`, `POST /api/auth/login` | ✅ |
| Content `/content` | `GET/POST/PATCH/DELETE /api/content` | ✅ |
| Audit `/audit` | `GET /api/audit`, `GET /api/audit/export` | ✅ |
| Tenants `/tenants` | `GET/PATCH/DELETE /api/tenants`, `POST /api/impersonate` | ✅ |

### Pages with BROKEN routes:
| Page | Broken Call | Issue |
|------|------------|-------|
| **Settings** `/settings` | `GET/PUT /api/v1/operator/settings` | Route does not exist |
| **IP Warmer** `/ip-warmer` | `POST /api/warmup/ip/{ip}/start\|pause\|resume\|reset\|day`, `POST /api/warmup/advance` | 6 routes don't exist |
| **Campaigns** `/campaigns` | `PATCH /api/campaigns/{id}` | Dynamic route missing |
| **Calendar** `/calendar` | `PATCH /api/calendar/events/{id}/status`, `PATCH /api/calendar/availability/{id}` | 2 routes missing |
| **System** `/system` | `POST /api/system/workers/{id}/restart`, `POST /api/system/alerts/{id}/acknowledge` | Worker route missing + method mismatch on alert |
| **Features** `/features` | `DELETE /api/features` | DELETE handler not exported |
| **CRM** `/crm` | `PATCH/DELETE/POST /api/crm/leads` | Only GET exported |

### Unused API routes (no frontend consumer found):
| Route | Methods | Notes |
|-------|---------|-------|
| `/api/audit/alerts` | GET, PUT | Not called by audit page; may be for programmatic use |
| `/api/integrations` | GET, POST | No integrations page exists |
| `/api/integrations/[id]` | GET, POST, PUT, DELETE | No integrations page exists |
| `/api/settings/backup` | GET, POST | Not called by settings page (it calls `/api/v1/operator/settings`) |
| `/api/settings/backup/run` | POST | Same |
| `/api/settings/backup/dr-test` | POST | Same |
| `/api/proxy` | POST | Not called by any page |
| `/api/sales/leads/enrich` | POST | Not called by any page (enrichment may be backend-only) |

---

## 8. Summary by Severity

| Severity | Count | Description |
|----------|-------|-------------|
| 🔴 CRITICAL | 6 | Missing API routes — entire features are dead buttons |
| 🟠 HIGH | 3 | HTTP method mismatches — mutations fail with 405 |
| 🟡 MEDIUM | 5 | Fire-and-forget mutations without rollback |
| 🔵 LOW | 3 | DOM anti-patterns (acceptable in context) |
| 🟢 SECURITY | 1 | Settings page missing RBAC restriction |
| 🟢 SECURITY NOTE | 1 | CSP may block mCaptcha external script |

### Immediate Action Items (Priority Order):

1. **Create 10+ missing API route files** (§1.1–1.6) — Entire pages are non-functional
2. **Add missing HTTP method exports** (§2.1–2.3) — CRM, features, system alerts broken
3. **Add `/settings` to ADMIN_PAGE_PREFIXES** — Any operator can currently change platform settings
4. **Add rollback to fire-and-forget mutations** (§3.1–3.5) — Data inconsistency risk
5. **Update CSP for mCaptcha** if mCaptcha is enabled in production

### What's Working Well:

- ✅ **No `window.confirm` anywhere** — All confirmations use `useDialog()` with `dialog.confirm()`
- ✅ **CSRF tokens on all mutations** — Every POST/PATCH/PUT/DELETE includes `getCsrfToken()` and `X-CSRF-Token` header
- ✅ **Middleware is comprehensive** — 4-layer security, sliding sessions, constant-time crypto
- ✅ **All pages have loading states** — Either `PageLoadingState` component or custom spinner
- ✅ **Empty states present** — Most lists show "No items found" type messages when empty
- ✅ **Calendar, GDPR, Risk, CRM pages have proper optimistic rollback**
- ✅ **No hardcoded credentials or URLs** — Environment variables used throughout
- ✅ **Rate limiting on login** — DB-backed with IP-based lockout
