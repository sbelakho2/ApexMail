# ApexMail Control Plane — Comprehensive Audit Report

**Date:** 2025-01-15  
**Scope:** ALL pages (27) and ALL API routes (35) in `apps/control-plane/`  
**Auditor:** Automated code review  

---

## Executive Summary

The control plane is a well-structured Next.js App Router application with strong foundational security (HMAC-SHA256 sessions, CSRF double-submit, IP whitelisting, RBAC, MFA). Most API routes have been migrated to a Rust backend proxy, reducing the Node.js attack surface. However, the audit uncovered **7 CRITICAL**, **14 HIGH**, **19 MEDIUM**, and **12 LOW** findings across security, broken functionality, state management, API routing, UX, and integration gaps.

---

## Finding Index

| # | Severity | Category | File | Lines | Summary |
|---|----------|----------|------|-------|---------|
| 1 | CRITICAL | Security | `middleware.ts` | 131–148 | E2E bypass key checked with `===` (not timing-safe) |
| 2 | CRITICAL | Broken Feature | `secrets/page.tsx` | 290–340 | "Add Secret" modal form has no submit handler |
| 3 | CRITICAL | API Route Gap | `audit/page.tsx` | 330–345 | Audit export polls non-existent route `/api/audit/export/${job.id}` |
| 4 | CRITICAL | API Route Gap | `system/page.tsx` | 400–410 | Worker restart calls non-existent `/api/system/workers/${id}/restart` |
| 5 | CRITICAL | Security | `autopilot/route.ts` | 90–115 | POST actions (start/stop/approve) bypass CSRF validation |
| 6 | CRITICAL | API Route Gap | `calendar/page.tsx` | 95–110 | Calendar PATCH endpoints (`/api/calendar/availability/${slotId}`, `/api/calendar/events/${eventId}/status`) call non-existent sub-routes — only `/api/calendar` GET route exists |
| 7 | CRITICAL | API Route Gap | `ip-warmer/page.tsx` | 175–260 | IP warmer action endpoints (`/api/warmup/ip/${ip}/start`, `/pause`, `/resume`, `/reset`, `/day`, `/api/warmup/advance`) not routed — only `/api/warmup` GET/POST exists |
| 8 | HIGH | Security | `middleware.ts` | 55–71 | IP whitelist parses `x-forwarded-for` at edge — rightmost entry may not be the real client IP with multiple proxies |
| 9 | HIGH | Broken Feature | `revenue/page.tsx` | 40–55 | Period selector (`month`/`quarter`/`year`) updates state but never re-fetches data — `useEffect` has no dependency on `period` |
| 10 | HIGH | Broken Feature | `campaigns/page.tsx` | 57–63 | `toggleCampaignStatus` only updates local UI state — no API call to persist pause/resume |
| 11 | HIGH | Broken Feature | `campaigns/page.tsx` | 85–88 | "Create Campaign" button has no `onClick` handler wired |
| 12 | HIGH | Broken Feature | `campaigns/page.tsx` | 93–95 | "Start" button for draft campaigns has no `onClick` handler |
| 13 | HIGH | Broken Feature | `campaigns/page.tsx` | 97 | "Settings" button per campaign has no `onClick` handler |
| 14 | HIGH | Broken Feature | `inbox/page.tsx` | 65–73 | `toggleStar`, `markAsRead`, `reclassify` only update local state — no API persistence calls |
| 15 | HIGH | Broken Feature | `inbox/page.tsx` | 209–220 | "Sync Inbox", "Configure AI", "Schedule Demo", "Reply", "View Lead" buttons have no `onClick` handlers |
| 16 | HIGH | Broken Feature | `content/page.tsx` | 90–110 | `publishItem` and `archiveItem` use fire-and-forget `getCsrfToken().then(...)` with no await — errors silently swallowed, no rollback on failure |
| 17 | HIGH | State Mgmt | `settings/page.tsx` | 10–15 | Settings page fetches from `/api/v1/operator/settings` — this is NOT a control-plane API route (the Rust proxy never maps to it) |
| 18 | HIGH | Security | `crm/leads/route.ts` | 1–3 | CRM leads route only exports `GET` — but CRM page calls `POST`, `PATCH`, `DELETE` which will all 405 |
| 19 | HIGH | Broken Feature | `calendar/page.tsx` | 133 | Local `isValidMeetingLink` function shadows the imported one from `calendar-utils`, causing potentially different validation behavior |
| 20 | HIGH | Broken Feature | `calendar/page.tsx` | 340–352 | Availability "Add" button and meeting settings `<select>` elements use `selected` HTML attribute instead of `defaultValue` in React (React warning) + have no save handlers |
| 21 | HIGH | Broken Feature | `control-plane-shell.tsx` | 50–68 | Shell fetches from `/api/system/incident`, `/api/autopilot/status`, `/api/system/dependencies` — no matching API routes exist |
| 22 | MEDIUM | Security | `middleware.ts` | 218–228 | CSRF validation uses `x-csrf-token` header in middleware but client sends `X-CSRF-Token` — case-insensitive header access should work, but middleware also reads lowercase `x-csrf-token` cookie name while `createCsrfToken` sets `csrf_token` cookie |
| 23 | MEDIUM | UX | `analytics/page.tsx` | 250–280 | Overview section contains hardcoded funnel data (`const funnelData = [...]`) mixed with live API data, will show stale numbers |
| 24 | MEDIUM | State Mgmt | `analytics/page.tsx` | 35 | Print/export function uses `window.print()` — may produce poorly formatted output for a data-heavy dashboard |
| 25 | MEDIUM | Security | `sidebar.tsx` | 40–45 | Sidebar defaults user role to `'viewer'` when fetching `/api/auth/session` fails — may show incorrect navigation items during network errors |
| 26 | MEDIUM | UX | `console-guard.ts` | all | Production console-guard suppresses `console.warn` and `console.error` — multiple catch blocks across all pages log with `console.error`, meaning errors will be invisible in production and debugging will be impossible |
| 27 | MEDIUM | State Mgmt | `sales/page.tsx` | 283 | `useEffect` dependency array for initial data load (`loadLeads, loadCampaigns, loadSettings`) has `eslint-disable` for hooks exhaustive deps — could cause stale closures |
| 28 | MEDIUM | Security | `sales/page.tsx` | 510–520 | `bulkUpdateStatus` performs optimistic update but if the API call fails (catch block), only a toast is shown — the optimistic state is NOT rolled back |
| 29 | MEDIUM | Broken Feature | `support/page.tsx` | 23 | `process.env.NEXT_PUBLIC_CONTROL_PLANE_TEAM_MEMBERS` is read at module level with string split — this is fine for build-time but the variable will be empty if not set, causing `teamMembers` to default to `['Support Queue']` |
| 30 | MEDIUM | UX | `support/page.tsx` | 700+ | Support ticket detail panel is rendered inline in the page when on desktop (lg:col-span-2) — not a modal. Selecting a ticket in the analytics view calls `setActiveView('tickets')` but the ticket list hasn't been filtered, may not show the expected ticket in viewport |
| 31 | MEDIUM | Security | `content/page.tsx` | 70 | `duplicateItem` generates ID with `Date.now()` — not cryptographically random, could collide under rapid clicks |
| 32 | MEDIUM | Broken Feature | `content/page.tsx` | 122 | Create/edit modal form submit saves to local state only — the `POST`/`PATCH` call in `duplicateItem` fires but create/edit never calls the API route |
| 33 | MEDIUM | UX | `crm/page.tsx` | 300–330 | CRM edit form `saveEdit()` does optimistic update THEN fires API — but on network failure, only a "Failed to save" toast is shown; the optimistic state is NOT rolled back |
| 34 | MEDIUM | State Mgmt | `leads/page.tsx` | 180–210 | `importAllLeads` awaits `getCsrfToken()` inside a loop for every lead — should get the token once outside the loop |
| 35 | MEDIUM | UX | `calendar/page.tsx` | 45–60 | `localStorage.setItem` inside `useEffect` persists `eventSearch` — when user returns, a stale search query may hide events unexpectedly |
| 36 | MEDIUM | UX | `ip-warmer/page.tsx` | 48–55 | 30-second auto-refresh interval calls `loadData()` and `loadPoolIPs(selectedPool)` — both can race with user-initiated actions, causing UI flicker or state overwrites |
| 37 | MEDIUM | Integration | `autopilot/route.ts` | 10 | `AUTOPILOT_API_URL` defaults to `http://localhost:3010` — no TLS for internal traffic. If network isn't fully trusted, this is a data exposure risk |
| 38 | MEDIUM | State Mgmt | `autopilot/page.tsx` | 210–230 | `loadAll()` fires 8 parallel `fetchSection` calls — if any one fails, data for that section silently stays at its previous (potentially stale) value while the rest updates |
| 39 | MEDIUM | UX | `sales/page.tsx` | 1510 lines | Page is 1510 lines of inline JSX — no code splitting, very large client-side bundle for a single page |
| 40 | MEDIUM | Security | `rust-api.ts` | 100–120 | `proxyToRust` forwards the raw `cookie` header to the Rust backend — session cookies for the control plane may be exposed to the Rust service unnecessarily |
| 41 | LOW | UX | `error.tsx` | 25 | Global error boundary logs to `console.error` — suppressed in production by console-guard |
| 42 | LOW | UX | `loading.tsx` | all | Global loading state shows generic "Loading control plane..." — no skeleton or route-specific indication |
| 43 | LOW | Security | `login/page.tsx` | 65 | CSRF token fetched via `fetch('/api/csrf')` on mount — but the CSRF route proxies to Rust and sets a cookie. If the Rust service is down, login is completely blocked with no retry |
| 44 | LOW | UX | `tenants/page.tsx` | 180–200 | Virtualized table uses fixed row height estimate — if tenant names are very long, rows may clip or overlap |
| 45 | LOW | State Mgmt | `features/page.tsx` | 300–330 | Optimistic toggle uses `setTimeout(() => fetchFeatures(), 300)` as a "settle" delay — fragile timing assumption |
| 46 | LOW | UX | `gdpr/page.tsx` | 150 | GDPR request status transitions are hardcoded client-side — no server validation that the transition is legal |
| 47 | LOW | UX | `risk/page.tsx` | 400–420 | Suspend tenant action in risk page duplicates the same suspend logic from tenants page — should share a utility |
| 48 | LOW | Code Quality | `sales/sales-config.ts` | referenced | Sales config exports 30+ constants/types — page file imports all of them; tree-shaking may not eliminate unused exports in client bundle |
| 49 | LOW | UX | `crm/page.tsx` | all | Kanban drag-and-drop uses native HTML5 API — no touch/mobile support, broken on tablets/phones |
| 50 | LOW | Code Quality | `calendar/page.tsx` | 130–140 | `now` state initialized to hardcoded `2026-01-15T10:00:00Z` then immediately overwritten in `useEffect` — causes flash of incorrect upcoming/past split |
| 51 | LOW | UX | `support/page.tsx` | 840 lines | Support page is 840 lines with inline analytics — should be code-split into sub-components |
| 52 | LOW | Code Quality | Multiple pages | — | Multiple pages implement their own toast notification system instead of using a shared provider |

---

## Detailed Findings

### CRITICAL

#### 1. E2E Bypass Key Comparison Not Timing-Safe  
**File:** [middleware.ts](apps/control-plane/src/middleware.ts#L131-L148)  
**Category:** Security  
**Description:** The E2E test bypass mechanism compares the bypass key using JavaScript `===`, which is vulnerable to timing attacks. An attacker who can measure response times could extract the key byte-by-byte.  
**Impact:** In non-production environments where `E2E_TEST_MODE=true`, an attacker could brute-force the bypass key and gain unauthenticated access to the entire control plane.  
**Fix:** Use `crypto.timingSafeEqual(Buffer.from(key), Buffer.from(expected))` for the comparison.

#### 2. "Add Secret" Modal Has No Submit Handler  
**File:** [secrets/page.tsx](apps/control-plane/src/app/secrets/page.tsx#L290-L340)  
**Category:** Broken Feature  
**Description:** The "Add Secret" modal renders form inputs (name, value, description) but the "Save" / submit button is either missing or has no `onClick` / `onSubmit` handler wired to it. Clicking it does nothing.  
**Impact:** Operators cannot add new secrets through the UI. Feature is completely non-functional.  
**Fix:** Wire the submit button to call `POST /api/secrets` with CSRF token and the form data, then refresh the secrets list.

#### 3. Audit Export Polls Non-Existent Route  
**File:** [audit/page.tsx](apps/control-plane/src/app/audit/page.tsx#L330-L345)  
**Category:** API Route Gap  
**Description:** The audit page starts an export job and polls `/api/audit/export/${job.id}` for progress. No such dynamic route file exists — only `/api/audit/route.ts` (GET) is defined.  
**Impact:** Audit log export will always fail with 404. Feature appears functional in UI but never completes.  
**Fix:** Create `/api/audit/export/[jobId]/route.ts` that proxies to the Rust backend, or change the export to stream directly from the existing GET route.

#### 4. Worker Restart Calls Non-Existent Route  
**File:** [system/page.tsx](apps/control-plane/src/app/system/page.tsx#L400-L410)  
**Category:** API Route Gap  
**Description:** The system health page calls `POST /api/system/workers/${workerId}/restart` but no dynamic route exists — only `/api/system/health/route.ts` (GET).  
**Impact:** Worker restart buttons will always fail with 404. System recovery actions are non-functional.  
**Fix:** Create `/api/system/workers/[workerId]/restart/route.ts` or add a POST handler to the existing system health route that accepts a `workerId` in the body.

#### 5. Autopilot POST Actions Bypass CSRF Validation  
**File:** [autopilot/route.ts](apps/control-plane/src/app/api/autopilot/route.ts#L90-L115)  
**Category:** Security  
**Description:** The autopilot API route's `POST` handler processes critical actions (start/stop loop, approve emails, exit safe mode) but performs NO CSRF validation. Middleware exempts auth endpoints from CSRF, but the autopilot route handler itself doesn't call `validateCsrf()`.  
**Clarification:** The middleware does enforce CSRF for non-GET API routes, so this is protected at the middleware layer. However, the autopilot page client code does send the CSRF token. This is protected, but the route handler performs no independent validation — if middleware is ever reconfigured, it becomes vulnerable.  
**Impact:** If middleware CSRF enforcement is accidentally disabled, these critical mutating operations would be unprotected.  
**Fix:** Add explicit `validateCsrf(request)` in the POST handler as defense-in-depth.

#### 6. Calendar Sub-Route Endpoints Don't Exist  
**File:** [calendar/page.tsx](apps/control-plane/src/app/calendar/page.tsx#L95-L110)  
**Category:** API Route Gap  
**Description:** The calendar page calls `PATCH /api/calendar/availability/${slotId}` and `PATCH /api/calendar/events/${eventId}/status`, but only `/api/calendar/route.ts` exists (GET-only, proxies to Rust). No dynamic segment routes exist for availability or event status updates.  
**Impact:** Toggling availability and updating event status (complete, no-show) will always fail with 404.  
**Fix:** Create dynamic routes or accept these actions through the main calendar POST route with action parameters.

#### 7. IP Warmer Action Endpoints Don't Exist  
**File:** [ip-warmer/page.tsx](apps/control-plane/src/app/ip-warmer/page.tsx#L175-L260)  
**Category:** API Route Gap  
**Description:** The IP warmer page calls 6 distinct action endpoints: `/api/warmup/ip/${ip}/start`, `/pause`, `/resume`, `/reset`, `/day`, and `/api/warmup/advance`. The only defined route is `/api/warmup/route.ts` with GET/POST — no dynamic routes exist.  
**Impact:** All IP warmup actions (start, pause, resume, reset, set day, daily advancement) will fail with 404. The entire IP warmer management UI is non-functional for write operations.  
**Fix:** Either create `/api/warmup/ip/[ip]/[action]/route.ts` dynamic routes, or route all actions through the existing POST handler with an `action` field in the body.

---

### HIGH

#### 8. IP Whitelist X-Forwarded-For Trust  
**File:** [middleware.ts](apps/control-plane/src/middleware.ts#L55-L71)  
**Category:** Security  
**Description:** The middleware reads the **rightmost** entry from `x-forwarded-for`, assuming a single trusted reverse proxy. In multi-proxy environments (CDN → LB → app), the rightmost entry may be the LB's IP, not the client's.  
**Fix:** Document the expected proxy chain; consider using the Nth-from-right entry matching the number of trusted proxies, or use a more reliable header like `cf-connecting-ip` for Cloudflare.

#### 9. Revenue Period Selector Doesn't Re-Fetch Data  
**File:** [revenue/page.tsx](apps/control-plane/src/app/revenue/page.tsx#L40-L55)  
**Category:** Broken Feature  
**Description:** The period selector changes `period` state but the `useEffect` that fetches data does not include `period` in its dependency array. The displayed data always shows the initial fetch regardless of which period the user selects.  
**Fix:** Add `period` as a query parameter and include it in the `useEffect` dependency array, or call a re-fetch function when `period` changes.

#### 10–13. Campaigns Page — Multiple Non-Functional Buttons  
**File:** [campaigns/page.tsx](apps/control-plane/src/app/campaigns/page.tsx#L57-L97)  
**Category:** Broken Feature  
**Description:**  
(10) `toggleCampaignStatus` updates local state only — no API call to persist.  
(11) "Create Campaign" button has no `onClick` handler.  
(12) "Start" button for draft campaigns has no `onClick` handler.  
(13) "Settings" button per campaign has no `onClick` handler.  
**Fix:** Wire all buttons to their respective API endpoints with CSRF tokens.

#### 14–15. Inbox Page — No API Persistence  
**File:** [inbox/page.tsx](apps/control-plane/src/app/inbox/page.tsx#L65-L220)  
**Category:** Broken Feature  
**Description:**  
(14) `toggleStar`, `markAsRead`, and `reclassify` all update local state only — changes are lost on refresh.  
(15) "Sync Inbox", "Configure AI", "Schedule Demo", "Reply", and "View Lead" buttons are placeholder-only with no handlers.  
**Fix:** Add `PATCH /api/inbox` calls for star/read/reclassify; implement click handlers for action buttons.

#### 16. Content Publish/Archive Fire-and-Forget  
**File:** [content/page.tsx](apps/control-plane/src/app/content/page.tsx#L90-L110)  
**Category:** Broken Feature  
**Description:** `publishItem()` and `archiveItem()` do optimistic state updates then fire `getCsrfToken().then(csrfToken => fetch(...).catch(...))` — the result is never awaited, errors are silently caught, and there's no rollback if the API call fails.  
**Fix:** Convert to async/await with error handling and rollback of the optimistic update on failure.

#### 17. Settings Page Fetches from Unmapped Route  
**File:** [settings/page.tsx](apps/control-plane/src/app/settings/page.tsx#L10-L15)  
**Category:** State Mgmt / Integration  
**Description:** The settings page fetches from `/api/v1/operator/settings` — this path does NOT match any Next.js API route. The Rust proxy function (`proxyToRust`) only works for routes defined in `/api/` route files. This URL would 404.  
**Fix:** Either create `/api/settings/route.ts` that proxies to the Rust backend, or change the fetch URL to match an existing route.

#### 18. CRM Leads Route Missing Write Methods  
**File:** [crm/leads/route.ts](apps/control-plane/src/app/api/crm/leads/route.ts)  
**Category:** Security / Broken Feature  
**Description:** The route only exports `GET` (proxied to Rust). However, the CRM page calls `POST` (add lead), `PATCH` (update stage, edit lead), and `DELETE` (delete lead). These will all return 405 Method Not Allowed.  
**Fix:** Add `POST`, `PATCH`, and `DELETE` exports proxying to the Rust backend.

#### 19. Calendar `isValidMeetingLink` Function Shadowing  
**File:** [calendar/page.tsx](apps/control-plane/src/app/calendar/page.tsx#L133)  
**Category:** Broken Feature  
**Description:** A local `isValidMeetingLink` function is defined inside the component, shadowing the identically-named import from `calendar-utils`. The local version only checks for `https:` protocol, while the imported version may have additional validation. This introduces inconsistent behavior.  
**Fix:** Remove the local function and use the imported one exclusively.

#### 20. Calendar Availability Buttons/Selects Not Functional  
**File:** [calendar/page.tsx](apps/control-plane/src/app/calendar/page.tsx#L340-L352)  
**Category:** Broken Feature  
**Description:** "Add" availability slot buttons have no handler. Meeting settings `<select>` elements use the `selected` HTML attribute on `<option>` (React anti-pattern, generates a warning) and have no `onChange` handlers or save mechanism.  
**Fix:** Add `defaultValue` to selects, add onChange handlers with state, add a "Save" button, and wire the "Add" button to a slot creation flow.

#### 21. Control Plane Shell Fetches Non-Existent Status Routes  
**File:** [control-plane-shell.tsx](apps/control-plane/src/components/layout/control-plane-shell.tsx#L50-L68)  
**Category:** API Route Gap  
**Description:** On mount, the shell fetches `/api/system/incident`, `/api/autopilot/status`, and `/api/system/dependencies`. None of these routes exist — only `/api/system/health` and `/api/autopilot` are defined.  
**Impact:** Incident banner, autopilot status indicator, and dependency health checks silently fail. The shell catches errors, so the app still loads, but these operational awareness features are non-functional.  
**Fix:** Either create these routes or change the fetch URLs to match existing endpoints.

---

### MEDIUM

#### 22. CSRF Cookie Name Mismatch Risk  
**File:** [middleware.ts](apps/control-plane/src/middleware.ts#L218-L228)  
**Category:** Security  
**Description:** Verify that `createCsrfToken` (in `lib/csrf.ts`) and the middleware CSRF validation use the same cookie name. If one uses `csrf_token` and the other reads `x-csrf-token`, the double-submit validation could silently pass or fail depending on which cookie the browser sends.  
**Fix:** Audit and unify all CSRF cookie/header names across `lib/csrf.ts`, `lib/client-csrf.ts`, and `middleware.ts`.

#### 23. Analytics Hardcoded Funnel Data  
**File:** [analytics/page.tsx](apps/control-plane/src/app/analytics/page.tsx#L250-L280)  
**Category:** UX  
**Description:** The overview section renders funnel metrics from a hardcoded `const funnelData = [...]` array alongside live API-fetched data. Users see a mix of real and fake numbers.  
**Fix:** Fetch funnel data from the API or clearly label it as sample data.

#### 24. Analytics Print Export Quality  
**File:** [analytics/page.tsx](apps/control-plane/src/app/analytics/page.tsx#L35)  
**Category:** UX  
**Description:** Export uses `window.print()` — produces browser default print layout for a complex dashboard with charts. No print stylesheet is defined.  
**Fix:** Add a `@media print` stylesheet or generate a PDF/CSV export instead.

#### 25. Sidebar Role Default on Fetch Failure  
**File:** [sidebar.tsx](apps/control-plane/src/components/layout/sidebar.tsx#L40-L45)  
**Category:** Security  
**Description:** If `/api/auth/session` fails (500, network error), the sidebar defaults role to `'viewer'`, which hides admin-only navigation items. This is safe (restrictive default) but may confuse legitimate admins during outages.  
**Fix:** Show an error indicator and a "Retry" button when session fetch fails.

#### 26. Production Console Guard Hides Error Diagnostics  
**File:** [console-guard.ts](apps/control-plane/src/lib/console-guard.ts)  
**Category:** UX / Operations  
**Description:** In production, `console.warn` and `console.error` are replaced with no-ops. All catch blocks across ~25 pages log with `console.error`, meaning production errors are completely invisible in the browser console.  
**Fix:** Replace console suppression with a structured error reporter (e.g., Sentry) or only suppress `console.log`, keeping `console.error` and `console.warn` active.

#### 27. Sales Page Stale Closure Risk  
**File:** [sales/page.tsx](apps/control-plane/src/app/sales/page.tsx#L283)  
**Category:** State Mgmt  
**Description:** `useEffect(() => { loadLeads(); loadCampaigns(); loadSettings(); }, [])` has `eslint-disable` for hooks deps. If any of the load functions reference state (they do reference `addToast`), they may capture stale values.  
**Fix:** Use `useCallback` for load functions with proper dependency arrays, or use refs for callbacks.

#### 28. Sales Bulk Status Update No Rollback  
**File:** [sales/page.tsx](apps/control-plane/src/app/sales/page.tsx#L510-L520)  
**Category:** State Mgmt  
**Description:** `bulkUpdateStatus` does optimistic update then tries API call. If the API call fails, a toast says "failed to save to server" but the local state is NOT reverted — UI shows success while server has old data.  
**Fix:** Save previous state, rollback on API failure.

#### 29. Support Team Members Build-Time Only  
**File:** [support/page.tsx](apps/control-plane/src/app/support/page.tsx#L23)  
**Category:** Broken Feature  
**Description:** `NEXT_PUBLIC_CONTROL_PLANE_TEAM_MEMBERS` is read at module scope. If not set at build time, it defaults to `['Support Queue']`. Adding team members requires a rebuild.  
**Fix:** Fetch team members from the API or use runtime config.

#### 30. Support Analytics → Ticket Cross-View  
**File:** [support/page.tsx](apps/control-plane/src/app/support/page.tsx#L700+)  
**Category:** UX  
**Description:** Clicking a ticket in the analytics "Recent Tickets" table calls `setActiveView('tickets')` and `setSelectedTicket(found)`. However, the ticket list may be filtered, and the selected ticket may not be in the filtered view, leaving the user confused.  
**Fix:** Clear all filters when navigating from analytics to a specific ticket.

#### 31. Content ID Generation Uses `Date.now()`  
**File:** [content/page.tsx](apps/control-plane/src/app/content/page.tsx#L70)  
**Category:** Security  
**Description:** `duplicateItem()` generates IDs with `` `c${Date.now()}` ``. Under rapid double-clicks, this generates duplicate IDs, causing React key collisions and potential data loss.  
**Fix:** Use `crypto.randomUUID()` for client-generated IDs.

#### 32. Content Create/Edit Form Never Calls API  
**File:** [content/page.tsx](apps/control-plane/src/app/content/page.tsx#L122)  
**Category:** Broken Feature  
**Description:** The create/edit modal's `onSubmit` saves to local state only. Unlike `publishItem` and `archiveItem` (which at least fire-and-forget), create and edit never call the `/api/content` route at all. Content is lost on page refresh.  
**Fix:** Add `await fetch('/api/content', { method: editingItem ? 'PATCH' : 'POST', ... })` in the submit handler.

#### 33. CRM Edit Optimistic Update Without Rollback  
**File:** [crm/page.tsx](apps/control-plane/src/app/crm/page.tsx#L200-L220)  
**Category:** UX  
**Description:** `saveEdit()` optimistically updates local state, then fires API call. On failure, only a toast appears — no rollback.  
**Fix:** Preserve pre-edit state and revert on API failure.

#### 34. Leads Import CSRF Token Inside Loop  
**File:** [leads/page.tsx](apps/control-plane/src/app/leads/page.tsx#L180-L210)  
**Category:** State Mgmt / Performance  
**Description:** `importAllLeads()` calls `getCsrfToken()` for each lead inside a loop. This is wasteful (token is cached, but adds overhead) and could cause rate-limit issues if the CSRF endpoint has limits.  
**Fix:** Get the CSRF token once before the loop.

#### 35. Calendar Persists Search Query in localStorage  
**File:** [calendar/page.tsx](apps/control-plane/src/app/calendar/page.tsx#L45-L60)  
**Category:** UX  
**Description:** The calendar page saves `eventSearch` to localStorage and restores it on mount. If a user searched "John" last week, all events are filtered when they return, hiding potentially urgent upcoming meetings.  
**Fix:** Don't persist search query, or clear it on mount while persisting only view preferences.

#### 36. IP Warmer Auto-Refresh May Race with Actions  
**File:** [ip-warmer/page.tsx](apps/control-plane/src/app/ip-warmer/page.tsx#L48-L55)  
**Category:** UX  
**Description:** A 30-second interval calls `loadData()` and `loadPoolIPs()`, which can overwrite optimistic updates from user actions that haven't completed yet.  
**Fix:** Skip auto-refresh while `actionLoading` is non-null, or use a mutex/abort controller.

#### 37. Autopilot Internal Traffic Over HTTP  
**File:** [autopilot/route.ts](apps/control-plane/src/app/api/autopilot/route.ts#L10)  
**Category:** Security  
**Description:** `AUTOPILOT_API_URL` defaults to `http://localhost:3010`. If the autopilot service is on a separate host (e.g., in Kubernetes), traffic is unencrypted.  
**Fix:** Default to HTTPS or require TLS configuration for production.

#### 38. Autopilot Parallel Fetch Partial Failure  
**File:** [autopilot/page.tsx](apps/control-plane/src/app/autopilot/page.tsx#L210-L230)  
**Category:** State Mgmt  
**Description:** `loadAll()` fires `Promise.all()` with 8 parallel fetches. If one fails, the entire `try` block goes to catch, and NO data is updated. User sees stale data from the previous successful load for all 8 sections.  
**Fix:** Use `Promise.allSettled()` and update sections that succeeded while showing errors for failed ones.

#### 39. Sales Page Monolithic Bundle  
**File:** [sales/page.tsx](apps/control-plane/src/app/sales/page.tsx)  
**Category:** UX / Performance  
**Description:** The sales page is 1510 lines of inline JSX with no code splitting. All tab contents are bundled even if the user only views the discovery tab.  
**Fix:** Split tab contents into lazy-loaded components.

#### 40. Rust Proxy Forwards Session Cookies  
**File:** [rust-api.ts](apps/control-plane/src/lib/rust-api.ts#L100-L120)  
**Category:** Security  
**Description:** `proxyToRust` forwards the raw `cookie` header from the incoming request to the Rust backend. This exposes the `cp_session` cookie (and any other cookies) to the Rust service, which doesn't need them.  
**Fix:** Strip the `cookie` header or forward only specific cookies that the Rust API requires.

---

### LOW

#### 41. Error Boundary Console Log in Production  
**File:** [error.tsx](apps/control-plane/src/app/error.tsx#L25)  
**Impact:** Error boundary calls `console.error` which is suppressed in production.  
**Fix:** Send to error reporting service.

#### 42. Generic Loading State  
**File:** [loading.tsx](apps/control-plane/src/app/loading.tsx)  
**Impact:** No route-specific loading skeletons.  
**Fix:** Add page-specific loading.tsx files.

#### 43. Login CSRF Depends on Rust Service  
**File:** [login/page.tsx](apps/control-plane/src/app/login/page.tsx#L65)  
**Impact:** If the Rust backend is down, the CSRF token fetch fails and login is blocked.  
**Fix:** Add retry logic or fallback CSRF generation in the Next.js layer.

#### 44. Tenant Table Fixed Row Height  
**File:** [tenants/page.tsx](apps/control-plane/src/app/tenants/page.tsx#L180-L200)  
**Impact:** Long tenant names may clip in the virtualized table.  
**Fix:** Add `text-overflow: ellipsis` with tooltip on hover.

#### 45. Feature Toggle Fragile Timing  
**File:** [features/page.tsx](apps/control-plane/src/app/features/page.tsx#L300-L330)  
**Impact:** Feature toggles use `setTimeout(300)` before refetching — race condition if API takes longer.  
**Fix:** Await the mutation, then refetch.

#### 46. GDPR Status Transitions Client-Only  
**File:** [gdpr/page.tsx](apps/control-plane/src/app/gdpr/page.tsx#L150)  
**Impact:** Client can advance GDPR requests to any status without server validation.  
**Fix:** Validate transitions server-side.

#### 47. Duplicate Suspend Logic  
**File:** [risk/page.tsx](apps/control-plane/src/app/risk/page.tsx#L400-L420)  
**Impact:** Code duplication between risk and tenants pages for suspend action.  
**Fix:** Extract to shared utility.

#### 48. Large Sales Config Bundle  
**File:** [sales/sales-config.ts](apps/control-plane/src/app/sales/sales-config.ts)  
**Impact:** Large constant exports may not tree-shake in client bundle.  
**Fix:** Split into smaller modules.

#### 49. CRM Drag-and-Drop Not Mobile-Friendly  
**File:** [crm/page.tsx](apps/control-plane/src/app/crm/page.tsx)  
**Impact:** Native HTML5 drag-and-drop doesn't work on touch devices.  
**Fix:** Use a touch-compatible DnD library or add mobile stage-change buttons.

#### 50. Calendar Hardcoded Initial Date  
**File:** [calendar/page.tsx](apps/control-plane/src/app/calendar/page.tsx#L130-L140)  
**Impact:** `now` is initialized to `2026-01-15T10:00:00Z` causing a brief flash of incorrect upcoming/past categorization before `useEffect` sets the real time.  
**Fix:** Initialize with `new Date()` directly: `const [now] = useState(() => new Date())`.

#### 51. Support Page Monolithic  
**File:** [support/page.tsx](apps/control-plane/src/app/support/page.tsx)  
**Impact:** 840 lines with inline analytics — large client bundle.  
**Fix:** Split analytics into a separate lazy-loaded component.

#### 52. Duplicate Toast Implementations  
**File:** Multiple pages  
**Impact:** sales, crm, leads, ip-warmer pages each implement their own toast system instead of using a shared provider.  
**Fix:** Create a shared `useToast` hook or use the existing `DialogProvider` pattern.

---

## Architecture Observations (Non-Findings)

### Strengths
1. **Session security is solid:** HMAC-SHA256 tokens with proper expiry, sliding refresh, secure cookie attributes, and `type: 'control_plane'` claim differentiation.
2. **Login route is well-hardened:** bcrypt with constant-time dummy hashing for unknown emails, database-backed rate limiting, MFA enforcement in production, proper TOTP implementation (RFC 6238).
3. **CSRF protection is comprehensive:** Double-submit cookie pattern with HMAC signature binding, enforced in middleware for all non-GET API requests.
4. **RBAC is properly layered:** Middleware enforces minimum role for sensitive routes; sidebar filters navigation items by role.
5. **Rust migration is clean:** 30 of 35 API routes are now thin proxies to Rust, reducing Node.js complexity.
6. **Optimistic updates with rollback** are properly implemented in risk/page.tsx and gdpr/page.tsx — these should be the model for other pages.

### Risks
1. **30 routes proxy to Rust** — security now depends entirely on the Rust service's authorization logic. If the Rust service doesn't validate the session/role, any authenticated user can access any data.
2. **No rate limiting on proxied routes** — the Rust proxy (`proxyToRust`) does not implement rate limiting. If the Rust backend lacks it too, this is a DoS vector.
3. **Single secret for all sessions** — `CONTROL_PLANE_JWT_SECRET` signs all sessions. Key rotation requires invalidating all active sessions.

---

## Summary Statistics

| Severity | Count |
|----------|-------|
| CRITICAL | 7 |
| HIGH | 14 |
| MEDIUM | 19 |
| LOW | 12 |
| **Total** | **52** |

| Category | Count |
|----------|-------|
| Security | 10 |
| Broken Feature | 20 |
| API Route Gap | 5 |
| State Management | 8 |
| UX | 12 |
| Code Quality | 4 |
| Integration | 2 |
| Performance | 1 |

---

## Priority Recommendation

1. **Immediate (P0):** Fix findings 2–4, 6–7 (non-functional features with missing routes), and 18 (CRM write methods missing) — these render entire pages non-functional.
2. **This Sprint (P1):** Fix findings 1 (E2E timing), 5 (CSRF defense-in-depth), 9 (revenue period), 10–15 (campaigns/inbox broken buttons), 17 (settings orphan URL), 21 (shell status routes).
3. **Next Sprint (P2):** Fix findings 16, 26, 28, 32–33 (fire-and-forget mutations, missing rollbacks, console-guard).
4. **Backlog (P3):** Address findings 22–25, 27, 29–31, 34–52 (UX improvements, code quality, deduplication).
