# Control Plane Exhaustive Audit — Final Report

**Scope:** `apps/control-plane/src/` — 22 page files, 54 API routes, 7 library files, middleware  
**Methodology:** Line-by-line file review + targeted `grep` across 6 categories

---

## Summary

| Category | Findings |
|----|----|
| 1. Security / Auth / RBAC | 0 |
| 2. Error Handling | 12 |
| 3. Wiring / Integration | 1 |
| 4. UI/UX Quality | 5 |
| 5. State Management | 2 |
| 6. Feature Completeness | 0 |
| **Total** | **20** |

Security/auth/RBAC is solid: middleware enforces IP whitelist, CSRF validation, session auth, and RBAC roles across all routes. Every client-side mutating fetch includes `getCsrfToken()` + `X-CSRF-Token` header + `credentials: 'include'`. No findings there.

---

## Findings

### Category 2 — Error Handling

---

**C1 · High** — `inbox/page.tsx` L362 — **Raw `alert()` instead of `dialog.alert()`**

The AI config save handler uses the browser's native `alert()`, which is inconsistent with every other page in the app (all use `dialog.alert()` from the shared confirm-dialog component). Worse, `inbox/page.tsx` does not import `useDialog` at all.

```tsx
// Current (line 362)
alert(err instanceof Error ? err.message : 'Failed to save AI config');
```

**Fix:** Import `useDialog` from `../../components/ui/confirm-dialog`, instantiate `const dialog = useDialog()`, and replace with:
```tsx
dialog.alert({ title: 'Save Failed', message: err instanceof Error ? err.message : 'Failed to save AI config' });
```

---

**C2 · Medium** — `content/page.tsx` L193 — **Delete failure is silent to user**

`deleteItem` catch block rolls back state and logs to console, but never notifies the user the delete was reverted. The user sees the item briefly disappear then reappear with no explanation.

```tsx
} catch (err) {
    console.error('Failed to persist delete:', err);
    setContent(previousContent);
    // ← no dialog.alert() or user feedback
}
```

**Fix:** Add user feedback after rollback:
```tsx
} catch (err) {
    console.error('Failed to persist delete:', err);
    setContent(previousContent);
    dialog.alert({ title: 'Delete Failed', message: 'Could not delete the item. The change has been reverted.' });
}
```

---

**C3 · Medium** — `content/page.tsx` L505 — **Content create/edit persist failure is silent**

The form submit handler persists content via a fire-and-forget `.catch(err => console.error(...))`. If the API call fails, the user sees the optimistic local update but is never told it didn't persist to the backend. On page refresh the change is lost.

```tsx
}).catch(err => console.error(`Failed to persist content ${editingItem ? 'update' : 'create'}:`, err));
```

**Fix:** Convert the fire-and-forget chain into an awaited call and show `dialog.alert` on failure, or at minimum roll back the local state:
```tsx
}).then(res => {
    if (!res.ok) throw new Error('Failed');
}).catch(() => {
    if (editingItem) {
        setContent(prev => prev.map(item => item.id === editingItem.id ? editingItem : item));
    } else {
        setContent(prev => prev.filter(item => item.id !== itemData.id));
    }
    dialog.alert({ title: 'Save Failed', message: 'Could not save content to the server. Your changes have been reverted.' });
});
```

---

**C4 · Medium** — `features/page.tsx` L127 — **Flag toggle persist failure is silent**

`toggleFlag` catch block rolls back and logs to console but never informs the user.

```tsx
.catch(err => {
    console.error('Failed to persist flag toggle:', err);
    setFlags(previousFlags);
});
```

**Fix:** Add `dialog.alert({ title: 'Toggle Failed', message: 'Could not persist the flag change. It has been reverted.' })` after the rollback.

---

**C5 · Low** — `features/page.tsx` L147 — **Percentage update persist failure is silent**

`updatePercentage` has the same pattern: rollback + `console.error`, no user feedback. Since percentage sliders fire on every change event this is lower severity, but the user should be told if the final value couldn't persist.

**Fix:** Same as C4 — add `dialog.alert` in the catch block.

---

**C6 · Medium** — `features/page.tsx` L86 — **Initial load failure is silently swallowed**

`loadData` catch block only does `console.error('Failed to load feature flags:', err)`. There is no error state, no `PageErrorState`, and no retry mechanism. The user sees the loading spinner disappear and an empty page with no explanation.

**Fix:** Add a `loadError` state, set it in the catch, and render `PageErrorState` when it's present:
```tsx
const [loadError, setLoadError] = useState<string | null>(null);
// in catch:
setLoadError(err instanceof Error ? err.message : 'Failed to load feature flags');
// before return:
if (loadError) {
    return <PageErrorState description={loadError} onRetry={() => { setLoadError(null); setLoading(true); loadData(); }} />;
}
```

---

**C7 · Medium** — `inbox/page.tsx` L78, L97, L120 — **Optimistic rollbacks are silent**

`toggleStar`, `markAsRead`, and `reclassify` all follow the same pattern: optimistic update → API call → `.catch(() => { setMessages(previousMessages); })`. When the API fails, the UI silently reverts. The user may not even notice their action was undone.

**Fix:** Add a lightweight banner/toast or `dialog.alert` in each catch to inform the user the action couldn't be saved. Example:
```tsx
.catch(() => {
    setMessages(previousMessages);
    dialog.alert({ title: 'Action Failed', message: 'Could not save the change. Please try again.' });
});
```

(This requires adding `useDialog` import — see C1.)

---

**C8 · Medium** — `settings/page.tsx` L596 — **Integration connect/configure failure is silent**

The integration button's catch block only does `console.error('Integration action failed:', err)`. Additionally, when `!res.ok`, the response is silently ignored (no error branch). The user gets no feedback.

**Fix:** Add user-visible error handling:
```tsx
if (!res.ok) {
    setSaveError(`Integration ${action} failed (${res.status}). Please try again.`);
    return;
}
```
And in the catch: `setSaveError('Integration action failed. Please check your network.');`

---

**C9 · Low** — `settings/page.tsx` L1128 — **Backup run failure is silent**

The "Run Backup Now" button's catch block only does `console.error('Backup failed:', err)`. The user clicks the button and gets no feedback when it fails.

**Fix:** Add `setSaveError('Backup failed. Please try again.');` in the catch block.

---

**C10 · Low** — `settings/page.tsx` L1151 — **DR test failure is silent**

Same pattern as C9: the DR failover test catch block only logs to console.

**Fix:** Add `setSaveError('DR test failed. Please try again.');` in the catch block.

---

**C11 · Low** — `calendar/page.tsx` L482 — **Add availability slot failure is silent**

The "Add" slot button's catch block rolls back the UI and logs to console, but never informs the user.

```tsx
} catch (err) {
    console.error('Failed to add availability slot:', err);
    setAvailability(prev => prev.filter(s => s.id !== newSlot.id));
}
```

**Fix:** Add `setLoadError('Failed to add availability slot. Please try again.');` after rollback.

---

**C12 · Medium** — `analytics/page.tsx` L48/L90 — **Error state is set but never rendered**

`analyticsError` state is declared and populated in the catch block, but is never referenced in the JSX. Load failures result in a blank/empty analytics view with no explanation.

**Fix:** Add an error banner in the rendering path, e.g.:
```tsx
{analyticsError && (
    <div className="mb-4 rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
        {analyticsError}
    </div>
)}
```

---

### Category 3 — Wiring / Integration

---

**C13 · Medium** — `autopilot/page.tsx` L223 — **`loadAll` failure leaves page in inconsistent state**

When `loadAll` fails (line 223: `console.error('Failed to load autopilot data:', e)`), loading is set to false but `overview` remains null. The page does render a retry button in that case (lines 315-320), **but** the 8 parallel `fetchSection` calls use `Promise.all` — a single section failing causes ALL sections to be lost. If only the `safety` endpoint is down, the user loses all data even though overview/metrics/candidates loaded fine.

**Fix:** Use `Promise.allSettled` instead of `Promise.all`, and apply partial results for sections that succeeded:
```tsx
const results = await Promise.allSettled([...]);
if (results[0].status === 'fulfilled') setOverview(results[0].value);
// ... etc for each section
```

---

### Category 4 — UI/UX Quality

---

**C14 · Medium** — `calendar/page.tsx` L500–L524 — **React `selected` attribute on `<option>` elements**

Four `<select>` elements in the Meeting Settings section use `<option selected>` instead of React's `defaultValue` prop on the parent `<select>`. In React, the `selected` attribute on `<option>` is non-standard and produces a console warning. Uncontrolled selects should use `defaultValue`.

```tsx
// Current
<select className="...">
    <option>15 minutes</option>
    <option selected>30 minutes</option>  // ← React warning
    <option>45 minutes</option>
</select>

// Fix
<select defaultValue="30 minutes" className="...">
    <option>15 minutes</option>
    <option>30 minutes</option>
    <option>45 minutes</option>
</select>
```

**Fix:** Add `defaultValue` to each `<select>` element and remove the `selected` attributes from the four affected `<option>` tags (lines 500, 509, 516, 524).

---

**C15 · Low** — `calendar/page.tsx` L493–L530 — **Meeting settings changes are not persisted**

The Meeting Settings section (Discovery Call Duration, Demo Duration, Buffer, Booking Notice) renders local-only `<select>` elements with no `onChange` handler and no state backing them. Changes are lost on navigation. There is no API call to save these settings.

**Fix:** Add state variables for each setting, wire onChange handlers, and persist via the calendar settings API.

---

**C16 · Low** — `content/page.tsx` L99 — **Publish action has no confirmation dialog**

`publishItem` immediately changes content status to "published" optimistically without asking for confirmation. Publishing makes content publicly visible — this is a significant action that should get a confirmation step (like `archiveItem` gets `dialog.alert` on failure, but the issue here is the lack of a pre-action confirmation).

**Fix:** Add `dialog.confirm({ title: 'Publish Content', message: 'This will make the content publicly visible. Continue?', confirmLabel: 'Publish' })` before the optimistic update.

---

**C17 · Low** — `content/page.tsx` L121 — **Archive action has no confirmation dialog**

Same as C16 — `archiveItem` immediately archives content optimistically without user confirmation. Archiving removes content from public view.

**Fix:** Wrap in `dialog.confirm({ title: 'Archive Content', message: 'This will remove the content from public view. Continue?', confirmLabel: 'Archive', variant: 'destructive' })`.

---

**C18 · Low** — `inbox/page.tsx` — **Missing `PageErrorState` import and load error handling**

The inbox page uses `useApiResource` for data loading, which provides error state. However, it does not import `PageErrorState` from `async-state`. If the API returns an error, the `useApiResource` hook handles the loading/error display generically, but the inbox config save (C1) still needs the dialog import to properly handle errors.

(This finding is subsumed by C1 — fixing C1 requires adding the dialog import which also enables future error state improvements.)

---

### Category 5 — State Management

---

**C19 · Low** — `sales/page.tsx` L612 — **Race condition with `setTimeout` for post-enrichment refresh**

After calling the enrichment API, the code blindly waits 3 seconds and then refreshes:
```tsx
setTimeout(() => loadLeads(), 3000);
```

This is unreliable — enrichment may take longer, or finish faster. The leads may be stale when displayed.

**Fix:** Instead of setTimeout, poll for completion or wire a webhook/SSE event for enrichment completion:
```tsx
// Poll approach:
const pollForEnrichment = async () => {
    for (let i = 0; i < 10; i++) {
        await new Promise(r => setTimeout(r, 2000));
        const res = await fetch('/api/sales/leads/enrich?status=check', { credentials: 'include' });
        if (res.ok) { const data = await res.json(); if (data.done) break; }
    }
    await loadLeads();
};
pollForEnrichment();
```

---

**C20 · Low** — `sales/page.tsx` L331 — **Missing dependency array items in initial load `useEffect`**

```tsx
useEffect(() => { loadLeads(); loadCampaigns(); loadSettings(); }, []); // eslint-disable-line react-hooks/exhaustive-deps
```

The ESLint suppression hides the fact that `loadLeads`, `loadCampaigns`, and `loadSettings` are referenced but not in the dependency array. While the suppression is intentional (fire-once), the `loadLeads` function closes over `leads` state via the `updateLeadNotes` callback. A safer pattern would be to use refs for the initial load.

**Fix (optional):** Extract stable loader refs or move the initial load into a `useCallback` with empty deps and call from the effect, removing the ESLint suppression.

---

## Non-Findings (Verified Clean)

The following areas were audited and found to be correctly implemented:

1. **CSRF on all mutating fetches** — every POST/PATCH/PUT/DELETE call includes `getCsrfToken()` + `X-CSRF-Token` header
2. **`credentials: 'include'` on all fetches** — session cookies are always forwarded
3. **Middleware RBAC** — all routes properly validate role (`viewer|operator|admin|owner|super_admin`)
4. **Dangerous actions require confirmation** — tenant suspend, secret rotate/revoke, killswitch toggle, override delete, content delete, lead delete all use `dialog.confirm()`
5. **`proxyToRust`** properly forwards method, query string, body, and sets `x-api-key` for server-to-server auth
6. **`useEffect` cleanup** — all intervals (system, audit, gdpr, analytics, ip-warmer, page) have proper `clearInterval` in return functions
7. **API routes** — proxied routes (45+) properly delegate to Rust admin API; direct routes (auth, autopilot) have explicit input validation
8. **Campaign, tenant, and secret pages** — use `dialog.alert` for all mutation errors with descriptive messages
9. **Risk and GDPR pages** — use visible `setError()` state with proper rollback on failures
10. **CRM and leads pages** — use toast notification system for all error feedback
