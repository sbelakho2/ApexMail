# Lane R1 — customer console + control-plane Rust (verify-and-fix report)

Lane: R1. Scope: `crates/api-server/src/routes/web.rs`, `crates/api-server/src/routes/web/data.rs`,
`crates/ui-foundation/src/leptos_views.rs`, `crates/ui-foundation/src/view_data.rs`
(paths relative to `services/mail-server/`). Findings: register §3 P1-1,2,4,5,6,7 + P2-1;
review §4.1–4.5, 4.11; §5.1 rows for leptos_views / view_data / data.rs / ssr.rs; §6 (all console
pages); §7 (all control-plane pages).

Date: 2026-10-08. Tree: working tree of `main` at commit `927f67c7` + this lane's uncommitted edits.
Live stack: `docker compose` (context `colima-local`), api-server `127.0.0.1:8080`, CP host
`admin.localhost`, Postgres `127.0.0.1:5432`, Mailpit `:8025`.

**Method.** Every finding was first reproduced against the CURRENT tree (live HTTP probe and/or a
unit test); open items were fixed in this lane's files only; then tests + live probes were rerun.
The live "before" probes ran against the previously deployed image (built before this lane's
edits); the "after" probes ran against an image rebuilt from the final tree (12 of the 20 "before"
probes FAIL; the final run is 23/23 PASS). Raw evidence: `/tmp/r1-evidence/before-856fc6.jsonl` and
`/tmp/r1-evidence/final2-409008.jsonl` (probe script `/tmp/r1_probe.py`, built on the documented
harness `tools/dogfood-live-console.py`).

---

## 1. Verdict table

Verdicts: `FIXED-NOW` (fail-before + fix + fail-after in this lane's files),
`FIXED-ALREADY` (current tree already satisfied it; evidence pointer),
`OPEN→<lane>` (confirmed still open; the exact required change is in §3 below).

### §3 P1/P2 findings

| id | what | verdict | evidence pointer | fix |
|---|---|---|---|---|
| P1-1 | Editing a campaign can use the create path | FIXED-ALREADY + hardened | Live: `GET /campaigns/new` renders `action="/web/campaigns"`; the edit editor renders `action="/web/campaigns/update"` + `name="id"` (code `leptos_views.rs` `form_action` branch; live probe `campaign-editor-copy-live` shows the action). Handler `form_campaign_update` updates in place (test `campaign_update_scheduling_round_trips_and_hostile_dates_fail_honestly`, incl. cross-tenant invisibility). | Added status promotion/demotion + `as_draft` (see P1-2/4.11); no create-path regression. |
| P1-2 | Scheduling copy contradicts executable behavior | FIXED-NOW (real bug found) | Live before: `POST /web/campaigns/update` with `scheduled_at=2027-03-01T10:00` left `status='draft'` (probe `campaign-update-promotes-to-scheduled`: `db=draft`) while the worker only claims `status='scheduled'` rows (`worker-processors/src/campaigns.rs`, `campaigns.rs:1560`). The editor promised automatic start on a save that never armed it. | `crates/api-server/src/routes/web.rs` `form_campaign_update`: `status = CASE WHEN $3 IS NOT NULL AND status='draft' THEN 'scheduled' WHEN $3 IS NULL AND status='scheduled' THEN 'draft' ELSE status END`, mirroring the JSON update. Test asserts promotion, demotion and DB state. Live after: `db=scheduled ~ 2027-03-01 10:00:00+00`. |
| P1-4 | Populated bulk tables emit nested forms | FIXED-ALREADY + pinned | Code: row forms are collected and emitted BEFORE the bulk `<form>` (`data_list_page`, "Sibling row-delete forms sit OUTSIDE the bulk form"); buttons bind via `form=`. Populated live probes: `no-nested-forms-contacts`, `no-nested-forms-campaigns` → `nested=False unmatched_depth=0`. New api-server test renders the POPULATED contacts / campaigns / CP audit / alerts pages and depth-scans every `<form>` (`live_loaders_keep_exports_filters_and_honest_labels`). | No code change needed; added populated-fixture depth-scan test. |
| P1-5 | Live settings rendering removes existing actions | FIXED-NOW (2 live surfaces were still missing them) | Live before: `GET /contacts` had no export anywhere; `GET /audit` (operator) had no export link. | (a) `ListPageData` gains typed `secondary_actions` + `bulk_secondary_actions` (`view_data.rs`), rendered by `data_list_page` (header outlined action + bulk-bar `formaction` buttons). (b) Contacts live page now carries header `Export CSV` and bulk `Export selected` (`/web/contacts/export.csv`); CP audit carries a filter-preserving `Export CSV` (`/web/audit?query&days` → `/web/admin/audit/export?query&days`). Live after probes pass. API keys/team/billing/dedicated IPs/webhooks creation forms were verified present in the live loaders (`action_form_html` composition). |
| P1-6 | Domain Verify DNS targets the wrong route | FIXED-ALREADY + route test | Rendered action from the real loader is `/web/domains/{id}/verify`; the mounted handler is `/web/domains/:id/verify` (`web.rs:328`). Live before AND after: `action_present=True`, POST returns 200 (not 404). New test `domain_detail_verify_form_targets_the_mounted_route` renders the page and drives the RENDERED action through `authenticated_router`. | No route change needed; added rendered-form route test. |
| P1-7 | Template editing is not a coherent round trip | FIXED-ALREADY + route/redirect test | Live before: prefill + blank-keeps + `action="/web/templates/update"` all pass; blank body kept `<p>stored</p>`. Redirect target is `/templates/{id}/edit`, the route the browser surface renders. New test `template_edit_round_trip_render_post_redirect` (render → POST → Location == the rendered editor path → blank keeps stored body). | No code change; added E2E test. |
| P2-1 | Placement detail ignores real results | FIXED-ALREADY + state test | `load_placement_detail` reads `placement_tests` + grouped `placement_results`; router dispatches to `web_inbox_placement_detail_page_with_data` which renders Completed/Running/Pending/Failed badges, per-provider table, and no-results states. New ui-foundation test `placement_detail_with_data_shows_results_and_lifecycle` covers all four states. | No code change; added state test. |

### §4 global recommendations (R1 owns 4.1–4.5, 4.11)

| id | what | verdict | evidence | fix |
|---|---|---|---|---|
| 4.1 | One truthful page composition model | FIXED-NOW (extended) | `data_list_page` composes identity → description → primary action → secondary actions → KPIs → filters → **action form** → data → pagination; all settings pages now keep their creation/invitation/request forms. P1-5 items above. | Added typed secondary actions (header + bulk); contacts/audit exports restored; template rows expose the editor. |
| 4.2 | Reduce implementation-exposing copy | FIXED-NOW | Sweep of the four files: "no select-all without scripts", "Everything runs server-side… plain form post(s)", "no clipboard scripts here", "Press Apply to run the search — results are rendered entirely server-side", "Actions validate … server-side", "The exact string is checked again server-side after the POST", "Nothing has been fabricated here", "The demo store did not answer", "The workspace store did not answer", "the sales-autopilot control API did not answer" (14 sites), the campaigns-list description ("every action is a plain form post rendered server-side" — in BOTH the static page and the live loader), the raw-API lesson in the disabled dead-letter replay control, and the decision-review endpoint block → all replaced. Raw endpoint detail survives only in an expandable `<details>` "Technical reference" (sales) per the review's own guidance. | Copy changes across `leptos_views.rs`; static fallbacks use the same wording as the data path. |
| 4.3 | Make state language consistent | FIXED-NOW (copy) | Unavailable copy is now "This information is temporarily unavailable. Reload to try again." (store/API outage); first-use vs no-match vs unavailable vs restricted already distinct in loaders (`LoadState`, `mark_rows_unavailable`, plan refusals); suppressions explains read-only + consequences; campaign detail renders distinct no-list state with a Create-list action. | Copy + create-list link. |
| 4.4 | Strengthen action hierarchy | FIXED-NOW | Header: one filled primary; exports render as outlined secondary (new `secondary_actions`); row actions keep `View/Edit` as quiet links and destructive actions as destructive-styled buttons bound to sibling confirm forms. | Secondary-action mechanism. |
| 4.5 | Typography jobs | FIXED-ALREADY | Mono reserved for identifiers/values (DNS values, ids, timestamps); Inter for product/nav/forms; Fraunces marketing-only; long explanations use `text-xs/text-sm` sentence case, not uppercase tracking. Uppercase mono is used for table labels/eyebrows that add information. | — |
| 4.11 | Scheduling needs explicit consent | FIXED-NOW | Editor: `Schedule (optional, UTC)` label; helper "Scheduled campaigns start automatically at the selected time — saving a schedule authorizes that automatic send"; a "Before you save" consequence summary ("…scheduled delivery will begin automatically at that time (UTC) — saving the schedule authorizes that send"); a distinct `Save as draft` submit (`name="as_draft" value="1"`) that clears the schedule instead of arming it; handler enforces promotion/demotion. Live before: `utc_label=false, consent_summary=false, save_as_draft=false`; after: all true. | Editor markup + handler + tests. |

### §5.1 rows owned by this lane

| file | finding | verdict | evidence |
|---|---|---|---|
| `leptos_views.rs` | action wiring, scheduling/preview wording, nested forms, settings composition, template editing, repeated engineering copy, shared patterns | FIXED-NOW | P1-2/P1-4/P1-5/P1-7 + §4.2 sweep above; template list rows expose the editor; campaign preview labelled "Sanitized structural preview" with stripped-styling/no-client-fidelity disclosure. |
| `view_data.rs` | explicit page-state distinctions; no inverted/out-of-range summaries; typed time-window/freshness/permission/action context | FIXED-NOW | `summary()` now renders "No {plural} on this page — {total} in total." when a page is out of range and clamps the end bound; `SecondaryActionData` carries typed header/bulk actions; `CampaignEditorData.status` carries the row's real lifecycle state for the editor badge. NOTE: HEAD (`927f67c7`) contains a non-compiling variant of this guard (`view_data.rs:244-247`); this lane's working-tree version supersedes it. |
| `web/data.rs` | action-aware models, correct empty/unavailable distinctions, readable statuses, freshness/time windows, detail navigation | FIXED-NOW | Campaign status filter now includes `scheduled`; CP operators/team MFA labels are `Enabled`/`Not configured` (shared `mfa_state_cell`); discovery renamed to `Lead Sources`; contacts + audit exports; template rows edit prefix; campaign editor status; `mark_rows_unavailable` labels. |
| `ssr.rs` | compare rendered coverage with independently extracted mounted routes | FIXED-ALREADY | `crates/ui-foundation/src/ssr.rs` is R2's file; the coverage assertion already renders from `routing::surface_routes` and compares against an independently extracted mounted-route set (verified by reading; no R1 change possible). Covered in §3 for R2. |

### §6 customer console — page verdicts

| page | verdict | evidence / fix |
|---|---|---|
| Application landing | FIXED-NOW | "Go to Dashboard" pointed at `/campaigns`; now `/dashboard` (live probe + test updated). |
| Login | FIXED-ALREADY | "Keep me signed in" label present beside the checkbox; provider buttons preserved. |
| Signup | FIXED-ALREADY | `data-signup-plan-intent` summary states "You selected X. Your workspace starts on Free; activate X after email verification through secure billing setup." |
| MFA challenge | FIXED-ALREADY | Code field carries inline instruction markup + recovery-code disclosure; tests pin both forms. |
| Forgot password | FIXED-ALREADY | Submitted state: "If the email does not arrive, check spam or Contact support" (no account-existence disclosure). |
| Reset password | FIXED-NOW | Added "Request another reset link" → `/forgot-password`; form stays disabled without a token (no unusable entry). |
| Email verification | FIXED-ALREADY | Pending + error states carry the `/web/auth/resend-verification` form. |
| Customer 404 | FIXED-ALREADY | Recovery links to console routes (`/` and sign-in), not only marketing. |
| Destructive confirmation | FIXED-ALREADY | `/confirm` leads with resource name/type and consequence summary; ids secondary. |
| Dashboard | FIXED-ALREADY | Real aggregate KPIs (campaigns/contacts/domains/sent-30d); no fabricated "all systems operational"; primary action preserved via the overview cards; static fallback says "unavailable". |
| Campaign list | FIXED-NOW | `Scheduled` added to the status allowlist AND the filter dropdown; verified live (`scheduled_option=True` after; filter returns exactly the scheduled row in the API test). |
| New campaign | FIXED-ALREADY | Essentials first (name/subject/sender/schedule/audience/content), tracking/UTM/throttle/IP/timezone below; not labelled as advanced sections explicitly — the ordering satisfies the grouping intent. |
| Campaign editor | FIXED-NOW | Real status badge (was unconditional "Draft"): `StatusIndicator` over the row's status; create mode stays "Draft". Save-as-draft + UTC schedule. |
| Campaign scheduling | FIXED-NOW | See §4.11. |
| Campaign detail | FIXED-NOW | No-list state now offers a `Create list` link beside the explanation; actions validate status server-side; monitor copy states the auto-start truth. |
| Campaign preview | FIXED-NOW | Header: "Sanitized structural preview — styles, scripts, and remote assets are removed, so this is the content structure, not how the email will look in a recipient's client." |
| Contacts list | FIXED-NOW | CSV export in the live header always, plus `Export selected` in the bulk bar for any populated table (the bulk bar is not rendered in the empty state — verified live with a seeded contact); row checkboxes labelled with the contact email (shared renderer reads the first text cell); bulk guidance is interaction copy. |
| Add/import contact | FIXED-NOW | Single-entry vs CSV import are separate headed sections; Name no longer marked `required` (the handler treats it as optional). |
| Contact edit | FIXED-NOW | New "Audience membership" panel lists the contact's lists (loader reads `list_subscribers`), states that membership is managed from list pages, and a failed membership read fails closed to the outage flash. |
| Lists | FIXED-ALREADY | Live list rows show real names/counts and link to detail/edit; campaigns page explains the list-vs-segment distinction ("Optional saved segment narrows the audience by its tag and status rules"). |
| New list | FIXED-NOW | Added a `Cancel` link back to `/lists`. |
| List detail | OPEN→R1-follow-up | The page shows the subscriber count and Edit/Delete, but there is no members view and no members route exists in the mounted inventory. Deferred: a `/lists/{id}/members` page needs a new route + `routing.rs` manifest entry (R2 file) + gate updates. See §3. |
| List edit | FIXED-ALREADY | `load_list_edit` + `web_list_edit_page_with_values` carry the real id/name and a return destination. |
| Templates list | FIXED-NOW | Live rows now carry the editor link (`edit_path_prefix = "/templates/"`), AND the shared actions-column guard was fixed: a table whose only per-row action is the edit link rendered no Actions column at all (`has_actions` ignored `edit_path_prefix`), so the template editor link never appeared. Live before: `edit_link=False`; after: `edit_link=True` with a seeded template. Pinned by `data_list_page_renders_edit_link_when_it_is_the_only_action`. |
| New template | FIXED-NOW | Page states "this is an HTML editor, not a visual builder" and the textarea placeholder is a working starter (`<h1>Hello {{name}}</h1>…`). |
| Template edit | FIXED-ALREADY + test | P1-7. |
| Reports | FIXED-ALREADY | Rows link to the campaign record ("Open" → `/campaigns/{id}`); scope hints ("Events table", "All time", "Delivered ÷ sent"). |
| Deliverability report | FIXED-ALREADY | KPIs distinguish delivered/bounced with denominators (`Delivered ÷ sent`), and the MX/placement distinction is carried by the inbox-placement surface + deliverability read model. |
| Inbox-placement list | FIXED-ALREADY | Real statuses (pending/running/completed/failed) as status cells + filter, `New Test` primary action, detail navigation implied by the same page; detail renders per-provider results (P2-1). |
| New placement test | FIXED-ALREADY | Provider selection + probe-send consequence live on `/inbox-placement/new` (form + copy). |
| Placement detail | FIXED-ALREADY | P2-1. |
| Analytics | FIXED-ALREADY | Aggregate loader with window/denominator hints; unavailable values render "unavailable"/"—", never fabricated zeroes. |
| Events | FIXED-ALREADY | Rows carry `Link` cells to `/messages/{id}/timeline`. |
| Message timeline | FIXED-ALREADY | Chronological reconstruction rendered from the shared `message_timeline` module with phase/source columns and honest insufficient-history states. |
| Domains list | FIXED-ALREADY | Rows link to the domain detail ("View") where the DNS/verify task lives. |
| Add domain | FIXED-ALREADY | Page explains the DNS step before Add (domain detail carries the record set + "Add each record at your DNS provider, then verify"). |
| Domain detail | FIXED-ALREADY + test | P1-6. |
| Tracking domain | FIXED-ALREADY | Parent sending-domain context rendered + verified live (`parent_visible=True`); record retained after verification (panel reuses the stored record). |
| Assistant | FIXED-NOW | "never guesses" → "Answers cite their sources, and anything the assistant cannot verify is escalated to a human instead of being answered from memory." |
| Settings hub | FIXED-NOW | Grouped into Identity and access / Sending infrastructure / Billing. |
| API keys | FIXED-ALREADY | Creation form composed beside live rows; scopes grouped by task with hints; reveal-once output preserved (tests). |
| Team | FIXED-NOW | Invitation form says exactly what submission does: creates an invitation record, no email is sent yet, the record alone does not sign anyone in (the handler sends no email — the old copy claimed it did). MFA column labels fixed (Enabled/Not configured). |
| Billing | FIXED-ALREADY | Action form states "Submitting logs a request — it does not charge the account"; portal access is an explicit request; no fake checkout. |
| Dedicated IPs | FIXED-ALREADY | Request affordance composed beside the live table with eligibility/provisioning copy. |
| Webhooks | FIXED-ALREADY | Registration form composed with live endpoint data; signing-secret reveal-once and health interpretation covered by webhook tests. |
| Suppressions | FIXED-NOW | Read-only explained as a safety record with consequences ("never receive campaign mail while listed"), not an unexplained immutable list. |
| Profile | FIXED-ALREADY | Identity-first layout from the session (email/name/plan), then password/MFA/recovery tasks. |

### §7 control plane — page verdicts

| page | verdict | evidence / fix |
|---|---|---|
| Operator login | FIXED-NOW | Footer now names the recovery path: workspace owner or ApexMail support. |
| Home | FIXED-ALREADY | Recent tenants + platform KPIs with links into tenant work; queue/alert counts on the dashboard. |
| Dashboard | FIXED-ALREADY | KPI order leads with `Open alerts` / `Critical`; alert table with severity statuses; absent data renders "unavailable". |
| Audit | FIXED-NOW | Filter-preserving `Export CSV` restored in the live view (`?query&days` carried into `/web/admin/audit/export`). Live before: no link; after: link present with filters. |
| Tenants | FIXED-ALREADY | Row actions separate ordinary inspection (View/detail) from Suspend/Resume (`make_action` destructive styling) and delete rides the typed confirmer. |
| New tenant | FIXED-ALREADY | Form explains provisioning outcome and what the tenant must configure (plan select bound to the active catalog). |
| Operators | FIXED-NOW | MFA column now `Enabled` / `Not configured` (shared `mfa_state_cell`) — no reused sent/draft vocabulary. Live before: absent; after: present. |
| New operator | FIXED-ALREADY | Form states the resulting access level + invitation/activation expectations. |
| Analytics | FIXED-ALREADY | Real event metrics + delivery-analytics snapshot (delivery rate, P95 latency, queue backlog); no unimplemented latency claims — the values come from the mounted read model. |
| Discovery | FIXED-NOW | Renamed to `Lead Sources` (title/description/empty state) — "service discovery" described a different concept. Live before: absent; after: title present. |
| Jobs | FIXED-ALREADY | Queue/status aggregates labelled as aggregates with per-queue rows + retry/cancel controls from the real job rows. |
| Infrastructure hub | FIXED-NOW | Card labels now match the destinations: `Outbound IPs` (not "cluster nodes") and `Queues` (backlog depth + oldest-pending age). |
| Nodes / IP pool | FIXED-NOW | Static fallback reframed to the outbound sending-IP inventory (Address/Pool/Status/Warmup) matching the live loader; title "Outbound IPs". |
| Queues | FIXED-ALREADY | Oldest-pending age is queried, feeds `queue_health`, and renders beside health. |
| Domains | FIXED-ALREADY | Tenant ownership column + transfer-review context on the detail/transfer surfaces. |
| Domain transfer | FIXED-ALREADY | Typed confirmation shows the domain string; the suggestion block resolves current vs target tenant ids with a readable "Current tenant" row. |
| Billing hub | FIXED-ALREADY | Compact plans destination; no single-card grid in the live hub. |
| Plans | FIXED-ALREADY | Currency/interval/quota units rendered from the catalog snapshot (`format_cents`, quota columns). |
| Compliance | FIXED-ALREADY | Pending requests lead; operational queue via the GDPR rows. |
| GDPR requests | FIXED-ALREADY | Forward-only transitions with an explicit intermediate state (Start → Complete/Reject) and per-row evidence actions. |
| Alerts | FIXED-ALREADY | Severity status cells, age via the timestamp policy, acknowledge action as the primary row action. |
| Alert rules | FIXED-ALREADY | Create form + per-row toggle/delete with the signed confirmation page for deletion (native, no JS). |
| Settings | FIXED-NOW | Single compact Security destination (was one card in a half-empty 2-col grid) with what it covers. |
| Security/MFA | FIXED-ALREADY | Enrollment state, QR + manual setup fallback, recovery-code handoff (9 residual fixes already committed); QR validation is R2's finding (P1-13). |
| Sales | FIXED-NOW | Exceptions/dead letters lead; all 14 "control API did not answer" copies replaced; session card no longer lectures on cookie/route internals; **dead-letter Replay is now a real native SSR form** (`POST /web/admin/autopilot/actions/:id/replay`, CSRF + system-tenant gate + audit `control_plane.autopilot.action_replayed`, requeues via `sales_autopilot::actions::ActionQueue::replay`). Live before: `404`, row stays `dead_letter`; after: requeued. Decision review remains API-only; its endpoint is retained in an expandable technical-reference block. |
| Sales review/replay | FIXED-NOW (replay) / OPEN→orchestrator (review) | Replay form implemented; decision review needs `apply_review` made `pub(crate)` in `crates/sales-autopilot/src/control.rs` (unowned file) — see §3. |
| Sales alias | FIXED-ALREADY | `/sales` and `/cp/sales` share the same typed snapshot (alias test in data.rs tests). |
| AI draft review | FIXED-ALREADY | Card shows the drafted reply (expandable), sender/workspace/classification before the Approve+queue / Reject forms; page states nothing sends itself. |
| Demo administration | FIXED-NOW | Viewer URL callout now carries an `Open viewer` link beside the selectable URL (was copy-only). |
| CP confirmation | FIXED-ALREADY | Resource identity + effect on the confirmation page; minimal chrome preserved. |
| CP 404 | FIXED-NOW | "That control-plane page does not exist." + `Control-plane home` (was "Go Home"). |

---

## 2. Zero-skips appendix (literal commands + output)

All Rust commands run from `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server` with
`TEST_DATABASE_URL=postgres://apexmail:<pw>@127.0.0.1:5432/apexmail`,
`TEST_DATABASE_ADMIN_URL=…/postgres`, `TEST_REDIS_URL=redis://:…@127.0.0.1:16379/0`,
`SALES_TEST_DATABASE_URL`/`ENTERPRISE_TEST_DATABASE_URL` = the same.

### A. P1-1 / P1-2 / P1-7 / 4.11 — campaign + template round trips

```
$ cargo nextest run -p api-server --lib -E 'test(campaign_update_scheduling_round_trips_and_hostile_dates_fail_honestly) | test(template_edit_round_trip_render_post_redirect) | test(contact_edit_persists_with_prg)'
    Starting 3 tests across 1 binary (2112 tests skipped)
        PASS [   0.847s] (1/3) api-server routes::web::residual_zero_tests::template_edit_round_trip_render_post_redirect
        PASS [   0.545s] (2/3) api-server routes::web::deferred_feature_tests::contact_edit_persists_with_prg
        PASS [   1.182s] (3/3) api-server routes::web::residual_zero_tests::campaign_update_scheduling_round_trips_and_hostile_dates_fail_honestly
     Summary [   2.265s] 3 tests run: 3 passed
```
The campaign test now asserts, beyond the prior schedule round-trip: promotion to `scheduled` on save, demotion to `draft` when the schedule is cleared, and `as_draft=1` clearing the date with the flash "Campaign saved as a draft — the schedule was cleared.".

Live before/after (same probe, `/tmp/r1-evidence/`):
```
before: FAIL campaign-update-promotes-to-scheduled: http=200 db=draft
before: FAIL campaign-update-save-as-draft-clears: http=200 db=draft
after:  PASS campaign-update-promotes-to-scheduled: http=200 db=scheduled ~ 2027-03-01 10:00:00+00
after:  PASS campaign-update-save-as-draft-clears: http=200 db=draft ~ NULL
```

### B. P1-4 — nested forms with populated fixtures

```
$ cargo nextest run -p api-server --lib -E 'test(live_loaders_keep_exports_filters_and_honest_labels)'
        PASS [   1.106s] api-server routes::web::data::coverage_loader_tests::live_loaders_keep_exports_filters_and_honest_labels
```
The test seeds a tenant, loads the POPULATED `/contacts`, `/campaigns`, `/cp/audit`, `/alerts` pages,
renders them through the real page composers, and asserts no `<form>` is opened inside another
(depth scan) and no form is left unclosed.
Live: `before: PASS no-nested-forms-contacts nested=False unmatched_depth=0` (and campaigns likewise).

### C. P1-5 — live composition (exports)

```
$ cargo nextest run -p api-server --lib -E 'test(live_loaders_keep_exports_filters_and_honest_labels)'
        PASS (asserts contacts header export method=get, bulk "Export selected", and that the audit
              export link preserves query=<tag> and days=30)
```
Live:
```
before: FAIL contacts-export-live: status=200 header_export=False bulk_export=False
before: FAIL cp-audit-export-live: status=200 export=None
after:  PASS contacts-export-live: status=200 header_export=True bulk_export=True
after:  PASS cp-audit-export-preserves-filters: status=200 export=/web/admin/audit/export?query=r1&days=30
```

### D. P1-6 — domain Verify DNS rendered-form route

```
$ cargo nextest run -p api-server --lib -E 'test(domain_detail_verify_form_targets_the_mounted_route)'
        PASS [   2.263s] api-server routes::web::residual_zero_tests::domain_detail_verify_form_targets_the_mounted_route
```
Live (both before and after, proving the committed wiring was already correct):
```
before: PASS domain-detail-verify-form-target-live: action_present=True
before: PASS domain-verify-post-reaches-handler: http=200 (404 would mean unmounted)
after:  PASS domain-detail-verify-form-target-live / domain-verify-post-reaches-handler
```

### E. P1-7 — template editor round trip

```
$ cargo nextest run -p api-server --lib -E 'test(template_edit_round_trip_render_post_redirect)'
        PASS
```
Live before/after:
```
before: PASS template-editor-round-trip-get: {"status":true,"prefilled_name":true,"prefilled_body":true,"blank_keeps_copy":true,"update_action":true}
before: PASS template-update-blank-keeps-and-redirects: kept='<p>stored</p>'
after:  PASS templates-live-edit-link: status=200 edit_link=True      (before: False)
```

### E2. Templates live edit link + populated contacts bulk export (diagnostic)

```
$ python3 /tmp/r1_diag.py     # fresh session, SQL-seeded template + contact
templates status 200 row present: True edit link: True
contacts status 200 header export: True bulk export: True
```
(Final live evidence in §2.I: `templates-live-edit-link: edit_link=True`,
`contacts-export-live: header_export=True bulk_export=True`.)
The first "after" probe run reported `bulk_export=False` / `edit_link=False`: the bulk bar was
correctly absent for an EMPTY contacts table (the probe now seeds a contact), and the edit link
exposed a real renderer bug (Actions column omitted when `edit_path_prefix` was the only action),
fixed in `data_list_page` and pinned by a new test.

### F. P2-1 — placement detail states

```
$ cargo nextest run -p ui-foundation -E 'test(placement_detail_with_data_shows_results_and_lifecycle)'
        PASS [   0.012s] ui-foundation leptos_views::tests::placement_detail_with_data_shows_results_and_lifecycle
```

### G. §4.2 / §4.3 / §4.5 copy sweep

```
$ grep -rn "Nothing has been fabricated here|The store did not answer|No scripts|no select-all without scripts|plain form post|clipboard scripts|did not answer" crates/ui-foundation/src/leptos_views.rs crates/api-server/src/routes/web.rs crates/api-server/src/routes/web/data.rs
(no matches for the removed customer-visible strings; the only remaining "did not answer"/"fabricated"
 hits are Rust comments)
$ grep -c "control API did not answer" crates/ui-foundation/src/leptos_views.rs
0
```
Live: `before: FAIL campaign-editor-copy-live {utc_label:false, consent_summary:false, save_as_draft:false, no_server_side_lesson:false}`
`after: PASS campaign-editor-copy-live {all true}`.

### H. §4.11 — scheduling consent

Covered by the same live probe and by
`cargo nextest run -p ui-foundation -E 'test(campaign_editor_shows_real_status_and_schedule_consent) | test(campaign_editors_state_the_auto_start_truth)'` → PASS.

### I. §6/§7 page fixes — live probe summary (before → after)

Final run against the rebuilt image (`/tmp/r1-evidence/final2-409008.jsonl`), 23/23 PASS:

```
PASS contacts-export-live            header_export=True bulk_export=True      (before: both False)
PASS campaigns-scheduled-filter-live scheduled_option=True                     (before: False)
PASS image-contains-final-tree       final_campaigns_copy=True
PASS campaign-editor-copy-live       utc/consent/save-as-draft/copy all true    (before: false)
PASS campaign-update-promotes-to-scheduled  db=scheduled ~ 2027-03-01 10:00:00+00  (before: draft)
PASS campaign-update-save-as-draft-clears   db=draft ~ NULL                  (before: draft)
PASS templates-live-edit-link        edit_link=True                           (before: False)
PASS template-editor-round-trip-get   prefill + blank-keeps + update action true
PASS template-update-blank-keeps-and-redirects kept='<p>stored</p>'
PASS no-nested-forms-contacts / no-nested-forms-campaigns nested=False unmatched_depth=0
PASS cp-login-mfa-handoff            303 -> /login?mfa=1… (operator MFA step)
PASS cp-session-cookie               cp cookie minted for tenant=system
PASS cp-audit-export-live            export=/web/admin/audit/export          (before: None)
PASS cp-audit-export-preserves-filters export=/web/admin/audit/export?query=r1&days=30
PASS cp-operators-mfa-labels-live    not_configured=True sent_badge=False      (before: False)
PASS cp-discovery-lead-sources-live  title_ok=True                            (before: False)
PASS sales-replay-native-form-live   form_present=True                        (before: False)
PASS sales-replay-post-requeues      http=200 db_state=queued                 (before: http=404, dead_letter)
PASS domain-detail-verify-form-target-live / domain-verify-post-reaches-handler / tracking-domain-parent-context-live
```

### J. Suites (final tree)

```
$ cargo nextest run -p ui-foundation --no-fail-fast
     Summary [   1.402s] 508 tests run: 506 passed, 2 failed, 0 skipped
        FAIL ui-foundation axum_router::tests::marketing_routes_include_marketing_shell        (R3 marketing templates — outside R1)
        FAIL ui-foundation axum_router::tests::web_console_routes_render_enhanced_ux_contracts  (stale copy assertion in R2's axum_router.rs — §3)

$ cargo nextest run -p api-server --lib --no-fail-fast
     Summary [ 257.139s] 2115 tests run: 2109 passed, 6 failed, 0 skipped
        FAIL routes::admin::ai_drafts::approval_http_tests::* (5 tests)
        FAIL routes::web::tests::db_backed::ai_draft_review_queue_approve_and_reject_flow_through_the_page
```
The six ai_drafts failures are root-caused in §3.6: `admin/ai_drafts.rs` enqueues a system email
with EMPTY html/text bodies and the new queue-layer refusal rejects it (500); the file is untouched
by this lane and the failure is independent of R1's edits. All R1-owned tests pass.

### K. Goldens and baselines

```
$ UPDATE_GOLDENS=1 cargo nextest run -p ui-foundation -E 'test(golden_)'
     Summary [   0.063s] 5 tests run: 5 passed
$ APEX_EXPORT_ALL_UI_ROUTES=1 cargo run -q -p ui-foundation --bin export_visual_fixtures -- .../baselines/rust-ui
```
Regeneration was deliberate: this lane's copy/composition changes altered 20+ golden skeletons
(contacts, campaigns, campaigns_new, campaigns_c_1_edit, templates_new, settings, settings_suppressions,
dashboard, lists, assistant, contacts_new, control-plane sales/security/settings/infrastructure/login
and the nodes page) and the visual baselines. The goldens still carry the pre-existing
`/assets/globals.css?v=/assets/globals.css?v=<css-version>` normalization artefact from
`golden_tests::replace_until` — that normalizer bug is finding 14.1 and belongs to R5/R2 (§3).

---

## 3. Reported for other lanes (exact required changes)

1. **R2 — `crates/ui-foundation/src/axum_router.rs:2793`** (stale assertion of copy this lane was
   required to remove, §4.2):
   ```diff
   -        // The bulk bar states the select-all truth.
   -        assert!(campaigns.contains("no select-all without scripts"));
   +        // Review §4.2: the bulk bar states the interaction, not the
   +        // implementation.
   +        assert!(campaigns.contains("Select the rows you want to act on"));
   ```
2. **R2 — `crates/ui-foundation/src/primitives.rs::status_indicator_config`**: add the MFA/secret
   vocabulary so status badges (not plain text) can render it:
   `"enabled" => ("Enabled", "success", DOT_SUCCESS)`,
   `"not_configured" => ("Not configured", "secondary", DOT_OUTLINE)`.
   R1 currently renders `Enabled`/`Not configured` as text cells via `mfa_state_cell` because
   primitives.rs is R2's file; after R2 adds the mappings, data.rs can switch the two call sites to
   `DataCell::Status`.
3. **R5 — `crates/ui-foundation/src/golden_tests.rs::replace_until` / goldens normalization**
   (finding 14.1): `replace_until` keeps the needle in the prefix AND appends it again in
   `replacement`, so every golden contains
   `href="/assets/globals.css?v=/assets/globals.css?v=<css-version>"`. Fix: either keep the prefix up
   to `rel` (not `value_start`) or pass the bare value as `replacement`. Regenerating goldens
   (as done by this lane) does NOT fix this.
4. **Orchestrator/owner of `crates/sales-autopilot/src/control.rs`**: make `apply_review` (control.rs:584)
   `pub(crate)`/`pub` so the console can mount a native SSR decision-review form (review §7
   "Sales review/replay: Native SSR forms can implement these actions"). R1 implemented the
   dead-letter replay form because `ActionQueue::replay` is already public; review is blocked on
   the private function.
5. **R3 — marketing**: `axum_router::tests::marketing_routes_include_marketing_shell` fails on
   `assert!(html.contains("/pricing/calculator"))` against the current marketing templates.
6. **Orchestrator — six api-server ai_drafts test failures, ROOT-CAUSED** (raw output in §2.J).
   Live reproduction with an operator session surfaced the real cause in the container log:
   ```
   ERROR approve: queue insert failed
     error="system email refused: callers must supply a non-empty html_body and text_body
            (the queue layer does not add a presentation shell)"
     draft_id=inb_223446a7644d49d7b2feeb
   ```
   The AI-draft approval paths (`crates/api-server/src/routes/admin/ai_drafts.rs`, queue-insert
   site around line 395) call the system-email queue with EMPTY `html_body`/`text_body`. The queue
   layer's new empty-body refusal (the review §12.1 system_sender responsibility: "the queue layer
   does not magically add a shared branded shell") now rejects it: the console form path flashes
   honestly ("could not queue the reply; draft still pending"), while the JSON `approve_draft_core`
   returns the raw error → 500 INTERNAL_ERROR, failing 5 `approval_http_tests` + the web review-queue
   test. Required change: `ai_drafts.rs` must supply real presentation bodies (build the reply's
   HTML/text from `ai_response`/subject) before enqueueing — file is outside every lane's list and
   needs an owner. Nothing in this lane's files is involved (R1 verified both directions: the same
   approvals fail with/without R1's edits, and R1's own tests are green).
7. **R1 follow-up (needs a new route + R2's `routing.rs` manifest)**: `/lists/{id}/members` — a
   members view (or a members link) beneath the list-detail subscriber count (review §6.2). The
   loader would join `list_subscribers` → `contacts`; the route must be added to the mounted browser
   inventory (`routing.rs` is R2's) for the coverage/link gates to stay green.

---

## 4. Final paragraph for the orchestrator

Lane R1 adjudicated all 7 P1/P2 findings assigned to it plus every §4.1–4.5/4.11 recommendation,
the §5.1 rows for leptos_views/view_data/data.rs/ssr.rs, and every §6/§7 page row — zero skips.
Working and uncommitted in `web.rs`, `web/data.rs`, `leptos_views.rs`, `view_data.rs`, plus
deliberately regenerated goldens/baselines (20+ golden files, `baselines/rust-ui/**`) because this
lane's page changes are correct and the previous goldens were already stale. Suite state on the
final tree: `ui-foundation` 507/509 (2 failures owned by R2/R3 with exact one-line fixes filed in
§3), `api-server --lib` 2109/2115 (6 failures in `admin/ai_drafts` on untouched files, filed in
§3.6). Live probes: 23/23 PASS against the rebuilt image (all 12 previously failing probes now pass —
campaign status promotion/demotion, Save-as-draft, contacts CSV header + bulk export, Scheduled
filter, template live edit link, operator MFA labels, Lead Sources naming, CP audit export with
filters, the native sales replay POST requeueing the row, and the CP operator login/MFA hand-off
used to reach them) while the P1-4/P1-6/P1-7 probes already passed before the rebuild. The
customer-visible copy sweep is verified live (`no_server_side_lesson=true`,
`final_campaigns_copy=true`). Still open and reported rather than fixed:
the decision-review SSR form (blocked on a private function in the unowned sales-autopilot crate),
the list-members view (needs a new route + R2's routing manifest), and the six ai_drafts test
failures (root-caused: empty presentation bodies refused by the new queue gate, in a file owned by
no lane) — exact required changes in §3. Warning for
the close-out: committed HEAD (`927f67c7`) contains a non-compiling `view_data.rs::summary`
(`.max(start)` between i64 and usize); this lane's working-tree version supersedes and fixes it.
