# Lane R6 — leftover closer (team invite delivery, browser email shells, dna_verify reds, api-server test-build, list members, sales review form, ai_drafts approval, warnings)

Date: 2026-10-08. Tree: working tree of `main` at `927f67c7` + all lane edits (R1/R2/R3/R4/R5 + this
lane). Live stack: `docker compose` — api-server `127.0.0.1:8080` (host `127.0.0.1`, web surface),
Postgres `127.0.0.1:5432`, Mailpit `127.0.0.1:8025`. No git commit (per register rule 6). KiwiCaptcha
untouched (section 11 stays EXCLUDED).

**Method.** Each of the eight filed leftovers was reproduced against the CURRENT tree or the
CURRENT deployed image (built from the pre-R6 tree), then fixed in this lane's files only, then
re-proved with a literal after-run. The deployed image was rebuilt from the final tree
(`docker compose build api-server` → `docker compose up -d api-server`) and every live "after"
probe ran against it. Zero skips: all eight items are adjudicated below with command + output.

---

## 1. Verdict table (items 1–8)

| # | item (filed by) | verdict | fail-before (literal) | fix (files) | fail-after (literal) |
|---|---|---|---|---|---|
| 1 | Team invite delivers nothing (R5) | **FIXED-NOW** | Live pre-fix image: invite → `db.status='invited'` but `verification_hash_len=0 setup_hash_len=0`, `messages=[]` in Mailpit, flash still `Invitation created.` — `=== 2/5 PASS ===` | `web.rs::form_team_invite` mints verification+setup tokens, stores their sha256 hashes + expiries in `users.metadata`, queues the two-link invitation mail through the shared shell + `queue_system_email_in_transaction` in the SAME tx, then flashes delivery; `web.rs::form_reset_password` accepts `status='invited'` and promotes it to `active` (the acceptance step); new `web.rs::enqueue_team_invite_email` builder | Live rebuilt image: `13/13 PASS` — mail in Mailpit, verification link verifies (`email_verified=t`), setup link accepts the invitation (`status='active'`, `$argon2` hash, token consumed), teammate logs in (`http=200 session=True`) |
| 2 | Browser email shells on the shared renderer (R5) | **FIXED-NOW** | Live pre-fix image: all three browser mails — `viewport=False bg_pair=False footer=False`, `fallback=False`, text `unrequested=False footer=False` — `=== 4/16 PASS ===` | `web.rs`: the web signup verification, web forgot-password reset and web resend-verification shells now render through `render_transactional_email(TransactionalEmail { … })`; text bodies gain the unrequested-mail line + `© 2026 ApexMail — https://apexmail.ee`; each keeps its distinct link semantics | Live rebuilt image: `=== 16/16 PASS ===` (all three shells carry viewport + bg pair + visible fallback URL + footer, single `<h2>`, no legacy inline body) |
| 3 | dna_verify reds (R5) | **FIXED-NOW** | `cargo run -p ui-foundation --bin dna_verify` → `10/13 rendered-output checks pass` + `3 rendered-output check(s) FAILED`, EXIT=1 (`apex-dial`, `apex-chart-monoline`, `bg-success-500 text-white">all nominal`) | `leptos_views.rs::web_dashboard_page` renders the DIAL (270° track, no fill, value `—`) and the MONOLINE chassis in the no-data fallback (no fabricated series); `control_plane_dashboard_page` restores the solid all-nominal cell `bg-success-500 text-white` (contrast-safe: `--success-500` is the monochrome `#52525b`, white ≈ 7.3:1, documented in the ribbon comment) | `13/13 rendered-output checks pass`, **EXIT=0**; the dashboards' other DNA markers unchanged |
| 4 | api-server lib-test build red (R5) | **FIXED-ALREADY (import present) + re-proved** | Removing `data.rs:7880 use crate::routes::web::{cp_data_page, web_data_page};` reproduces the filed error exactly: `web/data.rs:8663:17: error[E0425]: cannot find function web_data_page in this scope` / `8665:17: … cp_data_page` → `could not compile api-server (lib test) due to 2 previous errors` | none needed (the import is in the current tree at `web/data.rs:7880`, inside `coverage_loader_tests`) | `cargo check -p api-server --lib --tests` → EXIT=0 (and the whole 320-test filtered suite builds and runs) |
| 5 | List members view (R1) | **FIXED-NOW** | Pre-fix: no members route/view — the list detail rendered `Subscribers` as text with no link, and `/lists/{id}/members` fell through to the list-detail catch-all | `view_data.rs` gains `ListMemberData`/`ListMembersData`; `web/data.rs::load_list_members` joins `list_subscribers → contacts` (readable identity, status, added date, newest first); `leptos_views.rs::web_list_members_page[_with_values]` renders the table + empty state (`No subscribers on this list yet` with `Add a contact → /contacts/new`); `web.rs` mounts GET `/lists/:id/members` (same route style as `/lists/:id`); the list detail's Subscribers KPI links `Inspect members →` | Live rebuilt image `/tmp/r6_members_probe.py`: `=== 8/8 PASS ===` (real subscriber identity/email/status/count, the detail link, the empty state + next action, the demo segment answering 200); api-server test `list_members_view_lists_subscribers_and_the_detail_links_to_it` PASS |
| 6 | Sales decision review as a native SSR form (R1) | **FIXED-NOW** | Pre-fix: the sales page carried the dead-end copy `Approving or rejecting a decision with a note is not available in this console yet.` and no review form; `sales_autopilot::control::apply_review` + `ReviewAction`/`ReviewOutcome` were private | `control.rs`: `apply_review`, `ReviewAction` (+ `parse`/`as_str`), `ReviewOutcome`, `RevalidationReport` are `pub` (matching `ActionQueue::replay`'s pattern); `leptos_views.rs::sales_exception_item` mounts the native approve/reject + note form on pending-approval rows (`/web/admin/autopilot/decisions/{id}/review`, hidden `return_to=/sales`), blocked rows carry none, dead-end copy + technical reference updated; `web.rs::form_autopilot_decision_review` delegates to `apply_review` in the sales tenant with the operator identity + audit row, route mounted in `admin_router` | New tests PASS: `sales_decision_review_form_decides_through_the_mounted_route` (303 + DB `review_status='rejected'`, `reviewed_by`, `review_note`; second post refused with `cannot be reviewed`), `sales_page_renders_the_native_review_form_for_pending_approvals` (live loader), `sales_pending_approval_rows_carry_the_native_review_form` (view); `cargo nextest run -p sales-autopilot` `959 tests run: 959 passed, 0 skipped` |
| 7 | ai_drafts approval 500s (R1, root-caused) | **FIXED-NOW** | `cargo nextest run -p api-server --lib -E 'test(ai_drafts)'`: `Summary [5.408s] 14 tests run: 9 passed, 5 failed` — approve paths answered `500 INTERNAL_ERROR` (empty `html_body` refused by the queue layer) | `admin/ai_drafts.rs::approve_draft_core` renders the draft through the SAME shared shell (`render_transactional_email`: heading = subject with a fallback, `body_html` = the escaped draft text as paragraphs, no action buttons, footer link) and queues text = the draft reply; nothing else changed | Same filter after the fix: `Summary [7.609s] 14 tests run: 14 passed, 2101 skipped` (and the 6th, the console review-queue test `ai_draft_review_queue_approve_and_reject_flow_through_the_page`, passes in the 320-test gate run) |
| 8 | Warning clean-up | **FIXED-NOW** | `cargo check -p api-server -p ui-foundation`: `crates/ui-foundation/src/leptos_views.rs:3259/3289/3373/7133/7188/7360/7490: warning: multiple lines skipped by escaped newline …` + `warning: ui-foundation (lib) generated 7 warnings` | removed the seven blank lines inside the string continuations (the escaped newline already skipped them, so the rendered HTML is byte-identical) | `cargo check -p api-server -p ui-foundation --message-format=short` → empty output, **EXIT=0**; `rustfmt --check` on all six touched files → clean |

Supporting (non-item) claim: the goldens/visual baselines are stale by design (this lane's plus the
wave's view edits) — the brief orders NO regeneration here; the fold does the global pass.

---

## 2. Zero-skips appendix (literal commands + output)

All Rust commands run from `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server` with
`TEST_DATABASE_URL=postgres://apexmail:<pw>@127.0.0.1:5432/apexmail`,
`TEST_REDIS_URL=redis://:<pw>@127.0.0.1:16379/0` (probes use the harness's documented connection
constants). Live probes: `/tmp/r6_invite_probe.py`, `/tmp/r6_email_probe.py`,
`/tmp/r6_members_probe.py` (built on the documented `tools/dogfood-live-console.py` harness).

### A. Item 1 — team invite delivers (live, before → after)

```
$ python3 /tmp/r6_invite_probe.py        # against the pre-fix deployed image
PASS invite POST answers the PRG redirect :: status=303 location=/settings/team
FAIL invite flash states the DELIVERY (not 'Invitation created.') :: claim='Invitation sent to'=False legacy_claim=True
PASS invited row exists (status='invited') :: db.status='invited'
FAIL invited row stores BOTH hashed acceptance tokens :: verification_hash_len=0 setup_hash_len=0
FAIL invitation mail lands in Mailpit :: messages=[]
=== 2/5 PASS ===                        # EXIT=1
```

```
$ docker compose build api-server && docker compose up -d api-server
$ python3 /tmp/r6_invite_probe.py        # against the rebuilt image
PASS invite POST answers the PRG redirect :: status=303 location=/settings/team
PASS invite flash states the DELIVERY (not 'Invitation created.') :: claim='Invitation sent to'=True legacy_claim=False
PASS invited row exists (status='invited') :: db.status='invited'
PASS invited row stores BOTH hashed acceptance tokens :: verification_hash_len=64 setup_hash_len=64
PASS invitation mail lands in Mailpit :: messages=['You have been invited to an ApexMail workspace']
PASS mail HTML carries the shared shell (viewport + footer) :: html_bytes=3565
PASS mail carries both acceptance links (HTML) :: reset+verify links present
PASS mail text mirrors both links + the unrequested note :: text_bytes=567
PASS mail is a WORKSPACE invitation, not a control-plane one :: workspace copy
PASS both links are absolute URLs :: verify=True setup=True
PASS verification link verifies the invited address :: http=200 location=/settings/team db.email_verified=t
PASS password-setup link sets the password and accepts the invitation :: http=303 db.status='active' hash='$arg' token_consumed=True
PASS the accepted teammate can log in with the password :: http=200 session=True status=None
=== 13/13 PASS ===                       # EXIT=0
```
Probe fixture note: the fresh tenant is moved to the active `pro` plan (10 seats) before the invite
— the Free plan's 1-seat cap correctly refuses a second member, which is the entitlement gate, not
the defect. Unit-level proof rides `team_invite_gates_on_the_caller_role` (now also asserts the 64-hex
token hashes, the three expiries, and the queued mail with both links) and
`team_invite_enforces_role_and_identity_rules` (same, cross-module fixture).

**Deliberate deviation from the brief's literal helper.** The brief named
`crate::routes::auth::enqueue_operator_invite_email`. That builder's copy — subject "You have been
invited to the ApexMail control plane", body "An ApexMail operator invited … to the control plane",
"Control-plane access also requires MFA enrollment at first sign-in" — is false for a workspace
teammate (they are not an operator and never enroll CP MFA). Reusing it verbatim would ship a new
false claim, exactly the class of defect this wave closes, so `web.rs` instead adds
`enqueue_team_invite_email`: the SAME shared shell (`render_transactional_email`), the SAME
same-transaction queue helper, workspace copy, and the same two-step acceptance contract. The
report-for-fold section carries the alternative if the orchestrator insists on one shared builder
(parameterize `auth.rs`'s builder with an audience enum — R5's file).

### B. Item 2 — browser email shells (live, before → after)

```
$ python3 /tmp/r6_email_probe.py          # pre-fix image
FAIL signup-verification: HTML is the shared shell (viewport + bg pair + footer) :: viewport=False bg_pair=False footer=False
FAIL signup-verification: HTML button fallback URL is visible text :: fallback=False link=False
FAIL signup-verification: text body carries the unrequested note + footer :: unrequested=False footer=False
FAIL forgot-password-reset: HTML is the shared shell … :: viewport=False bg_pair=False footer=False
FAIL resend-verification: HTML is the shared shell … :: viewport=False bg_pair=False footer=False
=== 4/16 PASS ===                          # EXIT=1
```
```
$ python3 /tmp/r6_email_probe.py          # rebuilt image
PASS signup-verification: HTML is the shared shell (viewport + bg pair + footer) :: viewport=True bg_pair=True footer=True
PASS forgot-password-reset: HTML button fallback URL is visible text :: fallback=True link=True
PASS resend-verification: text body carries the unrequested note + footer :: unrequested=True footer=True
=== 16/16 PASS ===                         # EXIT=0
```
Code-level: `grep -c "render_transactional_email(&TransactionalEmail" web.rs` → `4` (3 shells +
the team-invite builder); `grep -c 'font-family:ui-monospace,monospace;line-height:1.6' web.rs` →
`0` (the legacy inline body is gone).

### C. Item 3 — dna_verify (before → after)

```
$ cargo run -p ui-foundation --bin dna_verify
✗ web dashboard · 270° dial present
✗ web dashboard · monoline chart present
✗ CP dashboard · service ribbon slots
10/13 rendered-output checks pass
3 rendered-output check(s) FAILED                # EXIT=1
```
```
$ cargo run -q -p ui-foundation --bin dna_verify
13/13 rendered-output checks pass                # EXIT=0
```
The three restored markers are honest: the dial draws its track with **no value arc** and the value
text `—` (aria-label `delivery · 30d: —`), the monoline renders its **empty** series (no strokes),
and the copy says `Delivery health is unavailable and the chart has no strokes until your first
send — an absent figure is not zero.` The CP ribbon's white ink is the contrast-corrected pair for
the monochrome token (`--success-500: 82 82 91`).

### D. Item 4 — api-server lib-test build (fail-before reproduced by removal)

```
$ python3 - <<'PY'   # temporarily remove the import
… open('crates/api-server/src/routes/web/data.rs') … del "use crate::routes::web::{cp_data_page, web_data_page};"
PY
$ cargo check -p api-server --lib --tests --message-format=short
crates/api-server/src/routes/web/data.rs:8663:17: error[E0425]: cannot find function `web_data_page` in this scope: not found in this scope
crates/api-server/src/routes/web/data.rs:8665:17: error[E0425]: cannot find function `cp_data_page` in this scope: not found in this scope
error: could not compile `api-server` (lib test) due to 2 previous errors
```
```
# import restored at web/data.rs:7880 (inside coverage_loader_tests)
$ cargo check -p api-server --lib --tests
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 5.65s      # EXIT=0
```

### E. Item 5 — list members view (live + tests)

```
$ python3 /tmp/r6_members_probe.py         # rebuilt image
PASS POST /web/lists accepted :: status=303
PASS list row exists for the posting tenant :: list_id=1e1df8e8-8931-46ed-9139-b9f9f409fe20
PASS GET /lists/{id}/members answers 200 :: status=200
PASS members page renders the subscriber identity + email + status :: identity=True email=True
PASS members page states the exact count :: count line present
PASS list detail links its subscriber KPI to the members view :: status=200 link=True
PASS empty list renders the empty state with the next action :: status=200 empty_state=True next_action=True
PASS non-UUID demo segment answers without error :: status=200
=== 8/8 PASS ===                            # EXIT=0
```
```
$ cargo nextest run -p api-server --lib -E 'test(list_members_view)'
PASS routes::web::coverage_detail_session_tests::list_members_view_lists_subscribers_and_the_detail_links_to_it
```
Fixture note: the console has no add-to-list control yet, so the probe inserts one contact +
membership with psql (the same rows the JSON `/v1/lists/{id}/subscribers` API would create); the
empty-list arm is created through the console form itself.

### F. Item 6 — sales review form (tests)

```
$ cargo nextest run -p api-server --lib -E 'test(sales_decision_review_form) | test(sales_page_renders_the_native_review_form)'
PASS routes::web::tests::db_backed::sales_decision_review_form_decides_through_the_mounted_route
PASS routes::web::data::tests::sales_page_renders_the_native_review_form_for_pending_approvals
$ cargo nextest run -p ui-foundation -E 'test(sales_pending_approval_rows_carry_the_native_review_form)'
PASS ui-foundation leptos_views::tests::sales_pending_approval_rows_carry_the_native_review_form
$ cargo nextest run -p sales-autopilot
     Summary [  44.463s] 959 tests run: 959 passed, 0 skipped
```
The POST test seeds an `enforcement='await_approval', review_status='pending'` decision in the
sales tenant, drives the RENDERED action through the mounted router, and verifies the DB row
(`rejected` + `reviewed_by` + `review_note`) plus the terminal-review refusal flash
(`cannot be reviewed`).

### G. Item 7 — ai_drafts approval (before → after)

```
$ cargo nextest run -p api-server --lib -E 'test(ai_drafts)' --no-fail-fast      # pre-fix
        FAIL … approval_http_tests::approve_refuses_without_marketing_consent_and_stays_recoverable
        FAIL … approval_http_tests::approve_rolls_back_entirely_when_the_audit_write_fails
        FAIL … approval_http_tests::approval_http_surface_end_to_end
        FAIL … approval_http_tests::approve_writes_operator_attribution_audit_with_the_reply
        FAIL … approval_http_tests::first_response_approval_uses_the_priority_lane_and_closes_the_request
     Summary [   5.408s] 14 tests run: 9 passed, 5 failed, 2101 skipped
```
(the panics are all `left: 500 right: 200` with `INTERNAL_ERROR`; the raw queue refusal is R1's
`system email refused: callers must supply a non-empty html_body and text_body`).
```
$ cargo nextest run -p api-server --lib -E 'test(ai_drafts)' --no-fail-fast      # post-fix
     Summary [   7.609s] 14 tests run: 14 passed, 2101 skipped
```
The sixth filed failure (the console arm,
`routes::web::tests::db_backed::ai_draft_review_queue_approve_and_reject_flow_through_the_page`,
whose raw pre-fix failure is in R1's §2.J) now passes inside the 320-test gate run:
`PASS [ 2.003s] (239/320) … ai_draft_review_queue_approve_and_reject_flow_through_the_page`.

### H. Item 8 + gates

```
$ cargo check -p api-server -p ui-foundation --message-format=short
(no output)                                       # EXIT=0 — zero warnings
$ rustfmt --edition 2021 --check <the six touched files> && echo FMT_CLEAN
FMT_CLEAN
$ cargo nextest run -p api-server --lib -E 'test(ai_drafts) | test(web) | test(invite)' --no-fail-fast
     Summary [  57.595s] 320 tests run: 320 passed, 1798 skipped
$ cargo nextest run -p sales-autopilot
     Summary [  44.463s] 959 tests run: 959 passed, 0 skipped
$ cargo nextest run -p ui-foundation --no-fail-fast
     Summary [   1.465s] 514 tests run: 509 passed, 5 failed, 0 skipped
   FAIL axum_router::tests::form_field_map_repopulates_values_and_renders_errors   (R2 file/test, see §3.5)
   FAIL axum_router::tests::marketing_routes_include_marketing_shell               (R3 marketing templates)
   FAIL golden_tests::golden_{web,control_plane}_skeletons_match_the_checked_in_files  (fold regenerates)
   FAIL pixel_parity::tests::rendered_pages_match_the_committed_visual_baseline_skeleton (fold regenerates)
```
The five ui-foundation reds are all outside this lane's eight items; the two golden/parity reds are
the wave-wide stale baselines the brief defers to the fold, and the other two are analyzed in §3.5
with the exact required change.

---

## 3. Report for fold (routing counts, manifest, registry, residuals)

### 3.1 `crates/ui-foundation/src/routing.rs` (R2 file) — route counts

`counts_declared_routes`: **`declared_route_count("web")` 39 → 40** and **`total_route_count()` 130
→ 131**. Add the comment in the test's style:

```rust
// Lane R6 (review §6.2): /lists/{id}/members joins the web manifest — the
// list detail's subscriber count is inspectable — web 39 → 40, total
// 130 → 131.
assert_eq!(declared_route_count("web"), Some(40));
…
assert_eq!(total_route_count(), 131);
```

### 3.2 `docs/development/ui-baseline-manifest.json` — the new entry

Web surface `"routeCount": 39` → `"routeCount": 40`; insert after the `/lists/l_1/edit` entry:

```json
{"path": "/lists/l_1/members", "name": "List Members", "category": "dashboard", "authRequired": true, "canonicalPattern": "/lists/[id]/members"}
```

### 3.3 `crates/ui-foundation/src/axum_router.rs` (R2 file) — the render arm

`render_web` needs the manifest route to resolve. Add BEFORE the two `/lists/…` catch-alls (order
matters — the `/lists/{id}/edit` arm and the final `/lists/` catch-all must stay after it):

```rust
// /lists/{id}/members — the list detail's subscriber count is inspectable
// (review §6.2). With data the api-server composes the real rows
// (`load_list_members`); this arm is the manifest/render-inventory skeleton.
p if p.starts_with("/lists/") && p.ends_with("/members") => leptos_views::web_list_members_page(),
```

The api-server side is already live: `web.rs::detail_router` mounts
`.route("/lists/:id/members", get(web_list_members))` (same `web_list_detail` contract: session
redirect, non-UUID demo segment via `state_ssr_fallback`, honest not-found flash, outage ≠ not
found). Until the fold lands §3.1–3.3, the non-UUID demo segment still resolves through the
`/lists/` catch-all (probe: `status=200`) — the fold makes it render the members skeleton.

### 3.4 Fold regeneration

Goldens (`golden_tests`), `baselines/rust-ui/**` (pixel parity) and the exported fixtures must be
regenerated globally — this lane's dashboard/list-detail/sales/members markup changes are in the
same regeneration set, and the fold's normalizer fix (finding 14.1) is already on its list.
Also refresh the generated UI-strings catalog (`tools/extract_ui_strings.py` →
`docs/development/ui-strings-catalog.json`), which still records the retired
`"Invitation created."` flash (line 3847); no gate reads it, but the fold keeps it truthful.

### 3.5 Residual ui-foundation reds owned by other files (exact required change)

1. `axum_router::tests::form_field_map_repopulates_values_and_renders_errors`
   (`crates/ui-foundation/src/axum_router.rs:4045`, R2): after the P1-12 "replace the checked state"
   rework the injection strips every rendered `checked` and re-adds it only for posted values. The
   test posts `events=message.accepted|message.delivered` for form `webhook-create`, but the
   ROUTE's page (`/settings/webhooks`, static fallback) renders `data-form-id`-less checkboxes with
   `message.sent|bounced|complained`, so `html.matches(" checked").count() == 0` (probe). Fix
   either side coherently: render the static webhooks form with `data-form-id="webhook-create"` and
   the live loader's event vocabulary, or re-pin the test to values the static form carries.
2. `axum_router::tests::marketing_routes_include_marketing_shell` asserts
   `/pricing/calculator` inside the marketing templates — R3's file (already filed by R1/R5).

### 3.6 Files touched by this lane (uncommitted, as required)

`crates/api-server/src/routes/web.rs`, `crates/api-server/src/routes/web/data.rs`,
`crates/api-server/src/routes/admin/ai_drafts.rs`, `crates/ui-foundation/src/leptos_views.rs`,
`crates/ui-foundation/src/view_data.rs`, `crates/sales-autopilot/src/control.rs`. Nothing else was
edited — `routing.rs`, `axum_router.rs`, the manifest, the test files and the CSS are reported here
for the fold (§3.1–3.5). `crates/api-server/src/routes/auth.rs` and `forgot_password.rs` were NOT
touched; see 3.7 for the one behavioural note that follows from that.

### 3.7 Two interpretations to record

1. **Route shape.** The brief wrote `/web/lists/:id/members`; the existing list-detail GET route on
   this surface is `/lists/:id` (`detail_router`), with `/web/*` reserved for POST form twins, so
   the members page is mounted as GET `/lists/:id/members` (the brief's own "match the existing
   list-detail route style"). The console_internal_links gate resolves it through the
   `/lists/` catch-all today and through §3.3's arm after the fold.
2. **Invited-account acceptance path is browser-only by design.** `web.rs::form_reset_password`
   now accepts `status='invited'` and promotes it to `active`; the JSON twin
   (`routes/auth.rs::reset_password`) still requires `status='active'`. The invitation mail links to
   the browser page (`/reset-password?token=&email=`), so the documented flow completes; a caller
   POSTing the same token to the JSON endpoint still gets the honest "This account is not active."
   refusal. If the fold wants byte-identical JSON/browser semantics, promote the JSON twin's status
   guard in `auth.rs` with the same `invited → active` UPDATE.

---

## 4. Final paragraph for the orchestrator

Lane R6 adjudicated all eight filed leftovers with zero skips and left the tree measurably
healthier: the tenant team invite now MINTS both credentials, stores their hashed tokens in
`users.metadata`, queues the two-link workspace invitation in the SAME transaction and only then
flashes delivery — proved end to end live (13/13: Mailpit mail → verification link verifies →
setup link accepts the invitation → the teammate logs in); the three browser email shells (signup
verification, forgot-password reset, resend verification) render through R5's shared
`render_transactional_email` with visible fallback URLs and mirrored plain-text bodies (live 4/16 →
16/16); `dna_verify` is 13/13/EXIT=0 with the dial and monoline restored honestly in the no-data
dashboard and the CP ribbon's solid all-nominal cell back under the contrast-corrected monochrome
tokens; the api-server lib-test build is green with the `web_data_page`/`cp_data_page` import proved
load-bearing by removal; the list-members view ships (loader + view + detail link + empty state,
live 8/8) pending only the three routing/manifest/registry lines reported for the fold; the
sales decision review is a native SSR form on the owner-only page backed by a now-public
`apply_review` (transactional, operator-attributed, tested through the mounted route, with
sales-autopilot 959/959); the ai_drafts approval path renders the draft through the shared shell and
its five reds (plus the console review-queue test) are green; and the seven escaped-newline
warnings are gone, leaving `cargo check -p api-server -p ui-foundation` at exit 0 with zero
warnings. Final suites: api-server `—lib` filtered gate 320/320, sales-autopilot 959/959, the new
targeted tests 10/10, ui-foundation 509/514 (the five reds are two stale-baseline classes the fold
regenerates and two residual assertions in R2/R3 files, each analyzed with its exact required change
in §3.5). The only deliberate deviation from the brief is item 1's email builder: reusing
`enqueue_operator_invite_email` verbatim would mail a workspace teammate the control-plane/MFA
claim, so the handler uses the same shared shell, same transactional queue helper and
workspace-appropriate copy, with the parameterized-builder alternative recorded for the fold.

