# Lane R6 — leftover closer: filed defects across lanes (verify-and-fix, zero skips)

You are an extremely rigorous verifier-fixer. Lanes R1/R3/R5 completed and filed these exact
leftovers for whoever owns the files next. You own the listed files NOW (previous owners are done).
Read `register.md` for the standing rules (verdicts with literal evidence, real global fixes, no
KiwiCaptcha, no git commit, report + zero-skips appendix + orchestrator paragraph).

## Your files

`crates/api-server/src/routes/web.rs`, `crates/api-server/src/routes/web/data.rs`,
`crates/ui-foundation/src/{leptos_views.rs, view_data.rs}`, `crates/api-server/src/routes/admin/ai_drafts.rs`,
`crates/sales-autopilot/src/control.rs`. If you need `routing.rs`/`axum_router.rs`/`primitives.rs`/
CSS/test files, put the exact required change in your report ("report for fold") instead of editing.

## Work items (each: fail-before → fix → fail-after, literal evidence)

1. **Team invite delivers nothing** (`web.rs` ~4700-4736; filed by R5): the handler inserts
   `users … status='invited'` with `password_hash='!invited-pending-activation'`, mints NO tokens and
   queues NO email, then flashes "Invitation created." Copy the canonical operator path
   (`web.rs` ~8637-8690): mint verification + password-setup tokens via
   `apexmail_lib::id::generate_verification_token()`, store the hashed tokens/expiries in
   `users.metadata`, call `crate::routes::auth::enqueue_operator_invite_email(&mut tx, …)` in the
   SAME transaction, and only then flash success. Prove with a live test: invite from the Team page
   → the mail lands in Mailpit (`http://127.0.0.1:8025/api/v1/messages`) → the link verifies.
2. **Browser email shells on the shared renderer** (`web.rs` ~3040-3056 and ~3395-3409; filed by
   R5): replace the inline `format!` verification HTML with
   `crate::routes::system_sender::render_transactional_email(TransactionalEmail { … })` so browser
   and API twins are structurally identical; add the fallback URL + unrequested-mail line to the
   plain-text bodies. Keep the distinct link semantics.
3. **dna_verify reds** (filed by R5): `cargo run -p ui-foundation --bin dna_verify` exits 1 (10/13):
   the web dashboard no longer emits `apex-dial`/`apex-chart-monoline` and the CP dashboard ribbon
   lost the `all nominal` markup. Either restore the intended markers in `leptos_views.rs` (the
   design DNA gate is the contract — do NOT weaken the gate) or, if a marker was deliberately
   retired, change BOTH the design gate and the views coherently with a comment. End state: the gate
   is green AND the rendered dashboards carry the intended DNA.
4. **api-server lib-test build red** (`web/data.rs` ~8663-8665: `cannot find function web_data_page /
   cp_data_page`): import/re-export the two functions so the whole api-server test suite builds.
5. **List members view** (filed by R1): the Lists page shows a member count with no way to inspect
   members. Add the members view: a `/web/lists/:id/members` (match the existing list-detail route
   style) view + loader showing the subscribers (readable identity, status, added date), linked from
   the list detail's member count, with an empty state that offers the next action. Report the exact
   `routing.rs`/manifest count delta for fold.
6. **Sales decision review as a native SSR form** (filed by R1): make
   `crates/sales-autopilot/src/control.rs::apply_review` (~584) `pub`/`pub(crate)` (matching
   `ActionQueue::replay`'s visibility pattern) and mount a native form on the owner-only sales page
   (approve/reject with the review payload the function needs). R1 already shipped the dead-letter
   Replay form; mirror its structure. Add tests.
7. **ai_drafts approval 500s** (filed by R1, root-caused): the AI-draft approval queue insert calls
   the system-email queue with EMPTY `html_body`/`text_body` and the queue layer refuses
   (`system email refused: callers must supply a non-empty html_body and text_body`). Fix the
   approval path to render the draft through the shared transactional shell (R5's
   `render_transactional_email`) — the SAME shell R5 built for the other emails — or queue the
   draft's own HTML when present; never leave the approval broken. Reproduce the 6 failing
   `admin::ai_drafts` tests live before, green after.
8. **Clean-up**: any `cargo check -p api-server -p ui-foundation` warning introduced by these paths
   must be gone (the tree currently has zero warnings after fold-level fixes).

## Gates to run after your changes

`cargo nextest run -p api-server --lib -E 'test(ai_drafts) | test(web) | test(invite)'`,
`cargo nextest run -p sales-autopilot`, `cargo run -p ui-foundation --bin dna_verify`,
`cargo check -p api-server -p ui-foundation`, `cargo fmt` on touched files. Do NOT regenerate goldens
(the fold step does a global regeneration with the fixed normalizer).

## Deliverable

`docs/audit/ui-external-review-2026-10-08/lane-r6-closer.md`: verdict table for items 1-8 with
fail-before/fail-after evidence, zero-skips appendix, "report for fold" (routing counts etc.),
final orchestrator paragraph.
