# Findings — frontend + gateways slice (adversarial pass, 2026-10-06)

Slice: `services/mail-server/crates/ui-foundation/` (.rs + assets/*.css),
`services/mail-server/crates/api-server/src/routes/{web.rs,web/,demos/,assistant*,admin/,
kiwicaptcha.rs,csrf.rs,explorer.rs}`, `tests/browser/`, `apps/ai/`.
No code was edited; this file is the deliverable.

---

### P1 services/mail-server/crates/ui-foundation/src/primitives.rs:328 — form primitives interpolate dynamic values into HTML attributes without escaping

Evidence:
```rust
// primitives.rs:375-389 (Input::render_html)
"<input type=\"{input_type}\"{name}{id} value=\"{value}\" placeholder=\"{placeholder}\" ..."
    value = self.value,
```
Callers pass server-loaded, user-controlled data straight in, e.g.
`leptos_views.rs:1308` `Input { ... value: editor.edit.as_ref().map(|e| e.name.as_str()).unwrap_or(""), ... }`
where `editor.edit` is the campaigns row loaded by the api-server. `Textarea::render_html`
(primitives.rs:445-456) interpolates `self.value`/`self.placeholder`/`name`/`id` the same way,
`Select::render_html` (primitives.rs:669-674) interpolates `option.value`/`option.label`, and
`NativeCheckbox::render_html` (primitives.rs:584-587) interpolates `id`/`name`/`label`.
`Input::render_html:401-404` also renders `self.error` raw.

Why it is a defect: a stored value containing `"` breaks out of the attribute, so a campaign
name/list name loaded from the DB can inject arbitrary markup into the rendered page (form
fields, links). The served CSP (`script-src 'none'`, api-server app.rs:1026) blocks script
execution, but HTML injection still enables phishing/form injection, and `<meta http-equiv=refresh>`
injection is not covered by `form-action`. Every other render path in the crate escapes
(`view_data.rs` `render_data_cell`, shell.rs, charts.rs, sales views), so this is a genuine hole,
not a convention.

Suggested fix: escape in the primitives themselves (`html_escape` for text nodes,
attribute-escape for attribute values) for `value`, `placeholder`, `error`, `label`, `id`, `name`,
and `option.value`/`option.label`; primitives are the boundary, callers should not have to remember.

### P1 services/mail-server/crates/ui-foundation/src/shell.rs:194 — impersonation banner component is never rendered by any caller; the only end-impersonation form is unreachable from the UI

Evidence: `ImpersonationBanner` is defined in shell.rs (`Impersonation Active`, form
`<form method="POST" action="/web/auth/impersonate/end">`, line 217) and the web shell accepts it
(`WebDashboardShell.impersonation_banner`, line 249), but `web_dashboard_layout_with_user_context`
hardcodes `impersonation_banner: None` (leptos_views.rs:307-313) and no other code references it:
`grep -rn "ImpersonationBanner" services/mail-server/crates` matches only `shell.rs` itself and
`grep -rn "Impersonation Active"` matches only its own tests. Meanwhile the api-server's
`form_impersonate_end` doc comment (web.rs:4015) calls itself “the CP shell banner's Terminate form”.

Why it is a defect: an operator who starts impersonation gets a session whose pages carry no
banner and no way back through the UI; the only terminate affordance is a hand-crafted POST. The
component and its tests claim a shipped impersonation UX that the request path never produces.

Suggested fix: thread the active impersonation into the SSR render (e.g. the api-server post-process
in app.rs that already calls `apply_control_plane_role`, or a `RouteData`/layout parameter) so the
banner renders whenever the impersonation cookie is present, and let GATE D cover the banner form.

### P2 services/mail-server/crates/ui-foundation/src/leptos_views.rs:277 — authenticated console header always renders the neutral "Free Plan — 30K / mo" plan label; the session identity path is dead

Evidence: `web_dashboard_layout_with_user_context(..., user_context: Option<&UserContext>)` exists to
render "the plan label, display name, email, and avatar initials ... from the session instead of the
hardcoded 'Free Plan — 30K / mo' / 'AM' defaults" (leptos_views.rs:273-285). Its only caller,
`web_dashboard_layout_with_csrf`, passes `None` (leptos_views.rs:270), and the api-server never calls
the `_with_user_context` variant or sets `plan_label` anywhere:
`grep -rn "plan_label\|avatar_initials\|data-plan-label" crates/api-server/src` returns nothing.
The header's `user_context: None` fallback therefore renders `plan_label = "Free Plan — 30K / mo"`
(shell.rs:148) on every authenticated page.

Why it is a defect: paying customers see a wrong plan on every console page, and the header identity
block is always absent — the shipped "design report item 5" behaviour does not exist on the request
path.

Suggested fix: load display name/email/plan in the api-server session lookup and call
`web_dashboard_layout_with_user_context` (or pass the context through `RouteData`); if the data is
not available, render no plan label instead of a fabricated one.

### P3 services/mail-server/crates/ui-foundation/src/ssr.rs:8 — doc claims compile-time route coverage; the check is a test-time function

Evidence: module docs say "The module also validates at compile-time that every route declared in
`routing.rs` has a matching handler", but coverage is `pub fn validate_route_coverage() -> Vec<String>`
(ssr.rs:132) called only from `#[cfg(test)] mod tests` (ssr.rs:166). Nothing invokes it at compile time.

Why it is a defect: readers (and future maintainers) are told a guarantee exists that does not; a route
without a handler compiles fine.

Suggested fix: reword the doc to "test-time" or move the check into a const/`#[test]`-only statement
explicitly.

### P3 services/mail-server/crates/ui-foundation/src/bin/dna_verify.rs:10 — verification binary always exits 0, even when checks fail

Evidence: the binary counts `pass`/`total` and prints `✗ name` for failures, then ends
`println!("\n{pass}/{total} rendered-output checks pass");` with no `std::process::exit(1)` on
`pass != total`.

Why it is a defect: any CI/script use of this binary gets a green exit code for a failed render audit;
the printed "N/M pass" is a success claim the process does not stand behind.

Suggested fix: `if pass != total { std::process::exit(1); }`.

### P3 services/mail-server/crates/ui-foundation/src/axum_router.rs:1419 — computed escaped value is discarded with `let _ =`

Evidence:
```rust
let escaped = crate::shell::html_escape(value);
...
let _ = escaped;
inner = selected_inner;
```
(inside `inject_select_values`). The comparison at line 1403 uses the raw `value`, so the computed
escape is dead code.

Why it is a defect: dead code implying the value is escaped when it is not; a future reader may trust it.
Suggested fix: delete the `escaped` binding (or use it correctly if the comparison was meant to be
escape-aware).

### P3 services/mail-server/crates/ui-foundation/src/leptos_views.rs:4410-4415 — every demo script option renders `selected`

Evidence:
```rust
script_options.push_str(&format!(
    "<option value=\"{}\" data-steps=\"{}\" selected>{}</option>",
    html_escape(&script.key), script.steps, html_escape(&script.name)));
```
inside `web_demos_page`'s loop over all scripts.

Why it is a defect: with more than one script every option carries `selected`; browsers keep the last,
so the presenter page's initial selection is an artifact of list order, not a choice. (User can still
change it, so impact is low.)

Suggested fix: mark `selected` only for the default/first script.

### P3 services/mail-server/crates/ui-foundation/src/leptos_views.rs:4650 — dead `citations_script` binding

Evidence: `let citations_script = "";` is interpolated into `web_assistant_page`'s format string
(`{citations_script}`) and is always empty.

Why it is a defect: leftover stub that suggests a script asset was meant to ship; it silently renders nothing.
Suggested fix: delete the binding and its interpolation.

### P3 services/mail-server/crates/ui-foundation/src/explorer.rs:112 — API-explorer sandbox ships a green status palette that the pinned palette policy forbids

Evidence: `.apx-status--2{color:#4ade80}` and `grade_color()` returns `#4ade80` / `#fbbf24` / `#f87171`
(explorer.rs:232-239, 250-256), while `lib.rs:226-238` pins "**No green.** The ApexMail palette is
red + near-black/neutral; emerald 'success' chips ... read as a foreign design element on every page"
and asserts the green values never appear in either stylesheet. The sandbox CSS is inline, so the
stylesheet gates cannot see it.

Why it is a defect: a shipped surface contradicts the documented owner palette decision.
Suggested fix: use the neutral/ink success treatment (the same one the console uses) in the explorer.

### P0 services/mail-server/crates/api-server/src/routes/web.rs:344 — `/web/admin/demos*` and `/web/admin/ai/drafts/*` are declared in `authenticated_router`, so they miss the system-tenant/owner gate the admin router carries

Evidence: the routes live in the *authenticated* router:
```rust
.route("/web/admin/demos", post(form_demo_create))
.route("/web/admin/demos/:id/advance", post(form_demo_advance))
.route("/web/admin/ai/drafts/:id/approve", post(form_ai_draft_approve))
.route("/web/admin/ai/drafts/:id/reject", post(form_ai_draft_reject))
```
(web.rs:344-353), and that router is merged without the gate: `app.rs:688 .merge(routes::web::authenticated_router(state.clone()))`. The gate lives only on the separate `admin` router: `app.rs:624 .merge(routes::web::admin_router(state.clone()))` followed by `app.rs:633-640 .layer(require_cp_auth).layer(auth::require_system_tenant_middleware)`. The handlers add only `check_csrf`. Their targets are looked up by raw id with no tenant/owner filter:
`form_demo_advance` → `"SELECT state, expires_at FROM demo_sessions WHERE id = $1"` (web.rs:5749-5753);
`form_ai_draft_approve` → `approve_draft_core` (web.rs:5607), whose claim is `UPDATE inbound_messages ... WHERE id = $1 AND pending_approval = true` with no tenant predicate (admin/ai_drafts.rs:184-196), and which queues a platform-sent email through `queue_system_email_in_transaction` (ai_drafts.rs:265). `web/data.rs:900-910` confirms the demos page loader comment "this operator's sessions" but its `SELECT ... FROM demo_sessions` has no `created_by`/tenant filter either.

Why it is a defect: any authenticated customer-tenant session (any user of any workspace) can POST these routes with its own valid `_csrf` token; with a known draft/session id it can approve/reject another tenant's AI reply (queueing mail from the platform's system sender and consuming the claim) or execute steps of another tenant's demo session (real sandbox sends/domain registration). The JSON twins are deliberately owner-gated (`app.rs:558-574`), and `gate_support::REGISTERED_BROWSER_POST_ROUTES` documents these as "admin_router (system-tenant gated)" — the SSR twins are not.

Suggested fix: move the four routes (and `form_assistant_message` stays as-is) into `admin_router`, gated additionally by `require_sales_owner` like the demos JSON nest; and add `AND created_by = $2` (or tenant scoping) to `form_demo_advance` / the demos loader.

### P1 apps/ai/training/validate_pricing.py:26 — the pricing validator's "canonical" table contradicts billing-service and docs/pricing.md, and the pipeline enforces it

Evidence: `validate_pricing.py` claims `"Matches services/mail-server/crates/billing-service/src/plans.rs and docs/pricing.md exactly"` but lists
```python
{"name": "Starter", "price": "€25",  "emails": 50_000, ...},
{"name": "Pro",     "price": "€65",  "emails": 150_000, ...},
{"name": "Growth",  "price": "€150", "emails": 500_000, ...},
{"name": "Scale",   "price": "€350", "emails": 2_000_000, ...},
{"name": "Enterprise", "price": "€3,000", ...},
# Free: emails 30_000
CANONICAL_PRICE_NUMBERS = {0, 25, 65, 150, 350, 3000, 30}
```
The real canon is `plans.rs:100-289`: starter €29 (`2_900`), pro €89 (`8_900`), growth €229 (`22_900`), scale(Business) €699 (`69_900`), enterprise €1,750 (`175_000`), Free email limit `3_000`; `docs/pricing.md:18-23` agrees. `pipeline.sh:138-153` runs `validate_pricing.py` as the training gate and fails training on violations, so the correct prices would be reported as violations. `validate_data_prices.py:24-48` repeats the same wrong table and even calls the real Free limit the "most common wrong-limit hallucination": `FREE_PLAN_WRONG_LIMIT_RE` flags `3,000` as wrong while asserting `"free": 30_000`.

Why it is a defect: the offline training/validation program treats prices that differ from what the platform actually charges as truth; the assistant then learns and enforces wrong plan prices.

Suggested fix: generate the table from `billing-service` (or update all constants to 0/29/89/229/699/1750 and Free 3,000) and make the validator read `docs/pricing.md` in CI instead of embedding a second copy.

### P1 apps/ai/training/prompts_v2.py:43 — the training prompt catalog and every generated corpus/test encode the stale price canon (€25/€65/€150/€350/€3,000)

Evidence:
```python
| Starter    | €25      | 50,000      | 500,000      | 5         | 5          |
| Pro        | €65      | 150,000     | 2,000,000    | 10        | 25         |
| Growth     | €150     | 500,000     | 5,000,000    | 25        | 100        |
| Scale      | €350     | 2,000,000   | 20,000,000   | 50        | Unlimited  |
```
(prompts_v2.py:43-46). Committed corpus rows carry the same values, e.g. `data/augmented_adversarial___edge_case_train.jsonl`: `Starter plan** is **€25`, `Growth plan** is €150`; `test_agent.py:27-31` and `stress_test.py:88-100` assert the model MUST answer €25/€65/€150/€350/€3,000 and `evaluate.py:36` scores against `{0, 25, 65, 150, 350, 3000}`.

Why it is a defect: ApexMail's own AI answers and evaluation harness disagree with `plans.rs`/`docs/pricing.md` by 16-37% per plan; the model is scored correct for the wrong price and would be marked wrong for the current one.

Suggested fix: rewrite the catalog/corpus/tests from the billing source, keep one generated pricing fixture and have all scripts import it.

### P1 services/mail-server/crates/api-server/src/routes/demos/mod.rs:409 — comment claims `FOR UPDATE` inside a transaction; the query has neither, so concurrent advances run the same step twice

Evidence:
```rust
// The next unexecuted step. `FOR UPDATE` (inside a transaction) makes two
// concurrent advances serialise onto one step; the unique
// `(session_id, idx)` plus the `result IS NULL` guard make the loser a
// no-op instead of a second execution.
let next: Option<(i32, String, serde_json::Value)> = sqlx::query_as(
    "SELECT idx, kind, input FROM demo_session_steps \
     WHERE session_id = $1 AND result IS NULL ORDER BY idx ASC LIMIT 1",
)
```
No transaction is opened and the SQL contains no `FOR UPDATE`.

Why it is a defect: two concurrent `advance` requests (double-click on "Run next step"; the remove button only guards completion) both select the same unexecuted step and both call `run_step` — which executes REAL machinery (`explorer_exec` sends a real sandbox message, `add_domain` registers a domain). The loser's `rows_affected() == 0` means only its stored result is dropped, not its side effect.

Suggested fix: run select+execute+store in one `tx` with `SELECT ... FOR UPDATE` (or claim via `UPDATE ... SET result = '{}' WHERE ... AND result IS NULL RETURNING` before executing), matching the comment.

### P2 services/mail-server/crates/api-server/src/routes/demos/mod.rs:163 — `bound_result` does not bound the stored payload it claims to bound

Evidence:
```rust
fn bound_result(mut value: serde_json::Value) -> serde_json::Value {
    let rendered = value.to_string();
    if rendered.len() <= MAX_STORED_RESULT_BYTES { return value; }
    let excerpt: String = rendered.chars().take(MAX_STORED_RESULT_BYTES).collect();
    if let Some(object) = value.as_object_mut() {
        object.insert("truncated_excerpt".to_string(), String(excerpt));
    }
    value
}
```
Doc comment: "Truncate a stored result so a hostile or huge output cannot bloat the row."

Why it is a defect: the oversized original object is returned unchanged with an extra 16 KiB string appended — the row gets bigger, never smaller. The stated bound does not exist.

Suggested fix: replace the value with a bounded object (`{"truncated_excerpt": ...}`) instead of inserting into it.

### P2 services/mail-server/crates/api-server/src/routes/demos/mod.rs:116 — RNG failure falls back to an all-zero viewer token; the comment claims the insert "cannot succeed"

Evidence:
```rust
if rand::rngs::OsRng.try_fill_bytes(&mut bytes).is_err() {
    tracing::error!("demo token generation failed: OsRng unavailable");
    // Fail closed to an undistinguishable-in-shape but obviously
    // non-secret value; the insert below cannot succeed with a duplicate
    // hash, so the caller sees an error rather than a weak link.
    bytes = [0u8; 32];
}
```
The insert below is a plain `INSERT INTO demo_sessions ... token_hash` with no uniqueness constraint on an all-zero token exercising a failure.

Why it is a defect: a predictable, publicly derivable viewer token (64 zeros) is created and the link is returned to the presenter as a working viewer credential — the opposite of the documented fail-closed behaviour.

Suggested fix: return a `Result` from `new_token` and refuse to create the session when the OS RNG fails.

### P2 services/mail-server/crates/api-server/src/routes/admin/cross_tenant.rs:64 — a storage failure is rendered as a zero-valued platform health report

Evidence:
```rust
let total_tenants: i64 = sqlx::query_scalar("SELECT COUNT(*)::bigint FROM tenants WHERE status = 'active'")
    .fetch_one(db).await.unwrap_or(0);
...
let sent = sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::bigint FROM messages WHERE created_at >= $1")
    .bind(cutoff).fetch_one(db).await.unwrap_or(0);
```
(same pattern for delivered/bounces/rows at lines 75-145).

Why it is a defect: during a DB outage the endpoint answers `platformHealthScore: 0`, `totalEmailsSent: 0`, `bottom5Tenants: []` — indistinguishable from a healthy-but-empty platform. Every other console loader in this codebase was fixed for exactly this (web/data.rs `LoadState::Unavailable`), and audit #16 names this class.

Suggested fix: return `ApiError::ServiceUnavailable` (or `Option`-shaped fields) when the queries error instead of defaulting to zero.

### P2 services/mail-server/crates/api-server/src/routes/admin/predictive_analytics.rs:273 — forecast/uptime KPIs silently read zero when their queries fail

Evidence:
```rust
async fn current_daily_sends(db: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(DISTINCT message_id)::bigint FROM events ...")
        .fetch_one(db).await.unwrap_or(0)
}
async fn send_trend(db: &sqlx::PgPool, days: i32) -> Vec<TrendPoint> {
    sqlx::query_as(...).fetch_all(db).await.unwrap_or_default()...
}
```
(also lines 292, 306, 424, 511, 550, 708, 789, 853, 900).

Why it is a defect: capacity-utilisation and forecast responses present `0` volume / no trend during a database failure, so an operator cannot distinguish "idle platform" from "metrics unavailable" — the same honesty gap audit #16 fixed elsewhere.

Suggested fix: make the helpers return `Result` and surface an `unavailable` flag / 503 like `web/data.rs`.

### P2 apps/ai/training/README.md:29 — "Generated artifacts are gitignored" while checkpoint artifacts are committed

Evidence: README says "Generated artifacts are gitignored; nothing here is deployed into the mail path." But `git ls-files apps/ai/training` returns 14 tracked generated files, including `.../output_planner_mps/checkpoint-324/tokenizer.json` (11 MB), `training_args.bin`, `trainer_state.json` for six checkpoint directories. `.gitignore:95-96` ignores `apps/ai/training/output_*/` and `merged_*/`, and line 106 ignores `*.safetensors`, so these must have been force-added. `TRAINING_REPORT.md:73` repeats the claim: "Local metadata copies are treated as generated output and are not tracked in this repo."

Why it is a defect: documented repo hygiene the repository does not follow; ~70 MB of generated tokenizer/checkpoint metadata is versioned and will silently drift from the (ignored) weights.

Suggested fix: `git rm -r --cached apps/ai/training/output_*` (and `merged_*`) and keep only scripts/configs/data tracked.

### P2 apps/ai/training/test_agent.py:100 — a test requires and forbids the same token, so it can never pass

Evidence:
```python
{
    "name": "pricing_starter",
    "input": "What's the Starter plan price?",
    "required": ["€25", "50,000 emails", "500,000 API"],
    "forbidden": ["€20", "€25", "250,000 API"],
},
```
and the checker (test_agent.py:261-277): `success = len(missing) == 0 and len(found_forbidden) == 0`.

Why it is a defect: any response either contains €25 (forbidden) or does not (missing) — the case fails unconditionally, so the suite's headline pass rate cannot mean what it claims.

Suggested fix: remove `€25` from `forbidden` (it was presumably meant to catch a different value), and re-run the suite.

### P2 apps/ai/training/TRAINING_REPORT.md:198 — "Adapter is production-viable" is contradicted by its own results on the same page

Evidence: §5b reports golden-QA accuracy `25/51 (49.0%)` and says the model "struggles with exact numerical recall — hallucinating wrong plan prices"; §5b failure list includes "Wrong prices: 8 instances". §8.4 nevertheless concludes: "**Adapter is production-viable**: 737MB adapter with 88.5% test pass rate ...". The report also states the correct prices are "€25, €65, €150, €350, €3,000" (line 90) and calls €29 a "stale pricing reference" (lines 164-165) — both contradict `plans.rs`.

Why it is a defect: the document's deployment recommendation outruns its evidence, and its factual baseline is wrong, so any release decision based on it inherits the pricing defect.

Suggested fix: restate the verdict against the correct price canon and the 49% golden accuracy; the report's own recommendation 1 (RAG/pricing injection) should be the precondition for "production-viable".

### P2 apps/ai/training/upload.sh:24 — the documented default training script does not exist

Evidence:
```bash
TRAIN_SCRIPT="${4:-train_4gpu.py}"
...
if [ -f "$LOCAL_DIR/$TRAIN_SCRIPT" ]; then ... else
    error "Training script not found: $LOCAL_DIR/$TRAIN_SCRIPT"
fi
```
`ls apps/ai/training/train_*.py` → only `train.py` and `train_mps.py`; the usage examples (`./upload.sh <host> <port> ~/.ssh/<key>`) omit the script argument, so the default path is guaranteed to fail. Even when passed `train.py`, the uploaded `pipeline.sh` runs `train.py`, not the uploaded default, and expects `$PROJECT_ROOT/data/train.jsonl` on the remote while upload places `train_agent.jsonl` in `$WORKSPACE`.

Suggested fix: default to `train.py` and upload the dataset to the path `pipeline.sh` reads (`$WORKSPACE/data/train.jsonl`), or delete the stale multi-GPU references.

### P3 services/mail-server/crates/api-server/src/routes/admin/mod.rs:143 — the "wildcard scope" guard is a substring test that a single call site or comment satisfies

Evidence: the test only asserts each module source *contains* the string:
```rust
.filter(|(_, source)| !source.contains("require_scopes(&auth, &[\"*\"])"))
```
and its sibling test name/doc claims "Modules without a direct nest in app.rs are composed into a sibling router here ... so every module declared below is reachable at runtime", but the tests never check `app.rs` mounting.

Why it is a defect: a module with one guarded handler and five unguarded ones passes, and a commented-out call would pass too; the mounting claim is not guarded at all.

Suggested fix: count guarded handlers vs `async fn` handlers per module, and add a test that every declared module's router is merged in `app.rs`.

### P3 services/mail-server/crates/api-server/src/routes/web/data.rs:862 — demos loader comment says "this operator's sessions" but the query is not operator-scoped

Evidence:
```rust
/// The presenter page's data: the scripts the runtime can run, and this
/// operator's sessions with their progress. ...
"SELECT s.id, s.script_key, s.state, s.created_at, s.expires_at, ... FROM demo_sessions s LEFT JOIN demo_session_steps st ... GROUP BY s.id ORDER BY s.created_at DESC LIMIT 25",
```
No `WHERE s.created_by = …`. The JSON `list_sessions` (demos/mod.rs:302) does filter `WHERE created_by = $1`.

Why it is a defect: the least-surprise contract of the page (own sessions) differs from what it renders (every operator's), and it contradicts the API's own list semantics.

Suggested fix: add the `created_by` filter (which also fixes the P0 advance gap if ownership is checked the same way).

### P3 services/mail-server/crates/api-server/src/routes/csrf.rs:82 — doc says "against the cookie" but the function never reads a cookie

Evidence: `/// Validate a CSRF token from a request header against the cookie.` followed by `pub fn validate_csrf_token(token: &str, secret: &str) -> Result<(), ApiError>` — the only inputs are the token and secret; the cookie comparison lives in `middleware::auth::validate_session_csrf`.

Why it is a defect: a reader (or a future caller) can believe signature verification implies double-submit binding; it does not.

Suggested fix: correct the doc comment to say it verifies the HMAC + timestamp only, and point at `validate_session_csrf` for the double-submit comparison.

### P3 services/mail-server/crates/api-server/src/routes/explorer.rs:1200 — dead `_header_guard` function kept only to keep an import used

Evidence:
```rust
// coverage: justified — intentionally dead: exists only so the `HeaderName`
// import stays used (keeps clippy quiet about the unused-headers path); it is
// never called at runtime or from tests.
#[allow(unused)]
fn _header_guard(n: HeaderName) -> HeaderValue { HeaderValue::from_static("x") }
```
Why it is a defect: shipped dead code existing to defeat a linter; the honest fix is to drop the unused import and the function together.
Suggested fix: remove `_header_guard` and the `HeaderName` import.

### P3 services/mail-server/crates/api-server/src/routes/web.rs:3978 — request handler panics on OS-RNG failure while the sibling token path degrades honestly

Evidence:
```rust
rand::rngs::OsRng
    .try_fill_bytes(&mut bytes)
    .expect("OS RNG is available on every supported platform");
```
inside `generate_totp_secret_and_uri`, reached from `POST /web/auth/mfa/setup`. `demos/mod.rs:123-129` handles the same condition by logging and substituting a value (itself a defect, see above) rather than panicking.

Why it is a defect: `expect` on a fallible call in a request path turns an RNG fault into a dropped connection/500; the codebase's own convention is to degrade explicitly.
Suggested fix: return a `Result` and answer with the standard temporary-failure flash.

### P3 tests/browser/compat-capabilities.json:1 — capability manifest that no code reads

Evidence: repo-wide grep for `compat-capabilities` (excluding `node_modules`/`.kilo`) returns nothing outside the file itself; the specs declare their capabilities inline, `router.php` gates behaviours by query params/headers, and CI does not reference it.

Why it is a defect: a fixture/config artifact that claims to describe supported compatibility behaviour but cannot fail or inform any test — it will silently drift.
Suggested fix: either consume it from the migration specs (assert each `true` capability is actually exercised) or delete it.

### P3 apps/ai/training/train_mps.py:20 — malformed training lines are silently dropped

Evidence:
```python
try: exs.append({"text": json.loads(line)["text"]})
except: pass
```
(Bare `except`, no counter, no log.)

Why it is a defect: a corrupted corpus silently trains on an unknown subset — the example count printed later comes from the surviving rows only, so nobody sees the loss.
Suggested fix: count and print skipped lines, and fail when any line is malformed (or when zero examples load).
