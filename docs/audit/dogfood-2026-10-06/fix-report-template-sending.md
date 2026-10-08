# Fix report — template-based sending (server + SDKs)

Agent: `fix-template-sending`. Date: 2026-10-07. Base revision: `97a8877b`
(sibling agents' uncommitted working tree was present throughout). Deliverable
of `docs/audit/dogfood-2026-10-06/brief-template-sending.md`.

**Continuation note.** The prior attempt died on a provider balance error and
left NOTHING on disk: `git status` was clean, no
`fix-report-template-sending.md` existed, no stash or side worktree carried
its work. This pass therefore implemented the brief end to end; there was no
partial state to preserve.

**Ownership.** Only the files the brief names were edited:

| Area | Files edited |
|---|---|
| Server | `services/mail-server/crates/api-server/src/routes/messages.rs` (template arms + tests), `services/mail-server/crates/api-server/Cargo.toml` (adds the `template-renderer` path dep) |
| SDKs | `packages/sdk-go/{apexmail.go,apexmail_payload_contract_test.go,apexmail_live_contract_test.go,README.md,CHANGELOG.md}` |
| SDKs | `packages/sdk-python/{src/apexmail/resources/emails.py,tests/test_payload_contract.py,README.md,CHANGELOG.md}` |
| SDKs | `packages/sdk-php/{src/Resources/Emails.php,tests/PayloadContractTest.php,README.md,CHANGELOG.md}` |
| SDKs | `packages/sdk-java/{src/main/java/ee/apexmail/Emails.java,src/test/java/ee/apexmail/EmailsSendRequestTest.java,README.md,CHANGELOG.md}` |
| SDKs | `packages/sdk-ruby/{lib/apexmail.rb,test/payload_contract_test.rb,README.md,CHANGELOG.md}` |
| Docs | `docs/api/endpoints/messages.md` |

Not touched: `ai_chat.rs`, `web.rs` assistant functions, `reply_handler/**`,
`ai-service/**`, `billing-entitlements/**`, plan seeds, `docs/eval/**`. No
docker builds; host tests only, with the brief's
`TEST_DATABASE_URL`/`TEST_REDIS_URL`.

## Status table

| Item | Status | One-line evidence |
|---|---|---|
| 1 server: template sends through the existing path | **FIXED** | render+send 202 with rendered subject/html/text persisted; unknown/cross-tenant 404; missing variable 422; batch partial; idempotent replay byte-identical |
| 2 tests (fail-before, no silent deletion) | **FIXED** | 4 new tests fail 4/4 on the old behaviour (422 "not implemented"); 97/97 `routes::messages` tests green now; old rejection tests replaced (diff below) |
| 3 SDKs re-add `template_id`/`template_data` | **FIXED** | Go `ok`, Python `87 passed`, PHP `48 tests / 112 assertions OK`, Java surefire 0 failures, Ruby `89 checks passed` |
| 4 docs accurate + SDK READMEs | **FIXED** | `variables`→`template_data`, fictional Handlebars blocks removed, fake batch `defaults`/response shapes corrected, object-form address examples fixed |

---

## Item 1 · Server: `POST /v1/messages` + `/batch` accept `template_id`/`template_data` — FIXED

The documented contract in `docs/api/endpoints/messages.md` is now true: the
`template_id` 422 (`"template-based sending is not implemented"`) is gone and
template sends run through the EXISTING send path (consent gate, suppression,
domain readiness, quota, idempotency ledger, queue).

**Where** (`services/mail-server/crates/api-server/src/routes/messages.rs`):

- `resolve_template_send` (line ~1110) loads the tenant-scoped template from
  the canonical `templates` table and renders subject/html/text through the
  shared `template_renderer::renderer::TemplateRenderer` — the SAME crate and
  pipeline the template-renderer service and `POST /v1/templates/:id/render`
  use; no second renderer was written. The load query is the renderer's own
  `WHERE id = $1 AND tenant_id = $2`, so another tenant's template is
  indistinguishable from a missing one → `404 NOT_FOUND`
  (`"template not found: <id>"`).
- Missing variables: the renderer reports every unresolved merge field; the
  send path refuses the request with 422 naming EACH missing variable
  (`"template variable 'name' is missing from template_data"`) before
  anything is rendered into a message or queued — no partial render. Renderer
  failures (syntax/size/timeout) are named 422 refusals; only store failures
  are 500s.
- Precedence: the stored template supplies subject/html/text; an explicit
  request `subject`/`html`/`text` overrides the corresponding rendered field
  (the overriding subject is still merge-resolved and header-hardened by the
  renderer; `html`/`text` overrides are literal content). The docs were
  silent on the override case, so this rule was implemented AND written into
  `docs/api/endpoints/messages.md` in this change.
- Flow: single send resolves the template AFTER the idempotency-ledger
  replay checks (a retry replays the stored response even if the template was
  changed or deleted since) and BEFORE `tx.begin()`/quota — a refusal writes
  nothing and consumes no quota. Batch resolves per item BEFORE that item's
  quota reservation; an unusable template rejects only its item, preserving
  partial semantics.
- `SendMessageRequest` gained `Clone` and `subject` became
  `#[serde(default)]` (a template may supply it, so the wire may omit it).
  Requests without a template BORROW the parsed body unchanged
  (`Cow::Borrowed`) — the transactional path is byte-identical: same
  validation errors, same idempotency hash (still computed over the original
  request), same inserted bytes.
- `validate_send` only relaxes the "subject/html-or-text required" gates when
  a real `template_id` is present; the FINAL rendered content is validated
  against the same invariants (non-empty subject, ≤998 chars, no CRLF,
  non-empty body) before the insert.
- `validate_send_options` now checks the new pair's shape instead of
  rejecting it: `template_data` must be a JSON object, and
  `template_data` without `template_id` is a named 422. An empty/whitespace
  `template_id` is treated as absent, matching the existing blank-field
  convention (e.g. `reply_to`), so those requests keep their old behaviour.

### Before (reproduced)

Command (in a clean worktree at the base revision, with only the new tests
applied; see "Verification method" in Notes):

```
$ cd services/mail-server && TEST_DATABASE_URL=… TEST_REDIS_URL=… \
    cargo test -p api-server --lib template_send -- --nocapture
…
thread '…template_send_renders_persists_and_replays_idempotently' panicked:
  left: 422  right: 202
  body: {"error":{"details":["field 'template_id' is not supported by this
    endpoint: template-based sending is not implemented; …"]}}
thread '…template_send_refusals_leave_nothing_queued' panicked:
  left: 422  right: 404
thread '…batch_template_send_keeps_partial_semantics' panicked:
  left: Number(0)  right: 1   (accepted=0, both items rejected)
thread '…template_send_options_are_accepted_and_shape_violations_named' panicked:
  a template send must pass option validation
test result: FAILED. 0 passed; 4 failed; 0 ignored
```

Full red output: `/tmp/fail-before-template-send.txt` (captured during this
session).

### After (working tree, in place)

```
$ cd services/mail-server && TEST_DATABASE_URL=… TEST_REDIS_URL=… \
    cargo test -p api-server --lib routes::messages
test result: ok. 97 passed; 0 failed; 0 ignored; 1977 filtered out

$ cargo test -p api-server --lib template_send
test …::template_send_options_are_accepted_and_shape_violations_named ... ok
test …::template_send_refusals_leave_nothing_queued ... ok
test …::batch_template_send_keeps_partial_semantics ... ok
test …::template_send_renders_persists_and_replays_idempotently ... ok
test result: ok. 4 passed; 0 failed

$ cargo test -p api-server --lib missing_template_variables
test result: ok. 1 passed; 0 failed

$ cargo test -p api-server --lib send_endpoint_rejects_invalid_payloads_and_writes_nothing
test result: ok. 1 passed; 0 failed

$ cargo test -p api-server --lib validation_coverage_tests
test result: ok. 2 passed; 0 failed
```

---

## Item 2 · Tests — FIXED

**Added (all in `messages.rs`, all fail-before-verified above):**

| Test | Proves |
|---|---|
| `template_send_renders_persists_and_replays_idempotently` | 202; the message row AND every `email_queue` row carry the RENDERED subject/html/text (`Welcome Ada`, `<h1>Hello Ada</h1>`, `Hello Ada`) — never `{{ name }}`; same `Idempotency-Key` + payload → byte-identical response with no second message; explicit overrides win (`Override Grace`, `<p>override body</p>`) |
| `template_send_refusals_leave_nothing_queued` | unknown id → 404 "template not found"; ANOTHER tenant's id → 404; missing variable → 422 naming `template variable 'link' is missing from template_data`; `template_data` without id / non-object → 422; after every refusal `(messages, queued) == (0, 0)` |
| `batch_template_send_keeps_partial_semantics` | 200 with `accepted=1, rejected=1`; item 0 queued with rendered content, item 1 rejected with `template not found: …`; exactly one message + one queue row written |
| `template_send_options_are_accepted_and_shape_violations_named` | option validation accepts a template send and names the malformed `template_data` shapes |
| `missing_template_variables_are_extracted_from_renderer_warnings` | deduplicated variable extraction from the renderer's warning contract |

**Replacement of the old rejection tests (not a silent deletion).** From
`git show HEAD:…/messages.rs`:

```
3882:    fn template_id_is_rejected_naming_the_field() {
             body.template_id = Some("tmpl_123".into());
             assert!(errors.len() == 1 && errors[0].contains("'template_id'"), …)
3893:    fn template_data_is_rejected_naming_the_field() {
             body.template_data = Some(serde_json::json!({"x": 1}));
             assert!(errors.len() == 1 && errors[0].contains("'template_data'"), …)
…
5857:        cases.push((with(|v| v["template_id"] = serde_json::json!("tpl")),
                 StatusCode::UNPROCESSABLE_ENTITY, "template_id"));
```

Both unit tests are replaced by
`template_send_options_are_accepted_and_shape_violations_named`, whose first
assertion is the exact inverse (a template send must PASS option validation)
and whose remaining assertions cover the still-invalid shapes. The router
case is replaced by three cases: unknown template → `404` `"template not
found"`, `template_data` without `template_id` → `422` `"requires
'template_id'"`, list `template_data` → `422` `"must be a JSON object"` (see
the diff of `send_endpoint_rejects_invalid_payloads_and_writes_nothing`).
The old test NAME is gone on purpose — `cargo test --lib template_id` now
matches 0 tests, and the red run above shows the replacement failing against
the old behaviour before the fix.

---

## Item 3 · SDKs — FIXED

Every SDK serializes `template_id`/`template_data` on send/batch again (the
`server 422s them` reason is gone), accepts a template-only request
(subject/html/text optional when a template is present), and still refuses
the shapes the server refuses, client-side and named. Each SDK's contract
test follows its existing style.

| SDK | Source change | New/updated contract tests | Evidence |
|---|---|---|---|
| Go | `SendEmailRequest.subject` → `omitempty`; `TemplateID`/`TemplateData` now emitted by `MarshalJSON`; validation allows template-only sends; refuses `template_data` without id and non-object `template_data` (`isJSONObject`) | `TestSendTransmitsTemplateFieldsAndAllowsTemplateOnlyRequest` (replaces the GO-6 client-side rejection test; asserts the fields reach the wire, template-only sends omit subject/html, invalid shapes never reach the server); exact-shape test now requires `template_id`/`template_data`; live-contract section now refuses `template_data` without id | `go test ./...` → `ok`; the three touched tests `--- PASS` |
| Python | `build_send_payload` takes optional subject + template fields; sync/async `send` and batch validation allow template-only sends via `_validate_template_fields` | `TemplateSendContract` (4 tests): template-only send reaches the wire and omits subject/html/text; batch normalization; shape refusals never reach the wire | `PYTHONPATH=src pytest -q` → `87 passed` |
| PHP | `send()` validates the template pair, relaxes subject/body requirements with `template_id`; refuses `template_data` without id and list-shaped `template_data` | `testTemplateOnlySendSerializesTemplateFields`, `testTemplateShapeViolationsAreRefusedClientSide` | `vendor/bin/phpunit` → `OK (48 tests, 112 assertions)` |
| Java | `SendRequest.toMap` omits blank subject; `validateSendParams`/batch validation allow template-only sends; `isJsonObjectShaped` refuses non-object `template_data` | `templateOnlySendSerializesTemplateFieldsAndOmitsEmptyContent`, `templateShapeViolationsAreRefusedClientSide` | `mvn -q -B test` exit 0; surefire `EmailsSendRequestTest tests=4 errors=0 failures=0`, all suites 0 failures |
| Ruby | `send_email`/`build_send_payload` subject optional; validation allows template-only sends and names bad `template_data` | template-only + refusal blocks + batch forwarding in `test/payload_contract_test.rb` | `ruby test/payload_contract_test.rb` → `payload contract: 89 checks passed` |

Each SDK CHANGELOG gained an `Unreleased`/Added entry, and each README shows
a template-send example (Go's README no longer claims template sends are
unsupported).

---

## Item 4 · Docs — FIXED

`docs/api/endpoints/messages.md` drift fixed while implementing:

- `template_id`/`template_data` parameter rows now state the real semantics;
  `subject`/`html` marked optional with a template.
- The "Using Templates" example used the field name `"variables"` — the wire
  field is `template_data`; example fixed and `to` corrected to the array
  form the API accepts.
- "Template Syntax" claimed Handlebars with `{{#if}}`/`{{#each}}` blocks —
  the renderer only supports `{{ variable }}` / dotted / dashed substitution.
  Section rewritten to the implemented contract (HTML-escaping in bodies, no
  escaping in subject/plain text, missing variables refused).
- New precedence/refusal rules documented (request overrides; 404 unknown or
  cross-tenant; 422 missing variables with nothing queued; object-shaped
  `template_data`).
- Batch section was fictional: it documented an unsupported `defaults` field
  and `batchId/totalAccepted/messages/errors` response. It now matches the
  server (`{messages: […]}` in, `{accepted, rejected, results[]}` out, per-item
  ids omitted when rejected, partial-success example with a template error),
  and the batch-size claim (was "up to 1000", rate table 100/500/1000 by plan)
  now states the real server-side cap (`API_MESSAGES_MAX_BATCH_SIZE`, 100 by
  default, plan-independent).
- Error table: `VALIDATION_ERROR` documented as 400/422 (422 for send-option
  and template refusals); `NOT_FOUND` notes cross-tenant.
- Code examples: object-form addresses (`{"email": …}`) replaced with the
  accepted RFC 5322 string forms; a template-send cURL example added.
- Prose-lint parity: `tools/docs-lint.sh` per-file count for
  `docs/api/endpoints/messages.md` is unchanged from HEAD (13 isolated
  violations; the committed baseline row is 25 and the baseline run no longer
  lists this file as an overage — the one remaining overage is
  `docs/operations/monitoring.md`, edited by a sibling agent).

---

## Notes / decisions

- **Verification method.** Sibling agents were editing the shared working
  tree concurrently (mid-edit `analytics`/`enterprise`/`api-server` compile
  breakage appeared and disappeared during this pass), so the fail-before run
  was executed in a clean `git worktree` pinned at the base revision with
  only the new tests applied; the final green runs were then repeated IN
  PLACE on the actual working tree once it compiled again (97 + 4 + 1 + 1 + 2
  tests, all green). The temporary worktree contains no deliverable and was
  removed.
- **Renderer instance.** A `TemplateRenderer` is constructed per template
  resolution (cheap; the renderer's cache is per-instance). Storing a
  long-lived renderer in `AppState` would add cross-request render caching but
  was out of the brief's ownership; the render cache key is fully
  content-addressed, so this is a performance note, not a correctness gap.
- **No entitlement gate added.** Reading/rendering a template requires only
  the `templates:read` scope today; gating SENDS on `custom_templates` would
  be a new product restriction the brief did not ask for. Tenants without the
  entitlement cannot create templates, and any template they can name already
  exists in their tenant.
- **Snapshot semantics.** The rendered bytes are what is persisted; a
  template edited between render and dispatch does not change an accepted
  send. Idempotent replays are answered from the ledger before any template
  load, so replay works even if the template was deleted afterwards.
- **No commits were made** — the deliverable is the working tree, matching
  the sibling fix waves.
- **Full-suite context.** A full `cargo test -p api-server --lib` run taken
  while sibling agents were active ended `2071 passed; 5 failed`. None of
  the five failures touches `routes::messages` (retention, tracking_domains,
  two `web.rs` ATO tests, one `web.rs` draft-review test); all 97
  `routes::messages` tests plus both `validation_coverage_tests` passed in
  that same run. Re-running the five: the first three pass in isolation; the
  two `web.rs` re-runs were blocked by a transient `ui-foundation` compile
  error from a sibling's in-flight edit, and `web.rs` is explicitly outside
  this brief's ownership.
