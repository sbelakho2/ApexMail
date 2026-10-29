# Adversarial file-by-file review — frontend + gateways slice

You are auditing the ApexMail repo FILE BY FILE, adversarially. Work from the working tree at
/Users/sabelakhoua/IdeaProjects/ApexMail (branch main, dirty tree — that is expected).

## Your slice (every file, none skipped)
1. `crates/ui-foundation/` (all .rs + assets/*.css) — services/mail-server/crates/ui-foundation
2. `crates/api-server/src/routes/web.rs`, `routes/web/`, `routes/demos/`, `routes/assistant*`,
   `routes/admin/`, `routes/kiwicaptcha.rs`, `routes/csrf.rs`, `routes/explorer/`
3. `tests/browser/` (all files)
4. `apps/ai/` (all files)

## Bar each file must clear (report a finding when it does not)
- **Correctness**: logic that cannot do what its name/docs claim; off-by-one; inverted conditions;
  dead branches; unwrap/expect on a fallible path in a request handler; TODO/FIXME/stub/placeholder
  or `todo!()`/`unimplemented!()` left in shipped code.
- **Honesty (audit #16)**: a storage/upstream failure rendered as an empty/zero value; a metric or
  log claiming success the code cannot know; docs/comments describing behavior the code lacks
  (or vice versa); a test asserting an unrepresentative fixture.
- **Security**: missing tenant scoping on a query (`tenant_id` absent where rows are per-tenant);
  missing CSRF on a state-changing browser POST; missing auth/role check; unescaped user input in
  HTML (XSS) or in SQL; open redirect; secret/PII written to logs; fail-open on an auth check.
- **Wiring**: a handler registered but never mounted; a route mounted but no handler; a form action
  that no route serves; a class/handler referenced but undefined; env var read that nothing sets or
  set that nothing reads (check `docker-compose.yml` + `ci/` too when the file reads env).
- **Quality**: duplicated logic that already drifted; a function that silently ignores an error
  (`let _ =` on a Result whose failure matters); a comment that contradicts the code.

## Deliverable
Write findings to `docs/audit/dogfood-2026-10-06/findings-frontend-and-gateways.md`, one entry per
finding:
```
### <severity: P0|P1|P2|P3> <file>:<line> — <one-line title>
Evidence: <the exact code/datum that proves it, quoted>
Why it is a defect: <one or two sentences>
Suggested fix: <minimal, concrete>
```
Severity: P0 = security/data-loss/user-blocking; P1 = wrong behavior users hit; P2 = wiring/honesty
gap or dead code shipping; P3 = polish.

Rules:
- Read EVERY file in your slice. Track progress: append `- [x] <path>` lines to
  `docs/audit/dogfood-2026-10-06/progress-frontend-and-gateways.md` as you go (batch them, but do
  not skip a file).
- Report only defects you can prove from the file contents; no speculation, no style nits.
- Do NOT edit code — this slice reports only. (A later wave fixes.)
- If a file is clean, say so in the progress file with `- [x] <path> (clean)`.
- Keep going until your slice is exhausted; work in batches and write intermediate progress so a
  stopped run is still useful.
