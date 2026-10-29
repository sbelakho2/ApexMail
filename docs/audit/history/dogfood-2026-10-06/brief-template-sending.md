# Brief — IMPLEMENT template-based sending (server + SDKs)

Repo root: /Users/sabelakhoua/IdeaProjects/ApexMail. Owner directive: no
"not implemented" end states — and `docs/api/endpoints/messages.md`
DOCUMENTS `template_id` as a send field (with examples) while
`POST /v1/messages` 422s it as "template-based sending is not implemented".
Make the documented contract true.

## Ground truth to read
- `crates/api-server/src/routes/messages.rs:215-217` (fields exist),
  `:828-850` (the `unsupported_template_fields` rejection to REMOVE).
- `crates/api-server/src/routes/templates.rs` (template CRUD +
  `custom_templates` entitlement; the template row shape: subject/html/text +
  variables).
- `crates/template-renderer/**` (the renderer crate — use IT, do not write a
  second one; check its public API and how other callers use it).
- `docs/api/endpoints/messages.md` (the documented semantics: which fields the
  template supplies vs the request overrides; variable substitution rules).

## Implement
1. Server: `POST /v1/messages` and the batch endpoint accept `template_id` +
   `template_data` (variables): load the tenant-scoped template (404/named
   refusal when absent or another tenant's), render subject/html/text through
   the renderer, apply documented precedence (request fields override
   template? — follow the docs; if the docs are silent on a case, implement
   the sane rule and update the docs in the same change), then flow through
   the EXISTING send path (consent gate, quota, idempotency, queue).
   Missing template variables → a named validation refusal (no partial
   render, nothing queued). Keep the transactional path byte-identical for
   requests without templates.
2. Tests: render+send persists the RENDERED subject/html (not the raw
   template), variables substituted; unknown/cross-tenant template refused
   with nothing queued; missing variable refused; batch partial semantics
   preserved; idempotency replay returns the same message; the previously
   red path (template_id 422) now passes — prove the old rejection test is
   replaced, not deleted silently.
3. SDKs (`packages/sdk-{go,php,python,java,ruby}/**`): re-add `template_id`/
   `template_data` to the send method(s) (the earlier pass removed them
   because the server 422d — that reason is gone), with contract tests
   mirroring each SDK's existing test style. Note in each CHANGELOG.
4. Docs: `docs/api/endpoints/messages.md` stays accurate (fix any drift you
   find while implementing); SDK READMEs mention template sends.

## Rules
- Every claim needs a can-fail test/proof (command + output).
- Own: `routes/messages.rs` (the template arms), your test files,
  `packages/sdk-*/**`, `docs/api/endpoints/messages.md`, SDK READMEs. Do NOT
  touch `ai_chat.rs`, `web.rs` assistant functions, `reply_handler/**`,
  `ai-service/**`, `billing-entitlements/**`, plan seeds, `docs/eval/**`.
- No docker builds. Host tests with:
  TEST_DATABASE_URL=postgresql://apexmail:bebc8cefdc096e5247f8864e5c0edf78099df23058133321@127.0.0.1:5432/apexmail
  TEST_REDIS_URL=redis://:dev-redis-password-minimum-32-chars@127.0.0.1:16379/0
- Report: `docs/audit/dogfood-2026-10-06/fix-report-template-sending.md`.
