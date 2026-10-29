# Lane R1 — customer console + control plane Rust (verify-and-fix every finding)

You are an extremely rigorous verifier-fixer. **ZERO SKIPS**: every finding below is adjudicated with
literal command/output evidence. A fix counts only if the CURRENT tree shows it. Read
`docs/audit/ui-external-review-2026-10-08/review.md` (the full external review) and
`docs/audit/ui-external-review-2026-10-08/register.md` (rules, ownership, verdict schema) FIRST.

## Your scope

`crates/api-server/src/routes/web.rs`, `crates/api-server/src/routes/web/data.rs`,
`crates/ui-foundation/src/leptos_views.rs`, `crates/ui-foundation/src/view_data.rs`.
Findings: review §3 P1-1,2,4,5,6,7 + P2-1; §4.1-4.5, 4.11; §5.1 rows for leptos_views,
view_data.rs, data.rs, ssr.rs; §6 (ALL auth/campaigns/contacts/templates/analytics/domains/
assistant/settings pages); §7 (ALL control-plane pages).

**Do NOT edit** any other file. If a fix needs `shell.rs`, `primitives.rs`, CSS, a test file, or a
gate, state the exact required change in your report for lane R2/R5 to implement.

## Known-already-fixed items (verify, do not re-fix blindly)

- P1-4 nested bulk/row forms: recon says row-delete forms are siblings wired with `form=`
  (leptos_views ~1040-1080). VERIFY it holds for EVERY populated bulk table (contacts, campaigns,
  audit, suppressions…) and with populated fixtures; report any remaining nesting.
- P1-7 partially: template editor loads stored values and blank body keeps stored content (recent
  wave). VERIFY: editor prefill, blank-subject/body semantics on BOTH create and update, redirect
  target is the editor/detail route that actually exists, and the round trip end-to-end (render →
  POST → redirect → GET).
- Campaign editor already posts `/web/campaigns/update` with a hidden id (recent wave). Verify the
  full identity-preserving E2E and the audit's related sub-findings (Draft badge honesty, native
  field types, scheduling consent copy 4.11).

## Environment

Live stack running (docker context `colima-local`): api-server `http://127.0.0.1:8080`; web console
= default Host, control plane = `-H 'Host: admin.localhost'`. Logins/recipes:
`docs/audit/dogfood-2026-10-06/dogfood-live-console.md` §1 + §10 (login limiter) and
`dogfood-live-control-plane.md`. Postgres `127.0.0.1:5432` user `apexmail`, password per
`secrets/postgres_password.txt`. Test env for cargo:
`TEST_DATABASE_URL=postgres://apexmail:<pw>@127.0.0.1:5432/apexmail`,
`TEST_DATABASE_ADMIN_URL=…:5432/postgres`, `TEST_REDIS_URL=redis://:dev-redis-password-minimum-32-chars@127.0.0.1:16379/0`,
`SALES_TEST_DATABASE_URL`/`ENTERPRISE_TEST_DATABASE_URL` = the same. Run tests with
`cargo nextest run -p api-server --lib -E 'test(...)'`; after changes also
`cargo nextest run -p ui-foundation` (goldens live there — if a golden changes because YOUR page
change is correct, update the golden deliberately and say so; goldens are in
`crates/ui-foundation/goldens/**` and the manifest `docs/development/ui-baseline-manifest.json`).

Rebuild for live verification: `docker compose build api-server && docker compose up -d api-server`
(context colima-local).

## Method per finding

1. Locate the CURRENT code (audit line numbers are stale).
2. Capture fail-before evidence (live HTTP probe and/or a unit test that fails on the current code).
3. Fix properly: shared builders, one composition model (review §4.1): page identity + description +
   primary action + metrics + filters + data + pagination; forms keep their action forms when the
   data-backed table replaces a handwritten body. Retained form state must be scoped to the correct
   form (§4.10 — coordinate: retention machinery lives in R2's files; for your pages prove the
   rendered association is right and file the mechanism bug to your report).
4. Copy pass (§4.2/§4.3/§4.5): implementation-exposing copy ("Nothing has been fabricated", "No
   scripts", "store did not answer", raw API paths in disabled controls) → user-centered wording
   with honest state language (first-use / no-match / unavailable / restricted / running / failed /
   stale). This is GLOBAL: prefer shared helpers/constants over per-page strings; do not introduce
   new long engineering explanations.
5. Add/adjust tests pinning the new behaviour (api-server lib tests + goldens).
6. Fail-after evidence: rerun the probe + tests, capture literal output.

## Deliverable

`docs/audit/ui-external-review-2026-10-08/lane-r1-console.md`:
- Verdict table for EVERY finding listed above (id | what | verdict | evidence pointer | fix).
- Zero-skips appendix: literal command + output per finding group.
- "Reported for other lanes" section: exact required changes for R2/R5 files.
- Final paragraph for the orchestrator: counts + anything left failing with its exact error.
