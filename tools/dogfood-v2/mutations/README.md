# dogfood-v2 mutation patch set

The `--mutation-test` mode proves the harness can catch defects by seeding
known defects into a **scratch copy** of the product and requiring every one
to be caught.

## How a run is wired

1. `harness/mutation.py` maintains a scratch copy of the product (default
   `/Users/…/ApexMail-scratch-v2`, created on first use as an rsync snapshot
   of the **working tree** — the state the deployed stack is built from,
   including uncommitted product changes; seeding against `git worktree`/HEAD
   would mutate a *different* product, e.g. HEAD lacks the `mfa-verify`
   captcha scope the live server accepts). The LIVE tree is never edited.
2. It builds the **clean control** (`cargo build -p api-server`, incremental
   via `CARGO_TARGET_DIR=<main tree>/services/mail-server/target`), starts it
   on `127.0.0.1:18080` with the live api-server's own environment plus two
   overrides — the private port and the dedicated **test Redis (16379)** — and
   runs the union of every mutation's targeted probes. Those runs are the
   attribution baseline.
3. For each mutation: `git apply <patch>` in the scratch copy → incremental
   rebuild → restart the mutant → run that mutation's probes → reverse-apply
   the patch (with a copy-back-from-the-main-tree fallback) and verify every
   touched file is byte-identical again.
4. A mutation is **CAUGHT** only when a targeted probe fails in the mutant
   run with a failing CHECK that did not fail in the clean control run — a
   check that is already red clean can never be credited with catching a
   mutation (that would be "the harness happened to be red", not detection).
5. The **mutation→partition gate** (`harness/mutation.py::partition_proof`)
   then fails the battery (non-zero) when any probe-bearing partition has no
   CAUGHT mutation among its catching probes. Evidence is a caught probe,
   never the mutation's family label: the label is validated to name a
   partition, but only `catching_probes` credit one. `--mutation-only`
   (partial runs) skips the gate; full batteries enforce it.
6. `--mutation-test` exits non-zero if any mutation is MISSED or the
   partition gate is unproven. The full per-mutation attribution lands in
   `out/mutation-report.json` and `out/mutation-findings.json`;
   `--mutation-only <id>` re-runs a single mutation.
7. Both product binaries under test are rebuilt from the scratch copy and
   run natively: `api-server` on `127.0.0.1:18080` and `tracking-service` on
   `127.0.0.1:18081` (the tracking probes aim at the native mutant, so a
   tracking-service patch is actually exercised). The native mutants talk to
   the dedicated test Redis (16379) and the compose Postgres; the DB
   endpoint can be moved with `DOGFOOD_V2_DB_HOST`/`DOGFOOD_V2_DB_PORT`
   (a host where 5432 is taken).

## Safety rails

- Patches may only touch `services/mail-server/**`; the loader refuses any
  patch whose paths fall outside that prefix or contain `kiwicaptcha` or
  `packages/` (KiwiCaptcha stays a black box; the product's PHP/JS packages
  are never seeded).
- Mutants use the test Redis and a private port, so the shared live stack's
  limiter/session state is never disturbed; the only shared resource is
  Postgres, where every probe works on uniquely-named disposable fixtures.
- The scratch copy is reverted after every mutation and re-verified in a
  `finally` block; a file that cannot be restored aborts the run.
- The set is reversible by construction: deleting the scratch directory and
  the patch files leaves the repository byte-identical (it was never
  written).

## Families covered

Every probe-bearing partition has at least one seeded defect whose targeted
probe(s) must trip it (the partition gate enforces the caught version of
this); `p.<partition>.*` names the probe that is expected to catch it.

| family | mutation | defect | catching probe(s) |
|---|---|---|---|
| surface | M11 SSR route dropped | ledger-enumerated public SSR page (/compliance) answers 404 | `p.surface.ssr_reach` |
| auth | M12 CSRF guard dropped | cookie-session writes without the CSRF header are admitted | `p.auth.csrf_contract` |
| authz | M01 tenant scoping dropped (IDOR read) | cross-tenant contact read | `p.authz.cross_tenant_idor` |
| authz | M02 scope guard no-op | every tenant role/write scope admitted | `p.auth.api_key_lifecycle`, `p.authz.role_matrix` |
| console | M13 SSR contacts scope dropped | /contacts scopes to the system tenant; new contacts vanish | `p.console.crud_roundtrip` |
| cp | M14 CP session + tenant gates no-op | customer sessions reach /v1/admin/* | `p.cp.json_admin` |
| marketing | M15 /dpa route dropped | linked marketing page answers 404 | `p.marketing.content` |
| money | M16 catalog price zeroed | /v1/billing/plans reports priceMonthly=0 | `p.money.plan_catalog` |
| mail | M17 template refusal dropped | unresolved {{variables}} accepted instead of 422 | `p.mail.template_send` |
| tracking | M18 unknown token → 503 | invalid tracking tokens 5xx | `p.tracking.route_contract` |
| bots | M19 /api-console route dropped | the advertised capability page answers 404 | `p.bots.capability_pages` |
| hostile | M05 HTML escaping dropped | stored/served HTML escapes nothing | `p.hostile.xss_stored`, `p.hostile.xss_reflected` |
| hostile | M06 CRLF subject guard dropped | header injection admitted | `p.hostile.crlf_injection` |
| state | M04 verification token replay | single-use email-verification token replayed | `p.auth.signup_verification` |
| resource | M07 login rate bound dropped | no 429 from the public auth limiter | `p.resource.login_rate_bound` |
| errors | M03 edit-after-send returns 200 | false success on a refused transition | `p.state.out_of_order` |
| errors | M10 empty/invalid required email accepted | required-field validation skipped | `p.errors.taxonomy` |
| infra | M20 /health/deep route dropped | the deep health contract answers 404 | `p.infra.health` |
| pipeline | M21 /v1/events route dropped | the delivery-event API answers 404 after a real campaign delivery | `p.pipeline.events_consistency` |
| invariants | M22 contact tenant scope dropped | fixture contact rows lose their tenant scope | `p.inv.fixture_scoping` |
| pipeline | M08 enqueue dropped (jobs lost) | accepted sends never reach the worker/Mailpit | `p.mail.send_to_mailpit`, `p.pipeline.worker_liveness` |
| invariants | M09 suppression gate dropped | sends to suppressed recipients accepted | `p.mail.suppression_consent` |

Patches are generated from and apply to `base_commit` in `manifest.json`.
