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
5. `--mutation-test` exits non-zero if any mutation is MISSED. The full
   per-mutation attribution lands in `out/mutation-report.json` and
   `out/mutation-findings.json`; `--mutation-only <id>` re-runs a single
   mutation.

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

| family | mutation | catching probe(s) |
|---|---|---|
| authz | M01 tenant scoping dropped (IDOR read) | `p.authz.cross_tenant_idor` |
| authz | M02 scope guard no-op | `p.authz.role_matrix`, `p.auth.api_key_lifecycle` |
| hostile | M05 HTML escaping dropped | `p.hostile.xss_stored`, `p.hostile.xss_reflected` |
| hostile | M06 CRLF subject guard dropped | `p.hostile.crlf_injection` |
| state | M04 verification token replay | `p.auth.signup_verification` |
| resource | M07 login rate bound dropped | `p.resource.login_rate_bound` |
| errors | M03 edit-after-send returns 200 | `p.state.out_of_order` |
| errors | M10 empty/invalid required email accepted | `p.errors.taxonomy` |
| pipeline | M08 enqueue dropped (jobs lost) | `p.mail.send_to_mailpit`, `p.pipeline.worker_liveness` |
| invariants | M09 suppression gate dropped | `p.mail.suppression_consent` |

Patches are generated from and apply to `base_commit` in `manifest.json`.
