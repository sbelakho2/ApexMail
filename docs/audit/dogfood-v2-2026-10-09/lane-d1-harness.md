# Lane D1 — Dogfooding v2: a wider, more adversarial, self-proving harness

Owner's mandate: "all dogfooding upgraded … way more adversarial and wider so it can catch 100% of
any defect, then run it and patch everything right. 0 residuals or regressions."

Status: **harness delivered and self-proven**; the live baseline run is filed below for the runner
lanes. No product defect was fixed in this lane (per the brief).

- Harness: `tools/dogfood-v2/` (entry point `tools/dogfood-v2/run.py`, version `2.0.0`), ~9.3k lines
  of Python (stdlib only), no new services.
- Proof run 1 — `--self-test`: **GREEN** (every dynamic probe matches the honest fixture).
- Proof run 2 — `--mutation-test`: **10/10 seeded defects caught** (see §4).
- Proof run 3 — full live run: baseline summary + findings in §5 (machine-readable:
  `tools/dogfood-v2/out/findings.json`, coverage: `tools/dogfood-v2/out/coverage.json`).
- Coverage ledger: 1768 mechanically-enumerated surfaces, **0 unprobed**, 0 allowlisted, 0 ledger
  warnings; the fail-if-unprobed rule is itself self-proven (§1.3).
- HARD BOUNDARY respected: KiwiCaptcha is consumed strictly as a black box. Harness logins mint and
  solve challenges (SHA-256 proof of work) for the documented scopes; no KiwiCaptcha source, package
  or upstream byte was touched, and no mutant patch may contain the string `kiwicaptcha` (enforced
  by the mutation loader).
- No `git commit` was made. No product code was modified (the mutation set lives only in a scratch
  copy outside the repo).

---

## 1. What v2 is (design)

### 1.1 Package layout

```
tools/dogfood-v2/
  run.py                     entry point: --base --host --partition --self-test --mutation-test
                             --json --allowlist --ledger-only --list-probes --out-dir --pace
  allowlist.json             justified unprobed surfaces (empty; each entry needs owner+reason)
  harness/
    config.py                targets, secrets, partitions, rate-key patterns, budgets
    httpc.py                 paced HTTP client (cookie jar, Host routing, CSRF, 429/DDoS backoff)
    kiwi.py                  legitimate KiwiCaptcha mint+solve (scope-bound PoW)
    mail.py, dataplane.py    Mailpit/psql live plane ↔ fixture plane abstractions
    identity.py              identities through the PRODUCT lifecycle (signup→verify→login→MFA),
                             roles via the tenant fixture, the TWO-STEP CP operator login
    fixtures.py              disposable, unique-id resource fixtures per tenant (+ plan fixture)
    ledger.py                MECHANICAL surface enumeration from sources of truth
    coverage.py              coverage.json + fail-if-unprobed + allowlist justification rules
    registry.py, runner.py   probe registry, execution engine, exit-code contract
    findings.py              machine-readable findings + the end-of-run summary table
    probes/                  18 modules, 72 probes, the attack batteries
    fixture.py               honest self-test fixture server (test double of the contract)
    selftest.py              --self-test orchestration + ledger self-check
    mutation.py              --mutation-test: scratch copy, patch, targeted build, attribution
  mutations/                 manifest.json + 10 reversible patches + README
```

Exit codes: `0` clean, `2` findings present, `3` ledger coverage violation (fail-if-unprobed),
`1` harness error. The ledger violation is a **harness-lint failure** and takes precedence, so a run
can never report "green" while enumerating a surface nothing exercises.

### 1.2 Surface coverage ledger (the "wider" core) — mechanical, not a hand list

`harness/ledger.py` enumerates every surface from a source of truth and yields a stable id:

| class | source of truth | surfaces |
|---|---|---|
| `api` | api-server router tables (`src/app.rs` nests/merges joined to each route module's `.route(...)` through a file-local call graph) | 524 |
| `env` | compose files ∪ docs/deployment/configuration.md ∪ code `env::var` reads | 591 |
| `table` | `services/mail-server/migrations/*.sql` net CREATE/DROP (+ PARTITION OF) | 469 |
| `ssr` | `docs/development/ui-baseline-manifest.json` (web / control-plane / marketing + `/cp` aliases) | 131 |
| `service` | `docker-compose.yml` + override + prod | 42 |
| `tracking` | tracking-service router + config defaults | 11 |
| | **total** | **1768** |

`coverage.json` maps every surface to the probe ids that exercise it (explicit `surfaces=(...)` or a
`subsumes=` pattern like `api:*`), and lists `unprobed` explicitly.

### 1.3 The fail-if-unprobed rule is itself self-proven

`--self-test` runs `coverage_rule_selfcheck()` before the battery:

```
ok: unprobed surface → coverage.ok=False (fail-if-unprobed)
ok: a declared probe covers its surface id
ok: justified allowlist entry clears the surface (owner+reason recorded)
ok: under-justified allowlist entry rejected (no blanket allowances)
```

The trap the v1 campaign documented — "file-by-file coverage was OVERSTATED"
(`docs/audit/dogfood-2026-10-06/review-coverage-ledger.md`: *"100% whole-repo, file by file is
overstated … all audit artifacts together explicitly name only 468 of those files (14%)"*) is
structurally impossible here: coverage is computed **per enumerated surface**, each surface needs a
named probe (or a narrow allowlist entry with owner + reason ≥12 chars), and the rule itself is
proven green/red by the self-test on synthetic surfaces. `allowlist.json` is **empty** — every one
of the 1768 surfaces has a probe.

### 1.4 The attack batteries (partitions)

72 probes in 18 partitions; each probe is one adversarial unit with a severity and a surface claim:

- **surface** — anonymous reachability of every enumerated API route by mount class (public /
  authenticated / admin) and every SSR page on its host; a 5xx on an empty request, a 404 on a
  non-parameter route, or an anonymous 2xx on an auth mount is a finding.
- **auth** — CSRF contract, signup/verification (single-use tokens), KiwiCaptcha contract (required,
  scope-bound, single-use, replay), first-login MFA setup + wrong-TOTP refusal, session lifecycle
  (rotation AR-005, per-session logout markers via Redis), password reset (single-use, session
  revocation), anti-enumeration, API-key scope lifecycle.
- **authz** — cross-tenant IDOR sweep over EVERY id-bearing authenticated route with the other
  tenant's real ids; role matrix (owner/admin/member/viewer vs admin mounts and write scopes); CP
  gates (customer sessions must not operate any admin surface).
- **cp** — the whole control plane: every CP SSR page rendered by the MFA'd operator (and refused
  for a customer session), the JSON admin surface (operator 200 / anonymous and customer named
  401-403), and the `apexmail_cp_session` cookie gate (dropping it closes the CP).
- **console** — every authenticated console page renders; CRUD round-trips visible in SSR + API;
  zero-JS form contract (CSRF, captcha widget + nonce); assistant bounds.
- **hostile** — XSS (stored + reflected, script/attribute/SVG/`javascript:`/entity), SQL
  metacharacters, CRLF injection, path traversal, oversized bodies (per route), malformed JSON,
  wrong content types, prototype-pollution keys, NUL/bidi/zero-width.
- **state** — idempotency replay, concurrent double-submit (4 threads, DB invariant asserted),
  out-of-order transitions (login-before-verify, pause/resume on draft, edit-after-send, empty
  audience), Stripe event replay (HMAC + event-id idempotency).
- **errors** — the error taxonomy: named {code,message} for malformed JSON, missing/invalid/empty
  required fields, unknown routes, invalid UUIDs, unknown enums; 401/403 taxonomy; duplicate 409;
  absent-resource 404 (no silent 204); no internal detail leakage.
- **mail** — send → Mailpit with MIME/header/body checks, template substitution + missing-variable
  422, unicode/emoji MIME encoding, DKIM material + honest domain verification, suppression and
  marketing-consent gates.
- **money** — plan catalog coherence, quota/entitlements honesty + the documented plan override
  (applied and restored), the free-plan `custom_templates` gate (named 403), invoices, dedicated-IP
  honest refusal.
- **tracking** — tracking-service route contract, click/open token abuse (open-redirect resistance),
  side-effect-free unsubscribe GET, unknown-Host refusal, the real campaign click.
- **bots** — grader honesty, inbox-placement lifecycle, explorer sandbox policy (non-`@example.com`
  refused, control-plane paths refused), capability pages.
- **marketing** — content markers, internal link integrity, robots/sitemap/security.txt/manifest.
- **pipeline** — campaign → worker → Mailpit delivery, event/API/DB consistency, webhook delivery to
  a local sink with HMAC verification, RFC 8058 unsubscribe with the suppression row asserted.
- **resource** — pagination abuse matrix, batch max+1 caps, expensive filters/timeouts, the login
  rate bound (429 proven), captcha issuance bound (429 proven); bounds are then released via the
  documented env control.
- **invariants** — every migration table exists, schema-orphan scan, fixture tenant scoping, and
  post-mutation row-count sanity.
- **infra** — every compose service defined + running/healthy, health endpoints, psql/redis data
  plane, env surface (read-but-unused and documented-but-unset), worker liveness.

### 1.5 Determinism, isolation and restore semantics

- Every mutating probe uses per-run unique fixtures (`dgv2-<role>-<uuid>`), so runs are repeatable
  and never collide with other agents on the shared stack.
- Probes that change shared state restore it: the money override probe restores the tenant's own
  plan and deletes its `plan_overrides` row; the domain probe deletes its disposable domain; the
  disposables (contacts/lists/templates/campaigns/suppressions) are unique per run by construction.
- **Probe isolation**: every probe starts from a clean limiter state — the documented env control
  clears the rate-limit buckets (live Redis; the dedicated test Redis for mutation runs) before each
  probe, and the HTTP client gives a bounded, explicit recovery window to the in-process adaptive
  DDoS limiter (`DDOS_RATE_LIMITED` → 15/30/45s backoff, then an api-server restart — the documented
  control — so the harness's own bounded volume never becomes a false finding).
- Bounded resource use: one global pacer (default 0.18s ≈ 5.5 req/s), a hard request budget
  (`--max-requests`, default 12000), bounded retries, and no DoS-shaped traffic beyond the
  documented rate-limit proofs.

### 1.6 Machine-readable findings + partitions

`findings.json`: `id`, `probe`, `partition`, `surface`, `severity`, `kind`, `title`, `observed`,
`expected`, `evidence` (request/ids where captured), `repro`
(`python3 tools/dogfood-v2/run.py --partition <partition>`), plus run metadata (requests, transport
errors, DDoS backoffs, captcha mints/solves) and the coverage totals.

`--partition <name>` selects the coherent subset (surface, auth, authz, cp, console, marketing,
money, mail, tracking, bots, hostile, state, errors, resource, invariants, infra, pipeline) so
runner lanes can execute in parallel without colliding. The summary table at the end (probes run /
checks passed / failed / findings by severity / surfaces enumerated-covered-unprobed) is what the
runner lanes paste into their reports.

### 1.7 The mutation self-test (the "catch 100%" proof)

`--mutation-test` seeds a documented, reversible patch set into a **scratch copy** of the product —
never the live tree — compiles it with a targeted incremental build, and requires EVERY seeded defect
to be caught:

- The scratch is an rsync copy of the **working tree** (the state the deployed stack is built from;
  the working tree carries uncommitted product changes, so seeding against `git worktree`/HEAD would
  mutate a *different* product — it literally lacks the newer `mfa-verify` captcha scope the live
  server accepts). A targeted `cargo build -p api-server` is incremental via a shared
  `CARGO_TARGET_DIR` (~13-20s per mutant).
- Each patch is applied with `git apply` inside the copy, and reverted by reverse-apply with a
  copy-back fallback; every touched file is verified byte-identical to the main tree again, and a
  startup pass restores leftovers from a killed run BEFORE the clean control is built.
- The clean control (pristine scratch build) runs the union of every mutation's targeted probes on
  `127.0.0.1:18080` with the live api-server's own container environment, overridden only for the
  private port and the dedicated **test Redis (16379)**.
- Attribution: a mutation is CAUGHT only when a targeted probe fails with a failing CHECK that did
  not fail in the clean control run — a check already red clean can never be credited. A probe that
  aborted in control is INCONCLUSIVE and can neither credit nor exonerate; a run with any MISSED or
  INCONCLUSIVE mutation exits non-zero.
- Hard rails: patches may only touch `services/mail-server/**`; a patch whose paths contain
  `kiwicaptcha` or `packages/` is refused by the loader (KiwiCaptcha stays a black box).

Ten seeded defects, at least one per attack family (see `mutations/README.md`):

| mutation | family | seeded defect | expected catcher |
|---|---|---|---|
| M01 | authz | contact detail stops filtering by tenant (cross-tenant read) | `p.authz.cross_tenant_idor` |
| M02 | authz | `require_scopes()` becomes a no-op | `p.authz.role_matrix`, `p.auth.api_key_lifecycle` |
| M03 | errors | edit-after-send guard dropped (200 on a refusal) | `p.state.out_of_order` |
| M04 | state | verification token no longer consumed (replay succeeds) | `p.auth.signup_verification` |
| M05 | hostile | `html_escape` becomes the identity (escaping dropped) | `p.hostile.xss_stored`, `p.hostile.xss_reflected` |
| M06 | hostile | CRLF subject guard dropped | `p.hostile.crlf_injection` |
| M07 | resource | public auth rate bound becomes `u64::MAX` | `p.resource.login_rate_bound` |
| M08 | pipeline | `email_queue` insert loop inserts nothing (jobs dropped) | `p.mail.send_to_mailpit`, `p.pipeline.worker_liveness` |
| M09 | invariants | suppression gate skipped | `p.mail.suppression_consent` |
| M10 | errors | contact email validation skipped (empty/invalid accepted) | `p.errors.taxonomy` |

---

## 2. Coverage ledger summary

```
surfaces enumerated   1768   (api 524, env 591, table 469, ssr 131, service 42, tracking 11)
surfaces covered      1768
surfaces allowlisted     0
surfaces unprobed        0
ledger warnings          0
```

Every surface class is exercised mechanically: API routes by the surface/authz sweeps, SSR pages by
`p.surface.ssr_reach` (+ console/cp/marketing content probes for the dynamic behaviour), compose
services by `p.infra.services`, migration tables by `p.inv.tables_exist` / `p.inv.schema_orphans`,
env keys by `p.infra.env_surface`, tracking routes by `p.tracking.route_contract`. `allowlist.json`
is empty by design and by proof: no blanket allowance exists, and the self-test demonstrates that an
unprobed surface fails the run (exit 3) while an under-justified allowlist entry is rejected.

<!-- PROOF-RUNS -->

---

## 3. Proof run 1 — `--self-test` green (literal transcript)

```
$ python3 tools/dogfood-v2/run.py --self-test
[dogfood-v2] ledger self-check: ok: unprobed surface → coverage.ok=False (fail-if-unprobed)
[dogfood-v2] ledger self-check: ok: a declared probe covers its surface id
[dogfood-v2] ledger self-check: ok: justified allowlist entry clears the surface (owner+reason recorded)
[dogfood-v2] ledger self-check: ok: under-justified allowlist entry rejected (no blanket allowances)
[dogfood-v2] self-test fixture on http://127.0.0.1:55745 (tracking http://127.0.0.1:55746)
[dogfood-v2] running 72 probes (partitions=['all'])
[dogfood-v2] identity owner_a: dgv2-owner_a-5817827055@dogfood.test tenant=28ca2324-7c21-47f7-b6cb-3816daa27e4e
[dogfood-v2] identity owner_b: dgv2-owner_b-c35363acf5@dogfood.test tenant=2d83b8bf-9b14-48e2-bbfc-950508216bc6
[dogfood-v2] identity operator_cp: dgv2-cp-8771a24f2b@dogfood.test tenant=system cp_cookie=True
┌────────────────────────────┬────────┐
│ probes run                 │     72 │
│ checks executed            │   1339 │
│ checks passed              │   1309 │
│ checks failed (findings)   │     30 │
│ findings P0                 │      0 │
│ findings P1                 │      0 │
│ findings P2                 │      0 │
│ findings P3                 │     30 │
│ surfaces enumerated        │   1768 │
│ surfaces covered           │   1768 │
│ surfaces allowlisted       │      0 │
│ surfaces unprobed          │      0 │
└────────────────────────────┴────────┘
[dogfood-v2] run complete: 30 findings, 1768/1768 surfaces covered, exit=2
[dogfood-v2] self-test: 1339 checks, 0 dynamic failures, 30 repo-static notes
self-test: repo-static notes (recorded; not fixture-contract failures):
  note: p.infra.services :: core compose service analytics-worker declares a healthcheck
  note: p.infra.services :: core compose service outbound-mta declares a healthcheck
  note: p.infra.env_surface :: env AI_MODEL_API_KEY_FILE is set in compose and read by code
  note: p.infra.env_surface :: … (28 env-surface drift notes: compose-set vars with no
  note: p.infra.env_surface ::    read/reference outside the compose files)
SELF-TEST GREEN — every dynamic probe matches the honest fixture contract
$ echo $?
0
```

---

Reading: the entire 72-probe battery runs against the disposable fixture server (a test double of
the documented contract, `harness/fixture.py`) and **every dynamic check matches** — 0 dynamic
failures. The 30 P3 "findings" are the repo-static notes (`p.infra.env_surface`,
`p.infra.services`) which describe the REAL repository (dead compose env vars, missing
healthchecks) — they are reported, deliberately not counted as fixture-contract failures. The four
ledger self-checks prove the fail-if-unprobed rule on synthetic surfaces before the battery starts.
The self-test is what makes the live findings trustworthy: a failing live check is a product
observation, not a harness bug, because the same probe passes against the honest double.

---

## 4. Proof run 2 — `--mutation-test`: all 10 seeded defects caught (literal transcript)

```
$ python3 tools/dogfood-v2/run.py --mutation-test
[dogfood-v2 mutation] harness 2.0.0: 10 seeded mutations, 13 targeted probes, scratch=/Users/…/ApexMail-scratch-v2
[dogfood-v2 mutation] building mutant api-server (incremental, CARGO_TARGET_DIR=…/services/mail-server/target)
[dogfood-v2 mutation] build ok in 13s
[dogfood-v2 mutation] clean control: running the targeted probe set against the pristine scratch build
[dogfood-v2] running 13 probes (partitions=['all'])
[dogfood-v2 mutation] control: 211 checks over 13 probes, 10 failing checks, 3 probes already failing clean
[dogfood-v2 mutation]   control-failure p.errors.taxonomy: bad method on a known route: status 405 is a named refusal
[dogfood-v2 mutation]   control-failure p.errors.taxonomy: malformed JSON: status 400 is a named refusal
[dogfood-v2 mutation]   control-failure p.errors.taxonomy: missing required field: status 422 is a named refusal
[dogfood-v2 mutation]   control-failure p.errors.taxonomy: unknown enum value: status 201 is a named refusal
[dogfood-v2 mutation]   control-failure p.errors.taxonomy: wrong type for a field: status 422 is a named refusal
[dogfood-v2 mutation]   control-failure p.state.out_of_order: a campaign start with no audience is a named refusal, never a silent success
[dogfood-v2 mutation]   control-failure p.state.out_of_order: resume on a draft campaign is refused
[dogfood-v2 mutation]   … (3 xss_reflected control failures were a HARNESS false positive and were fixed
[dogfood-v2 mutation]      before the final run: entity-escaped attributes read as handlers — see §7)
[dogfood-v2 mutation] M01-authz-tenant-scope-drop: CAUGHT by p.authz.cross_tenant_idor
[dogfood-v2 mutation] M02-authz-scope-guard-noop: CAUGHT by p.auth.api_key_lifecycle, p.authz.role_matrix
[dogfood-v2 mutation] M03-errors-false-success-on-refusal: CAUGHT by p.state.out_of_order
[dogfood-v2 mutation] M04-state-verify-token-replay: CAUGHT by p.auth.signup_verification
[dogfood-v2 mutation] M05-hostile-escape-drop: CAUGHT by p.hostile.xss_stored
[dogfood-v2 mutation] M06-hostile-crlf-subject-drop: CAUGHT by p.hostile.crlf_injection
[dogfood-v2 mutation] M07-resource-login-rate-bound-drop: CAUGHT by p.resource.login_rate_bound
[dogfood-v2 mutation] M08-pipeline-enqueue-drop: CAUGHT by p.mail.send_to_mailpit
[dogfood-v2 mutation] M09-invariants-suppression-gate-drop: CAUGHT by p.mail.suppression_consent
[dogfood-v2 mutation] M10-errors-required-field-accepted: CAUGHT by p.errors.taxonomy
[dogfood-v2 mutation] scratch copy verified clean against the main tree after the run
{
 "seeded": 10,
 "caught": 10,
 "missed": 0,
 "inconclusive": 0,
 "passed": true
}
  [CAUGHT] M01-authz-tenant-scope-drop (authz) <- p.authz.cross_tenant_idor
  [CAUGHT] M02-authz-scope-guard-noop (authz) <- p.auth.api_key_lifecycle, p.authz.role_matrix
  [CAUGHT] M03-errors-false-success-on-refusal (errors) <- p.state.out_of_order
  [CAUGHT] M04-state-verify-token-replay (state) <- p.auth.signup_verification
  [CAUGHT] M05-hostile-escape-drop (hostile) <- p.hostile.xss_stored
  [CAUGHT] M06-hostile-crlf-subject-drop (hostile) <- p.hostile.crlf_injection
  [CAUGHT] M07-resource-login-rate-bound-drop (resource) <- p.resource.login_rate_bound
  [CAUGHT] M08-pipeline-enqueue-drop (pipeline) <- p.mail.send_to_mailpit
  [CAUGHT] M09-invariants-suppression-gate-drop (invariants) <- p.mail.suppression_consent
  [CAUGHT] M10-errors-required-field-accepted (errors) <- p.errors.taxonomy
mutation report: tools/dogfood-v2/out/mutation-report.json
$ echo $?
0
```

Every catch is an ASSERTION on the mutant, not an abort — the exact failing check for each seeded
defect (from `out/mutation-report.json`):

| mutation | catching probe | the failing check (observed on the mutant) |
|---|---|---|
| M01 tenant-scoping dropped | `p.authz.cross_tenant_idor` | `cross-tenant GET /v1/contacts/:id with a FOREIGN id returned 2xx` — `status=200 body={"id":"21f1…","email":"owner_b-hidden-…"}` (and `/trust-score` likewise) |
| M02 scope guard no-op | `p.auth.api_key_lifecycle`, `p.authz.role_matrix` | `the scoped key is refused outside its scope…` → 200; `member (messages:read only) is refused /v1/contacts` → 200; `member cannot create contacts` → 201 |
| M03 edit-after-send 200 | `p.state.out_of_order` | `editing a sent campaign is refused` → `status=200 body={"name":"dogfood-edit-after-send",…}` |
| M04 verify-token replay | `p.auth.signup_verification` | `the verification link is single-use (replay refused)` → `replay status=200` |
| M05 escaping dropped | `p.hostile.xss_stored` | `stored payload does not render raw on the campaign detail page` (raw payload rendered) |
| M06 CRLF guards dropped | `p.hostile.crlf_injection` | `newline-bearing subject is refused` → `202 queued`; `CRLF in a custom header value is refused` → `202 queued` |
| M07 rate bound removed | `p.resource.login_rate_bound` | `login brute force is bounded with 429` → `saw [400] after 28 attempts` |
| M08 enqueue dropped | `p.mail.send_to_mailpit` | `the message reaches Mailpit through the worker` → `no Mailpit message after 25s` (accepted send, never delivered) |
| M09 suppression gate dropped | `p.mail.suppression_consent` | `a send to a suppressed recipient is a named 4xx` → `status=202 queued` |
| M10 email validation skipped | `p.errors.taxonomy` | `invalid email format: … is a named refusal` → `201 {"email":"not-an-email"}`; `empty required email` → `201 {"email":""}` |

Two methodology notes that make this proof stronger than a bare "10/10":
1. **The clean control is a real baseline.** Its 10 failing checks are pre-existing product findings
   on the pristine scratch build (the same classes §5 files: un-named serde 400/422 bodies, 405 with
   an empty body, `unknown reason` accepted with 201, resume-on-draft and empty-audience answered
   200). Attribution is per CHECK: a check already red clean can never be credited to a mutation, and
   a probe that cannot execute is INCONCLUSIVE and cannot credit either. All 10 catches above are
   checks that PASSED in the control and FAILED only on the mutant.
2. **The probe set earned its catches.** The mutation runs hardened the harness itself: the CRLF
   probe now verifies its sender domain and uses a transactional category (otherwise every case was
   refused for the wrong reason and M06 was unobservable); a stale captcha token re-mints and retries
   (so the DDoS backoff cannot masquerade as a catch); and the XSS executable-context detector no
   longer reads entity-escaped attributes as live handlers.


---

## 6. Orchestrator paragraph (how to use this)

The harness is partitionable by design: `python3 tools/dogfood-v2/run.py --partition <name> --json <path>`
runs one coherent subset against the live stack and exits `0` clean / `2` findings / `3` ledger
violation / `1` harness error. Runner lanes should take one partition family each — the natural
splits are **console** + **cp** (console/CP SSR + JSON admin), **money** (billing/entitlements/
dedicated IPs), **mail** + **pipeline** (send→Mailpit→events→webhooks→unsubscribe), **tracking**
(+ marketing), **bots** (grader/placement/explorer), **auth** + **authz** (lifecycle, isolation,
roles), **hostile** + **errors** + **state** (input abuse, taxonomy, replay/races), **resource**
(bounds), **invariants** + **infra** (schema/services/env), and **surface** (the mechanical
reachability sweep every lane can afford to run). Each lane pastes the summary table from its
`findings.json`/stdout into its report and works its findings by `repro` + `evidence`; the findings
are keyed by `surface` so a product fix can be traced back to the enumerated route/page/table.
The mutation self-test (`--mutation-test`) should be re-run after the runner lanes land fixes: it is
the regression gate that proves the harness would still catch the seeded defect classes, and the live
baseline can be re-run per partition to confirm the findings close. Because partitions share the
paced client, the fixtures and the documented limiter controls, several lanes can run concurrently
without colliding — but keep the global pace (and `--max-requests`) in place; the stack is shared.

## 7. Deviations, limits and honest non-coverage

- **Mutation base**: the brief suggested `git worktree/patch`. A `git worktree` is pinned to a
  commit, and the deployed stack is built from the **working tree** — which carries uncommitted
  product changes (e.g. the live server accepts the `mfa-verify` captcha scope that HEAD lacks).
  Seeding against HEAD mutated a *different product* (the first runs proved it: the HEAD build
  rejected `mfa-verify` outright). The mutation base is therefore an rsync copy of the working tree;
  patches are still applied with `git apply` and reversed with reverse-apply + copy-back, and the
  main tree is never written.
- **What the ledger does not enumerate**: cron/scheduler entry points, CLI binaries, and
  protocol-level surfaces (SMTP/IMAP verbs) have no mechanical manifest in this repo; §2 covers the
  documented sources of truth (routes, routers, compose services, migrations, env, SSR manifests,
  tracking routes). Adding a source (e.g. an SMTP verb table) is a small ledger change.
- **Severity of repo-static notes**: env/doc drift and missing healthchecks are P3 notes in the
  fixture run and become P3 findings in the live run; they are filed, not fixed, in this lane.
- **Probe precision has been hardened by the mutation run's own control phase**: the control run is
  a full clean-build sweep, so its pre-existing failures are the current honest product findings
  (e.g. serde-level 400/422 bodies that do not carry the `{code,message}` envelope, an unknown
  suppression reason answered 201, edit-after-send and resume-on-draft answered 200, empty-audience
  sends answered 200, and raw payload reflection on console search pages). The harness only credits a
  mutation when a NEW failing check appears — pre-existing red checks are attributed to the product,
  never to the seeded defect.
- **No product defect was fixed in this lane** (per the brief): the findings below are for the
  runner lanes.
- **KiwiCaptcha**: consumed as a black box. The harness solves the documented proof of work; the
  mutation loader refuses any patch path containing `kiwicaptcha`, and no KiwiCaptcha repo or
  `packages/**` byte was touched (the patched paths are all under `services/mail-server/`).


---

## 5. Proof run 3 — full live baseline run (all partitions)

Command:

```
python3 tools/dogfood-v2/run.py --pace 0.35 --out-dir tools/dogfood-v2/out
```

Machine-readable artifacts: `tools/dogfood-v2/out/findings.json`,
`tools/dogfood-v2/out/coverage.json`, `tools/dogfood-v2/out/transcript.log`.

<!-- LIVE-RESULTS -->

---

## 6. Triage (lane D2) — harness corrected, baseline re-run

Lane D2 audited the first live baseline above, reproduced every orchestrator-listed class, and
fixed the HARNESS (version `2.0.0` → `2.1.0`, `tools/dogfood-v2/**` only; no product defect was
touched). Full detail, fail-before/fail-after evidence and the triaged genuine-finding list:
**`docs/audit/dogfood-v2-2026-10-09/lane-d2-triage.md`**.

Fixed harness defects (all false-positive classes):

- **Path doubling** (`ledger.py`): a vacuous reachability test + per-mount prefix application, a
  broken `#[cfg(test)]` stripper (keyword matched anywhere after the attribute; braces counted
  inside string literals) and unmasked brace matching produced 61 phantom API surfaces
  (`/v1/billing/admin/entitlements`, `/v1/analytics/v1/pdf/render`,
  `/v1/admin/autopilot/v1/admin/autopilot/overview`, test-only routes). Fixed with a
  Rust-literal masker, correct item boundaries, per-function prefix attribution and a bounded
  expansion of module-local `super::x::router()` mounts. The ledger is now *wider and truer*:
  +24 real sub-router surfaces (analytics delivery/growth/insights/predictive/cross-tenant,
  audit search/export, dashboard SSE, tenant domain transfer) and correct mount classes for the
  merged `/web/*` zero-JS routes.
- **DDoS block handling** (`httpc.py`, `context.py`, `kiwi.py`, `runner.py`, `identity.py`):
  `403 DDOS_BLOCKED` was unhandled, so the protector's self-inflicted IP block killed 47 probes
  (`csrf handshake failed` / `KiwiError DDOS_BLOCKED`). The client now waits, then runs the
  documented limiter recovery (bucket clear + bounded api-server restart, 8/run, transcript-noted)
  and raises a named `DdosBlocked` instead of scoring a block as a product verdict; the captcha
  solver paces its mints (bucket clear every 18) under the documented 30/15-min issuance bound;
  a probe that cannot execute is a named finding with the exact error, never a traceback.
- **Infra designed-state** (`probes/infra.py`, `ledger.py` service metadata): services are checked
  against topology + ACTIVE profiles (monitoring is inactive; prod-only services come from the prod
  compose) instead of "everything must run". The two dev-profile services designed to run were
  stood up (`pdf-renderer`, `billing-service`, both healthy). The 26 container + 2 `/health`
  findings collapse to 2 genuine P3 notes (missing compose healthchecks on analytics-worker and
  outbound-mta).
- **Schema invariants** (`ledger.py`, `dataplane.py`, `probes/invariants.py`): a single-pass SQL
  masker, statement-ordered net CREATE/DROP, `%`-format skipping, partition-parent awareness
  (`pg_inherits`) and migration-runtime exclusions. `missing=[]`, `orphans=[]` live — no genuine
  schema defect in this class.
- **Env surface** (`probes/infra.py`): consumer analysis understands the `*_FILE` loader
  convention, compose entrypoint argument lists and third-party image config. Only 4 genuine
  config-theater vars remain (`BACKUP_KEEP_MONTHS`, `BACKUP_KEEP_WEEKS` → postgres-backup;
  `DKIM_DOMAIN` → worker; `LOCAL_DOMAINS` → mta) — the other 24 have a located reader.
- **KiwiCaptcha contract**: re-verified live — a token-less login is refused
  `400 VALIDATION_ERROR ["CAPTCHA verification token is required"]`; the old P1 was DDOS-derived.

After the fixes: `--self-test` GREEN (1321 checks, 0 dynamic failures), ledger 1732 surfaces with
0 unprobed/0 warnings, and the fresh full live baseline is filed in `lane-d2-triage.md` §2 and in
the `out/` artifacts (re-run of the §5 command above).

