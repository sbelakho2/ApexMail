# ApexMail Sub-Module Audit Remediation Report — 2026-10-01

Companion to `submodule-deep-audit-2026-09-30.md` (192 findings: 4 P0, 34 P1, 74 P2, 80 P3).
This campaign fixed **all 192 findings plus 12 defects discovered during remediation**, then
adversarially verified every fix with fresh agents that were paid to defeat the fixes.

**Every finding is FIXED and VERIFIED or carries an explicitly documented environmental or
operator-action justification below. Zero silent residuals.**

## Campaign structure

| Wave | What | Agents | Result |
|---|---|---|---|
| 1 | Production fixes (SM1–SM11, SM13–SM15) | 15 | All findings implemented; every fix with a regression test where feasible |
| 2 | Test-suite rewrites (SM12) | 3 | The 4 P0 manufactured test suites now test production code; +30 net real tests; cargo-fuzz subproject |
| 3 | Integration sweep | 1 | Full workspace DB/Redis-backed run green; 1 production fix; 2 env root-causes fixed |
| 4 | Adversarial verify-repair (SM1–SM15) | 15 (+4 escalation follow-ups) | Every finding re-derived from the tree; bypasses attempted; 25+ fixes repaired/hardened |
| Final | fmt, dead catalog, tooling, fence wiring | coordinator | See "Final pass" |

## Verification scorecard (Wave 4)

Per-finding verdicts across all 15 modules: every one of the 192 findings was independently
re-derived from the tree (code read, not reports trusted), its regression test executed
(mutation-tested where the verifier could deactivate the fix), and bypasses attempted
(boundary values, alternate unfixed paths, fallback/degraded paths, config kill-switches,
sibling regressions, cross-module parity).

The adversarial wave caught and repaired **12 real defects beyond the original audit**:

1. **SAML federation hijack (SM8)** — `sso_configure` had no admin gate at any revision; any
   viewer-role member could repoint the tenant IdP cert/entity-ID. The original audit premise
   wrongly listed it as admin-gated; the fix wave trusted the premise; the verifier checked
   git history and restored `require_admin`.
2. **Data-access self-approval bypass (SM8)** — filing route accepted body-controlled
   `requester_id`, defeating approver≠requester. Stored requester now server-derived.
3. **Webhook-secret encryption parity (SM3+SM10)** — api-server and the delivery worker both
   read/wrote `webhooks.secret` as plaintext via raw SQL, bypassing the encrypted repo layer.
   Both stacks now use the identical `enc:v1:` envelope (AAD `webhook={id}`),
   decrypt-or-migrate reads, fail-closed on tampering.
4. **Sandbox budget amplification (SM6)** — extraction budget passed by value into recursion:
   sibling nested archives each got ~fresh budgets. Now shared `&mut`.
5. **Domain blocklist fail-open (SM6)** — IP saturation was handled; domain rejections were
   silently discarded. Now counted, logged, refused at ≥10% drop.
6. **Archive risk double-count (SM6)** — new `ARCHIVE_ENTRY_UNREADABLE` stacked on
   `ARCHIVE_ENCRYPTED` (7.0+3.0 → 10.0 REJECT), breaking the committed quarantine posture
   (and, per compose semantics discovered in SM13's verification, would have stacked at two
   distinct sites). Suppressed when encryption already fired; 4 fail-first tests.
7. **WAF gate re-bypass ×4 (SM5)** — whitespace-collapsed `javascript:` URIs, Unicode
   whitespace before `=`, boundary-free handler words, JSON `\u0000` NUL smuggling all
   bypassed the new structural gate. Gate signals now run on normalized input.
8. **SQL-guard literal smuggling (SM5)** — `'workspace_id=$1'` inside string literals
   satisfied the predicate regexes. Literals now blanked (current_setting argument preserved).
9. **Retry-after boundary bug (SM4)** — floor applied as clamp not addition: clients landed
   exactly ON the denial boundary. Found by a 48k-point property grid (10,430 failures).
10. **AI sanitizer case-fold bypass (SM9)** — stripper regexes lacked `(?i)`: `<SCRIPT>`
    uppercase sailed through. **Embedding NaN laundering (SM9)**: finite-but-huge components
    squared to +Inf → all-zero embedding shipped 200.
11. **Stripe freeze TOCTOU (SM7)** — last-writer-wins amount freeze let overlapping collectors
    mint two idempotency keys. Now first-writer-wins returning the effective amount.
12. **Explorer key invalidation storm (SM3)** — per-process cache + single row meant every
    cold replica re-minted and invalidated the others. Now Redis-published with adoption.

Plus: per-IP limiter observation deque uncapped (SM5), nine workspace routes failing open on
org-claim (SM5), migrate-route 500-on-unsupported ordering (SM5), legacy-store 0x02-nonce
decrypt lockout (SM1), lease-fence test walking the wrong ladder (SM1), imap FETCH
race-window panic + STORE op-word char-boundary panic (SM2), `DOMAIN_LITERAL_RE` accepting
CR/LF inside bracket literals — a header-injection surface found by fuzzing (SM4), four more
HA topology routes accepting the universal internal key (SM10), fake-tested suites in
bank_ingest/sweeps/auth-regression/security_regression (SM7/SM8), and a nullable
`billing_addresses.email` 500ing every admin invoice (Wave 3).

## Where things stand per module (full per-finding evidence in `/tmp/apexmail_audit/results/`)

All 15 modules: every finding FIXED + VERIFIED. Suite highlights from the final integrated
state: integration-tests **178/178** across 12 binaries (DB+Redis), api-server nextest
**1963/1964** (1 solo-pass flake), billing-service **614+82**, worker-processors **701**,
compliance **597/599** (2 documented superuser-role fixture limits), mta **716/717** (1
parallelism flake, passes solo), imap-server **295/295**, sales-autopilot **873**,
enterprise **336**, ui-foundation **453**, ai-service **438×2**, fuzz/perf/load **66/18/25**,
SDK suites green in Go/Python/Ruby/PHP/Java. `cargo fmt --check` clean; compose
base+dev+prod render clean; `promtool`, `otelcol validate`, `hadolint`, `shellcheck`,
`gitleaks` (full history), `ci/pipeline.sh selftest` all pass.

## Documented residuals (none silent)

**Environmental (machine-specific, verified):**
- compliance `hostile_db_tests` ×2: `REVOKE … FROM CURRENT_USER` cannot bind for a superuser
  test role — needs a non-superuser fixture role in CI.
- mta `fbl_stalled…` flake only under 700-test parallelism (passes solo); api-server
  `sandbox_cache_self_heals` ~1/Run when explorer tests act as siblings in parallel.
- isolation/compliance config env-race tests: pass serially/under nextest (canonical runner).

**Operator actions (impossible from the repo):**
1. Build/push the CI image and replace the all-zero placeholder digest in the `&ci_image`
   anchor (validate stage mechanically enforces the pin).
2. Branch protection: require review from code owners + add a second owner for `/ci/`,
   `/deploy/`, `.woodpecker.yml` (checklist in CODEOWNERS).
3. Set `APEXMAIL_HA_FENCING=true` once the ha service is deployed (wired into prod compose
   for api-server/worker/mta, default false, documented in `.env.production.example`).

**Design notes for a future wave (documented in code, not ignored):**
- The isolation regex SQL guard cannot correlate WHERE-scope across CTEs; a real SQL
  tokenizer (or the RLS backstop) closes it.
- `set_sync_mode(true)` in the ha crate mutates server-wide Postgres config with no
  crash-safe cleanup — a killed run wedged the dev cluster via
  `synchronous_standby_names='*'` (unwedged during Wave 3). Make it session-scoped or add
  cleanup-on-boot.
- Hostile-DB test fixtures need a non-superuser role (above).

## Post-verification targeted repair: browser-suite mass heal

The pre-existing risk-v2 decoy failures flagged during verification were root-caused and
fixed: the **test fixture** (`tests/browser/router.php` + hand-rolled spec pages) never
emitted the `data-kiwi-risk-src/-integrity` attributes that production always ships
(`KiwiCaptchaRuntime.php`), so the lazy `widget-risk.js` module — and with it the entire
decoy/honeypot renderer — never loaded in tests. The widget assets themselves were correct.
After mirroring production wiring into the fixture (and delivering strict-CSP as an HTTP
header so the WASM-unavailable test's premise is real again): the browser suite went from
**132 passed / 88 failed → 215 passed / 5 failed**, zero regressions, 83 tests healed,
zero assertion changes, kiwicaptcha byte-parity intact. The remaining locales-wiring gap
(same class, 4 tests) was repaired in a follow-up pass (suite 219/1), and the last real
defect the suite was pinning — the Retry control's WCAG 1.4.11 non-text contrast
(1.26:1 < 3:1) — was fixed with a compliant `--kiwi-border-strong` token across all three
parity-gated widget.css copies (a11y spec 15/15 including the computed-contrast test).
The chaining-spec instability — the last remaining failure — was root-caused as fixture
state pollution: the router's chain store persisted to a shared temp file where a 300s
obligation TTL outlived the 120s challenge TTL, so re-runs inside the window deterministically
failed on inherited expired obligations (the shared temp file also survives `git stash`,
which is why the flake looked "pre-existing on pristine HEAD"). Fixed with per-run store
namespacing + the production shared-store TTL mirror + a temp GC. Final acceptance:
**220 passed / 0 failed, three consecutive full-suite runs** (plus solo 11/11 ×4 and
back-to-back cadence that previously reproduced the pollution deterministically) — zero
assertion changes, zero widget-asset changes, parity intact. The browser suite that entered
this campaign at 132/88 now stands at 220/0.

## P0 closure note

The four P0s (manufactured test suites) are closed: `stub_detection_tests.rs` now contains 19
tests against the real rate limiter/circuit breaker/crypto/validation; `property_based_tests.rs`
runs 29 properties over production types; the concurrency suite drives the real router over
per-test canonical-chain DBs and defeats on clause removal; `load_isolation.rs` implements the
documented noisy-neighbour SLO with real thresholds. The CI log-gate that fails runs containing
skip markers remains in force.

## Cross-cutting improvements landed (from the audit's roadmap)

1. **"Wired or deleted"** — dead root `compliance/` package deleted; live `legal_entity.rs`
   catalog replaced with a `RUNTIME_PRICING_AUTHORITY` pointer (its embedded prices had
   drifted 10× on the free tier); `imap-proto-patched`'s status documented UNWIRED with the
   protection re-implemented in-server; sandbox extraction made real; HA promotion made real;
   smtp-auth-proxy de-coupled.
2. **False-green ended** — manufactured suites rewritten; CI blessing refuses advisory-fail;
   executor timeouts enforced; docker-absent fails closed; probes live-tested; parity gates
   added (pricing ×2, SDK versions, webhook vocabulary pinned).
3. **Silent-loss closed** — recipient accounting, sequence lease/reaper, ledger
   auto-provisioning + 3 new sweeps (wired into the compliance cron), deletion lifecycle,
   panic-aware supervision, flush-first analytics.
4. **Siblings unified** — one SSO email gate, one legal-hold authority, one webhook-vocabulary
   contract across 5 SDKs, one secret-at-rest convention across 3 stacks, one RUSTSEC ledger
   (4 copies in enforced lockstep), one test-harness crate.
5. **Bounded everything** — dkim index, cost buckets, blocklist, explorer keys, SSO staging,
   trust portal, LogAggregator, per-IP limiter tables.
