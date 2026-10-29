# Lane K1 — KiwiCaptcha mirrors refreshed to the upstream GitHub head (byte-identical)

Date: 2026-10-09 (wave `kiwicaptcha-integration-2026-10-09`). Lane K1, mirror refresh. No `git commit` was made; the
index was never touched (`git diff --cached --stat` is empty). All commands below are literal, run from
`/Users/sabelakhoua/IdeaProjects/ApexMail` unless stated otherwise.

## 1. Mirrored identity (sha + version)

- Upstream: `https://github.com/Bel-Consulting-OU/kiwicaptcha`, local clone
  `/Users/sabelakhoua/IdeaProjects/kiwicaptcha-standalone` (read-only for this lane; `fetch` only).
- **Mirrored content ≡ upstream commit `25f0d05e299e5dd33c500f7b4316bd9a0530cd2b`** (origin/main at verification
  end, 2026-10-09T14:42:25Z) **for the entire mirror surface, and object-identical to `ab1316b7ca0637f4a06d0d049afcedaf36796d24`**
  (the sha at refresh time — the head moved during the lane; see §2).
- **Package version: `kiwicaptcha` 1.7.0** (`packages/kiwicaptcha/Cargo.toml`; identical upstream and in ApexMail).
- Mirror surface (the c10db774 precedent): `packages/kiwicaptcha`, `packages/kiwicaptcha-php`,
  `packages/kiwicaptcha-risk`, `packages/kiwicaptcha-risk-php`, `packages/kiwicaptcha-wasm`, `tests/browser`.
- Tracked file parity: **1105/1105 upstream blobs match ApexMail byte-for-byte** (§4). Worktree file lists
  (excluding build artifacts) are equal at 1110/1110.

Raw evidence (this session's machine, ephemeral): `/tmp/k1-evidence/` — notably
`01` fetch/status, `03-before-diff-inventory.txt`, `04-rsync-itemize-*.txt`, `05-after-diff-proof.txt`,
`06-upstream-tracked-ls-tree.txt` + `06-paths.txt`/`06-upstream-hashes.txt`/`06-apex-hashes.txt`,
`07-*-worktree-files.txt`, `12b-crate-cargo-test.txt`, `13-cargo-check.txt`,
`14c-nextest-api-server-retry2.txt`, `15b-nextest-integration-tests-binaries.txt`, `16-npm-ci.txt`,
`17-playwright.txt`, `18-upstream-head-move-and-dirt.txt`, `24-playwright-recheck.txt`,
`25-playwright-full-rerun.txt`, `26-crate-test-pristine-replica.txt`, `29-redis-test-replica-control.txt`.

## 2. Upstream freshness, the head move, and the dirty worktree

At refresh time (14:16Z):

```
$ git fetch origin && git rev-parse HEAD origin/main
ab1316b7ca0637f4a06d0d049afcedaf36796d24
ab1316b7ca0637f4a06d0d049afcedaf36796d24
$ git status --short -- packages tests      # mirror surface: EMPTY (clean)
$ git status --short                        # only two tools/redteam entries (outside the mirror surface)
 M tools/redteam/fuzz/build.log
?? tools/redteam/engine/runs/20261009T141138Z-d3.17-cross-sdk-parity-seed-0x6b776d74.json
```

The two `tools/redteam` entries are outside the six-dir mirror surface, so they changed no mirrored byte; they were
recorded and not mirrored (the six dirs were copied from a worktree whose mirror surface was byte-clean).

**The head moved during verification** (a peer is actively working in the standalone repo — orchestrator addendum,
independently confirmed here):

```
$ git rev-parse HEAD origin/main                    # 14:31Z and again 14:42Z
25f0d05e299e5dd33c500f7b4316bd9a0530cd2b
25f0d05e299e5dd33c500f7b4316bd9a0530cd2b
$ git diff --name-status ab1316b7 25f0d05e          # the ENTIRE committed delta
M    tools/redteam/campaigns/d3.5-credential-stuffing.sh
M    tools/redteam/campaigns/lib/d35.driver.php
A    tools/redteam/engine/runs/20261009T141138Z-d3.17-cross-sdk-parity-seed-0x6b776d74.json
M    tools/redteam/fuzz/build.log

$ for d in <six dirs>; do git rev-parse ab1316b7:$d 25f0d05e:$d; done
packages/kiwicaptcha            51854867d357e95ecb422a6e3db05f1951781c01  (SAME-TREE)
packages/kiwicaptcha-php        9a9cb0049ce27be89718128f9b178b49ca1b8628  (SAME-TREE)
packages/kiwicaptcha-risk       3adc4456b789217632136bda153d3cae29166476  (SAME-TREE)
packages/kiwicaptcha-risk-php   f806c7eb24f17266a460c054934db7f8249b0db3  (SAME-TREE)
packages/kiwicaptcha-wasm       a899a710c8ef510575ed577940b0804c6f93b4e2  (SAME-TREE)
tests/browser                   ee2fbfd7bf5437ff1bb8c8115212c75372a0a2fc  (SAME-TREE)
$ git diff --name-only ab1316b7 25f0d05e -- <six dirs>   # (empty: no mirrored byte changed)
```

So the mirror is at the latest GitHub head's runtime bytes: every one of the six subtrees is object-identical at
`ab1316b7` and `25f0d05e`, and the ApexMail files match those objects blob-for-blob (re-proven against `25f0d05e`:
0/1105 mismatches, §4). The head move touched only `tools/redteam/**` (outside the established surface).

**Dirty upstream worktree: recorded exactly, never mirrored.** Snapshot at 14:31Z (10 files, all in the mirror
surface) — an in-progress peer refactor, all uncommitted:

```
 M packages/kiwicaptcha-php/tests/Support/BrowserlessForgerySolver.php
 M packages/kiwicaptcha-risk-php/src/Evidence/EvidenceModel.php
 M packages/kiwicaptcha-risk-php/src/Storage/PrincipalNetworkTagStoreInterface.php
 M packages/kiwicaptcha/integrations/symfony/src/Security/Agents/AgentSignatureVerifier.php
 M packages/kiwicaptcha/integrations/symfony/src/Security/StepUp/StepUpBootstrapGate.php
 M packages/kiwicaptcha/integrations/symfony/src/Security/StepUp/StepUpLockoutGuard.php
 M packages/kiwicaptcha/integrations/symfony/src/Security/StepUp/StepUpSessionBinding.php
 M packages/kiwicaptcha/integrations/symfony/src/Security/StepUp/TotpStepUpHandler.php
 M packages/kiwicaptcha/integrations/symfony/tests/BootstrapAdversarialTest.php
 M packages/kiwicaptcha/integrations/symfony/tests/FirstAttemptLoginGuardTest.php
($ git diff --stat: 10 files changed, 62 insertions(+), 206 deletions(-))
```

The dirty set grew to 27 entries by 14:42Z (still uncommitted, still not mirrored; full snapshot appended to
`/tmp/k1-evidence/18-upstream-head-move-and-dirt.txt`). The mirror contains only committed head bytes — no dirty
state was copied, and the refresh itself ran while the mirror surface was clean.

## 3. The precedent's include/exclude set (derived per-file, not guessed)

`git show --name-status c10db774` shows 67 changed files (4 A, 63 M) — a delta, not the surface. The derived
criterion is exact:

```
$ git ls-tree -r --name-only c10db774 -- <six dirs> | wc -l        -> 599
$ git ls-tree -r --name-only b32ec01e -- <six dirs> | wc -l        -> 599
$ comm (both sorted sets)  -> 0 lines both directions
```

i.e. at the c10db774 precedent the ApexMail mirror tree was **exactly upstream's tracked set** (599/599, matching
the commit message), with `target/`, `node_modules/`, `vendor/`, generated caches excluded. Direct checks on the
"`.phpunit.result.cache` / lockfiles included" point in the brief:

```
$ git cat-file -e c10db774:packages/kiwicaptcha-php/.phpunit.result.cache   -> lacks
$ git cat-file -e c10db774:packages/kiwicaptcha-php/composer.lock          -> lacks
$ git log --all -- 'packages/kiwicaptcha-php/.phpunit.result.cache'        -> empty (never tracked)
```

`.phpunit.result.cache` and `composer.lock` are git-ignored artifacts that exist on disk in both worktrees; they
were never part of the committed mirror. Per the brief they were treated as *included* files for the on-disk
refresh (copied/refreshed to upstream bytes — §4), and they remain untracked/ignored in ApexMail, so no junk can
ride into a commit. `.gitignore`, `Cargo.lock` and `tests/browser/package-lock.json` are tracked upstream and were
mirrored normally. Exclude set used for copy and proofs:
`target`, `node_modules`, `vendor`, `pkg`, `test-results` (verified: no tracked upstream path contains any of these
segments).

## 4. Refresh method, before/after inventory, parity proofs

Method (per dir): `rsync -ai --delete --exclude=target --exclude=node_modules --exclude=vendor --exclude=pkg
--exclude=test-results <upstream>/<dir>/ <apex>/<dir>/`. Itemized logs: `/tmp/k1-evidence/04-rsync-itemize-*.txt`.

### 4.1 Before inventory (`diff -rq` with the precedent's excludes)

`/tmp/k1-evidence/03-before-diff-inventory.txt` (749 lines). Per-dir summary:

| dir | files differing | only-in-one-side entries (dirs collapsed) |
|---|---|---|
| packages/kiwicaptcha | 177 | 151 |
| packages/kiwicaptcha-php | 75 | 43 |
| packages/kiwicaptcha-risk | 31 | 48 |
| packages/kiwicaptcha-risk-php | 51 | 71 |
| packages/kiwicaptcha-wasm | 22 | 3 |
| tests/browser | 23 | 32 |

Tracked-set delta (precise, commit vs commit): ApexMail mirror had 637 tracked paths; upstream `ab1316b7` has 1105;
common 635; only-upstream 470; only-ApexMail 2; content-differing 374.

### 4.2 After proofs

`diff -rq` (same excludes) is **empty with exit 0 for all six dirs**:

```
packages/kiwicaptcha       diff-exit=0 lines=0
packages/kiwicaptcha-php   diff-exit=0 lines=0
packages/kiwicaptcha-risk  diff-exit=0 lines=0
packages/kiwicaptcha-risk-php diff-exit=0 lines=0
packages/kiwicaptcha-wasm  diff-exit=0 lines=0
tests/browser              diff-exit=0 lines=0
```

Per-file git-blob parity (bulk `git hash-object --no-filters --stdin-paths`, compared to
`git ls-tree -r 25f0d05e`):

```
paths=1105  upstream-hashes=1105  apex-hashes=1105  mismatch-count=0
```

Worktree file lists (find, pruned of the excluded build dirs) are equal: 1110 vs 1110, **diff 0 lines**. The five
extra files relative to the tracked set are the upstream-carried ignored artifacts, byte-identical on both sides:
`packages/kiwicaptcha-php/{.phpunit.result.cache,composer.lock}`, `packages/kiwicaptcha-risk-php/.phpunit.result.cache`,
`packages/kiwicaptcha/integrations/symfony/{.phpunit.result.cache,composer.lock}`.

### 4.3 File/addition/deletion counts per mirrored dir

| dir | upstream tracked files | added | modified | deleted | on-disk files (excl. build dirs) |
|---|---|---|---|---|---|
| packages/kiwicaptcha | 517 | 204 | 175 | 1 (`examples/quickstart.rs`) | 519 |
| packages/kiwicaptcha-php | 185 | 42 | 73 | 1 (`tests/ShortSecretRefusalTest.php`) | 187 |
| packages/kiwicaptcha-risk | 90 | 48 | 31 | 0 | 90 |
| packages/kiwicaptcha-risk-php | 174 | 98 | 50 | 0 | 175 |
| packages/kiwicaptcha-wasm | 28 | 3 | 22 | 0 | 28 |
| tests/browser | 111 | 75 | 23 | 0 | 111 |
| **total** | **1105** | **470** | **374** | **2** | **1110** |

Deletion inventory (rsync itemize): the two tracked files above (ApexMail-only; `quickstart.rs` was deleted
upstream after 31b9e00b, `ShortSecretRefusalTest.php` was an Apex-side test that upstream never had) plus one
ignored local artifact, `packages/kiwicaptcha-risk-php/composer.lock` (upstream ships no lock for that package).
The `.phpunit.result.cache`/composer.lock pairs that upstream does ship were refreshed (`>f.st......`) — see the
itemize logs.

### 4.4 Embedded widget resource parity

Provenance rule (upstream, recorded): `packages/kiwicaptcha-wasm/assets` is canonical; `sync-assets.yml` and
`packages/kiwicaptcha/integrations/symfony/bin/sync-assets.sh` copy the release set to
`packages/kiwicaptcha/resources/` and the Symfony `Resources/public/`, and `tools/verify-asset-parity.sh` enforces
the trilocation equality. After the refresh, the four brief-named resources are byte-identical in all three
locations and to the upstream canonical blob:

| resource | sha256 | git blob | resources/ = wasm/assets = symfony/public = upstream |
|---|---|---|---|
| widget-driver.js | `32c39f3e1551b7ccf9310ba638ec414f8b93c8e6912e85d41ba946eb323309cb` | `69b16daaad31784cd8532d8baefe6a86daa1f222` | OK |
| widget.css | `5962e87a2d7fa912f079022e611f58fe5b1295c04bab30555a27ce12810804e5` | `ce8affc93f0a2f2d09748d0c7573de7bbe41637e` | OK |
| kiwicaptcha-wasm.js | `695c46fb37a103acfe146bcfa5c0e00e97f53cad92dc3a1ee408c52e24a57bbd` | `571220cd153ccbc312e1f7f8f993d20d5a5fac14` | OK |
| kiwi-worker.js | `0c3bf694ae251c0a023cf2b5bd08a45b9da0384199f50f1ef35b41d037982bad` | `a0e21a1dd79617e7a8d363288b9f7cb8dbdfd984` | OK |

(`execution-interpreter.js` was checked the same way during the full blob pass: `d73c79682317cc51aebf5e5883e065fbe60635d3`
at all three locations.)

## 5. ApexMail-side adaptations (all outside `packages/**` mirror bytes)

No ApexMail call-site adaptation was needed for compilation: `cargo check -p api-server -p integration-tests`
is rc=0 with zero errors/warnings against the refreshed API (§7). Three ApexMail-side items were required and are
documented here; no file under `packages/**` or `tests/browser/**` that is part of the mirrored (tracked) surface
was edited after copying.

### A1 — root `protocol/` register refresh (ApexMail-side data the mirrored bytes pin against)

The mirrored bytes read repo-root registers: Rust `include_str!("../../../protocol/execution-v1.json")`
(`packages/kiwicaptcha/src/execution.rs:3953`), `CARGO_MANIFEST_DIR/../../protocol/risk-v1/fixtures.json`
(`tests/redis_verify.rs:6502`), and PHP tests reading `../../protocol/{asn/sample-asn.tsv,
risk-v1/*-vectors.json, rsw-identity-v1/fixtures.json, solution-token-v1/fixtures.json,
telemetry-v1/evidence-vectors.json, risk-v2/identity*.json}`; `tools/check-risk-lua-parity.sh` compares
`protocol/risk-v1` against the package resources. ApexMail's `protocol/` was stale at the 31b9e00b era
(`execution-v1.json`: `max_execution_version: 5`, `opcode_count: 45` vs upstream `6`/`50`) and missed 27
registers entirely. Fail-before (after the mirror refresh, before this adaptation):

```
---- execution::tests::manifest_constants_match_the_module_register stdout ----
panicked at src/execution.rs:3960:9: assertion `left == right` failed   left: 5   right: 6
```

Adaptation: `rsync -ai --delete <upstream>/protocol/ <apex>/protocol/`. Result (itemize
`/tmp/k1-evidence/11-protocol-rsync-itemize.txt`): **27 new files, 12 content-updated, 1 mtime-only, 0 deletions**
(`execution-v1.json` + the 12 risk-v1 Lua/JSON updates; the 27 additions are listed below). Proofs:

```
$ diff -rq protocol <upstream>/protocol            -> empty (rc=0)
$ protocol entries=41  mismatches=0                (per-file git blob parity vs 25f0d05e)
$ find protocol -type f | wc -l                    -> 41
```

Added files (27): `limits.json`, `asn/sample-asn.tsv`, `risk-v1/{asn-vectors,attacker-denial-vectors,
hysteresis-vectors,outcomes-vectors,pricing-vectors,quarantine-vectors,target-vectors,trust-vectors}.json`,
`risk-v1/{calibration_v2,confirm_v2,correction_v2,decoy_escalation,marks,sharded_hysteresis,sharded_identity,
sharded_scope,target_failure,trust}.lua`, `risk-v2/{identity,identity-fixtures}.json`,
`rsw-identity-v1/fixtures.json`, `solution-token-v1/fixtures.json`,
`telemetry-v1/{client-perf-p1,evidence-vectors,payload}.json`.
Updated (12): `execution-v1.json`, `risk-v1/README.md`, `risk-v1/{assess_v2,calibration,confirm,correction,
outcome_confirm,outcome_correct,outcome_register,register_decision,risk-v1}.lua`, `risk-v1/fixtures.json`.
Note: `include_str!` is a cargo dep-info dependency but `rsync -a` preserves old mtimes, so one `touch
protocol/execution-v1.json` (mtime only — content unchanged, parity re-proven afterwards) was needed to force the
rebuild; the first post-refresh `cargo test` still used the stale build.

### A2 — stale local vendored path-package copies under the Symfony integration (ignored artifacts, not mirror bytes)

Root cause of the three browser-suite reds (§7): the fixture `tests/browser/router.php` loads
`packages/kiwicaptcha/integrations/symfony/vendor/autoload.php` when present, and composer's autoloader (registered
later with prepend=true) wins over the fixture's own loader. ApexMail's vendor copies of the two path packages were
installed 2026-09-13 (`"symlink": false` in the bundle's `composer.json` path repositories, so real copies), i.e.
from the pre-refresh packages; the refreshed bundle code and the fixture then resolved stale classes:

```
Fatal error: Uncaught InvalidArgumentException: execution version must be 1..5 (...) in
.../integrations/symfony/vendor/kiwicaptcha/kiwicaptcha-php/src/ExecutionChallengeGenerator.php:257
#0 .../Issuer.php(568): KiwiCaptcha\ExecutionChallengeGenerator::generate(..., 6)
```

(vendored `MAX_EXECUTION_VERSION = 5` vs refreshed `= 6`). `vendor/` is git-ignored in ApexMail
(`git check-ignore -v` evidence recorded) and excluded from the mirror by the precedent, so this is a local
environment repair, not a mirror edit: the two vendored copies were rsynced from the mirrored sources
(`rsync -a --delete --exclude=vendor packages/kiwicaptcha-php/ <vendor>/kiwicaptcha-php/`, same for risk-php).
After: `diff -rq <vendor>/kiwicaptcha-php/src packages/kiwicaptcha-php/src` clean, same for risk-php; the three
failing specs then passed (39/39) and the full suite went 440/440. Upstream's own worktree carries the same layout
with freshly synced vendor copies (mtimes 2026-10-06/08), confirming this is the standard local hygiene.

### A3 — `packages/kiwicaptcha/Cargo.lock` normalization and restore (disclosed)

The crate has no workspace ancestor in ApexMail (upstream's repo root is a workspace), so running `cargo test` in
place makes cargo normalize the package lock (it adds three entries to the package's dependency list:
`kiwicaptcha`, `num-bigint`, `num-integer`). This happened twice; both times the lock was restored to the exact
upstream bytes (`efaed9e8741f0ce3664154bcfb3d5323a6fa6692`, `25f0d05e:packages/kiwicaptcha/Cargo.lock`) and parity
re-proven (0/1105). A pristine-bytes run in a `/tmp` replica (crate + protocol copy) confirms the suite is green
without touching the mirror: 370/0/0 (§7). If the orchestrator re-runs the suite in place, restore that one file
(`rsync` from upstream or `git checkout` after staging) before the fold commit.

## 6. Findings handed to other lanes / the orchestrator

1. **HMAC secret floor raised upstream to 32 bytes.** `packages/kiwicaptcha/src/keys.rs:51`
   `pub const MIN_MASTER_BYTES: usize = 32`, enforced at every signing entry point (`challenge.rs:2848`
   "HMAC secret key is too short (minimum 32 bytes)"; dedicated test at `challenge.rs:3040`). This initially
   collided with ApexMail: the production validator floored `KIWI_SECRET_KEY` at 16 (`config.rs`), so a 16–31-byte
   secret would have passed startup validation and then failed every issuance with a 503, and two api-server tests
   using the 16-byte fixture secret `"kiwi-test-secret"` went red before K2's in-flight work landed. K2 has since
   fixed both in flight: `config.rs:1423-1426` now validates against the crate constant
   (`kiwicaptcha::keys::MIN_MASTER_BYTES`), and the test fixtures use the 32-byte
   `"kiwi-test-secret-0123456789abcdef"`. Remaining doc gap only: `.env.production.example:305` still says
   `<REQUIRED-random-16+-char-hmac-secret>` and should say 32+. Dev defaults are fine (`docker-compose.yml`
   default secret is 34 chars; `secrets/kiwi_secret_key.txt` is 64 bytes).
2. **Upstream-inherent red in the optional Redis lane** (beyond this lane's brief, recorded for completeness):
   `tests/redis_verify.rs::execution_armed_record_at_the_register_maximum_verifies_through_the_production_verifier`
   fails on pristine upstream bytes (reproduced in the `/tmp` replica of `25f0d05e`). Cause visible in
   `src/execution.rs:629`: the version-5 causal spine is gated with `if version == 5`, while
   `MAX_EXECUTION_VERSION` is 6, so the max-register program no longer carries the v5 spine ops the committed test
   asserts. Not fixed here (upstream bytes are read-only for this lane).
3. **`BROWSER_TEST_BASE_URL` is inert in the refreshed suite**: `tests/browser/playwright.config.mjs` ignores it
   and self-hosts the PHP fixture (`php -S 127.0.0.1:8085 router.php`, `reuseExistingServer: false`); the brief's
   command was run verbatim anyway.
4. Ignored upstream artifacts (`vendor/`, `.phpunit.result.cache`, `composer.lock`, `tests/browser/node_modules`,
   `test-results/`) are git-ignored in ApexMail — `git check-ignore` confirmed (`packages/kiwicaptcha-php/.gitignore`
   lines 2-3, `integrations/symfony/.gitignore:1`, `tests/browser/.gitignore:1`, root `**/target/`). They cannot
   enter the fold commit.
5. Upstream CI (`.github/workflows/ci.yml:49`) still references `cargo test -p kiwicaptcha --example quickstart`,
   but upstream HEAD no longer has `packages/kiwicaptcha/examples/quickstart.rs` — an upstream mid-development
   leftover, noted only.

## 7. Verification battery (literal commands + outputs)

### 7.1 Crate suite (default features) — GREEN

```
$ cd packages/kiwicaptcha && cargo test
test result: ok. 272 passed; 0 failed; 0 ignored; ...   (lib)
... 18 targets total ...
aggregate: passed=370 failed=0 ignored=0 targets=18     (includes Doc-tests)
```

Full log `/tmp/k1-evidence/12b-crate-cargo-test.txt`; an identical run on a pristine `/tmp` replica (upstream
bytes + protocol copy, mirror untouched) reproduced **370/0/0** (`26-crate-test-pristine-replica.txt`). No
`#[ignore]` markers exist in the crate; every target reports `0 ignored`.

Bonus upstream-CI lane (documented at `.github/workflows/ci.yml:1649`, beyond the README): `cargo test --features
redis --test redis_verify` with `RISK_REDIS_URL=redis://:dev-redis-password-minimum-32-chars@127.0.0.1:16379/0`
→ **101 passed / 1 failed / 0 ignored**; the one red is finding §6.2, reproduced on pristine upstream bytes
(`29-redis-test-replica-control.txt`).

### 7.2 ApexMail workspace compile — GREEN

```
$ cd services/mail-server && cargo check -p api-server -p integration-tests
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 2m 05s        (rc=0, no errors, no warnings)
```

The refreshed API compiles against the existing call sites with zero ApexMail-side changes.

### 7.3 `cargo nextest run -p api-server --lib -E 'test(kiwi) | test(schema_contract) | test(concurrency)'`

Env: `TEST_DATABASE_URL=postgres://apexmail:<secrets/postgres_password.txt>@127.0.0.1:5432/apexmail`,
`TEST_DATABASE_ADMIN_URL=...@127.0.0.1:5432/postgres`, `TEST_REDIS_URL=redis://:dev-redis-password-minimum-32-chars@127.0.0.1:16379/0`.

History (all logs kept): first attempt could not compile — 25 errors, all inside K2's then-in-flight 318-line test
block in `routes/web.rs` (lines 16448-16765: missing helpers `signed_form`/`loopback_ip`/`location`, `flash_text`
arity). After K2's block landed: 23 matched, **22 passed / 1 failed**. The two initial reds
(`k2_auth_surface_scopes_are_issued`, `challenge_issuance_persists_and_rate_limits_per_ip`) were the 32-byte
secret-floor drift (§6.1) on the 16-byte fixture; K2 fixed the fixture in place and both now pass. Current single
red:

```
FAIL api-server routes::web::tests::db_backed::wave_d_auth_gate_tests::public_auth_forms_enforce_csrf_and_kiwi_gates
     panicked at routes/web.rs:16410: "/web/auth/resend-verification must stay PRG on CSRF refusal"  left: 404  right: 303
```

This is K2's in-flight `resend-verification` route/test (route not yet registered), not mirror-related. Per the
orchestrator's sequencing instruction this run is **PENDING the orchestrator's ping** for a final green run against
the settled tree; everything else in the battery is final.

### 7.4 `cargo nextest run -p integration-tests` (schema_contract / concurrency)

The literal filter is name-based and matched 0 tests in this crate (those tests are entire binaries:

```
$ cargo nextest run -p integration-tests -E 'test(kiwi) | test(schema_contract) | test(concurrency)'
    Starting 0 tests across 14 binaries (184 tests skipped)  -> rc=4 "no tests to run"
```

so the meaningful equivalent was run with the same env:

```
$ cargo nextest run -p integration-tests -E 'binary(schema_contract_tests) | binary(concurrency_tests)'
    Starting 27 tests across 2 binaries (12 binaries skipped)
    Summary [22.2s] 27 tests run: 27 passed, 0 skipped      (19 schema_contract + 8 concurrency)
```

including `register_http_ceremony_persists_tenant_user_and_queue` (live signup through the API with the refreshed
mirror).

### 7.5 Browser suite (`tests/browser`) — GREEN

```
$ cd tests/browser && npm ci && BROWSER_TEST_BASE_URL=http://127.0.0.1:8080 ./node_modules/.bin/playwright test
```

Run 1 (before A2): 437 passed / 3 failed / 4.1m — `execution-v6-portable.spec.mjs` ×2 and
`migration.spec.mjs` (Turnstile siteverify `internal-error`), all traced to the stale vendored copy (A2).
Targeted re-run of the two spec files after A2: **39 passed (1.2m)**. Full re-run after A2:
**440 passed / 0 failed / 2.6m, rc=0** (`/tmp/k1-evidence/25-playwright-full-rerun.txt`). The suite runs against
its self-hosted PHP fixture on 127.0.0.1:8085 (see §6.3); `npm ci` rc=0 (playwright 1.62.1, chromium present).

### 7.6 Formatting

No ApexMail-side Rust was edited by this lane (the API compiled unchanged), so `cargo fmt` had nothing to format;
the A1/A2 changes are JSON/Lua/TSV/PHP/JS data and local ignored artifacts.

## 8. Zero-skips appendix

| # | Brief step | Status | Evidence |
|---|---|---|---|
| 1 | `git fetch`; `rev-parse HEAD origin/main` (expected ab1316b7) | DONE — ab1316b7; head later moved to 25f0d05e, handled (§2) | §2; /tmp/k1-evidence/01, 18 |
| 2 | `git status --short`; no changes that alter mirrored bytes; record dirt | DONE — mirror surface clean at refresh; tools/redteam dirt recorded; later 10→27 uncommitted upstream files recorded, none mirrored | §2; 18-upstream-head-move-and-dirt.txt |
| 3 | Record mirrored sha + `Cargo.toml` version | DONE — content ≡ 25f0d05e ≡ ab1316b7 (six subtrees object-identical); version 1.7.0 | §1, §2 |
| 4 | Derive the precedent include/exclude set per-file from c10db774 / ab4a6db0-style history | DONE — tracked set exactly (599/599); excludes target/node_modules/vendor/pkg/test-results; caches/locks never tracked (on-disk artifacts refreshed) | §3 |
| 5 | BEFORE `diff -rq` inventory per dir, saved | DONE — 749-line inventory, per-dir table | §4.1; 03-before-diff-inventory.txt |
| 6 | Replace with `rsync -a --delete` byte-identical copies | DONE — itemized logs for all six dirs | §4.2; 04-rsync-itemize-*.txt |
| 7 | AFTER `diff -rq` clean for every dir | DONE — all six exit 0, 0 lines | §4.2; 05-after-diff-proof.txt |
| 8 | Embedded widget resources byte-identical to canonical upstream | DONE — 4/4 (sha256 + git blob) at resources/ = wasm/assets = symfony/public = upstream | §4.4 |
| 9 | ApexMail-side call-site adaptations only if needed; minimal, documented | DONE — none needed for compilation (rc=0); three documented ApexMail-side repairs (protocol/, vendored copies, lock restore) | §5, §7.2 |
| 10 | `cd packages/kiwicaptcha && cargo test` | DONE — 370/0/0, 18 targets; pristine replica 370/0/0; Redis lane 101/102 with the one red upstream-inherent | §7.1 |
| 11 | `cargo check -p api-server -p integration-tests` | DONE — rc=0 (2m05s) | §7.2 |
| 12 | `cargo nextest run -p api-server --lib -E 'test(kiwi)|...'` | IN PROGRESS — 22/23; last red is K2's in-flight resend-verification route (404 vs 303). Final run pending the orchestrator's ping | §7.3 |
| 13 | api-server test env (`TEST_DATABASE_URL`, admin URL, `TEST_REDIS_URL`) | DONE — all runs used the exact env (password read from `secrets/postgres_password.txt`) | §7.3-7.4 |
| 14 | `cd tests/browser && npm ci && ... playwright test` | DONE — 440 passed / 0 failed / rc=0 after A2; failures before A2 root-caused and evidenced | §7.5 |
| 15 | `cargo fmt` on touched ApexMail Rust | N/A — no ApexMail Rust touched | §7.6 |
| 16 | No `git commit`; don't touch docker-compose/routes | RESPECTED — index empty; K2's files untouched by K1 | header, §5 |
| 17 | Never edit `packages/**` / `tests/browser/**` upstream bytes | RESPECTED — tracked mirror bytes re-proven 0/1105 at the end; only ignored local artifacts (vendor/) and the ApexMail root `protocol/` were repaired | §4.2, §5 |

## 9. Fold-commit inventory (what the orchestrator should stage)

- Six mirrored dirs: **470 new files, 374 modified, 2 deleted** (per-dir table in §4.3). With porcelain's default
  untracked view these collapse into 344 directory-level entries — the all-files count is the correct staging set.
  Of the 470, 395 are under `packages/**` (204 kiwicaptcha, 42 php, 48 risk, 98 risk-php, 3 wasm) and 75 under
  `tests/browser` (two orchestrator-referenced subset figures, 312/131, are collapsed-view artifacts).
- Root `protocol/`: **27 new files, 12 modified** (§5-A1 list).
- Deletions to record: `packages/kiwicaptcha-php/tests/ShortSecretRefusalTest.php`,
  `packages/kiwicaptcha/examples/quickstart.rs`.
- Ignored/untracked artifacts that must NOT be staged (verified ignored): `packages/**/vendor/**`,
  `**/.phpunit.result.cache`, `packages/kiwicaptcha-php/composer.lock`,
  `packages/kiwicaptcha/integrations/symfony/composer.lock`, `**/target/**`, `tests/browser/node_modules/**`,
  `tests/browser/test-results/**`.
- If any Rust suite is re-run in place before staging, restore `packages/kiwicaptcha/Cargo.lock` to
  `efaed9e8741f0ce3664154bcfb3d5323a6fa6692` afterward (§5-A3).

## 10. Final orchestrator paragraph

Lane K1 has refreshed the entire KiwiCaptcha mirror surface to byte-identical upstream head bytes and proven it
three independent ways: filesystem (`diff -rq` empty on all six dirs), object-level (1105/1105 git blob shas equal
to `25f0d05e`, whose six subtrees are object-identical to the refresh-time `ab1316b7`), and worktree file-list
equality (1110/1110); the embedded widget resources are byte-identical across all three canonical locations. The
only ApexMail-side repairs were the stale root `protocol/` register (41/41 blob-identical after the refresh, and
exactly what the mirrored code reads), the stale Sep-13 local vendored path-package copies (ignored artifacts that
had been shadowing the refreshed sources in the browser fixture), and a disclosed one-file lock normalization and
restore — no mirrored tracked byte was ever edited, and no ApexMail call-site adaptation was needed to compile
(`cargo check` rc=0). The crate suite is green (370/0/0, plus a pristine-replica repeat), the schema-contract and
concurrency integration suites are green (27/27 live against Postgres/Redis), and the browser suite is green
(440/440, rc=0). Two items remain and are explicitly pending: the final `cargo nextest -p api-server --lib` run is
blocked only by lane K2's in-flight `resend-verification` route (current 22/23; the sole red is their test at
`web.rs:16410` asserting PRG while the route is not yet registered) — I will re-run it the moment the orchestrator
pings that K2 has landed, together with a browser re-run against the final tree if K2's KIWI_ENABLED flip warrants
one. One upstream-inherent defect is reported but deliberately not fixed (the `if version == 5` spine gate in
`src/execution.rs:629` versus `MAX_EXECUTION_VERSION = 6`, which makes one Redis-lane test fail on pristine
upstream bytes), and one cross-lane follow-up is noted: the 32-byte secret-floor mismatch was already fixed by K2
in flight (`config.rs` now validates against `kiwicaptcha::keys::MIN_MASTER_BYTES`; only
`.env.production.example:305` still documents the old 16+ floor). No commit was made; staging guidance is in §9.
