# fix-kiwicaptcha — captcha packages, adversarial fix pass (2026-10-06)

Slice owned: `packages/kiwicaptcha/**`, `packages/kiwicaptcha-wasm/**`,
`packages/kiwicaptcha-php/**`, `packages/kiwicaptcha-risk/**`,
`packages/kiwicaptcha-risk-php/**`, `protocol/risk-v1/**`.

Method: adversarial read of every verification/issuance path (Rust core, Redis
production verifier, PHP core, Symfony integration, WASM driver/worker, risk
engine Rust/PHP/Lua), parity gates, then each package's own suite with real
Redis (`RISK_REDIS_URL` / `KC_REDIS_URL` / `TEST_REDIS_URL` =
`redis://127.0.0.1:6379`) and the browser suite.

Baseline before fixes (working tree):

| suite | result |
|---|---|
| `cargo nextest` kiwicaptcha (+redis) | 400/400 PASS |
| `cargo nextest` kiwicaptcha-risk (+redis) | 230/230 PASS |
| `cargo nextest` kiwicaptcha-wasm | 1/1 PASS |
| phpunit kiwicaptcha-php (Redis env set) | 1121 tests, 0 fail, 4 skip (phpredis absent) |
| phpunit kiwicaptcha-risk-php (Redis env set) | 238/238 PASS |
| phpunit symfony integration (Redis env set) | 1547 tests, **2 errors + 1 failure** |
| asset parity gate / risk-Lua parity gate | OK |

Final (all runs serial — the Redis-backed suites share one Redis and
must not run concurrently; two concurrent runs produced spurious
cross-suite failures that both suites cleared when re-run alone):

| suite | result |
|---|---|
| `cargo nextest` kiwicaptcha (+redis) | 400/400 PASS |
| `cargo nextest` kiwicaptcha-risk (+redis) | 231/231 PASS (+1 regression test) |
| `cargo nextest` kiwicaptcha-wasm | 1/1 PASS |
| phpunit kiwicaptcha-php (Redis env set) | 1121 tests, 0 fail, 4 skip (phpredis absent) |
| phpunit kiwicaptcha-risk-php (Redis env set) | 239/239 PASS (+1 regression test) |
| phpunit symfony integration (Redis env set) | 1550/1550 PASS, 6 skip (recipe package not vendored in the repo) |
| browser `playwright test` (chromium default) | 220/220 PASS |
| browser `playwright.a11y.config.mjs` (chromium+firefox+webkit) | 240/240 PASS |
| browser firefox / real-chrome configs | 21/21 + 21/21 PASS |
| asset parity gate / risk-Lua parity gate | OK |

No NOT-FIXED items: every finding below is FIXED with a regression test.

---

## Findings

### F1 — [P1] Symfony config tree: secret-key validators reject `%env(...)%` secrets (own-suite regression)

**Where** `packages/kiwicaptcha/integrations/symfony/src/DependencyInjection/Configuration.php:47-55`
(`kiwi_captcha.secret_key`), `:428-435` (`risk.master_secret`), plus the
pre-existing same-shaped closures at `:717-724` (`risk.chaining.hmac_secret`)
and `:990-995` (`execution_key`).

**Evidence** Symfony's `ValidateEnvPlaceholdersPass` processes extension
configuration with the resolved env markers and lets `VariableNode::finalizeValue()`
throw when a node is *both* validated by a final-validation closure *and* not
allowed empty values:

```
InvalidConfigurationException: The path "kiwi_captcha.secret_key" cannot contain
an environment variable when empty values are not allowed by definition and are validated.
```

Reproduced by the bundle's own suite:
`RecipePackageValidationTest::testRecipeShapedConfigBootsAKernelAndPassesDoctorWithTheDsn`
and `::testUnresolvedEnvDsnFailsAtRuntimeNotAtContainerBuild` (2 errors), whose
recipe deliberately ships `secret_key: '%env(KIWI_CAPTCHA_SECRET)%'` — the
documented env-managed secret form. Verified by temporarily restoring HEAD's
`Configuration.php`: both tests pass at HEAD, error with the working-tree
validators. Same latent defect on `risk.master_secret` / `chaining.hmac_secret`
whose info strings explicitly recommend `%env(KIWI_RISK_SECRET)%`.

**Why** the working-tree change (previous fix pass) added `->validate()` closures
to nodes that legitimately receive env placeholders. Any deployment using the
documented env-secret form can no longer boot.

**Fix** placeholder-safe tree validation (drop `cannotBeEmpty()` and make each
closure tolerate `''`, the placeholder dummy value Symfony validates against;
there is no builder-level `allowEmptyValue()`), with the minimum enforced on the
resolved value at the consumption seam and a build-time literal lane in the
extension:
- `KiwiCaptchaExtension::createRiskKeys()` runtime factory refuses a resolved
  `risk.master_secret` under 16 bytes (Rust `RiskKeys::from_master` and PHP
  `RiskKeys::fromMaster` derive from any master without a length gate, so this
  is the only enforcement point for env-resolved masters).
- `ChainedChallengeTicketService` constructor refuses a resolved chaining
  secret under 16 bytes.
- `secret_key` resolved values are already refused by the core `Config`
  constructor, `execution_key` by `ExecutionChallengeGenerator::generate()`.

Status: **FIXED.**
- `Configuration.php`: `secret_key` drops `cannotBeEmpty()` and all four secret
  closures become empty-tolerant (`'' !== $v`), with the `%env()%` contract
  documented on the nodes. Literal short values are still refused at compile
  time.
- The extension adds the build-time literal lane: a literal `secret_key`
  under 16 bytes (including `''`, which must pass the tree for the placeholder
  form) fails at container build with the documented message; env markers are
  skipped and resolved at runtime.
- `KiwiCaptchaExtension::createRiskKeys()` added and wired as the
  `kiwi_captcha.risk.keys` factory: a resolved master under 16 bytes throws a
  typed `LogicException` at service construction (the only enforcement point
  for env-resolved masters — see the method doc).
- `ChainedChallengeTicketService::__construct()` refuses a resolved chain
  secret under 16 bytes.
- Regression tests: `ConfigurationTest::testResolvedRiskMasterSecretBelowTheMinimumFailsClosedAtRuntime`
  (guard + container-factory wiring), `ConfigurationTest::testLiteralEmptySecretKeyFailsClosedAtContainerBuildButEnvPlaceholdersPass`
  (literal lane + placeholder acceptance),
  `ConfigurationTest::testEnvPlaceholderIsAcceptedOnValidatedSecretNodes`
  (placeholder form accepted on all four nodes), plus the restored
  `RecipePackageValidationTest::testRecipeShapedConfigBootsAKernelAndPassesDoctorWithTheDsn`
  / `::testUnresolvedEnvDsnFailsAtRuntimeNotAtContainerBuild` (end-to-end
  `%env()%` secret boot). `ConfigurationTest` 134/134 PASS; both recipe tests
  PASS (12 assertions).

---

### F2 — [P2] Risk policy `global_floors` grammar: PHP accepted configs the Rust reference refuses (divergent acceptance)

**Where** `packages/kiwicaptcha-risk-php/src/RiskPolicy.php` (`fromConfig`, the
`global_floors` block) vs `packages/kiwicaptcha-risk/src/policy.rs:234-289`.

**Evidence** Rust requires `global_floors` present as exactly the five
canonical levels `0..4` (`PolicyError::InvalidGlobalFloors`, pinned by
`policy::tests::global_floors_require_exactly_five_entries`). PHP treated the
key as optional and merged `DEFAULT_GLOBAL_FLOORS` into whatever was supplied:

```
php -r "RiskPolicy::fromConfig(<config without global_floors>)"  -> ACCEPTED (defaults)
php -r "RiskPolicy::fromConfig(<floors 1..4, no level 0>)"       -> ACCEPTED (0 => allow implied)
```

so the same policy config was loaded by a PHP node and refused by a Rust node,
and an operator-omitted level was silently substituted with a built-in default
rather than surfaced. Note the Rust module doc example itself shows a `1..4`
map (Rust would refuse its own example) while every PHP test config supplied
`1..4`, confirming the two readers disagreed on the documented shape.

**Why** the brief's invariant: the PHP port must implement the same grammar
as the Rust reference — no divergent acceptance rules. A config one engine
loads and the other refuses splits a mixed fleet's policy silently.

**Fix** PHP now enforces the total grammar (five canonical levels `0..4`,
each exactly once, level 0 = `allow`; missing/partial/duplicated/out-of-range
shapes refused), matching Rust's acceptance set byte for byte. The Symfony
integration is unaffected in production (its extension always emits the five
levels); its tests' hand-built policy configs gained the canonical explicit
floor set (53 call sites across 17 files). The canonical README gained the
grammar clause.

Status: **FIXED.**
- Rust regression test: `policy::tests::global_floors_grammar_matches_the_php_port_acceptance_set`
  (same rejected shapes as the PHP test, canonical accepted).
- PHP regression test: `RiskPolicyTest::testGlobalFloorsRequireEveryCanonicalLevelExactlyOnce`.
- risk-php suite 239/239 PASS (was 238/238); Symfony suite re-run below.

---

### F3 — [P3] `kiwicaptcha-wasm/SECURITY.md` pinned a stale SRI hash in its copy-paste example

**Where** `packages/kiwicaptcha-wasm/SECURITY.md:48-49` (before fix).

**Evidence** the SRI example tag carried the literal
`sha384-osA8vjEQw8Gbqp8Z7Ap9Avv1rH03DOAJVKB7bFMvDSbgZ7N+UU7zFEdKrMfocdQR`, which
matches no current asset (`widget-driver.js` is currently
`sha384-nLVk4Wkpci6FHtuphlYMztE9WtxFgLSm+r9GSAEnyDiXHEoNz7fuM+FKMbdD7c4c`; no
asset matches the printed value). The example URL also still named
`v1.6.20` while the package is 1.7.0.

**Why** the document is the supply-chain guidance integrators copy; a
literal stale hash contradicts the document's own "do not copy values from
examples" rule and a copied value would block the asset (fail closed, but a
broken deployment that looks like a compromise). Low severity — the
authoritative SRI.txt/SHA256SUMS release artifacts are correctly pointed to.

**Fix** the example now uses the `sha384-<VALUE-FROM-SRI.txt>` placeholder
(consistent with the block above), the release path is `v1.7.0`, and a
sentence explains why the value is deliberately not literal.

Status: **FIXED** (docs only; no test can pin a placeholder hash — the CI
asset-parity gate plus `tools/sri-hashes.mjs` remain the byte-truth).

---

### F4 — [P3] One-off timing flake in `ExecutionChallengeDimensionTest` (test-side)

**Where** `packages/kiwicaptcha/integrations/symfony/tests/ExecutionChallengeDimensionTest.php::verifyWithRecord()`.

**Evidence** in the first full-suite run the version-3 grammar test failed
("the version-3 solve must verify") while passing in isolation and in all
later full runs: the helper called `verify()` without `$nowNs`, so the
server-measured minimum-duration floor (5 ms at 8 difficulty bits) was
measured against the wall-clock gap between issuance and the call — a gap
the test does not control.

**Why** a security-path test must not depend on host scheduling; a
`retries: 0` suite with a timing-dependent assertion reports false reds.

**Fix** the helper now passes a deterministic receipt 10 ms after the
stored `issuedAtNs` (asserting it is later), pinning the intended proof
verdict rather than the timing heuristic.

Status: **FIXED** — `ExecutionChallengeDimensionTest` 21/21 PASS (160
assertions); full-suite re-run below.

---

## Reviewed clean (adversarial checks that found no defect)

Recorded so the absence of a finding is auditable, not implied.

**Fail-closed verification order (Rust + PHP).** `verify_solution` /
`Verifier::verify` run shape → protocol gate → revoked-kid → kid resolution →
signature → Argon/RSW ceilings → TTL → scope → request binding → IP binding →
region/policy/issuer → execution binding → server-measured min duration →
proof → post-derive `final_revalidate` (fresh clock). Every missing input on a
bound check fails closed (`MissingClientIp`, `None` region/issuer vs an
expectation). `proof_is_valid` is algorithm-total: an RSW value on a
sha256/argon2id record is rejected without deriving a hash; counter != 0 or a
missing value on an RSW record is rejected; stray execution evidence on an
unarmed record is `ExecutionMismatch`, never ignored. Storage failures map to
`StorageUnavailable` / `ConsumeIndeterminate` (retryable), never to an allow.

**Crafted-token panic surface.** `SolutionToken::decode` pre-bounds the raw
bytes, requires canonical padded base64, exact 44-char/32-byte nonce, counter
< solver cap, duration ≤ 1 h, JSON-object telemetry, and canonical unpadded
base64url for the `digest:trace` tail; every failure is a typed `DecodeError`.
A scripted scan of non-test Rust found 15 `unwrap/expect/panic` sites; each was
read: HMAC/HKDF "cannot fail" invariants, `Rws` parity checks on values already
proven odd, and the execution graph expects that are guarded by
`nodes.contains_key` at every call site (`graph_detach` reaches its expect only
from arms that checked membership; `OP_DOM_CREATE`/`OP_DOM_CHILD`/`OP_DOM_CLONE`
register every node that can become `cur`). `decode()` rejects unknown/late
opcodes per version, ids shorter than 4 bytes, non-canonical base64 and trailing
bytes. No attacker-controlled index or slice is unguarded.

**Replay/consumption machinery.** Read the Redis production path end to end:
single runtime-state snapshot, cheap-failure fused `delete_if_pending` that
preserves consumed evidence, compositional `replay_security_check` before any
exempt-failure replay, atomic consume with `first` winner, operation-identity
gated stored-success replay, `ConsumeIndeterminate` on uncertain I/O, verified
WAIT barriers, three-checkout connection model. The `redis_verify` suite and
the real-Redis PHP suites (fault-injection, failover, worker-death, concurrency)
are green against a real Redis with the Lua consumers.

**Secrets.** Rust and PHP issuance and the generic verifier enforce the
documented 16-byte HMAC minimum; the PHP verifier has the per-call seam gate
and the Rust production verifier has the kid-resolution seam gate (both fixed
in the previous round, re-verified here). Debug/`__debugInfo` shapes redact the
secret, execution key and rsw lambda only where non-null. Config-tree minimums
for literal secrets are enforced for `secret_key`, `risk.master_secret`,
`risk.chaining.hmac_secret`, `execution_key`, `secrets_by_kid` and the
siteverify secret keys; env-resolved values are enforced at the consumption
seams (F1).

**Rate limiting.** `IssuanceRateLimiter` is a real sliding window (per-client +
deployment global) on Redis with `TIME` from the server and one Lua script per
decision; the non-Redis fallbacks keep a real global window and the local prune
uses `> cutoff` matching the Lua `ZREMRANGEBYSCORE ... -inf cutoff` boundary.
Backend failure raises and the controller answers 503 (fail closed); denials
cost nothing (no partial charge); the controller consults the limiter before
any issuance (rate-limit 429 codes are distinct from risk denials).

**WASM solver / JS fallback parity.** SHA-256 preimage is
`prefix || decimal counter || salt` in the wasm Rust, the pure-JS fallback and
the worker fallback; Argon2id uses the record's m/t/p with the same
`prefix || decimal counter` password and salt; RSW derives the base as
`SHA-256(prefix || nonce) mod n` and renders 512 hex. The driver dispatches on
the response's explicit `algorithm` field, validates the response against the
issuance contract, refuses downgrades, assembles the exact token grammar
(`nonce.counter.duration.telemetry[.digest:trace][.rsw512]`), and an armed
challenge without a working interpreter/worker enters the unavailable state
instead of a weaker fallback. The worker enforces the wasm protocol version
before `ready` and never solves Argon without wasm.

**Asset drift.** Canonical `packages/kiwicaptcha-wasm/assets` is byte-identical
to both mirrors (`packages/kiwicaptcha/resources`,
`integrations/symfony/Resources/public`); the parity gate passes; the
`release-assets.txt` list matches the 9 canonical assets; no literal SRI value
remains in the docs (F3).

**Risk engine parity.** All 10 Lua scripts byte-identical across
`protocol/risk-v1`, `kiwicaptcha-risk/resources`, `kiwicaptcha-risk-php/resources`
(mechanical md5 check and `tools/check-risk-lua-parity.sh`, which also pins
SolveSuccess trust-neutrality). 21 event kinds kind-for-kind in Rust and PHP.
Scoring is integer-only in both; fixtures (22 vectors) and fuzz corpora pass;
HKDF identity anchors match; hysteresis/capacity ordering is
ladder → strongest(minimum, floor) → argon capacity, identical in
`policy.rs` and `RiskPolicy.php`. Protocol constants cross-checked
Rust↔PHP (TTL 300, skew 60, solver cap 5M, difficulty 1..20, Argon t 3..6
issuance / 3..16 verification, m ≤ 65536, p 1..4, RSW T 10k..300k, protocol
version 4, duration ceiling 3.6M) — all equal. The one divergence found
(`global_floors` grammar, F2) is fixed.
