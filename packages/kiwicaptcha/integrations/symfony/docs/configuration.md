# Configuration

The bundle is configured under the `kiwi_captcha` key in
`config/packages/kiwi_captcha.yaml`. Every option is shown below with its
default and validation. Options are validated at container-compile time where
possible; the same bounds are enforced by the core package at runtime.

## Quick start (verified flow)

An ordinary installation configures four keys and nothing else. The
profile fills every safety-relevant default, the secret comes from the
environment, and the DSN builds every Redis-backed service:

```yaml
# config/packages/kiwi_captcha.yaml
kiwi_captcha:
    protection_profile: balanced   # balanced | privacy_strict | high_abuse | compatibility
    secret_key: '%env(KIWI_SECRET_KEY)%'
    public_base_url: '%env(KIWI_PUBLIC_URL)%'
    redis_dsn: '%env(KIWI_REDIS_DSN)%'
```

- `.env`: `KIWI_SECRET_KEY` (generated), `KIWI_REDIS_DSN` and
  `KIWI_PUBLIC_URL` (localhost defaults), all written by the Flex
  recipe; see [flex-recipe.md](flex-recipe.md).
- `redis_dsn` and `public_base_url` are env-managed (twelve-factor):
  credentials, private hosts, TLS endpoints and database selection
  belong in your environment or secrets manager, never in
  source-controlled config files. The container resolves the
  placeholders; the bundle validates the resolved DSN (redis:// or
  rediss:// with a host, fail-closed) when the client is constructed.
  A literal override in
  this file is still possible and keeps the same validation.
- `public_base_url` carries the same canonical-origin contract in both
  forms.
  A literal is validated at container build time.
  An env-resolved value is validated with the identical rule when the
  challenge controller is constructed at runtime: https only, a host,
  no credentials, no path, no query, no fragment.
  An invalid resolved origin fails closed with an error naming
  `kiwi_captcha.public_base_url`.
- Predis is a direct dependency of the bundle, so the DSN path works
  out of the box; no separate client install is needed.
- The Flex recipe ships this exact file; see
  [flex-recipe.md](flex-recipe.md).

Boot check: `bin/console kiwicaptcha:doctor` reports one status per
check and exits non-zero on any failure. The minimal config above must
reach `[PASS] Redis reachability`, `[PASS] Storage atomicity` and no
`[FAIL]` row; every remaining `[WARN]` row names the deployment
decision still open.

What the DSN builds: the challenge storage
(`KiwiCaptcha\Storage\RedisStorage`, atomic, so the production storage
guard passes), the distributed issuance rate limiter, the Argon2id
admission semaphore and, under `high_abuse`, the risk state store. An
explicit service id wins over the DSN for its knob (`storage`,
`redis_service`, `risk.redis_service`); see "Advanced configuration"
below.

## Protection profiles

Ordinary deployments operate at the policy level: set one
`protection_profile` and let the bundle derive the safety-relevant knobs
you do not set. The profile fills **safe derived defaults** for the knobs
it governs. With `protection_profile: null` (the default) every knob
keeps its individual default and behavior is byte-identical to the
pre-profile configuration.

**The profile is the LOWEST-precedence configuration layer.** Symfony
merges your config files in order, so the bundle applies the profile as
the first, weakest layer of that merge: an explicit value in **any**
config file always wins over the profile. This matters for layered
configurations:

```yaml
# config/packages/kiwi_captcha.yaml
kiwi_captcha:
    protection_profile: high_abuse
    rate_limit: 1          # explicit: wins over the profile's rate_limit 5

# config/packages/prod/kiwi_captcha.yaml
kiwi_captcha:
    rate_limit: 100        # a LATER layer's explicit value also wins
```

```yaml
# config/packages/kiwi_captcha.yaml
kiwi_captcha:
    protection_profile: high_abuse

# config/packages/prod/kiwi_captcha.yaml
kiwi_captcha:
    protection_profile: compatibility   # the LAST profile wins
```

```yaml
# config/packages/kiwi_captcha.yaml
kiwi_captcha:
    protection_profile: compatibility   # dev compatibility posture

# config/packages/prod/kiwi_captcha.yaml
kiwi_captcha:
    protection_profile: null            # explicit null CLEARS the profile
```

The layering semantics:

- The **final profile** is the last config layer containing the
  `protection_profile` key; later layers override earlier ones. An
  explicit `null` is a real selection: it clears the profile, its
  derived defaults are dropped, and the visible `protection_profile`
  field reports null in lockstep — the effective behavior always
  corresponds to the visible field. A prod overlay can therefore
  neutralize a dev compatibility profile with `protection_profile:
  null`.
- The profile fills its derived defaults only where no layer set the
  knob explicitly. The profile defaults are the first array of the
  merge, so a later layer that carries only `protection_profile` can
  never override an explicit setting from an earlier layer. A base
  `rate_limit: 1` stays 1 under a prod `protection_profile: high_abuse`
  overlay, and the profile's other defaults still apply where no layer
  set them.
- Nested values merge key-by-key: an explicit `risk.weights.replay` in
  one layer wins, and the profile still fills the other weights.
- `high_abuse` chained step-up engages when
  `risk.request_binding_authority` is wired in **any** layer; the
  conditional is evaluated on the final merged configuration. Without
  an authority anywhere, chaining stays off. An explicit
  `risk.chaining.enabled` always wins, and an explicit `true` without an
  authority is still refused at compile time.

```yaml
kiwi_captcha:
    protection_profile: balanced   # balanced | privacy_strict | high_abuse | compatibility | ha_safe
```

| Knob | balanced | privacy_strict | high_abuse | compatibility | ha_safe |
|------|----------|----------------|------------|---------------|---------|
| `algorithm` | sha256 | sha256 | sha256 | sha256 | sha256 |
| `difficulty_bits` / `argon2_difficulty_bits` | 18 / 8 | 18 / 8 | 18 / 8 | 18 / 8 | 18 / 8 |
| `argon_m_kib` / `argon_t` / `argon_p` | 0 / 3 / 1 | 0 / 3 / 1 | 0 / 3 / 1 | 0 / 3 / 1 | 0 / 3 / 1 |
| `challenge_ttl_secs` | 120 | 120 | 120 | 300 | 120 |
| `rate_limit` | 10 | 10 | 5 | 10 | 10 |
| `rate_limit_global` | 500 | 500 | 2000 | 500 | 500 |
| `resource_capacity.issuance_per_second` | 500 | 500 | 2000 | 500 | 500 |
| `privacy_mode` / `telemetry` | strict / off | strict / off | strict / off | strict / off | strict / off |
| `enforce_telemetry` | false | false | false | false | false |
| `min_duration_ms` | derived | 0 | derived | derived | derived |
| `binding_mode` | nonce_ip_hmac | none | nonce_ip_hmac | none | nonce_ip_hmac |
| `risk.enabled` | false | false | true | false | false |
| `risk.decoy_v3_enabled` | false | false | true | false | false |
| `risk.client_context` | false | false | false | false | false |
| `risk.execution_challenge` | off | off (forced) | on | off | off |
| `risk.max_outstanding_challenges` | 20 | 20 | 10 | 20 | 20 |
| `risk.max_outstanding_challenges_global` | 100000 | 100000 | 250000 | 100000 | 100000 |
| `risk.hard_limits.process_per_second` | 10000 | 10000 | 5000 | 10000 | 10000 |
| `risk.weights.bad_proof / malformed / replay / action_failure` | contract | contract | 320 / 340 / 380 / 160 | contract | contract |
| `replay_durability` | best_effort | best_effort | best_effort | best_effort | operator_managed |
| `ha_authority` | none | none | none | none | pinned_primary |

Profile rationale:

- balanced is the current default configuration, documented as such.
  Picking it changes nothing: the derived values equal the tree defaults,
  so behavior is byte-identical to no profile.
- privacy_strict is the strongest first-party privacy posture. The
  binding tag is dropped (`binding_mode: none`), so no IP-derived state
  exists anywhere. Every behavioral evidence surface stays off and the
  server-side solve-timing heuristic is disabled (`min_duration_ms: 0`).
  Trade-off: relay protection is off, as documented on `binding_mode`.
- high_abuse is for public signup/login surfaces under attack. Risk
  is enabled, so it requires a Predis client and the extension fails
  fast without one. The abuse-evidence weights rise, so proven abuse
  outvotes trust signals sooner. Per-source limits tighten and the
  aggregate issuance bounds widen in lockstep. The decoy surface arms
  with protocol-v3 emission, which only engages once the central
  `min_protocol_version` floor confirms (>= 3). The ExecutionChallengeV1 gate
  arms (see the "ExecutionChallengeV1" section below) once the floor
  confirms >= 4, writing protocol-v4 records with the signed execution
  commitment. Chained-
  challenge step-up engages automatically when
  `risk.request_binding_authority` is wired in any configuration layer
  (the conditional runs on the final merged configuration).
- compatibility maximizes integration compatibility: sha256, a
  conservative 300 s TTL (Turnstile token-lifetime parity), binding off
  (IP churn behind NAT/mobile), risk and the decoy surface off
  (protocol-v2 emission), no behavioral coupling.
- ha_safe is the replay-safe HA posture: the deployment that wants the
  authority-change contract mechanically enforced instead of only
  contracted. It derives `replay_durability: operator_managed` +
  `ha_authority: pinned_primary` and mirrors balanced everywhere else.
  The pinned-primary authority guard is initialized explicitly
  (`php bin/console kiwicaptcha:ha-initialize`, or by provisioning
  `ha_authority_expected`; production never auto-pins). It refuses on
  any authority change. The doctor reports its state
  and fails the deploy gate when the authority moved or the guard is
  unarmed. Requires a direct single-node Predis client (a Predis
  Sentinel/Cluster aggregate or a phpredis client is refused at
  container build time). See the "HA authority" section below and
  docs/ha-authority.md.

The profiles never override an explicitly configured knob: the profile
defaults are merged as the lowest-precedence layer, so they apply only
where the key is absent from your configuration. `protection_profile:
null` (the default) selects no profile, and any value outside the five
names is refused.

## HA authority: the mechanical replay-safety posture

```yaml
    # ── Authority-change replay safety ────────────────────────────────
    # replay_durability: best_effort    # best_effort | operator_managed | fail_closed
    # ha_authority: none                # none | pinned_primary
    # ha_authority_reverify_secs: 5     # the guard's verification cache window
    # ha_authority_expected: null       # "role|run_id", or a per-authority map (optional)
```

`replay_durability` declares the authority-change contract (see
redis-topologies.md). `ha_authority: pinned_primary` makes it
mechanical: the bundle wires the PinnedPrimaryAuthorityGuard around
the storage/limiter/risk client, so the deployment can choose a
mechanically enforced replay-safe HA mode instead of trusting the
operator alone.

How the pinned-primary guard behaves:

- Per distinct Redis authority the bundle wires one guard and one pin:
  the storage/limiter authority pins `{kiwi:<ns>}:authority:pin:storage`
  and a distinct `risk.redis_service` pins
  `{kiwi:<ns>}:authority:pin:risk`, each holding "role|run_id"
  write-once (`SET NX`) in the same security-Redis namespace as every
  other bundle key. A risk client that IS the storage client shares
  the storage pin.
- The runtime never auto-pins: an operator records the initial
  authority pin through the explicit bootstrap command
  `php bin/console kiwicaptcha:ha-initialize`; a guard with no pin and
  no `ha_authority_expected` refuses every use with the initialize
  message.
- On every use it re-verifies the serving authority: the role must
  equal the pinned role and the run_id must equal the pinned run_id.
  Any change — a promotion to a stale replica, a restarted primary
  with a new run_id, a re-pointed endpoint — raises the typed
  LogicException naming the pinned vs observed identity, and the
  deployment refuses to serve.
- `ha_authority_expected` (optional) is the operator-provisioned
  "role|run_id" identity. When set, the guard compares the serving
  authority against it instead of the pin key: the configuration IS
  the pin, and an immutable-identity deployment can skip the Redis pin
  entirely. Two forms are accepted:
  - the scalar string form applies the one identity to every authority
    (`ha_authority_expected: "master|<run_id>"`);
  - the per-authority map form applies a different identity to each
    authority: `{"storage": "master|<run_id>", "risk":
    "master|<run_id>"}`. This is the correct form for a deployment
    whose storage Redis and risk Redis are different servers (one
    scalar run_id cannot describe two authorities). When only one
    Redis is used, the storage entry covers the shared authority; an
    authority without an entry falls back to the pin key (it must be
    initialized). A shared physical authority must have exactly one
    expected identity: if storage and risk resolve to the same Redis
    client, supplying different identities for them is rejected at
    configuration time (the same identity may be repeated for both).
- The verification result is cached in-process per connection object
  for `ha_authority_reverify_secs` seconds (default 5), so the `INFO`
  probe costs one round trip per window per process per connection,
  not one per operation. A reconnect that replaces the connection
  object invalidates the cache. The components execute their Lua
  through the typed RedisSecurityCommandExecutor seam
  (docs/ha-authority.md). The seam's security-final lane (the
  siteverify finalize, the chain transitions, the post-solve final
  disposition) bypasses the window and re-verifies before every write
  (zero stale). The read and mutation lanes serve within the window.
- A missing pin after it was established is a refusal, never a silent
  re-pin. Re-pin explicitly after a deliberate authority change:
  quiesce the deployment, then run
  `php bin/console kiwicaptcha:ha-initialize --force` to record the
  new authority.
- The extension refuses the container build when the client is a
  Predis Sentinel/Cluster aggregate or a phpredis `\Redis` client:
  only a direct single-node Predis client can be mechanically guarded
  (predis/predis is a direct bundle dependency). A retry-enabled
  direct client is refused by the guard at runtime.

The doctor's "HA authority" check audits every distinct authority and
reports the guard state: the pinned identity, the last verification
and the posture. It passes when every guard is armed and stable. The
pass output states exactly what the guard enforces: per-authority
pins, zero-stale security-final transitions, the verified-WAIT
durability session (the causal fence write and the WAIT under the
same authority epoch as the mutation), connection-generation cache
invalidation, and the operator-initialized bootstrap. It fails on a
changed authority, an uninitialized deployment (naming
`kiwicaptcha:ha-initialize`), or an unarmed guard under the posture,
and it fails when the ha_safe profile's pinned_primary promise was
overridden away. See docs/ha-authority.md for the full design and the
deployment table.

Readiness under the posture: `/health/ready` forces a fresh guard
check per wired authority (the security-final lane, never the
ordinary verification window). A pod whose pin is uninitialized or
whose authority changed leaves the pool immediately with the
machine-readable reason `ha_authority_uninitialized` /
`ha_authority_changed` / `ha_authority_unreachable` (503). With
`ha_authority: none` the leg passes silently. See the operations
documentation for the health endpoints.


## ExecutionChallengeV1: the browser-execution dimension

ExecutionChallengeV1 is the Cap-style supplementary evidence layer of
the challenge stack. When armed, the challenge response carries an
`execution_program`, a deterministic bytecode blob. The widget driver
lazily loads the fixed audited interpreter asset,
`execution.<sha256>.js`, served by the immutable content-addressed
asset route with SRI. It runs the program in an ephemeral sandboxed
iframe (srcdoc with the `allow-scripts` and `allow-same-origin`
sandbox flags) and appends the resulting execution digest to the
solution token. The sandbox is DOM and execution isolation for the
first-party interpreter, whose bytes the content-addressed URL and
the native SRI check pin; it is not a hostile-code security
boundary. The verifier recomputes the expected digest from the stored
program and rejects a mismatch with the deterministic
`execution_mismatch` outcome.

Current status: the dimension is experimental and carries the
version-1 through version-4 grammars. Version 1 is the
construction-to-probe grammar. Version 2 adds the causal-consistency
semantics: every issued program opens with a guaranteed causal graph
(DOM construction: createElement, a mutate op, an append; a u8 array;
an observe op measuring the real layout height of the constructed
node). The observed byte lands in the u8 state, is read back, and is
checksummed or rotated over, so later exact entries and the final
digest depend on the browser-observed value. Version 3 adds a second
constructed node and the sibling-index traversal probe, a real DOM
walk over the built siblings. Version 4 builds a real nested tree
(two child nodes created under the current node) and probes the
deepest child with an ancestor-depth walk. The verifier replays the
whole graph forward from the reported value, checking bounds,
structure and whole-trace coherence; a short pure synthesis that
skips the write-through is rejected. The observed height is a genuine
browser measurement: the interpreter styles the probed node as a
fixed-width block rendering a canonical text line, so the value is
the engine's own default-font metrics. The mirrors never predict it;
their browser-equivalent traces use a fabricated reference value. In
short: the first-party client exercises real browser layout across
execution versions 2 through 4, while verification currently
establishes causal trace consistency with the claimed observation,
not cryptographic provenance of the layout values themselves. A
solver that implements the full public semantics can still fabricate
a coherent trace: the values are evidence, not a cryptographic proof
of a browser.

The dimension is controlled by these knobs:

- `kiwi_captcha.execution_key` (string, default null): the keyed-PRF
  secret that generates the programs. Null means execution challenges
  are never issued. The key never leaves the server: it only feeds the
  program generator, and the browser digest uses the program blob
  itself as its content-derived key, so rotating the key does not
  invalidate outstanding challenges.
- `risk.execution_challenge` (enum, default off): the issuance gate.
  When on, issuance arms the dimension when a risk trigger passes: a
  non-Allow risk decision, or every issuance when the risk engine is
  not wired. The two-phase protocol-v4 rollout gate applies: the
  confirmed central `min_protocol_version` floor must be >= 4 (the
  decoy surface separately requires >= 3), otherwise issuance stays
  execution-unarmed with a once-per-process warning. An armed issuance
  writes protocol v4: the record carries the signed execution
  commitment (hex SHA-256 of the stored program) inside the HMAC
  canonical, so stripping, substituting or injecting a program always
  invalidates the challenge. The gate is inert without an
  `execution_key`, so turning it on before configuring the key never
  breaks issuance and never arms anything.
- `kiwi_captcha.execution_required_version` (int 1..4, default 1):
  the server-owned required execution tier. When set above 1, an
  execution-armed request from a client below that tier is refused
  with the deterministic `CLIENT_EXECUTION_VERSION_UNSUPPORTED`
  outcome and is never downgraded to a weaker grammar. Raise it only
  after the fleet is fully on the destination generation (the cap
  above and the central `min_execution_version` floor at that tier
  everywhere).
  `kiwi_captcha.execution_min_required_version` is the semantic alias
  of this option: both spellings set the same value, and setting both
  to different values is refused as a configuration error. The legacy
  spelling stays valid through the one-major-version compatibility
  window, so an existing deployment never needs to change its config.

- `kiwi_captcha.execution_version` (int 1..4, default 1): the
  node's execution-program grammar cap. Version 4 is the nested-tree
  grammar: the child opcode (35) builds nodes under the current node
  and the depth probe (36) walks the real ancestor chain. Version 3
  is the sibling-index traversal grammar (opcode 34); version 2 is
  the causal observe grammar (opcode 33); version 1 is the
  construction-to-probe grammar every interpreter generation runs. A
  node emits a version above 1 only when the client advertised at
  least that version with the challenge request (the
  `Kiwi-Execution-Max-Version` request header), this cap is raised to
  it, and the confirmed central security-policy floor
  (`{kiwi:<ns>}:security-policy` `min_execution_version`) reaches it.
  The current widget driver sends the header when the execution tier
  is configured.
  Every other combination emits version 1, so a mixed fleet of older
  binaries and stale open pages is never handed the newer grammar.
  The cap defaults to 1: raising it declares the node ready to write
  the newer grammar, and the counterpart central floor is declared by
  the operator, see operations.md "Execution versioning".
  `kiwi_captcha.execution_max_version` is the semantic alias of this
  option, with the same both-spellings rule as above.

- `kiwi_captcha.execution_allow_downgrade` (bool, default false): the
  explicit downgrade-window escape hatch. The `high_abuse` profile
  arms the execution gate by default while the required tier defaults
  to 1, so raising the node cap alone would put the strongest abuse
  profile on a silently client-downgradeable grammar. When the
  profile is `high_abuse`, `risk.execution_challenge` is on and the
  required tier is below the node cap, the configuration is refused at
  compile time unless this flag is explicitly true. Set it to true
  only to accept the deliberate downgrade window during the fleet
  transition. The flag only lets the configuration compile: the
  doctor's posture audit accepts a downgrade window only while
  `protocol_rollout.mode: migration` is declared, and high_abuse in
  the normal state must require the strongest confirmed tier, see
  operations.md "Execution versioning".

The dimension is supplementary evidence only. It is never the sole
acceptance boundary: the proof-of-work proof and the record state
machinery always gate, and a missing or wrong digest fails with the
deterministic `execution_mismatch`, never a silent success. The
interpreter is a fixed audited bytecode VM with no eval and no new
Function. Its only browser-observed input is the observe op's byte:
the challenge-scoped layout height of the default-font text line. It
constructs no persistent device fingerprint. The DOM ops run in an
ephemeral sandboxed iframe (srcdoc with the `allow-scripts` and
`allow-same-origin` sandbox flags) created per challenge and removed
after the run. The iframe is containment for the first-party pinned
interpreter, not a hostile-code security boundary. A
SHA-only challenge without a program pays zero bytes for the
interpreter: the asset is fetched only when an armed challenge
arrives.

Profiles: the gate defaults off under `balanced` and
`compatibility`, it is forced off under `privacy_strict` (an explicit
override cannot re-arm it under the profile), and it defaults on under
`high_abuse`. An explicit `risk.execution_challenge` value in any
config layer always wins over the balanced and high_abuse derived
defaults; only privacy_strict keeps the force. Under `high_abuse`
with the gate on, an armed required tier below the node cap is
refused at compile time unless `execution_allow_downgrade` is
explicitly true. The balanced and privacy_strict profiles never apply
that compile-time invariant, yet their required tier is still audited
against the effective fleet tier by the doctor and the readiness
probe, see operations.md "Execution versioning".

## RSW time-lock: the optional sequential proof (experimental)

The rsw algorithm is an optional Rivest-Shamir-Wagner style time
lock, a sequential-cost rung of the proof ladder. The widget worker
performs T sequential modular squarings of a challenge-derived base
over a 2048-bit composite modulus. The server verifies instantly
through the factorization trapdoor, so verification cost stays
constant while the client cost scales linearly with T. The rung is
off by default: the algorithm stays sha256, no deployment needs the
rsw options, and every existing issuance path keeps its exact byte
shape. Issue rsw challenges only when the operator generated a
modulus and configured both secret fields below.

```yaml
# config/packages/kiwi_captcha.yaml
kiwi_captcha:
    secret_key: '%env(KIWI_SECRET)%'
    algorithm: rsw            # opt-in: sha256 (default) | argon2id | rsw
    rsw_modulus_n: '%env(RSW_MODULUS_N)%'   # base64 of n = p*q, 256 bytes
    rsw_lambda: '%env(RSW_LAMBDA)%'         # base64 of lcm(p-1, q-1)
    rsw_t: 75000             # sequential squarings, 10000..300000
```

### Modulus setup

Generate the pair exclusively with the shipped offline generator
[`tools/rsw-keygen`](../../../../../tools/rsw-keygen/README.md). The
tool draws two independent random 1024-bit primes, requires their
product to be exactly 2048 bits, and computes lambda = lcm(p-1, q-1).
It runs the trapdoor self-test against the shipped math before it
emits anything. Do not assemble n and lambda from ad-hoc prime
generation. No configuration validator can prove that a modulus was
securely built from two large primes, so the provenance of the pair
is the whole assurance.

Configure n as rsw_modulus_n and lambda as rsw_lambda, both canonical
standard base64 of the big-endian bytes. The keygen prints both the
hex and the base64 forms of each value. The modulus is public: it
rides the challenge response, because the client squares modulo it.
Lambda is the secret trapdoor and must never leave the server
configuration. Never share it with client material, logs, or any
record. The primes p and q are never stored anywhere in KiwiCaptcha
and appear only in the keygen's explicit --diagnostic output. Run the
generator on an offline trusted machine and keep that output out of
the repository.

Record the modulus fingerprint printed by the keygen
(rsw_modulus_n_sha256, the sha256 of the canonical 256-byte n). It is
the way to state which modulus a deployment holds. The command
`rsw-keygen --fingerprint` recomputes it from a configured n, and a
redeployment audit compares the two. Validation refuses the weak
shapes up front: an even or mis-sized modulus, a modulus with a small
prime factor, and a probable-prime modulus are configuration errors
at boot. So is a lambda that fails the deterministic consistency
spot-check `base^lambda == 1 (mod n)` over the fixed small-prime
base set (2, 3, 5, 7, 11, 13, 17 and 19). The spot-check is not a
proof that lambda is the true Carmichael value of n: only the keygen
p/q construction guarantees that. The full lcm relation still cannot
be verified without the primes, which is why the keygen provenance
and the fingerprint matter.

### The sequential cost T

rsw_t is the number of modular squarings the client performs, the
time-lock's difficulty knob. The validated range is 10,000..300,000:
below the floor the cost is immaterial, and the ceiling is a protocol
bound, not a device-performance claim: it keeps a legitimate solve
inside the challenge lifetime while the sequential cost stays
material. The per-deployment T choice must be derived from
measurements on the worst device the deployment supports, and the
qualification state must be documented; the client-performance lab
measures the real rsw rungs and documents the release-gate procedure
(`tools/client-perf/README.md`). There is no target-bits
concept: the proof is deterministic, so the signed canonical carries
the pinned protocol-floor value in the difficulty slot, and the
verifier checks the exact final value instead of leading zeros.

### Where the rung sits

The proof ladder keeps its ordinary rungs: probabilistic SHA-256 at
the floor, memory-hard Argon2id above it, and the optional
execution dimension as supplementary Cap-style evidence. The rsw rung
adds a different axis: fully sequential work with deterministic
verification. It resists the precomputation that weakens
difficulty-based proof when the same challenge prefix repeats, since
every challenge derives a fresh base from its signed prefix and
nonce. It is not memory-hard and not probabilistic, so it is a
complement to the other rungs, never a replacement for them. The
verifier needs the matching modulus and lambda configuration; an rsw
record redeemed against a verifier without the pair fails with the
deterministic unsupported_rsw_params outcome, and the risk layer
(risk-engine.md) does not combine with the rung. Expect the rung to
stay optional with sha256 as the default.

## Advanced configuration


The per-knob reference below is the advanced layer. Most deployments set
only a `protection_profile`, `secret_key`, `public_base_url` and
`redis_dsn`, and never touch these knobs. Every option stays available
and documented; a knob set explicitly always wins over the profile.

### Base configuration

```yaml
kiwi_captcha:
    secret_key: '%env(KIWI_SECRET_KEY)%'   # required, min 16 bytes
    algorithm: sha256                       # sha256 | argon2id
    difficulty_bits: 18                     # SHA-256 leading zero bits (18 = the ordinary default; 20 = the elevated rung, reached via adaptive risk escalation)
    argon_m_kib: 0                          # Argon2id memory (KiB); 0 = sha256 only
    argon_t: 3                              # Argon2id requires t >= 3 and p == 1
    argon_p: 1
    challenge_ttl_secs: 120
    route_prefix: /kiwi-captcha             # challenge endpoint prefix; the form
                                            # widget and standalone widget both
                                            # derive their endpoint from it.
                                            # Canonicalized at container build
                                            # time to ONE canonical form: must
                                            # begin with "/", no "//", "." or
                                            # ".." segments, no "\", "?", "#",
                                            # control characters or "%", and a
                                            # trailing "/" is normalized away
                                            # (with or without it configures
                                            # the same prefix)
    # Production requires a shared storage (Redis). With redis_dsn set,
    # the bundle constructs the Redis-backed services itself — no
    # storage service wiring needed. Without a DSN the bundle fails fast
    # with a LogicException if ArrayStorage is configured outside the
    # test/dev environment (kernel.environment or APP_ENV).
    # storage: kiwicaptcha.storage.redis    # atomic pending→consumed Lua
    #                                       # transition: the consumed
    #                                       # record and its deterministic
    #                                       # result are retained through
    #                                       # TTL, so a later caller
    #                                       # observes the consumed state
    #                                       # instead of re-verifying
```

### Asset delivery (`asset_mode`)

The widget assets (the CSS, the WASM runtime, the driver core, the
Argon worker and the driver's lazy widget modules) ship in two delivery
tiers, selected with `asset_mode`:

```yaml
kiwi_captcha:
    asset_mode: files     # files (default) | inline (compatibility / zero-request)
```

`files` (default) emits versioned immutable first-party asset URLs under
`{prefix}/assets/` (`widget.<sha256-64>.css`, `runtime.<sha256-64>.js`,
`driver.<sha256-64>.js`, `worker.<sha256-64>.js`,
`execution.<sha256-64>.js`, `risk.<sha256-64>.js`,
`telemetry.<sha256-64>.js`), served by the bundle
with a long immutable cache lifetime
(`Cache-Control: public, max-age=31536000, immutable`), the exact content
hash in the URL and the content-hash ETag. Each asset is emitted once per
page even with several widgets; the stylesheet and driver tags carry SRI
integrity attributes (browser-enforced SRI on the executed script).

**256-bit content addressing.** The hash in the asset URL is the full
sha256 digest of the served bytes (256 bits, 64 hex characters) — never
a truncated prefix. Two different byte strings can therefore never share
an addressable URL: a 48-bit truncation could in principle collide, a
full 256-bit digest cannot. The URL hash equals the ETag exactly, so the
address, the served bytes and the validator's digest are one and the
same value. The route constraint is `[0-9a-f]{64}`, and an unknown or
truncated hash is a 404, never a cache-bypass serve.

The runtime and the worker are the lazy heavy modules: the page never
downloads them eagerly. The widget container carries
`data-kiwi-runtime-src` + `data-kiwi-runtime-integrity` and
`data-kiwi-worker-src` + `data-kiwi-worker-integrity`, and the driver
fetches the WASM runtime and the Argon worker asset only when a
memory-hard challenge actually arrives. A page that only ever receives
SHA-256 challenges pays no request for the Argon machinery. The driver
hashes the fetched bytes and compares them against the page-issued
digests (a cryptographic preflight). Then the content-addressed
same-origin URLs are loaded by the browser APIs: the Worker constructor
for the worker asset, and the worker's importScripts for its WASM glue.
No Blob URL is created, so the worker download is deduplicated across
widgets like the runtime.

The driver itself is split the same way: the
always-loaded eager core (`widget-driver.js`) carries the bootstrap,
the challenge request, the SHA-256 solve, the state machine and the
lazy-module loader. The adaptive-risk solve tier and the armed-evidence
machinery (the Argon2id/rsw worker solve, the ExecutionChallengeV1
runner, the decoy rendering and the coarse client-context descriptor)
live in `widget-risk.js`. The core loads that module lazily when a
memory-hard challenge, an armed response or the risk-context opt-in
needs it. The non-default locale packs (de/fr/es/it/nl/pl/pt/ar) live
in `widget-locales.js`, loaded only when the core resolves a
non-default language (English pages pay zero bytes; a failed load
degrades to the English fallback with a console warning). The
telemetry session lives in `widget-telemetry.js`, loaded only when the
widget enables a session. The incumbent compatibility loader lives in
`widget-compat.js`, delivered inside the `/api.js` loader response and
never fetched elsewhere. The container carries the lazy module URLs +
SRI digests as `data-kiwi-risk-src`/`-integrity`,
`data-kiwi-telemetry-src`/`-integrity` and `data-kiwi-locales-src`/
`-integrity`, and the core injects the same-origin SRI-pinned module
script only on trigger, mirroring the worker asset's lazy fetch.

Why immutable caching: the URL contains the content hash, so the bytes
for a URL can never change. A browser or CDN may keep the response
forever, and a deployment upgrade simply emits new hashed URLs. Unknown
hashes are 404, so a stale page can never pair an old URL with new
content.

CSP per mode:

- `files` (default): the assets are same-origin, so the existing
  recommended profile already allows them (`script-src 'self'`,
  `style-src 'self'`); the lazy runtime and worker fetches use
  `connect-src 'self'`, and the same-origin Worker needs
  `worker-src 'self'` — `blob:` is never required.
- `inline` (compatibility / zero-request tier): the CSS, the WASM
  runtime and the driver are embedded into the page at render time
  (the historical zero-request behavior for the ordinary surface, no
  static asset handling). The `widget-risk.js` module is embedded the
  same way, so a memory-hard or armed challenge never needs an
  external fetch under a CSP that allows inline scripts but not
  `'self'`; `widget-telemetry.js` is embedded only when telemetry is
  enabled. The locale packs are never embedded in either tier: their
  content-addressed URL rides the container (like the execution
  interpreter), so a default-language inline page still pays zero
  bytes for translations. The worker is built from a Blob URL, so this
  tier needs `worker-src blob:`.

The execution dimension needs no extra directive in either tier. The
interpreter is a lazy first-party content-addressed asset in both
tiers (see the ExecutionChallengeV1 section above). The driver loads
it through a same-origin script tag inside the sandboxed srcdoc
iframe, so the page's own `script-src` governs the fetch; a SHA-only
page never triggers it. The `frame-src` directive does not
govern the about:srcdoc document, so a strict `frame-src 'none'`
profile stays compatible with execution challenges.

`inline` is the documented compatibility tier for ordinary
zero-request deployments. It embeds the CSS, the WASM runtime, the
driver core and the `widget-risk.js` module into the page at render
time. It embeds `widget-telemetry.js` when a session is enabled. Only
an execution-armed lifecycle fetches the interpreter asset, and only
a non-default-language widget fetches the locale module (the lazy
invariants of the sections above). A deployment that cannot serve or
cache the versioned asset URLs selects it explicitly.

#### Ordinary-bootstrap size target

The hard byte budgets live in `packages/kiwicaptcha/tools/perf-budget.sh`
and its baselines record (`perf-baselines.json`), enforced in CI. The
eager core (`widget-driver.js`) carries the raw 160,000-byte cap
forward, now with compressed caps of 30,720 gzip / 28,000 brotli
bytes; the lazy module assets (`widget-risk.js`,
`widget-telemetry.js`, `widget-locales.js`, `widget-compat.js`) carry
their own recorded raw-bytes rows and caps. The ordinary bootstrap, the bytes a plain
SHA-256 page downloads before any memory-hard or armed challenge,
targets **sub-30 KB compressed** (gzip or brotli) for the eager core
alone. The full browser suite, the asset-parity jobs and the perf
budget gate the split, so the caps stay real.

### Redis (`redis_dsn`)

`redis_dsn` is the first-class, high-level Redis connection setting. Set
one DSN and the bundle builds every Redis-backed service from it:

```yaml
# Twelve-factor form (recommended): the DSN lives in the environment.
kiwi_captcha:
    redis_dsn: '%env(KIWI_REDIS_DSN)%'
```

```yaml
# Literal form: the shape is validated at container build time.
kiwi_captcha:
    redis_dsn: 'redis://user:pass@redis.example.com:6379/0?prefix=kiwi'
```

What the DSN builds:

- The challenge storage (`KiwiCaptcha\Storage\RedisStorage`; atomic, so
  the production storage guard passes), the distributed issuance rate
  limiter, the Argon2id admission semaphore and, when risk is enabled,
  the risk state store. All of them run over one `Predis\Client` built
  from the DSN; Predis is a direct dependency of the bundle, so the DSN
  path works out of the box.
- The DSN shape is `redis://host:port/db?password=...&prefix=...` (or
  `rediss://` for TLS). The DSN is handed to `Predis\Client` verbatim,
  and the same fail-closed shape validation runs on both lanes. A
  literal DSN is validated at container build time. An env-resolved
  DSN is validated by the runtime guard when the client is constructed,
  since the value flows through the container's parameter bag and the
  load-time validation cannot see it. A malformed value
  is refused with a clear error naming the option, and an unreachable
  server is a runtime error on the first command, like any wired
  client.
- Env-managed DSNs follow twelve-factor practice: credentials, private
  hosts, TLS endpoints and database selection belong in the
  environment or a secrets manager, never in source-controlled config
  files. The manifest-declared `.env` default is
  `redis://127.0.0.1:6379/0`, and the bundle contract stays `redis://`
  or `rediss://`.
- An explicit service id wins over the DSN wherever both are set:
  `storage` (your own `StorageInterface` service), `redis_service`
  (your own client for the limiter/semaphore) and
  `risk.redis_service` (your own `Predis\Client` for the risk state).
  The DSN keeps filling the knobs you did not set.
- With `redis_dsn: null` (the default) every existing wiring stays
  byte-identical.

Validation notes:

- `secret_key`: at least 16 bytes; 32 random bytes recommended.
- `difficulty_bits`: SHA-256 difficulty, 1..=20 (the browser solver
  ceiling); the config tree ceiling tracks the core constant. The
  default 18 is the ordinary baseline (mean ≈ 262k hashes, p99 ≈
  1.21M, exhaustion ≈ 5.2×10⁻⁹ within the solver cap); 20 is the
  elevated rung, reached via adaptive risk escalation.
- `argon_t >= 3` and `argon_p == 1`: the intentional Argon2id protocol
  profile (libsodium's raw Argon2id interface, so Rust and PHP verify
  identical hashes).
- `challenge_ttl_secs`: bounded by the protocol ceiling (the record
  validation requires `expires_at - issued_at <= 300 s`).
- `algorithm`: the issued algorithm always comes from the server; a
  client-supplied `algorithm` field in the challenge POST is accepted only
  for forward-compatibility and never changes the issued algorithm.

### Privacy posture

```yaml
    # ── Privacy posture ──────────────────────────────────────────────────
    # privacy_mode: strict | standard (default strict). In STRICT mode the
    # extension FORCES telemetry 'off', same_origin_only true and
    # min_duration_ms 0 (the server-side solve-timing floor is a timing
    # heuristic and is disabled) — operator values for those keys are
    # overridden. In STANDARD mode the operator's choices pass through.
    # privacy_mode: strict
    # telemetry: off | minimal | full       # widget signal collection;
    #                                       # forced 'off' under strict
    # binding_mode: nonce_ip_hmac | none    # challenge IP binding; stored
    #                                       # tag is nonce-bound, never a
    #                                       # stable IP identifier; 'none'
    #                                       # issues challenges with an
    #                                       # EMPTY binding tag (maximum
    #                                       # privacy; relay protection
    #                                       # off) — fully wired through
    #                                       # to the core BindingMode.
    # same_origin_only: true                # reject cross-origin challenge
    #                                       # POSTs with 403
    #                                       # CROSS_ORIGIN_DENIED; forced
    #                                       # true under strict
    # min_duration_ms: null                 # explicit solve-timing floor in
    #                                       # ms (null = derive from
    #                                       # difficulty); forced 0 under
    #                                       # strict
    # enforce_telemetry: false              # reject bot-scored telemetry at
    #                                       # verification time
    #                                       # (defense-in-depth only)
```

The privacy modes themselves (strict vs standard, and why `binding_mode`
is never forced) are the privacy contract; see
[privacy.md](privacy.md#privacy-modes).

### Production hardening

```yaml
    # ── Production hardening ──────────────────────────────────────────────
    # Per-IP rate limit on challenge issuance (default 10 per window; 0 =
    # disabled). Mass challenge minting is what makes aggregate verification
    # work unbounded, so keep this on in production.
    # rate_limit: 10
    # Deployment-GLOBAL rate limit (default 500 per window; 0 = disabled),
    # enforced on every backend. Redis: exact distributed sliding window
    # shared by all workers. PSR-6 pool: the only no-Redis mode that
    # survives across requests (best-effort: races can briefly exceed the
    # cap). Object memory: long-lived-runtime-only (RoadRunner/Swoole/amphp
    # or a single CLI process) — under conventional PHP-FPM each request
    # rebuilds the limiter, so the object window is per-request and
    # provides no temporal limiting across requests. Global-only mode
    # (rate_limit: 0) works on all backends.
    # rate_limit_global: 500
    # rate_limit_window_secs: 60            # sliding window (default 60)
    # rate_limit_cache: null                # optional PSR-6 pool service id
    #                                       # used as the SHARED multi-process
    #                                       # fallback when no Redis client
    #                                       # exists (e.g. a Redis-backed
    #                                       # Symfony Cache pool). The pool
    #                                       # must be genuinely cross-worker:
    #                                       # a known in-memory adapter
    #                                       # (Symfony Cache ArrayAdapter or
    #                                       # a subclass) is REFUSED in
    #                                       # production, since its items
    #                                       # live per process. The class
    #                                       # check resolves parameter-
    #                                       # indirected ids
    #                                       # ('%kiwi.rate_pool%'), alias
    #                                       # chains, parent-declared pools
    #                                       # and %param% classes; a pool id
    #                                       # still unresolvable to a class
    #                                       # at compile time FAILS CLOSED
    #                                       # in production — reference a
    #                                       # concrete pool service id. The
    #                                       # pool items are namespaced per
    #                                       # deployment (empty namespace
    #                                       # keeps the legacy shapes), so
    #                                       # deployments sharing one pool
    #                                       # keep independent budgets.
    #                                       # Without a
    #                                       # pool, the fallback is a
    #                                       # per-object in-memory window:
    #                                       # temporal cross-request limiting
    #                                       # under conventional PHP-FPM
    #                                       # requires Redis or a genuinely
    #                                       # shared PSR-6 pool.
    # allow_nonredis_rate_limit_fallback: false
    #                                       # explicitly accepts the
    #                                       # non-Redis rate limiter in
    #                                       # production when any
    #                                       # temporal issuance limit is
    #                                       # set but no Redis client
    #                                       # and no rate_limit_cache
    #                                       # pool exist. Redis is the
    #                                       # exact distributed window;
    #                                       # a shared PSR-6 pool is
    #                                       # cross-request best-effort;
    #                                       # object memory is
    #                                       # long-lived-runtime-only and
    #                                       # request-local under
    #                                       # conventional PHP-FPM. The
    #                                       # deprecated
    #                                       # allow_local_global_limit_fallback
    #                                       # option still works as an
    #                                       # alias.
    #                                       # Raw client IPs are never stored:
    #                                       # every key is a peppered HMAC of
    #                                       # the IP (rate_limit_pepper
    #                                       # defaults to secret_key — a
    #                                       # compatibility fallback only).
    #                                       # The normal deployment model is
    #                                       # a dedicated stable pepper:
    #                                       # routine signing-key rotation
    #                                       # must not reset the per-client
    #                                       # rate-limit memory (the HMAC
    #                                       # identities anchor that memory,
    #                                       # and a fresh pepper derives
    #                                       # fresh identities, restarting
    #                                       # every client window empty).
    # rate_limit_pepper: '%env(KIWI_RATE_LIMIT_PEPPER)%'
    #                                       # dedicated stable abuse-identity
    #                                       # key (K_abuse-identity): HMAC
    #                                       # pepper for the per-IP rate-limit
    #                                       # pseudonyms. Stays stable across
    #                                       # routine signing-key rotations.
    # Aggregate Argon2id verification concurrency cap (default 2; 0 =
    # unlimited). Each Argon2id verification allocates argon_m_kib of memory —
    # size this to available memory. With a Redis client the cap is enforced
    # across ALL PHP-FPM workers (see the Argon2 section in operations.md).
    # argon2_max_concurrent_verifications: 2
    # argon2_saturation_pressure_cap: 64 # bounded SATURATION-PRESSURE
    #                                    # counter (NOT a queue: admission
    #                                    # is immediate and non-blocking —
    #                                    # nothing waits or queues behind
    #                                    # a saturated gate). The
    #                                    # deprecated argon2_max_waiters
    #                                    # name still works as an alias.
    # argon2_max_per_tenant: null        # PER-SCOPE CONCENTRATION cap: each
    #                                    # scope gets its own lease set in
    #                                    # addition to the global cap.
    #                                    # Null (default) derives
    #                                    # max(1, global - 1), so with the
    #                                    # default global cap of 2 one scope
    #                                    # can never occupy both slots. It
    #                                    # is a concentration cap, not a
    #                                    # guaranteed share or a
    #                                    # weighted-fair scheduler, and it
    #                                    # must be strictly below the
    #                                    # global cap (refused otherwise).
    #                                    # Anti-monopoly across scopes
    #                                    # requires a global concurrency of
    #                                    # at least 2: with a global cap of
    #                                    # exactly 1 there is only one
    #                                    # shared slot, so no implementation
    #                                    # can reserve capacity for another
    #                                    # scope.
    # argon2_lease_ms: 45000              # tokenized Redis lease lifetime in
    #                                    # ms; must exceed
    #                                    # argon2_max_verification_runtime_ms
    #                                    # by the 5000 ms safety margin
    #                                    # (compiled, see operations.md).
    # argon2_max_verification_runtime_ms: 30000
    #                                    # the deployment SLO for the
    #                                    # wall-clock a single Argon2
    #                                    # verification derivation may take
    #                                    # in this deployment, in ms. The
    #                                    # lease must exceed it by the 5000
    #                                    # ms safety margin (defaults: 45000
    #                                    # > 30000 + 5000 = 35000), enforced
    #                                    # at container compile time; the
    #                                    # declared runtime is a deployment
    #                                    # bound only, never an enforced
    #                                    # wall-clock timeout inside the
    #                                    # blocking hash (a pathological host
    #                                    # can still outlive the lease:
    #                                    # fencing keeps correctness, the
    #                                    # concurrency cap may be exceeded
    #                                    # in that expiry window).
    # argon2_semaphore_namespace: '%kernel.project_dir%'
    #                                       # per-deployment discriminator for
    #                                       # the Redis lease set and the
    #                                       # global rate-limit key; two
    #                                       # deployments sharing one Redis
    #                                       # instance must use different
    #                                       # namespaces
    # redis_service: null                   # optional Redis client service id
    #                                       # (\Redis or Predis\Client) for the
    #                                       # cross-worker Argon2 admission
    #                                       # gate and the atomic rate
    #                                       # limiter; when null, the
    #                                       # storage's own client is reused
    #                                       # if storage is RedisStorage, or
    #                                       # the redis_dsn client is used
    #                                       # when redis_dsn is set
    # strict_kid_verification: false        # OPTIONAL strict current-kid
    #                                       # verification: when true,
    #                                       # strict keyring resolution is
    #                                       # enabled even before the first
    #                                       # rotation: the current kid must
    #                                       # match from the first deployment
    #                                       # (any other kid -> UnknownKid),
    #                                       # and historical keys keep
    #                                       # verifying under rotation grace
    #                                       # when secrets_by_kid is
    #                                       # populated (historical +
    #                                       # current, never the current key
    #                                       # alone). Default false keeps
    #                                       # the legacy any-kid
    #                                       # single-secret semantics (see
    #                                       # security-hardening.md).
    # resume_claim_ttl_secs: 60             # recovery-derivation claim lease
    #                                       # (min 60): must cover the
    #                                       # maximum supported derivation
    #                                       # duration; fencing stays
    #                                       # correct on expiry (an
    #                                       # expired claim is released and
    #                                       # a retry re-claims it)
```

### Protocol rollout mode

```yaml
    # ── Protocol rollout state (v3/v4) ─────────────────────────────────
    # protocol_rollout:
    #     mode: normal                  # normal | migration (default normal)
    #
    # The explicit migration state: the deployment declares whether it is
    # deliberately in a two-phase protocol rollout (v3 and v4). mode
    # "normal" means no deliberate exception — under protection_profile:
    # high_abuse with risk.decoy_v3_enabled: false (or with the execution
    # gate on while the v4 floor is unconfirmed) the doctor FAILS the
    # protocol-writer check, because a false security switch alone
    # does not prove the deployment is intentionally deferring v3/v4
    # emission (a forgotten override must not silently persist). mode
    # "migration" declares the deliberate two-phase migration (v3/v4
    # emission deferred until the fleet floor is confirmed); the doctor
    # records the same high_abuse deferral as a WARN (exit 0). The mode
    # also gates the execution-versioning audit: the doctor accepts a
    # required-tier downgrade window only in the migration state, see
    # operations.md "Execution versioning".
    # The two-phase rollout procedures themselves are unchanged; see
    # operations.md "Protocol v3 two-phase rollout" and "Protocol v4
    # execution rollout".
```

### Risk configuration

The adaptive risk engine is opt-in and off by default. Enabling it adds a
first-party continuity cookie; see [privacy.md](privacy.md#continuity-cookie)
and [risk-engine.md](risk-engine.md):

```yaml
kiwi_captcha:
    # public_base_url: https://captcha.example.com  # the deployment's PUBLIC
    #                                               # origin from SERVER
    #                                               # CONFIG — the same-
    #                                               # origin check compares
    #                                               # against it, never the
    #                                               # Host header (set it in
    #                                               # production)
    risk:
        enabled: true
        # client_ip_mode: symfony_trusted_proxies  # how the canonical client IP is
        #                                           # derived — Symfony's
        #                                           # trusted-proxy machinery
        #                                           # (ignores forwarding
        #                                           # headers from untrusted
        #                                           # peers) or "direct"
        #                                           # (socket peer ONLY —
        #                                           # forwarding headers are
        #                                           # ALWAYS ignored)
        # trusted_proxies:                          # CIDRs of the trusted
        #     - 10.0.0.0/8                          # reverse proxies
        # reject_ambiguous_forwarding: false        # true = 400
        #                                           # AMBIGUOUS_FORWARDING
        #                                           # when a trusted peer
        #                                           # sends BOTH
        #                                           # X-Forwarded-For and
        #                                           # Forwarded; false = log
        # container_memory_mib: null                # readiness requires
        #                                           # concurrency x
        #                                           # the FIXED Argon
        #                                           # verification envelope
        #                                           # (risk.argon_verification_
        #                                           # memory_kib)
        #                                           # + 256 MiB headroom <=
        #                                           # budget; null = invariant
        #                                           # skipped (documented)
        # The risk-v1 state lives in Redis (EVALSHA of the canonical Lua).
        # Required: risk.redis_service (a Predis\Client service id) — or the
        # bundle's redis_service / RedisStorage client when it is a Predis
        # client, or the redis_dsn client (a Predis\Client) when redis_dsn
        # is set. phpredis (\Redis) is NOT supported by the risk engine,
        # and risk.enabled without any Predis client fails at container
        # compile.
        # redis_service: kiwicaptcha.risk.redis
        namespace: '%kernel.project_dir%'   # {kiwi:<namespace>} hash tag
        # master_secret: '%env(KIWI_RISK_SECRET)%'
        #                                   # HKDF master for the risk
        #                                   # identity keys. The normal
        #                                   # deployment model is a
        #                                   # dedicated stable secret
        #                                   # (K_abuse-identity): routine
        #                                   # signing-key rotation must
        #                                   # not reset the adaptive-risk
        #                                   # memory. When null, the keys
        #                                   # derive from secret_key
        #                                   # (compatibility fallback only).
        # source_epoch_secs: 900            # source identity rotation
        # subnet_epoch_secs: 900            # subnet (/24, /56) rotation
        # state_ttl_secs: 1800              # live counter TTL
        # principal_ttl_secs: 86400
        # dedupe_ttl_secs: 60               # identical event_id applied once
        # hysteresis_ms: 60000              # global-level hysteresis window
        # network_classifier_file: null     # optional "cidr,flag" file
        # region: eu-central-1              # OPTIONAL deployment region baked
        #                                   # into every issued challenge and
        #                                   # enforced at verification (a
        #                                   # result token issued in one
        #                                   # region is never redeemable
        #                                   # elsewhere — failover-replay
        #                                   # Option A)
        # redis:                            # challenge-storage hardening
        #     wait_replicas: 1              # WAIT for N replicas after storing
        #                                   # a challenge (async-replication
        #                                   # failover can otherwise lose the
        #                                   # record and replay a consumed
        #                                   # token against a "fresh" record)
        #     wait_timeout_ms: 100          # WAIT timeout for the replicas
        #     ttl_margin_secs: 60           # extra retention on challenge /
        #                                   # replay-security state BEYOND
        #                                   # token validity (must exceed max
        #                                   # clock skew + failover margin;
        #                                   # pair with a noeviction policy
        #                                   # on the security Redis)
        # max_outstanding_challenges: 20    # anti-stockpiling: unsolved
        #                                   # challenges per source
        # max_outstanding_challenges_global: 100000  # deployment-wide cap
        # challenge_origin_allowlist:       # origin-laundering defense: when
        #     - https://app.example.com     # non-empty, challenge POSTs must
        #                                   # carry an allowlisted Origin (or
        #                                   # Referer origin when
        #                                   # enforce_origin is false);
        #                                   # everything else gets 403
        #                                   # origin_rejected. Comparison is
        #                                   # STRUCTURED NORMALIZATION:
        #                                   # scheme/host/effective-port,
        #                                   # host lowercased, default ports
        #                                   # normalized (https 443 / http
        #                                   # 80), trailing dots stripped,
        #                                   # IDN -> punycode (ext-intl),
        #                                   # IPv6 kept bracketed —
        #                                   # "https://example.com" matches
        #                                   # "https://example.com:443",
        #                                   # "https://EXAMPLE.COM." and the
        #                                   # IDN/punycode spellings, never
        #                                   # ":444" / "http://" /
        #                                   # "evil-example.com"
        # enforce_origin: false             # true = Origin REQUIRED: missing
        #                                   # or "null" Origin -> 403
        #                                   # origin_rejected even without an
        #                                   # allowlist. Server-to-server
        #                                   # integrations (no Origin) keep
        #                                   # this false — the explicitly
        #                                   # trusted mode
        # enforce_fetch_metadata: false     # reject Sec-Fetch-Site:
        #                                   # cross-site challenge requests
        #                                   # (browser-laundering signal;
        #                                   # defense-in-depth only)
        # request_binding: null             # OPTIONAL STATIC transaction
        #                                   # binding (1..128 chars of
        #                                   # [A-Za-z0-9._:-]):
        #                                   # signed into every challenge when
        #                                   # the request sends no
        #                                   # request_binding field. For
        #                                   # DYNAMIC per-transaction
        #                                   # bindings the application
        #                                   # supplies one per request (the
        #                                   # widget carries it end-to-end,
        #                                   # see "Transaction binding")
        # health:
        #     enabled: true                 # registers {prefix}/health/live
        #                                   # + /health/ready (rollback-
        #                                   # resistant readiness split)
        #     argon_verification_memory_kib: 16384  # the FIXED memory
        #                                   # envelope of ALL adaptive Argon
        #                                   # challenges (1024..65536) — the
        #                                   # server verification cost is
        #                                   # bounded by this ONE value;
        #                                   # risk escalates the TARGET
        #                                   # DIFFICULTY, never the memory
        #     argon_escalation_target_bits: [1, 2, 4] # EXACTLY 3
        #                                   # entries (Argon16/32/64), each
        #                                   # 1..20 — the expected nonce
        #                                   # search space escalation
        #     security_epoch_cache_secs: 1  # cache of the central
        #                                   # security-policy read (1..30) —
        #                                   # revocation latency is one window
        #     security_epoch_max_stale_secs: 60 # max-stale FAIL-
        #                                   # CLOSED window (min 10) — past
        #                                   # last_success + window the
        #                                   # validator returns
        #                                   # temporary_unavailable and the
        #                                   # controller refuses issuance 503
        #     decoy_v3_enabled: false        # PROTOCOL-V3 WRITER SWITCH
        #                                   # (default false): when false,
        #                                   # issuance NEVER arms the
        #                                   # authenticated decoy and always
        #                                   # emits protocol v2 (byte-
        #                                   # compatible with parent-revision
        #                                   # verifiers). When true, issuance
        #                                   # MAY arm the decoy (v3), but
        #                                   # ONLY when the central security-
        #                                   # policy floor ({kiwi:<ns>}:
        #                                   # security-policy
        #                                   # min_protocol_version) is
        #                                   # confirmed >= 3; a lower or
        #                                   # unreadable floor falls back to
        #                                   # v2 with a once-per-process
        #                                   # warning. The execution surface
        #                                   # is gated separately at the v4
        #                                   # floor (risk.execution_challenge).
        #                                   # See operations.md "Protocol v3
        #                                   # two-phase rollout" and
        #                                   # "Protocol v4 execution rollout".
        #     result_receipt_signing_key: null  # OPTIONAL base64
        #                                   # 32-byte Ed25519 seed; when set,
        #                                   # valid verifications export
        #                                   # signed receipts (the HMAC
        #                                   # result verification stays
        #                                   # CENTRAL-ONLY)
        #     max_challenges_per_scope_per_minute: 0 # per-scope
        #                                   # fixed-window issuance cap
        #                                   # (0 = unlimited); > 0 requires
        #                                   # Redis; the window key carries
        #                                   # hex(hmac_sha256(scope, K_scope))
        #                                   # — the raw scope is never a
        #                                   # Redis key component
        #     policy_version: 1             # CHALLENGE security-policy epoch,
        #                                   # signed into every issued record
        #                                   # and enforced at verification —
        #                                   # BUMP it to immediately
        #                                   # invalidate ALL outstanding
        #                                   # challenges (origin/action-policy
        #                                   # changes, emergency revocation,
        #                                   # compromised tenant); cosmetic
        #                                   # changes must NOT bump it.
        #                                   # Independent of the risk-v1
        #                                   # contract version.
        #     weights: { ... }              # 13 risk-v1 weights (defaults = contract)
        #     global_floors:                # minimum action per global level
        #         1: sha16
        #         2: sha18
        #         3: sha20
        #         4: sha20
        #     scopes:
        #         login:                     # the app scope string
        #             # id: 1                # int scope in Redis state; MUST
        #             #                       # stay stable once deployed
        #             #                       # (defaults to crc32(scope name))
        #             base_risk: 100
        #             minimum: allow         # floor: never weaker than this
        #             degraded: allow        # action while the backend is down
        #             # post_solve_check: true   # valid solves re-assessed after
        #             #                       # the proof (deny -> 422
        #             #                       # kiwi.post_solve_rejected,
        #             #                       # step_up -> 422
        #             #                       # kiwi.post_solve_step_up_required)
        #         signup:
        #             base_risk: 200
        #     unknown_scope:                 # scopes NOT configured above
        #         mode: baseline             # baseline (default): engine
        #                                   # declines, default challenge is
        #                                   # issued; reject: TRUE rejection
        #                                   # (HTTP 429 RISK_DENIED, no
        #                                   # challenge); minimum: synthetic
        #                                   # policy (base_risk 100, min/
        #                                   # degraded sha20)
        #     calibration:
        #         enabled: false             # Redis score-bucket bias
        #         min_samples: 1000          # passed to the AggregateCalibrator
        #         max_adjustment: 150        #   (bias clamp bound)
        #         max_change_per_minute: 10  #   (adjustment rate bound)
        #         outcome_receipt_ttl_secs: 86400 # outcome/calibration receipt
        #                                   # + outcome-ledger lifetime (24 h
        #                                   # default; 3600..604800) — long
        #                                   # enough for fraud review /
        #                                   # moderation / chargeback labels
        #         mode: random_sample        # label selection: complete |
        #                                   # random_sample (Kiwi samples at
        #                                   # assessment time; unsampled
        #                                   # confirmations are consumed but
        #                                   # not recorded — status 2 — so
        #                                   # the label can never select
        #                                   # itself into the population) |
        #                                   # weighted (the app supplies the
        #                                   # inverse sampling probability
        #                                   # per confirmation)
        #         sampling_probability_ppm: 100000  # PPM chance a decision is
        #                                   # sampled (random_sample mode)
        #         minimum_resolution_ratio: 0.8 # random_sample resolution gate:
        #                                   # bias adjustment is suspended
        #                                   # while sampled total >=
        #                                   # min_samples but resolved/total
        #                                   # < this ratio (0 disables)
        #         false_positive_cost: 1.0  # class-normalized calibration:
        #         false_negative_cost: 2.0  #   price of a false positive vs
        #                                   #   a false negative (default:
        #                                   #   abuse slipping through costs
        #                                   #   twice a false rejection)
        #     nonce_to_decision_ttl_secs: 300   # short-lived challenge-nonce ->
        #                                   # decision-id handle TTL
        #                                   # (60..3600; independent of the
        #                                   # outcome lifetime)
        #     continuity_cookie:
        #         name: kiwi_risk_session
        #         ttl_secs: 15552000         # 180 days; 0 = session cookie
        #         # secure: null             # null = follow the request scheme
        #         # samesite: lax
        #         # http_only: true
```

### Scope identity

Scope ids are part of the Redis state identity. The `id` (or the
crc32-derived default) must stay stable once deployed. Renaming a scope or
reordering ids silently fragments its risk history. Two scopes sharing an id
collide and are refused at compile time.

`risk.allowed_scopes` (when configured) restricts issuance to the listed
scope names; a scope outside the server allowlist is refused before any
quota runs.

`risk.unknown_scope.mode` decides what happens to scopes not configured in
`risk.scopes`:

- `baseline` (default): the engine declines, and the default challenge is
  issued (no risk assessment for that scope).
- `reject`: true rejection, HTTP 429 `RISK_DENIED`, no challenge.
- `minimum`: a synthetic policy (base_risk 100, min/degraded sha20) applies.

### Transaction binding

A challenge can be bound to one application transaction. The issuing side
signs a `request_binding` (1..128 chars of `[A-Za-z0-9._:-]`)
into the record, and verification only accepts the solve when the final
POST presents the same binding. A challenge minted for one transaction is
never redeemable for another. The widget carries the binding end-to-end.
The binding is always server-originated in the bundle: the widget driver
never generates a binding of its own. The rendered widget container carries
exactly the value the backend rendered, nothing else.

Two binding modes:

1) **Client-chosen binding (public, basic anti-abuse).** The application
   lets the client choose the binding, e.g. a per-page random nonce the
   page JavaScript generates and passes to the widget. This is fine for
   basic anti-abuse (it proves the browser chose a nonce and carries it
   back), but the binding is client-controlled: it proves nothing about a
   trusted backend decision. Suitable when the binding is a transaction
   correlation tag, not an authorization signal.
2) **Backend-originated binding (the recommended sensitive-flow mode).**
   The application backend renders the binding server-side from a
   `flow_id` stored server-side. The Symfony form type's `request_binding`
   option, the static `risk.request_binding` config, or a per-render
   `request_binding` passed to the standalone widget carries a value the
   backend itself issued, a flow/session identifier the backend created
   and persists. The widget renders that value and only ever forwards it;
   the verification side enforces it against the signed record. A binding
   minted by the backend (and stored server-side) can be checked against
   the backend's own flow state after verification. A client can never
   invent a binding the backend did not issue.

- **Config** — `risk.request_binding` sets a static binding used whenever
  the request sends no `request_binding` field (e.g. server-side
  integrations). For dynamic per-transaction bindings (recommended: a
  backend-issued `flow_id` nonce per page load) the application supplies
  the value per request/form:
  - `KiwiCaptchaType` option `'request_binding' => $flowId` (defaults to the
    static config) → rendered as `data-kiwi-request-binding` on the widget
    container;
  - the standalone widget accepts `'request_binding'` in the
    `kiwi_captcha_widget({...})` context.

- **Widget flow** — the driver reads `data-kiwi-request-binding` and
  includes `request_binding` in the challenge POST body. The controller
  validates 1..128 chars of `[A-Za-z0-9._:-]` (422
  `INVALID_REQUEST_BINDING` otherwise), passes the value to the core
  Issuer, which signs it into the record, and on a successful solve
  creates the hidden `kiwi_request_binding` input in the form, next to the
  token input. The driver contains no binding-generation code (no
  `crypto.randomUUID`-style synthesis, pinned by test): the rendered
  container carries only the server-provided binding.

- **Verification** — after a valid verification, the validator compares the
  consumed record's signed binding against the request binding. The
  application controller copies the POSTed field into the request attribute
  before validating:

  ```php
  $request->attributes->set(
      KiwiCaptchaValidator::REQUEST_BINDING_ATTRIBUTE,
      (string) $request->request->get('kiwi_request_binding'),
  );
  $form->handleRequest($request);
  ```

  (The validator also falls back to the raw POSTed `kiwi_request_binding`
  field, so the plain widget flow works without the shim.) A bound record
  with a missing or mismatched binding fails with the same
  `invalid_or_expired` violation. No jti is exposed, the solve is burned
  (single-use), and the client re-solves. An unbound record skips the check
  entirely. The verified binding is exposed via
  `KiwiCaptchaValidator::verifiedRequestBinding()`
  (`VerifyOutcome::requestBinding()`).

### Identifier validation rules

Scope/tenant identifiers and request bindings are restricted to the
`[A-Za-z0-9._:-]+` alphabet with a 128-char ceiling. The static
`risk.request_binding` is validated against the same charset at compile
time. The verification side requires exact equality between the signed
record values and the values the final POST carries, so a challenge minted
under a valid identifier can never be redeemed under a different one. See
[Identifier validation](security-hardening.md#identifier-validation) for
the endpoint-level enforcement.

### Signing-key rotation and abuse-identity secrets

The deployment keeps two secret families with different lifetimes:

- **K_signing** (the signing key): `secret_key` plus the historical
  `secrets_by_kid` map and `revoked_kids`. Routine rotation moves the
  superseded key into the historical map, sets the new `secret_key`, and
  bumps `kid`. Rotating K_signing must be a routine, low-risk operation.
- **K_abuse-identity** (the rate/risk root keys): `rate_limit_pepper` and
  `risk.master_secret`. These derive the pseudonymous identities that
  anchor the per-client rate-limit memory and the adaptive-risk memory.

The normal deployment model is dedicated, stable root keys:

```yaml
kiwi_captcha:
    secret_key: '%env(KIWI_SECRET_KEY)%'            # K_signing, rotates
    rate_limit_pepper: '%env(KIWI_RATE_LIMIT_PEPPER)%'  # K_abuse-identity, stable
    risk:
        enabled: true
        master_secret: '%env(KIWI_RISK_SECRET)%'    # K_abuse-identity, stable
```

K_signing rotates on a schedule; K_abuse-identity stays stable for the
life of the deployment. A routine signing-key rotation therefore changes
nothing about the rate-limit windows or the risk state. An emergency root
compromise may intentionally rotate everything, resetting both families.

The derivation defaults (`rate_limit_pepper` and `risk.master_secret`
falling back to `secret_key`) are documented as a compatibility fallback
only: with those defaults in place, a routine signing-key rotation
silently resets every per-client rate-limit identity and every risk
pseudonym. The extension logs an advisory note at container build time
when rotation is configured (`kid` above 1 or a non-empty
`secrets_by_kid`) without dedicated root keys; the note never throws.

### Related documentation

- [privacy.md](privacy.md): what the privacy keys mean (modes, telemetry,
  binding).
- [risk-engine.md](risk-engine.md): how the risk options behave.
- [operations.md](operations.md): deployment options (rate limiting,
  admission gates, health endpoints, client-IP policy).
- [siteverify.md](siteverify.md): `risk.siteverify_secrets` and the
  siteverify endpoint.
- [migration.md](migration.md): `risk.sitekey_allowlist` and the migration
  surface.
