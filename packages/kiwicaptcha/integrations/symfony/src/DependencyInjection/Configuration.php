<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\DependencyInjection;

use BelConsulting\KiwiCaptchaBundle\RedisNamespace;
use KiwiCaptcha\Config;
use KiwiCaptcha\ExecutionChallengeGenerator;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskV2Weights;
use KiwiCaptcha\Risk\RiskWeights;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

/**
 * SECURITY-MAINTAINER material: the cross-field invariants enforced in
 * this tree are deep design rationale, intentionally not published at
 * the integration layer. See docs/operations.md for the maintainer
 * view and docs/security-hardening.md for the integration actions.
 */
final class Configuration implements ConfigurationInterface
{
    private const RISK_ACTIONS = ['allow', 'sha16', 'sha18', 'sha20', 'argon16', 'argon32', 'argon64', 'step_up', 'deny'];

    /**
     * True when the configured value is an unresolved Symfony env
     * placeholder such as `%env(NAME)%`, or its resolved placeholder
     * form. Such a value is resolved at runtime, so a compile-time
     * length floor cannot judge it; the same floor is enforced when
     * the core Config/service is constructed, exactly like
     * secret_key. A literal empty string is NOT a placeholder: it is
     * an explicitly invalid secret value and fails the build-time
     * floor instead of being deferred to runtime.
     */
    private static function isEnvPlaceholder(mixed $v): bool
    {
        if (!\is_string($v)) {
            return false;
        }

        return preg_match('/^%env\([^%]+\)%$/D', $v) === 1
            || preg_match('/^env_[a-f0-9]{16}_\w+_[a-f0-9]{32}$/iD', $v) === 1;
    }

    /**
     * True when the literal configured secret is under the core
     * `Config::MIN_SECRET_BYTES` floor. An env placeholder is not a
     * literal secret and is not judged here; see isEnvPlaceholder().
     */
    private static function isShortSecret(mixed $v): bool
    {
        return \is_string($v)
            && !self::isEnvPlaceholder($v)
            && \strlen($v) < Config::MIN_SECRET_BYTES;
    }

    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('kiwi_captcha');
        $root = $treeBuilder->getRootNode();

        $root
            // The execution-versioning aliases canonicalize before any
            // other processing, so both spellings of one concept set the
            // same value regardless of the layer that carries them.
            ->beforeNormalization()
                ->always()
                ->then(static fn (mixed $v): mixed => \is_array($v) ? self::canonicalizeExecutionVersioningAliases($v) : $v)
            ->end()
            ->children()
                ->scalarNode('protection_profile')
                    ->info('Policy-level posture preset (default null = every knob at its individual default; current behavior preserved byte-identically). The profile is the LOWEST-precedence configuration layer: it fills SAFE DERIVED DEFAULTS for the safety-relevant knobs, and an explicit value in ANY config file always wins (the profile defaults are merged first, so later layers — including a prod overlay that only sets protection_profile — can never override an explicit setting). Profiles: "balanced" = the current defaults, explicitly documented as such; "privacy_strict" = strongest first-party privacy (no IP-derived binding tag, every behavioral evidence surface off, timing heuristic off); "high_abuse" = stronger abuse posture (risk enabled with raised abuse-evidence weights, stricter per-source limits, wider aggregate issuance bounds, decoy surface on, chained step-up engages when a request-binding authority is wired in any layer — requires a Predis client); "abuse_first" = the high_abuse posture under its specification name (change.md Part 5 names the abuse profile abuse_first; the two names select the identical matrix, so a deployment may use either spelling); "compatibility" = maximal integration compatibility (sha256, conservative 300 s TTL, binding off, risk off, protocol v2 emission); "ha_safe" = the replay-safe HA posture (replay_durability operator_managed + ha_authority pinned_primary, the other defaults mirror balanced) — the mechanical pinned-primary authority guard makes the operator contract a real guarantee; the guard refuses on any authority change and the doctor reports its state. Every profile except compatibility also derives the risk engine stage composition (marks reader, continuous pricing, bucket trust; the explanation surface only under the abuse profiles), see the "Risk engine stage composition" section in docs/configuration.md. See docs/configuration.md "Protection profiles" for the full matrix and the layering semantics.')
                    ->defaultNull()
                    ->validate()
                        ->ifTrue(static fn ($v): bool => $v !== null && !\in_array($v, ['balanced', 'privacy_strict', 'high_abuse', 'abuse_first', 'compatibility', 'ha_safe'], true))
                        ->thenInvalid('must be one of "balanced", "privacy_strict", "high_abuse", "abuse_first", "compatibility", "ha_safe" (or null = no profile)')
                    ->end()
                ->end()
                ->scalarNode('secret_key')
                    ->info('HMAC secret key for signing/verifying challenges (min 32 bytes).')
                    ->isRequired()
                    ->cannotBeEmpty()
                    // The 32-byte floor is enforced by the core Config at
                    // runtime: a validate() closure here would reject an
                    // unresolved %env(...)% placeholder at container build
                    // (Symfony forbids env placeholders on validated nodes).
                ->end()
                ->scalarNode('issuer')
                    ->info('Deployment issuer stamped into every issued challenge (e.g. "auth-prod"). When set, the verifier REJECTS any record whose issuer does not match exactly — a dev/staging/prod mixup cannot validate cross-environment. The core long supported issuer; this makes it first-class bundle configuration.')
                    ->defaultNull()
                ->end()
                ->integerNode('kid')
                    ->info('Signing key id (1..4294967295) stamped into every issued challenge. Paired with secrets_by_kid + revoked_kids this is the controlled HMAC-key rotation control. The rotation procedure: move the superseded old kid and its key into secrets_by_kid, update secret_key to the new key, then bump kid to the new id. The current kid must never appear in secrets_by_kid — a historical entry for the current signing key would make the verifier select the wrong secret. The superseded secret remains valid for verification until its kid is revoked.')
                    ->min(1)
                    ->max(4294967295)
                    ->defaultValue(1)
                ->end()
                ->arrayNode('secrets_by_kid')
                    ->info('Verification-only secrets for historical signing key ids (map of canonical kid => secret, each >= 32 bytes, the same floor as secret_key). Rotation: move the superseded old kid and its key here, update secret_key to the new key, then bump kid — the current kid must never appear in this map. Verification of records signed under superseded kids uses these secrets.')
                    ->scalarPrototype()->end()
                    ->useAttributeAsKey('kid')
                    ->normalizeKeys(false)
                    ->defaultValue([])
                    ->validate()
                        ->ifTrue(static function (array $secrets): bool {
                            // Two distinct map keys that canonicalize to
                            // the same integer (e.g. the string key '02'
                            // next to the int key 2) would silently
                            // overwrite one historical secret downstream,
                            // so the duplicate is refused before any
                            // shape rule.
                            $seen = [];
                            foreach (\array_keys($secrets) as $kid) {
                                $canonical = (int) $kid;
                                if (isset($seen[$canonical])) {
                                    return true;
                                }
                                $seen[$canonical] = true;
                            }

                            return false;
                        })
                        ->thenInvalid('secrets_by_kid keys must be distinct canonical kids: two entries that resolve to the same integer would silently overwrite one historical secret')
                    ->end()
                    ->validate()
                        ->ifTrue(static function (array $secrets): bool {
                            foreach (\array_keys($secrets) as $kid) {
                                if (\is_int($kid)) {
                                    if ($kid < 1 || $kid > 4294967295) {
                                        return true;
                                    }

                                    continue;
                                }
                                if (preg_match('/^[1-9][0-9]*$/D', (string) $kid) !== 1) {
                                    return true;
                                }
                                $canonical = (int) $kid;
                                if ($canonical < 1 || $canonical > 4294967295) {
                                    return true;
                                }
                            }

                            return false;
                        })
                        ->thenInvalid('secrets_by_kid keys must be canonical decimal integers in 1..4294967295: a historical signing kid is written without leading zeros and without text, so "02", "0" and "foo" are all refused')
                    ->end()
                    ->validate()
                        ->ifTrue(static function (array $secrets): bool {
                            foreach ($secrets as $v) {
                                if (!\is_string($v) || self::isShortSecret($v)) {
                                    return true;
                                }
                            }

                            return false;
                        })
                        ->thenInvalid('secrets_by_kid values must be strings of at least 32 bytes (the core Config::MIN_SECRET_BYTES floor): a shorter historical key cannot verify and would only surface when a rotation makes it live. Rotate to a randomly generated 32-byte-or-longer secret. An %%env()%% placeholder is length-checked at runtime by the verifier constructor')
                    ->end()
                ->end()
                ->arrayNode('revoked_kids')
                    ->info('Signing key ids whose verification is REVOKED (emergency key-compromise response). A record signed under a revoked kid is rejected with UnknownKid IMMEDIATELY — even when its secret is present in secrets_by_kid. Revocation always wins over rotation.')
                    ->integerPrototype()->min(1)->max(4294967295)->end()
                    ->defaultValue([])
                ->end()
                ->booleanNode('strict_kid_verification')
                    ->info('OPTIONAL strict current-kid mode (default false): when true, strict keyring resolution is enabled even before the first rotation — the current kid must match from the first deployment (a record whose kid differs is rejected with UnknownKid), and with a non-empty historical secrets_by_kid map historical keys keep verifying under rotation grace (strict mode returns historical + current, never the current key alone). Default false keeps the legacy any-kid single-secret semantics: with an empty historical map the core accepts any record kid under the current secret, so an issuer holding the same HMAC secret under a different kid would verify unless issuer/region isolation is configured.')
                    ->defaultFalse()
                ->end()
                ->enumNode('algorithm')
                    ->values(['sha256', 'argon2id', 'rsw'])
                    ->defaultValue('sha256')
                ->end()
                ->enumNode('privacy_mode')
                    ->info("Privacy posture. 'strict' (default) FORCES: telemetry 'off', same_origin_only true, and min_duration_ms 0 (the server-side solve-timing floor is a timing heuristic and is disabled). 'standard' leaves those options under operator control. In strict mode the operator may still opt back INTO IP binding via binding_mode (binding is a relay-mitigation, not a privacy leak — the stored tag is nonce-bound, never a stable IP-derived identifier).")
                    ->values(['strict', 'standard'])
                    ->defaultValue('strict')
                ->end()
                ->enumNode('telemetry')
                    ->info("Widget behavioral telemetry collection: 'off' (default) sends no signal fields, 'minimal' and 'full' opt the widget into reporting bot-heuristic fields (client-controlled and forgeable — a supplement, never the security boundary). Forced to 'off' when privacy_mode is 'strict'. This is the legacy scorer surface the enforce_telemetry gate reads; the adaptive risk engine's evidence stage is armed separately through risk.evidence.telemetry (the data-kiwi-telemetry value the widget container renders).")
                    ->values(['off', 'minimal', 'full'])
                    ->defaultValue('off')
                ->end()
                ->enumNode('binding_mode')
                    ->info("Challenge binding: 'nonce_ip_hmac' (default) binds each challenge to the client IP via a nonce-bound HMAC tag (relay mitigation; the stored tag is unique per challenge, never a stable IP identifier). 'none' disables binding entirely — the core Issuer emits an EMPTY binding tag and verification skips the check (maximum privacy; relay protection off).")
                    ->values(['none', 'nonce_ip_hmac'])
                    ->defaultValue('nonce_ip_hmac')
                ->end()
                ->booleanNode('same_origin_only')
                    ->info('Reject challenge requests whose Origin header is not the application origin with HTTP 403 CROSS_ORIGIN_DENIED (cross-site abuse/CSRF hardening). Requests without an Origin header (curl, same-origin navigation) are allowed. Forced true when privacy_mode is strict.')
                    ->defaultValue(true)
                ->end()
                ->integerNode('rate_limit')
                    ->info('Max challenge issuances per client IP per rate_limit_window_secs (0 = disabled; default 10). Production deployments should keep this on — it bounds the aggregate verification work an attacker can trigger.')
                    ->defaultValue(10)
                    ->min(0)
                ->end()
                ->integerNode('rate_limit_global')
                    ->info('DEPLOYMENT-WIDE cap on challenge issuances per rate_limit_window_secs (0 = disabled; default 500). Enforced on every backend. The enforcement ladder: Redis executes an exact distributed sliding window, atomic and shared by all PHP-FPM workers. A shared PSR-6 pool keeps a best-effort shared window: a non-atomic read-modify-write can briefly exceed the cap under concurrency. Without either, the in-process window is exact per process, so N workers can approach N times the cap in aggregate. Global-only mode (rate_limit: 0) is supported on all backends. Exhaustion returns HTTP 429 with a distinct GLOBAL_RATE_LIMITED code. This hard limiter is the binding constraint on the default deployment: its window throughput (500 per 60s, about 8.3/s) is far below the default resource_capacity.issuance_per_second, so the default deployment is bounded here, not by the resource-pressure signal. Operators scaling beyond this limit must raise BOTH this cap and resource_capacity.issuance_per_second together; the global limiter stores one exact-timestamp member per admitted request, so its Redis cardinality is bounded by this cap itself, never by the window.')
                    ->defaultValue(500)
                    ->min(0)
                ->end()
                ->integerNode('rate_limit_rotation_secs')
                    ->info('HMAC rate-limit identity rotation period in seconds (default 3600; 0 disables rotation). The rate-limit key is HMAC(pepper, "kiwi-rate-v2|epoch|ip"): the same IP yields a DIFFERENT keyed pseudonym in every epoch, so Redis snapshots cannot correlate one source across time periods. The previous-epoch key is still checked so the sliding window stays exact across a rotation boundary. Linkability within one epoch is unavoidable for rate limiting.')
                    ->defaultValue(3600)
                    ->min(0)
                    ->max(86400)
                ->end()
                ->integerNode('rate_limit_window_secs')
                    ->info('Sliding-window size (seconds) for the issuance rate limits (per-client and global). The global limiter stores one exact-ms member per admitted request and prunes on every admission, so its Redis cardinality is bounded by rate_limit_global, never by this window; the value is capped at 3600 (1 hour) so a misconfiguration can never create a multi-hour window whose staleness weakens the limit.')
                    ->defaultValue(60)
                    ->min(1)
                    ->max(3600)
                ->end()
                ->integerNode('resume_claim_ttl_secs')
                    ->info('The recovery-derivation claim lease in seconds (default 60, lower bound 60): the recovery path claims the derivation of a resume claim under this lease, and the TTL must cover the maximum supported derivation duration. Fencing stays correct on expiry: an expired claim is released and a retry may re-claim the derivation.')
                    ->defaultValue(60)
                    ->min(60)
                ->end()
                ->integerNode('argon2_lease_ms')
                    ->info('Tokenized Redis lease lifetime in ms (default 45000). Must exceed the maximum verification request runtime (e.g. PHP request_terminate_timeout) by a safety margin — otherwise a lease can expire while its Argon2 hash is still running and another worker may enter.')
                    ->defaultValue(45000)
                    ->min(1000)
                    ->max(300000)
                ->end()
                ->integerNode('argon2_max_verification_runtime_ms')
                    ->info('The deployment SLO for the wall-clock a single Argon2 verification derivation may take in this deployment, in ms (default 30000, min 1000, max 300000). The Argon admission lease (argon2_lease_ms) must outlive any verification, so the deployment declares the verification runtime and the semaphore lease must exceed it by the safety margin (5000 ms): the extension refuses the container compile unless argon2_lease_ms > argon2_max_verification_runtime_ms + 5000, making the lease-expiry-before-hash-termination invariant a deliberate deployment SLO instead of an operator promise. The declared runtime is not an enforced wall-clock timeout around the blocking Argon hash: on a pathological host a hash can still outlive the lease (fencing keeps correctness, resource concurrency may still be exceeded in that expiry window).')
                    ->defaultValue(30000)
                    ->min(1000)
                    ->max(300000)
                ->end()
                ->scalarNode('argon2_semaphore_namespace')
                    ->info("Per-deployment discriminator for the Redis-backed Argon2 admission leases and the Redis global rate-limit key (defaults to kernel.project_dir). Two deployments sharing one Redis instance must use different namespaces so their lease sets and global windows do not compete. The raw value is derived into the key segment through the one versioned namespace derivation (namespace_key_version); it is never embedded raw.")
                    ->defaultValue('%kernel.project_dir%')
                ->end()
                ->integerNode('namespace_key_version')
                    ->info('The key-version contract of every derived deployment namespace (risk.namespace, argon2_semaphore_namespace, the security-policy readers, the Siteverify stores and the authority pins): 1 = the legacy sanitized shape ([A-Za-z0-9_.-] kept, every other byte `_`), 2 = the digest shape (n_ + the first 128 bits of SHA-256 over the complete raw bytes). When omitted, an existing deployment keeps the legacy shape so its key space survives the upgrade (the extension emits a configuration advisory); namespace_migration: fresh selects the digest shape for a new install. Version 2 changes every key family at once and therefore requires the namespace_migration acknowledgment (drained or fresh). Switching versions is never inferred from the namespace string.')
                    ->defaultNull()
                    ->validate()
                        ->ifTrue(static fn ($v): bool => $v !== null && !\in_array($v, [RedisNamespace::VERSION_LEGACY, RedisNamespace::VERSION_DIGEST], true))
                        ->thenInvalid('namespace_key_version must be 1 (legacy sanitized) or 2 (digest-derived)')
                    ->end()
                ->end()
                ->enumNode('namespace_migration')
                    ->info('The explicit namespace-migration acknowledgment, and the phase of the migration: none (default) = the deployment keeps the legacy sanitized derivation without a cutover. migrating_v2 = the transitional digest phase: the deployment has been quiesced and its pre-cutover state families (outstanding challenges, nonce decision handles, post-solve dispositions, risk aggregates and calibration state, rate-limit and Argon admission windows) drained, and the security-policy, chain and authority-pin readers still consult the legacy namespace so a revocation, an open obligation or a pre-cutover pin can never be silently abandoned. drained = the migration is COMPLETE: the digest derivation is authoritative and NO legacy namespace is read any more, so an unrelated deployment whose raw namespace used to collide under v1 can never couple to this one. fresh = a brand-new install with no pre-cutover state at all: the digest derivation, no legacy reads. The bundle refuses the digest version without one of these acknowledgments.')
                    ->values(['none', 'migrating_v2', 'drained', 'fresh'])
                    ->defaultValue('none')
                ->end()
                ->booleanNode('enforce_telemetry')
                    ->info('When true, the validator rejects tokens whose client-reported telemetry scores as bot-like. LEGACY opt-in hard gate kept only for explicit compatibility — new automation signals must become bounded risk factors instead; telemetry is client-controlled, so this is never the security boundary.')
                    ->defaultValue(false)
                ->end()
                ->integerNode('min_duration_ms')
                    ->info('Minimum solve duration in ms, enforced by SERVER-side timing (null/0 = disabled; the default derives the floor from the difficulty). In strict privacy mode this is forced to 0 — the timing heuristic is off.')
                    ->defaultNull()
                    ->min(0)
                ->end()
                ->integerNode('argon_m_kib')
                    ->info('Argon2id memory cost in KiB (only for argon2id; must be >= 8 * argon_p).')
                    ->defaultValue(0)
                    ->min(0)
                    // Same browser-solvable ceiling as the core
                    // (KiwiCaptcha\Config validates m_kib <= 65536).
                    ->max(65536)
                ->end()
                ->integerNode('argon_t')
                    // Unconditional floor only; the conditional Argon2id
                    // profile rules (t >= 3, p == 1, m_kib >= 8 * p) are
                    // enforced by KiwiCaptcha\Config when the extension builds
                    // it, so this tree must not duplicate those protocol
                    // constraints. The issuance-side ceiling
                    // (Config::MAX_ARGON_T = 6) is the browser-solver cap;
                    // the verifier's structural ceiling is 16 (a signed
                    // record with t in 7..16 passes the structural gates but
                    // is never issued), so the tree refuses the issuance
                    // ceiling at configuration time.
                    ->defaultValue(3)
                    ->min(1)
                    ->max(Config::MAX_ARGON_T)
                ->end()
                ->integerNode('argon_p')
                    ->defaultValue(1)
                    ->min(1)
                ->end()
                ->integerNode('difficulty_bits')
                    ->info('Leading zero bits for SHA-256 challenges (default 18). 18 is the ordinary baseline: mean ≈ 262k hashes, p99 ≈ 1.21M, and exhaustion within the widget\'s 20,000,000-hash cap is cryptographically negligible (≈ 7.3×10⁻³⁴). 20 is the elevated rung, reached via adaptive risk escalation (Argon and StepUp sit above it) — as the default it would collapse the ladder, because the risk resolver treats the configured difficulty as the floor and Allow/SHA16/SHA18/SHA20 would all issue SHA20, whose 20,000,000-hash exhaustion probability is ≈ 5.2×10⁻⁹.')
                    ->defaultValue(18)
                    ->min(1)
                    // Do not re-derive the protocol ceiling here: the single
                    // source of truth is KiwiCaptcha\Config (20, the wasm
                    // solver cannot go higher), so the tree can never drift
                    // from the core's constraint.
                    ->max(Config::MAX_SHA_TARGET_BITS)
                ->end()
                ->integerNode('argon2_difficulty_bits')
                    ->info('Leading zero bits for Argon2id challenges (default 4, max 10). The default was retuned from 8 after the client-performance lab measured the 8-bit rung (16 MiB, t=3, p=1) at ≈16 s p95 on a mainstream desktop — above the absolute 5000 ms UX ceiling; 4 keeps the ordinary solve inside the ceiling, with the elevated rungs reachable via adaptive risk escalation (never the default).')
                    ->defaultValue(4)
                    ->min(1)
                    // Same ceiling as the core's Argon2id target-bits max.
                    ->max(10)
                ->end()
                ->scalarNode('rsw_modulus_n')
                    ->info('The optional rsw time-lock modulus n = p*q as canonical standard base64 of exactly 256 bytes (top bit set, odd). The rsw algorithm (Rivest-Shamir-Wagner style) is an experimental optional rung: the client performs T sequential modular squarings over the 2048-bit composite, and the server verifies instantly through the factorization trapdoor. Required together with rsw_lambda when algorithm is rsw; ignored otherwise (null default = the rsw algorithm is not configured). The modulus is public; the secret lambda below is the trapdoor and must never leave the server configuration.')
                    ->defaultNull()
                ->end()
                ->scalarNode('rsw_lambda')
                    ->info('The rsw secret lambda = lcm(p-1, q-1) as canonical standard base64 of 1..256 even bytes, the trapdoor that lets the server verify without the T squarings. Required together with rsw_modulus_n when algorithm is rsw; ignored otherwise. Never stored on the record and never sent to the client.')
                    ->defaultNull()
                ->end()
                ->arrayNode('rsw_verification_keys')
                    ->info('The optional rsw trapdoor ROTATION keyring: a map of the modulus identity (64 lowercase hex — the canonical-byte rsw_modulus_n_sha256 the rsw-keygen prints, or its legacy base64-text alias during the migration window) to that trapdoor pair {modulus_n, lambda}. A record whose authenticated identity is not the active pair resolves through this keyring, so a rotation (or a mixed-node window during a rollout) keeps outstanding rsw challenges verifiable and reconstructible; a record whose identity is in neither fails closed. Leave it empty when a rotation instead relies on draining every outstanding challenge first.')
                    ->useAttributeAsKey('hash')
                    ->prototype('array')
                        ->children()
                            ->scalarNode('modulus_n')
                                ->cannotBeEmpty()
                                ->isRequired()
                            ->end()
                            ->scalarNode('lambda')
                                ->cannotBeEmpty()
                                ->isRequired()
                            ->end()
                        ->end()
                    ->end()
                    ->defaultValue([])
                ->end()
                ->booleanNode('rsw_identity')
                    ->info('The rsw identity writer switch (protocol v5, default false). When the algorithm is rsw, arming signs the canonical-byte modulus fingerprint (exactly the rsw-keygen rsw_modulus_n_sha256) into the canonical as the final segment and stamps the record protocol v5 — a pre-v5 verifier rejects the unknown version instead of silently ignoring the identity. The two-phase rollout gate requires the confirmed central min_protocol_version floor >= 5 before any node emits v5: deploy the reading binaries fleet-wide first, then enable this switch. When false (the default), rsw issuance keeps the legacy identityless protocol v2 shape.')
                    ->defaultValue(false)
                ->end()
                ->booleanNode('rsw_legacy_identity')
                    ->info('The bounded legacy rsw identity migration mode (default false). While enabled, the historical base64-text identity alias is accepted for identity-bearing records below protocol v5 and as an rsw_verification_keys key, so outstanding records issued before the canonical-byte fingerprint rule keep verifying. Enable it only during the upgrade drain: after the last legacy-capable writer is removed, wait one maximum challenge lifetime (the configured TTL) plus the allowed clock skew / retained-record margin, then set it back to false. A drained deployment must leave it off — the temporary grammar is refused fail-closed, and a legacy-alias keyring key is rejected at container build.')
                    ->defaultValue(false)
                ->end()
                ->integerNode('rsw_t')
                    ->info('The rsw sequential-squaring cost T (default 75,000; validated to 10,000..300,000 when algorithm is rsw). The client performs T sequential modular squarings; the server verifies instantly through lambda.')
                    ->defaultValue(75_000)
                    ->min(10_000)
                    // The issuance ceiling is the single source of truth
                    // (Config::MAX_RSW_T); the tree refuses it at
                    // configuration time.
                    ->max(Config::MAX_RSW_T)
                ->end()
                ->integerNode('challenge_ttl_secs')
                    ->defaultValue(120)
                    ->min(10)
                    ->max(Config::MAX_TTL_SECS)
                ->end()
                ->scalarNode('storage')
                    ->info('Service id implementing KiwiCaptcha\StorageInterface. Defaults to the in-memory ArrayStorage, which is only allowed in test/dev environments — in prod a shared storage is required or the container fails to compile. production verification also REQUIRES an atomic backend (KiwiCaptcha\AtomicStorageInterface — e.g. RedisStorage) so strict single-use holds under concurrency; the explicitly-named allow_best_effort_storage: true option is the escape hatch for deliberately weaker semantics. Siteverify additionally ALWAYS requires an atomic backend when siteverify_secrets is configured (its one-success provider contract depends on it).')
                    ->defaultValue('kiwi_captcha.storage.array')
                ->end()
                ->booleanNode('allow_best_effort_storage')
                    ->info('explicitly-named escape hatch accepting non-atomic storage semantics (e.g. Psr6Storage, whose consume is NOT atomic under concurrency — two racing requests can both win). Default false: production verification requires KiwiCaptcha\AtomicStorageInterface. NEVER set true for Siteverify — its one-success contract is impossible on a non-atomic backend and the container refuses the combination regardless.')
                    ->defaultFalse()
                ->end()
                ->booleanNode('allow_nonredis_rate_limit_fallback')
                    ->info('Explicitly accepts the non-Redis issuance rate limiter in production when any temporal issuance limit (rate_limit or rate_limit_global) is configured but no Redis client and no rate_limit_cache PSR-6 pool are wired. The documented choices: Redis (redis_service) is the exact distributed window; a shared PSR-6 pool (rate_limit_cache) is a cross-request best-effort window; the object-memory window is persistent-runtime-only (RoadRunner/Swoole/amphp or a single CLI process) and request-local under conventional PHP-FPM, so it provides no cross-request protection at all. Default false: production refuses the combination unless the weaker semantics are explicitly accepted.')
                    ->defaultFalse()
                ->end()
                ->booleanNode('allow_local_global_limit_fallback')
                    ->info('DEPRECATED alias for allow_nonredis_rate_limit_fallback: the legacy name still enables the non-Redis issuance rate limiter in production, but the new name covers ANY non-Redis temporal issuance limit (the per-client rate_limit included), not just the global cap. Production temporal limiting requires Redis (redis_service) or a genuinely persistent or shared PSR-6 pool (rate_limit_cache); the object-memory fallback is long-lived-runtime-only (RoadRunner/Swoole/amphp or a single CLI process) and gives no cross-request protection under conventional PHP-FPM. Default false: production refuses the combination.')
                    ->setDeprecated('bel-consulting/kiwicaptcha-symfony', '1.x', 'The "%node%" option is deprecated; use "allow_nonredis_rate_limit_fallback" instead.')
                    ->defaultFalse()
                ->end()
                ->booleanNode('allow_local_argon_admission_fallback')
                    ->info('Explicitly accepts the in-process Argon admission gate in production when argon2_max_concurrent_verifications > 0 but no Redis client is wired. The deployment-wide ceiling then degrades to the per-process gate: the aggregate of N workers can approach N times the configured concurrency. Default false: production refuses the combination.')
                    ->defaultFalse()
                ->end()
                ->scalarNode('redis_service')
                    ->info('Optional service id of a Redis client (\Redis or Predis\Client) used for the Redis-backed Argon2id admission semaphore AND the atomic global rate limiter. When set (and algorithm=argon2id with a positive argon2_max_concurrent_verifications), the concurrency cap is enforced ACROSS PHP-FPM workers, not just per process. When null, the extension falls back to the storage service itself if it is KiwiCaptcha\Storage\RedisStorage (its client is reused), and otherwise to the in-process semaphore (per-process only — see README).')
                    ->defaultNull()
                ->end()
                ->scalarNode('redis_dsn')
                    ->info('HIGH-LEVEL REDIS CONNECTION SETTING (default null): a single connection DSN. When set, the bundle builds the Redis-backed services automatically from this DSN: the challenge storage (KiwiCaptcha\Storage\RedisStorage), the distributed issuance rate limiter, the Argon2id admission semaphore and (when risk is enabled) the risk state store. The connection is built as a Predis\Client, so predis/predis must be installed. An explicit service id wins over the DSN for its knob: `storage` (a custom StorageInterface service), `redis_service` (a custom client for the limiter/semaphore) and `risk.redis_service` (a custom Predis client for the risk state). The DSN shape is redis://host:port/0?prefix=...&password=...; when redis_dsn is null (default) every existing wiring is byte-identical.')
                    ->defaultNull()
                ->end()
                ->scalarNode('route_prefix')
                    ->info('Prefix for the challenge endpoint routes (default /kiwi-captcha). Canonicalized at container build time to one canonical form: begins with a single "/", contains no empty ("//") or dot segments, no backslashes, no query strings, no fragments, no control characters and no percent-encoded bytes (a "%" is refused fail-closed), and the trailing slash is normalized away. Every route and Twig URL receives this canonical prefix.')
                    ->defaultValue('/kiwi-captcha')
                    ->validate()
                        ->always()
                        ->then(static function (mixed $value): string {
                            // The canonical form is decided here, once, so
                            // every consumer (the route loader, the Twig
                            // runtime, the form type and the container
                            // parameter) sees the same string. A literal
                            // that violates the path grammar is refused at
                            // compile time instead of producing a route or
                            // URL that cannot be addressed canonically.
                            if (!\is_string($value) || $value === '') {
                                throw new InvalidConfigurationException('kiwi_captcha.route_prefix must be a non-empty string path beginning with "/"');
                            }
                            if ($value[0] !== '/') {
                                throw new InvalidConfigurationException('kiwi_captcha.route_prefix must begin with "/" (a relative prefix is not a routable path)');
                            }
                            $canonical = $value;
                            if (str_ends_with($canonical, '/')) {
                                $canonical = substr($canonical, 0, -1);
                            }
                            if ($canonical === '') {
                                throw new InvalidConfigurationException('kiwi_captcha.route_prefix cannot be the bare root "/" (the canonical form must contain at least one segment)');
                            }
                            if (str_contains($canonical, '%')) {
                                throw new InvalidConfigurationException('kiwi_captcha.route_prefix must not contain "%" (percent-encoded path ambiguity is refused fail-closed)');
                            }
                            if (str_contains($canonical, '\\')) {
                                throw new InvalidConfigurationException('kiwi_captcha.route_prefix must not contain backslashes');
                            }
                            if (str_contains($canonical, '?')) {
                                throw new InvalidConfigurationException('kiwi_captcha.route_prefix must not contain a query string ("?")');
                            }
                            if (str_contains($canonical, '#')) {
                                throw new InvalidConfigurationException('kiwi_captcha.route_prefix must not contain a fragment ("#")');
                            }
                            if (preg_match('/[\x00-\x1F\x7F]/', $canonical) === 1) {
                                throw new InvalidConfigurationException('kiwi_captcha.route_prefix must not contain control characters');
                            }
                            // The empty element before the leading "/" is the
                            // absolute-path marker, not a segment; every
                            // other empty element ("//", a "/a//" tail) is a
                            // noncanonical double slash.
                            $segments = explode('/', $canonical);
                            for ($i = 1, $count = \count($segments); $i < $count; $i++) {
                                if ($segments[$i] === '') {
                                    throw new InvalidConfigurationException('kiwi_captcha.route_prefix must not contain "//" (empty path segments are refused)');
                                }
                                if ($segments[$i] === '.' || $segments[$i] === '..') {
                                    throw new InvalidConfigurationException('kiwi_captcha.route_prefix must not contain "." or ".." path segments');
                                }
                            }

                            return $canonical;
                        })
                    ->end()
                ->end()
                ->enumNode('asset_mode')
                    ->info('Widget asset delivery tier. "files" (default) is the recommended production tier: the theme emits versioned immutable first-party asset URLs ({prefix}/assets/widget.<sha256-64>.css, runtime.<sha256-64>.js, driver.<sha256-64>.js, worker.<sha256-64>.js — the full 256-bit sha256 hex of the served bytes) with long cache lifetimes and SRI integrity attributes, deduplicated once per page across widgets, and the driver fetches the WASM runtime and the Argon worker asset only when a memory-hard challenge arrives, so a plain SHA-256 page pays nothing for the Argon machinery. The worker runs as a same-origin Worker (no Blob), so files mode needs worker-src \'self\'. "inline" is the documented compatibility / zero-request tier: it embeds the CSS, the WASM runtime and the driver into the page at render time (the historical behavior) and builds its worker from a Blob URL, so inline needs worker-src blob:.')
                    ->values(['inline', 'files'])
                    ->defaultValue('files')
                ->end()
                ->arrayNode('asset_fallback_dirs')
                    ->info('Optional previous-release asset directories for ROLLING DEPLOYS. A page rendered by a new node can reference a lazy-module hash an old node is still serving, and the reverse; AssetController serves the requested content hash from the active assets directory first, then from each fallback directory in order, so worker/locales modules keep loading while the rollout settles. Keep the previous release\'s Resources/public directories mounted here (or front content-addressed assets with shared storage/a CDN). Without fallbacks an unknown hash is a 404, which degrades to worker-unavailable or English-only UI during the rollout.')
                    ->scalarPrototype()->end()
                    ->defaultValue([])
                ->end()
                ->scalarNode('rate_limit_cache')
                    ->info('Optional service id of a PSR-6 pool (Psr\\Cache\\CacheItemPoolInterface) used as SHARED, multi-process rate-limit state, e.g. a Redis-backed Symfony Cache pool. Only used when no Redis client is available for the atomic limiter. The pool must be genuinely cross-worker: a known in-memory adapter (Symfony Cache ArrayAdapter or a subclass) is refused in production, since its items live per process and provide no cross-worker limiting under PHP-FPM. The class check resolves parameter-indirected service ids (%param% placeholders), follows alias chains to the end, follows parent-declared pools (a framework.cache.pools entry with `parent: cache.adapter.array` is refused the same way) and resolves %param% classes; a pool id still unresolvable at compile time FAILS CLOSED in production (reference a concrete pool service id). In dev/test the guard does not apply. When omitted, a per-process in-memory sliding window is used (single-worker only — PHP-FPM workers share no memory).')
                    ->defaultNull()
                ->end()
                ->scalarNode('rate_limit_pepper')
                    ->info('Secret used to HMAC client IPs before they are used as rate-limit keys, so raw IPs are never stored. Defaults to secret_key when not set. Configure a dedicated, stable pepper instead: the HMAC identities anchor the per-client rate-limit memory, and a routine signing-key rotation must not silently reset that memory. A fresh pepper derives fresh identities, so every client window would restart empty. An emergency root compromise may intentionally rotate everything; a routine rotation should leave the rate-limit identities untouched.')
                    ->defaultNull()
                ->end()
                ->integerNode('argon2_max_concurrent_verifications')
                    ->info('Max concurrent Argon2id verifications (0 = unlimited). Each verification allocates argon_m_kib of memory, so size this to the available memory. The gate applies REGARDLESS of the locally selected issuance algorithm: shared Rust/PHP Argon records stay protected (a Symfony service issuing SHA challenges may still receive a solution for an Argon record written by a Rust service — the gate is consulted based on the STORED record\'s algorithm). With a Redis client available (redis_service, or RedisStorage as the storage backend) the cap is enforced across all PHP-FPM workers via tokenized leases; otherwise it is best-effort per process (see README for the multi-worker caveat).')
                    ->defaultValue(2)
                    ->min(0)
                ->end()
                ->integerNode('argon2_saturation_pressure_cap')
                    ->info('BOUNDED SATURATION-PRESSURE COUNTER of the Redis-backed Argon2id admission semaphore (default 64): when a cap is saturated, each refused contender increments a {..}:sem:waiters counter (with the lease lifetime\'s TTL). Once that counter EXCEEDS this cap (the boundary value equal to the cap does NOT trip), the acquire script returns its distinguishable sentinel (-1) after removing the contender\'s own entry, and acquire() maps it to the explicit fast-fail CapacityExceeded path: null immediately (surfaced as the captcha violation/429), no lease slot held, no counter residue — the fast-fail is observable through RedisAdmissionSemaphore::lastAcquireFastFailed(), so telemetry can tell a saturation storm from ordinary cap contention. Admission is immediate and non-blocking: nothing queues, blocks or waits behind a saturated gate — the counter is a gauge of saturation pressure, never a queue. The gauge can therefore never grow unboundedly during an Argon2id saturation storm (steady state = the cap).')
                    ->defaultNull()
                    ->min(1)
                ->end()
                ->integerNode('argon2_max_waiters')
                    ->info('DEPRECATED alias for argon2_saturation_pressure_cap: the legacy name described a bounded waiters guard, but the value is a bounded saturation-pressure counter — the semaphore never queues, waits or blocks; admission is immediate and non-blocking, and once the counter exceeds the value the acquire fast-fails with the distinguishable capacity sentinel (no slot held). The legacy name still wires the same value.')
                    ->setDeprecated('bel-consulting/kiwicaptcha-symfony', '1.x', 'The "%node%" option is deprecated; use "argon2_saturation_pressure_cap" instead.')
                    ->defaultValue(64)
                    ->min(1)
                ->end()
                ->scalarNode('public_base_url')
                    ->info("The deployment's public origin (e.g. https://captcha.example.com), taken from server config and never from the Host header. When set, the challenge endpoint's same-origin check compares the request Origin against this canonical origin instead of the request's own scheme and host. A forged Host header can therefore never make a cross-origin request look same-origin, and the expected origin stays stable behind load balancers. The value must be a canonical https origin (a host, no credentials, no path, no query, no fragment): a literal is validated at container build time, an env-resolved %env()% value when the challenge controller is constructed. When null (default), the same-origin check derives the expected origin from the request itself; this is allowed in test/dev only. In production with same-origin enforcement (the default) or Siteverify active, the value is required: the extension fails at container compile time otherwise.")
                    ->defaultNull()
                ->end()
                ->integerNode('argon2_max_per_tenant')
                    ->info('PER-SCOPE CONCENTRATION cap of the Redis-backed Argon2id admission semaphore: each scope string gets its OWN lease set ({kiwicaptcha:argon2:leases:<ns>}:<scope>, checked IN ADDITION to the global argon2_max_concurrent_verifications cap). A per-scope cap BELOW the global cap prevents one busy scope from monopolizing the shared capacity — it is a concentration cap, not a guaranteed share and not a weighted-fair scheduler: it never reserves a specific share for any tenant, it only bounds how much of the global capacity a single scope may occupy. Anti-monopoly across scopes requires a global concurrency of at least 2: with a global cap of exactly 1 there is only one shared slot, so no implementation can reserve capacity for another scope. Null (default) derives the effective cap from the global cap (max(1, global - 1)), so with the default global cap of 2 one scope can never occupy both slots. Explicit values must be strictly below the global cap when the global cap is positive (a cap at or above the global cap can never bind, so it is refused); the waiters guard stays global.')
                    ->defaultNull()
                    ->min(1)
                ->end()
                ->arrayNode('resource_capacity')
                    ->info('Deployment-wide issuance capacity (the shared Redis counter denominator of the resource-pressure provider\'s issuanceCapacity headroom). Separate from the per-process emergency cap (risk.hard_limits.process_per_second), which only bounds the in-process ProcessEmergencyCap admission layer.')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->integerNode('issuance_per_second')
                            ->info('Deployment-wide issuance capacity (shared Redis counter denominator). Default 500, aligned with the hard limiter rate_limit_global (500 per rate_limit_window_secs 60): the default deployment is constrained by that hard limiter, not by this capacity, so the two defaults make the same scale claim. The headroom formula max(0, cap - rate) * 1000 / cap denies only when the measured per-second issuance approaches this value. Operators scaling beyond the hard limiter must raise BOTH this denominator and rate_limit_global together — the global limiter stores one exact-timestamp member per admitted request, so its Redis cardinality is bounded by the cap itself, never by the window. Separate from the per-process emergency cap (hard_limits.process_per_second).')
                            ->defaultValue(500)
                            ->min(1)
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('risk')
                    ->info('Adaptive risk engine (kiwicaptcha/kiwicaptcha-risk-php, risk-v1 protocol): a privacy-first, self-hosted scoring layer that adapts challenge difficulty — or denies issuance — per source before a challenge is even minted. Stores only keyed ephemeral pseudonyms (no raw IPs, no stable identifiers); the optional continuity cookie is a first-party, HttpOnly, random 16-byte nonce (never an IP-derived identifier) that links requests from the same browser for the "session" signal. The canonical risk-v1 Lua state script ships INSIDE the package (resources/risk-v1.lua). OFF by default: enabling it requires a Predis\\Client (risk.redis_service, or the bundle redis_service / RedisStorage client when it is a Predis\\Client) — the extension fails fast with a LogicException otherwise.')
                    ->canBeEnabled()
                    ->children()
                        ->scalarNode('redis_service')
                            ->info('Optional service id of a Predis\\Client used for the risk state store (the canonical risk-v1 EVALSHA Lua script). When null, the extension reuses the bundle Redis client resolved from redis_service / RedisStorage when it is a Predis\\Client; otherwise risk.enabled fails at compile time with a LogicException.')
                            ->defaultNull()
                        ->end()
                        ->scalarNode('namespace')
                            ->info('Per-deployment discriminator for the risk Redis keys (hash tag {kiwi:<namespace>}). Defaults to kernel.project_dir; derived into the key segment through the versioned namespace derivation (namespace_key_version): version 1 sanitizes to [A-Za-z0-9_.-], version 2 emits the digest form (n_ + the first 128 bits of SHA-256 over the complete raw bytes). Two deployments sharing one Redis instance must use different namespaces so their risk state does not compete.')
                            ->defaultValue('%kernel.project_dir%')
                        ->end()
                        ->scalarNode('master_secret')
                            ->info('HKDF master key for the risk identity keys (source/subnet/session/principal). MUST be a high-entropy secret (%env(KIWI_RISK_SECRET)% recommended). When null, the bundle derives the keys from the captcha secret_key (documented fallback). Configure a dedicated, stable master secret: the derived identities anchor the adaptive risk memory, and a routine signing-key rotation must not silently reset that memory. A fresh master derives fresh pseudonyms, so every source/subnet/session counter restarts at zero and a source flagged earlier loses its memory. A compromise of one secret never leaks the other. An emergency root compromise may intentionally rotate everything; a routine rotation should leave the risk identities untouched.')
                            ->defaultNull()
                        ->end()
                        ->integerNode('source_epoch_secs')
                            ->info('Epoch length in seconds for the SOURCE pseudonym (default 900). The source identity rotates every epoch, so old snapshots cannot correlate one source across time periods.')
                            ->defaultValue(900)
                            ->min(60)
                        ->end()
                        ->integerNode('subnet_epoch_secs')
                            ->info('Epoch length in seconds for the SUBNET pseudonym (default 900).')
                            ->defaultValue(900)
                            ->min(60)
                        ->end()
                        ->integerNode('subnet_ipv4_prefix')
                            ->info('IPv4 subnet mask bits for the network cohort identity (default 24).')
                            ->defaultValue(24)
                            ->min(0)
                            ->max(32)
                        ->end()
                        ->integerNode('subnet_ipv6_prefix')
                            ->info('IPv6 subnet mask bits for the network cohort identity (default 56).')
                            ->defaultValue(56)
                            ->min(0)
                            ->max(128)
                        ->end()
                        ->integerNode('state_ttl_secs')
                            ->info('TTL of the live risk counters (source/subnet/session/global) in seconds (default 1800).')
                            ->defaultValue(1800)
                            ->min(60)
                        ->end()
                        ->integerNode('session_state_ttl_secs')
                            ->info('SERVER-SIDE risk session/state retention in seconds (default 1800, min 60): the TTL of the session pseudonym\'s risk state and of the first-seen session context/TLS records. Deliberately separate from continuity_cookie.ttl_secs: the browser cookie may legitimately be a session cookie (ttl_secs 0), while Redis security state must always carry a positive bounded expiry. Never derive this from the cookie lifetime.')
                            ->defaultValue(1800)
                            ->min(60)
                        ->end()
                        ->integerNode('principal_ttl_secs')
                            ->info('TTL of the principal counter in seconds (default 86400). The bundle never records a principal itself — when a PrincipalResolverInterface service is wired, the RESOLVED principal of the current request flows through pre-issue, post-solve and every feedback signal (HMAC-pseudonymized before storage); apps that want principal reputation but feed no principal feedback keep the counter dormant under this TTL.')
                            ->defaultValue(86400)
                            ->min(60)
                        ->end()
                        ->integerNode('dedupe_ttl_secs')
                            ->info('Event-dedupe window in seconds (default 60): an identical event_id is applied at most once, so retries of the same request never double-count.')
                            ->defaultValue(60)
                            ->min(1)
                        ->end()
                        ->integerNode('hysteresis_ms')
                            ->info('Global pressure level hysteresis window in ms (default 60000): the global level only leaves a band after this quiet window, so level flaps do not oscillate issuance policy.')
                            ->defaultValue(60000)
                            ->min(1000)
                        ->end()
                        ->arrayNode('saturations')
                            ->info('Raw counter saturations (fixed-point 1000 = one unit) for the state script; higher saturation = slower reaction to the signal.')
                            ->addDefaultsIfNotSet()
                            ->children()
                                ->integerNode('src_fast')->defaultValue(8000)->min(1)->end()
                                ->integerNode('src_slow')->defaultValue(100000)->min(1)->end()
                                ->integerNode('issue')->defaultValue(6000)->min(1)->end()
                                ->integerNode('bad')->defaultValue(4000)->min(1)->end()
                                ->integerNode('mal')->defaultValue(3000)->min(1)->end()
                                ->integerNode('rep')->defaultValue(2000)->min(1)->end()
                                ->integerNode('action')->defaultValue(6000)->min(1)->end()
                                ->integerNode('switch')->defaultValue(10000)->min(1)->end()
                                ->integerNode('global')->defaultValue(70000)->min(1)->end()
                                ->integerNode('trust')->defaultValue(10000)->min(1)->end()
                                ->integerNode('principal')->defaultValue(10000)->min(1)->end()
                            ->end()
                        ->end()
                        ->arrayNode('weights')
                            ->info('13 fixed-point weight fields (0..1000) of the risk-v1 scorer. Defaults are the contract defaults (identical to fixtures.json).')
                            ->addDefaultsIfNotSet()
                            ->children()
                                ->integerNode('source_fast')->defaultValue(RiskWeights::DEFAULT_SOURCE_FAST)->min(0)->max(1000)->end()
                                ->integerNode('source_slow')->defaultValue(RiskWeights::DEFAULT_SOURCE_SLOW)->min(0)->max(1000)->end()
                                ->integerNode('subnet_fast')->defaultValue(RiskWeights::DEFAULT_SUBNET_FAST)->min(0)->max(1000)->end()
                                ->integerNode('issue_debt')->defaultValue(RiskWeights::DEFAULT_ISSUE_DEBT)->min(0)->max(1000)->end()
                                ->integerNode('bad_proof')->defaultValue(RiskWeights::DEFAULT_BAD_PROOF)->min(0)->max(1000)->end()
                                ->integerNode('malformed')->defaultValue(RiskWeights::DEFAULT_MALFORMED)->min(0)->max(1000)->end()
                                ->integerNode('replay')->defaultValue(RiskWeights::DEFAULT_REPLAY)->min(0)->max(1000)->end()
                                ->integerNode('action_failure')->defaultValue(RiskWeights::DEFAULT_ACTION_FAILURE)->min(0)->max(1000)->end()
                                ->integerNode('scope_switch')->defaultValue(RiskWeights::DEFAULT_SCOPE_SWITCH)->min(0)->max(1000)->end()
                                ->integerNode('global_pressure')->defaultValue(RiskWeights::DEFAULT_GLOBAL_PRESSURE)->min(0)->max(1000)->end()
                                ->integerNode('network_risk')->defaultValue(RiskWeights::DEFAULT_NETWORK_RISK)->min(0)->max(1000)->end()
                                ->integerNode('trust_credit')->defaultValue(RiskWeights::DEFAULT_TRUST_CREDIT)->min(0)->max(1000)->end()
                                ->integerNode('principal_credit')->defaultValue(RiskWeights::DEFAULT_PRINCIPAL_CREDIT)->min(0)->max(1000)->end()
                            ->end()
                        ->end()
                        ->arrayNode('v2')
                            ->info('RISK-V2 ADDITIVE EVIDENCE WEIGHTS: the three fixed-point weight fields (0..1000) of the risk-v2 additive factors (honeypot/decoy evidence, session client-context consistency, trusted-edge TLS consistency), wired into the RiskGateway. The defaults ARE the contract defaults (identical to the risk-v2 package).')
                            ->addDefaultsIfNotSet()
                            ->children()
                                ->integerNode('honeypot_weight')->defaultValue(RiskV2Weights::DEFAULT_HONEYPOT)->min(0)->max(1000)->end()
                                ->integerNode('session_consistency_weight')->defaultValue(RiskV2Weights::DEFAULT_SESSION_INCONSISTENCY)->min(0)->max(1000)->end()
                                ->integerNode('tls_weight')->defaultValue(RiskV2Weights::DEFAULT_TLS)->min(0)->max(1000)->end()
                            ->end()
                        ->end()
                        ->integerNode('policy_version')
                            ->info("SECURITY-POLICY EPOCH stamped (signed) into every issued challenge record and enforced at verification. A node stamps and enforces max(configured, central min_policy_epoch), so raising the central {kiwi:<ns>}:security-policy min_policy_epoch above this configured value revokes only older challenges: every node follows the central epoch, the readiness probe stays ready for a node whose configured value is behind, and new issuances verify immediately. Outside a declared rollout window (risk.policy_rollout_min_epoch) the strict-equality contract stays: a record stamped under a different effective epoch is rejected with WrongPolicyVersion. Changing this configured value is therefore a coordinated cutover, not a local restart, because challenges the node issued earlier (stamped under the earlier value) are invalidated across every node that follows the central state — unless a rollout window is declared for the drain. Cosmetic configuration changes must NOT bump it. The risk-v1 policy CONTRACT version is internal to the risk package (RiskPolicy::CONTRACT_VERSION) and independent of this knob.")
                            ->defaultValue(1)
                            ->min(1)
                        ->end()
                        ->integerNode('policy_rollout_min_epoch')
                            ->info('DECLARED POLICY-ROLLOUT WINDOW FLOOR of the security-policy epoch (default null = no window, strict equality). While set, the verifier accepts a record whose policy_version sits within [floor, expected] (the expected epoch being max(risk.policy_version, central min_policy_epoch)), so a mixed N/N+1 fleet redeems challenges cross-node with zero spurious rejections while the old epoch drains. The floor is an EXPLICIT deployment declaration only: nothing derives it from the central min_policy_epoch, and it must be strictly lower than risk.policy_version — declare the OLD epoch here while bumping policy_version to the new one, then remove the window (strict equality returns) once every node serves the new epoch. A window is a bounded revocation delay, exactly as deliberate as the fleet drain it covers.')
                            ->defaultNull()
                            ->min(1)
                        ->end()
                        ->arrayNode('global_floors')
                            ->info('Minimum action per global pressure level 1..4 (default: 1=>sha16, 2=>sha18, 3=>sha20, 4=>sha20). The deployment-wide state script raises/lowers the level; the floor guarantees the aggregate posture tightens before per-source signals do. Index 0 is always Allow in the policy handed to the engine, and when global_pressure.enabled is false every floor is Allow (the global controller is off).')
                            ->useAttributeAsKey('level')
                            ->prototype('enum')
                                ->values(self::RISK_ACTIONS)
                            ->end()
                            ->defaultValue([
                                1 => RiskAction::Sha16->value,
                                2 => RiskAction::Sha18->value,
                                3 => RiskAction::Sha20->value,
                                4 => RiskAction::Sha20->value,
                            ])
                        ->end()
                        ->arrayNode('scopes')
                            ->info('Per-scope policy. The KEY is the application scope string (the one passed to the challenge endpoint / form "scope" option); "id" is the int scope identifier stored in Redis state — it MUST stay stable once deployed (defaults to crc32 of the scope name), two scopes must never share an id. Scopes NOT listed here are handled by the unknown_scope node (baseline = the adaptive engine declines to evaluate and the controller issues the default profile; reject = the controller returns the risk-denied 429 without issuing; minimum = synthetic policy base_risk 100 / minimum sha20 / degraded sha20).')
                            ->useAttributeAsKey('name')
                            ->arrayPrototype()
                                ->children()
                                    ->integerNode('id')
                                        ->info('Explicit int scope id (stable across deploys). Defaults to crc32(scope name) & 0x7fffffff.')
                                        ->defaultNull()
                                        ->min(1)
                                    ->end()
                                    ->integerNode('base_risk')
                                        ->info('Score floor for this scope before any signal is added (0..1000).')
                                        ->defaultValue(100)
                                        ->min(0)
                                        ->max(1000)
                                    ->end()
                                    ->enumNode('minimum')
                                        ->info('Hard minimum action: issuance can never be WEAKER than this regardless of signals (floor, not a target).')
                                        ->values(self::RISK_ACTIONS)
                                        ->defaultValue('allow')
                                    ->end()
                                    ->enumNode('degraded')
                                        ->info('Action used when the risk state backend is unavailable (circuit-breaker open / store failure). Availability-first by default: challenges are still issued with the bundle\'s own configured difficulty.')
                                        ->values(self::RISK_ACTIONS)
                                        ->defaultValue('allow')
                                    ->end()
                                    ->booleanNode('post_solve_check')
                                        ->info('When true, a VALID solve triggers a fresh POST-SOLVE assessment (SolveSuccess) with the same context; a Deny there fails the validation with the "kiwi.post_solve_rejected" error and a StepUp fails it with "kiwi.post_solve_step_up_required" (the application routes the user to MFA/passkey/email confirmation). The gateway does NOT confirm its own post-solve decision — ConfirmedLegitimate / ConfirmedAbuse are application-only signals that require a decision id.')
                                        ->defaultValue(false)
                                    ->end()
                                    ->scalarNode('target_field')
                                        ->info('OPTIONAL form field name carrying this scope\'s TARGET IDENTIFIER (the pre-auth claimed id, e.g. the username or email field of a login form). When configured, the risk engine\'s target resolver reads the submitted value through the versioned normalization pipeline (NFKC, case fold, trim, provider email canonicalization) and stores only its HMAC pseudonym; the outcome bridge\'s LoginFailure/CheckPassport lanes likewise address the failure report by the target pseudonym. Null (default) = the scope carries no target dimension and the bridge reports failures without a target handle.')
                                        ->defaultNull()
                                        ->validate()
                                            ->ifTrue(static fn ($v): bool => \is_string($v) && preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $v) !== 1)
                                            ->thenInvalid('risk.scopes.*.target_field must be a form field name of 1-128 characters of [A-Za-z0-9._:-]')
                                        ->end()
                                    ->end()
                                    ->floatNode('stake_usd')
                                        ->info('Per-action stake override in USD (the value of one successful abuse of THIS action, e.g. a comment submission is worth less than a bank transfer). When set it replaces the value_class default for the pricing ceiling check, so low-value submission forms need not carry a step-up minimum.')
                                        ->defaultNull()
                                        ->min(0)
                                    ->end()
                                    ->enumNode('value_class')
                                        ->info('The value class of this scope\'s protected action (low, standard, high, critical; default standard): what a solved request on this scope is worth to the deployment. The continuous pricing stage multiplies the risk score by the class weight (800, 1000, 1200, 1400 per mille) before quantizing onto the challenge ladder, so the same score prices a critical action (admin login, money movement) onto a stronger rung than a low one. The class only ever raises the composed action; the plain policy floors keep applying underneath. The calibrated declared abuse values (the solver reference table, measured attacker cost per 1000 over the 10x calibration margin) are: low 0.00005, standard 0.0001, high 0.0001, critical 0.0002 dollars per 1000 solves. A scope whose declared stake exceeds its rung\'s measured ceiling cannot be priced by raw proof of work at any difficulty. The doctor\'s verdict then says exactly that and points at the enforcement knob: escalate this scope\'s disposition policy by setting risk.scopes.<name>.minimum to step_up or deny.')
                                        ->defaultValue('standard')
                                        ->values(['low', 'standard', 'high', 'critical'])
                                    ->end()
                                ->end()
                            ->end()
                            ->defaultValue([
                                'contact' => ['id' => null, 'base_risk' => 60, 'minimum' => 'sha16', 'degraded' => 'sha18', 'post_solve_check' => false, 'value_class' => 'standard'],
                                'signup' => ['id' => null, 'base_risk' => 100, 'minimum' => 'sha16', 'degraded' => 'sha20', 'post_solve_check' => true, 'value_class' => 'standard'],
                                'login' => ['id' => null, 'base_risk' => 120, 'minimum' => 'sha18', 'degraded' => 'sha20', 'post_solve_check' => true, 'value_class' => 'standard'],
                                'password_reset' => ['id' => null, 'base_risk' => 180, 'minimum' => 'sha18', 'degraded' => 'sha20', 'post_solve_check' => true, 'value_class' => 'standard'],
                                'admin_login' => ['id' => null, 'base_risk' => 300, 'minimum' => 'sha20', 'degraded' => 'deny', 'post_solve_check' => true, 'value_class' => 'standard'],
                                'financial_action' => ['id' => null, 'base_risk' => 400, 'minimum' => 'sha20', 'degraded' => 'deny', 'post_solve_check' => true, 'value_class' => 'standard'],
                            ])
                        ->end()
                        ->arrayNode('unknown_scope')
                            ->info('Behavior for scopes that are not configured. minimum (default): unknown scopes are assessed under a synthetic policy (base_risk 100, minimum Sha20, degraded Sha20, ladder defaults) — a typo\'d scope string stays fail-safe (never silently weak) without taking the site down. reject: TRUE rejection — the controller returns the risk-denied response (HTTP 429 RISK_DENIED) without issuing any challenge. baseline: the adaptive engine declines to evaluate and the controller issues the default profile (baseline Kiwi verification still applies).')
                            ->addDefaultsIfNotSet()
                            ->children()
                                ->enumNode('mode')->values(['reject', 'baseline', 'minimum'])->defaultValue('minimum')->end()
                            ->end()
                        ->end()
                        ->enumNode('novelty_enforcement')
                            ->values(['learn', 'enforce'])
                            ->defaultValue('learn')
                            ->info('Network-novelty enforcement. "learn" (default, production-safe) records the network tag on every successful login without demanding a step-up, so a rollout never locks out existing users who have no network history yet. "enforce" demands step-up on a genuinely novel ASN/network. Switch to enforce after the learning window.')
                        ->end()
                        ->arrayNode('global_pressure')
                            ->info('Global attack-pressure controller (levels 0-4 with hysteresis).')
                            ->addDefaultsIfNotSet()
                            ->children()
                                ->booleanNode('enabled')->defaultTrue()->end()
                                ->integerNode('hysteresis_secs')->defaultValue(30)->min(1)->max(300)->end()
                            ->end()
                        ->end()
                        ->arrayNode('argon_capacity')
                            ->info('Never self-DoS: when Argon capacity is saturated, a decision that would otherwise issue Argon work is re-escalated to the interactive step-up flow (403 STEP_UP_REQUIRED) instead of weakening the guard to a weaker proof, so the capacity ceiling can never be traded for a lighter challenge.')
                            ->addDefaultsIfNotSet()
                            ->children()
                                ->booleanNode('enabled')->defaultTrue()->end()
                            ->end()
                        ->end()
                        ->integerNode('argon_verification_memory_kib')
                            ->info('The FIXED memory envelope for ALL adaptive Argon challenges : the server-side verification cost of an Argon challenge is bounded by this SINGLE value regardless of the risk decision. Risk escalates the TARGET DIFFICULTY (the expected nonce search space via risk.argon_escalation_target_bits), never the memory — the adaptive engine must never increase the SERVER verification cost as its difficulty mechanism.')
                            ->defaultValue(16384)
                            ->min(1024)
                            ->max(65536)
                        ->end()
                        ->arrayNode('argon_escalation_target_bits')
                            ->info('Target-difficulty escalation ladder of the three adaptive Argon actions: EXACTLY 3 entries — Argon16, Argon32, Argon64 — strictly increasing within 1..Config::MAX_ARGON2_TARGET_BITS (default [1, 2, 4]). The Argon2id memory stays at risk.argon_verification_memory_kib for every action (t=3, p=1); only the expected nonce search space escalates, so the server verification cost ceiling is risk-independent. The default was retuned from [1, 4, 8] after the client-performance lab measured the 8-bit rung (16 MiB, t=3, p=1) at ≈16 s p95 on a mainstream desktop — above the absolute 5000 ms UX ceiling; 4 keeps the highest ordinary rung inside the ceiling (rungs above it remain reachable, but only under adaptive escalation, never as the default). A ladder violating 1 <= rung1 < rung2 < rung3 <= Config::MAX_ARGON2_TARGET_BITS is refused at configuration time (the rungs must be strictly increasing and bounded by the core\'s Argon2id widget ceiling).')
                            ->integerPrototype()->min(1)->max(Config::MAX_ARGON2_TARGET_BITS)->end()
                            ->defaultValue([1, 2, 4])
                            ->validate()
                                ->ifTrue(static fn (array $v): bool => \count($v) !== 3
                                    || $v[0] >= $v[1]
                                    || $v[1] >= $v[2])
                                ->thenInvalid('must be EXACTLY 3 entries satisfying 1 <= rung1 < rung2 < rung3 <= '.Config::MAX_ARGON2_TARGET_BITS.' — the Argon16/32/64 target-bits ladder, bounded by Config::MAX_ARGON2_TARGET_BITS (the core\'s Argon2id widget ceiling)')
                            ->end()
                        ->end()
                        ->integerNode('security_epoch_cache_secs')
                            ->info('Cache TTL of the SecurityEpochMonitor\'s central security-policy read : the monitor reads `{kiwi:<ns>}:security-policy` hash\'s `min_policy_epoch` at most once per window, keeps a MONOTONIC in-process max (a regressed central value is ignored) and serves the last-observed epoch when Redis is unavailable. The bounded revocation latency of a policy bump is one cache window.')
                            ->defaultValue(1)
                            ->min(1)
                            ->max(30)
                        ->end()
                        ->integerNode('security_epoch_max_stale_secs')
                            ->info('MAX-STALE FAIL-CLOSED window of the SecurityEpochMonitor : after the last SUCCESSFUL central policy read, once now > last_success + max_stale the monitor reports stale — the cached epoch may be outdated (an emergency revocation could have landed while the node could not read). While stale, the validator fails verification closed (temporary_unavailable — the token is not burned, the server refuses to trust its own cache) and the challenge controller refuses issuance with 503 SERVICE_UNAVAILABLE. Within the window the cached max keeps serving (bounded outage tolerance). The availability trade-off is deliberate: a node that cannot confirm the central policy for max_stale seconds stops issuing and stops verifying, rather than serving potentially-revoked challenges forever.')
                            ->defaultValue(60)
                            ->min(10)
                        ->end()
                        ->booleanNode('decoy_v3_enabled')
                            ->info('PROTOCOL-V3 WRITER SWITCH (default false): when false (the default), challenge issuance NEVER arms the authenticated decoy and always emits protocol v2 — even when the adaptive risk engine is wired — so the deployment is byte-compatible with binaries whose verifiers reject protocol 3 as unknown. When true, issuance MAY arm the decoy (protocol v3), but ONLY when the central security-policy floor ({kiwi:<ns>}:security-policy min_protocol_version) is confirmed >= 3 — the two-phase rollout gate: the floor establishes that every serving binary accepts v3 before any node emits it. A floor below 3, an absent/unreadable central policy or a null security Redis falls back to protocol v2 with a once-per-process warning (fail-safe: v3 is never emitted on uncertainty). The execution surface is gated separately at the v4 floor, see risk.execution_challenge. See operations.md "Protocol v3 two-phase rollout" and "Protocol v4 execution rollout".')
                            ->defaultValue(false)
                        ->end()
                        ->arrayNode('decoy_escalation')
                            ->info('THE DECOY-ESCALATION AUTOFILL-QUALIFICATION GATE (change.md 3.2.2): the runtime arm switch of the one-rung session escalation after a server-confirmed decoy hit. "armed" (default false) is an EXPLICIT CONFIGURATION VALUE: when true the gate opens as a deliberate operator decision and the escalation no longer depends on any qualification matrix (the operator asserts the autofill/password-manager surfaces cannot trip the escalation on a real user). When false, the qualification matrix decides, fail-closed: the gate stays closed and the escalation is inert until every required surface carries a qualifying pass row. "qualification_matrix" / "qualification_registry" optionally point at a VERSIONED asset pair (schemas kiwicaptcha.autofill-qualification/1 and kiwicaptcha.autofill-surfaces/1) outside tests/browser/qualification; the doctor validates a configured pair and reports the gate state either way. A runtime security decision must not depend solely on tests/ QA data: opening the gate is either this explicit value or a versioned asset the doctor checks.')
                            ->children()
                                ->booleanNode('armed')
                                    ->info('EXPLICIT OPERATOR ARM SWITCH for the autofill-qualification gate (default false = fail-closed). When true, the gate is open by configuration value alone — no qualification matrix is consulted. When false, the matrix/registry pair decides (closed until every required surface qualifies). The doctor WARNs while this is true so a deliberate arm is never silent.')
                                    ->defaultFalse()
                                ->end()
                                ->scalarNode('qualification_matrix')
                                    ->info('OPTIONAL path to a versioned qualification-matrix asset (schema kiwicaptcha.autofill-qualification/1) replacing the committed tests/browser/qualification/autofill-matrix.json as the fail-closed runtime record. The doctor validates that a configured path is readable.')
                                    ->defaultNull()
                                ->end()
                                ->scalarNode('qualification_registry')
                                    ->info('OPTIONAL path to the versioned surface registry (schema kiwicaptcha.autofill-surfaces/1) paired with qualification_matrix. The doctor validates that a configured path is readable.')
                                    ->defaultNull()
                                ->end()
                            ->end()
                        ->end()
                        ->scalarNode('result_receipt_signing_key')
                            ->info('OPTIONAL base64 32-byte Ed25519 seed : when configured, the validator signs every valid verification result into an asymmetric receipt ({v, jti, tenant, request_binding, issued_at, expires_at, issuer, region, policy_version, algorithm, target_bits, m_kib, t, p} — the full replay-critical and work-profile set; tenant is the signed scope, not a multi-tenant separation id, so operators serving multiple tenants must use a distinct signing key per tenant) with sodium_crypto_sign_detached, exposed via KiwiCaptchaValidator::verifiedReceiptPayload() / ::verifiedReceiptSignature(). The result verification itself stays CENTRAL-ONLY (the HMAC secret never leaves the server); this key only enables EXPORTED result receipts that third parties verify with the PUBLIC key derived from this seed (never the private key). Signature verification alone is NOT sufficient for single-use actions: the integrator must atomically record the jti (INSERT IF NOT EXISTS / SET NX) and treat a pre-existing jti as a replay (verify_and_consume — README).')
                            ->defaultNull()
                        ->end()
                        ->integerNode('max_challenges_per_scope_per_minute')
                            ->info('PER-SCOPE issuance cap : when > 0, a Redis sliding-window log (a sorted set of admissions pruned to the last 60 s in one atomic Lua script) bounds how many challenges a scope may issue per minute — a public site key + claimed origin can no longer create unlimited billed verification work per scope. Any 60 s sliding window admits at most the cap, so a burst straddling a minute boundary yields exactly the cap, never twice. The quota keys on the SERVER-OWNED scope identity: the configured risk.scopes.<name>.id (stable u32), or the shared synthetic unknown-scope id — the raw scope string is NEVER a Redis key component , and the quota namespace is bounded by the server-owned set when risk.allowed_scopes is configured. The cap is only enforceable with a Redis client (fail-fast at compile time otherwise); each scope gets its own independent window; a warning is logged as the cap is approached (80%).')
                            ->defaultValue(0)
                            ->min(0)
                        ->end()
                        ->arrayNode('allowed_scopes')
                            ->info('SERVER-OWNED SCOPE ALLOWLIST: the list of application scope strings the challenge endpoint may issue for. Empty (default) = any syntactically valid scope is accepted (backward compatible). When NON-EMPTY, a scope outside the list is refused with 422 SCOPE_NOT_ALLOWED BEFORE the risk assessment and the quota checks — the per-scope issuance cap then operates over the server-owned namespace (bounded cardinality), which is the only configuration in which that cap is an independent security bound. Unknown scopes listed here but absent from the risk.scopes map are still assessed under the unknown_scope policy (minimum by default); adding the scope to risk.scopes gives it its own stable canonical id.')
                            ->scalarPrototype()
                                ->validate()
                                    ->ifTrue(static fn (string $v): bool => preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $v) !== 1)
                                    ->thenInvalid('Allowed scope names must match [A-Za-z0-9._:-]{1,128}.')
                                ->end()
                            ->end()
                            ->defaultValue([])
                        ->end()
                        ->arrayNode('sitekey_allowlist')
                            ->info('MIGRATION SITEKEY ALIAS MAP: public sitekey -> scope. A public sitekey is optional legacy metadata, never a secret. When the challenge request scope equals a configured sitekey, it is resolved to the mapped scope — the SERVER-OWNED mapping is authoritative, so an attacker-supplied sitekey can never reduce a route minimum security policy (unknown sitekeys stay scope names subject to allowed_scopes and the risk assessment). Typical: { "6Lc_abc123": "login" }.')
                            ->useAttributeAsKey('sitekey')
                            ->scalarPrototype()
                                ->validate()
                                    ->ifTrue(static fn (string $v): bool => preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $v) !== 1)
                                    ->thenInvalid('Mapped scope names must match [A-Za-z0-9._:-]{1,128}.')
                                ->end()
                            ->end()
                            ->defaultValue([])
                        ->end()
                        ->arrayNode('sitekeys')
                            ->info('SERVER-OWNED v3-style sitekey policy — public sitekey -> {default_scope, actions: {action: scope}, ttl_secs}. The BROWSER sends sitekey + action in the challenge request; the server resolves (sitekey, action) -> security scope, so a client can never invent protected scope names. An unknown action under a configured sitekey is REJECTED (never silently mapped). Sitekeys without a config entry resolve through sitekey_allowlist / the plain scope. The per-sitekey "binding" option is not offered: the core binds issuance by the GLOBAL binding_mode only, so a per-sitekey "required"/"none" claim could not be enforced (a misleading security promise); the global server-owned mode is the only binding control.')
                            ->useAttributeAsKey('sitekey')
                            ->arrayPrototype()
                                ->children()
                                    ->scalarNode('default_scope')
                                        ->defaultValue('login')
                                        ->validate()
                                            ->ifTrue(static fn (string $v): bool => preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $v) !== 1)
                                            ->thenInvalid('default_scope must match [A-Za-z0-9._:-]{1,128}.')
                                        ->end()
                                    ->end()
                                    ->arrayNode('actions')
                                        ->useAttributeAsKey('action')
                                        ->scalarPrototype()
                                            ->validate()
                                                ->ifTrue(static fn (string $v): bool => preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $v) !== 1)
                                                ->thenInvalid('action scope must match [A-Za-z0-9._:-]{1,128}.')
                                            ->end()
                                        ->end()
                                        ->defaultValue([])
                                    ->end()
                                    ->integerNode('ttl_secs')
                                        ->info('Optional per-sitekey challenge lifetime in seconds, overriding the global challenge_ttl_secs — use 300 for close Turnstile token-lifetime parity. Bounded 1..Config::MAX_TTL_SECS (300).')
                                        ->defaultNull()
                                        ->min(1)
                                        ->max(Config::MAX_TTL_SECS)
                                    ->end()
                                ->end()
                            ->end()
                            ->defaultValue([])
                        ->end()
                        ->arrayNode('chaining')
                            ->info('SELECTIVE CHAINED CHALLENGES: an initial inexpensive proof, followed by a risk reassessment at form-submission time. Only a post-solve action STRICTLY STRONGER than what the client actually solved opens a chain — the reassessment\'s action must be a stronger PoW action (e.g. an Argon action) that the solved challenge does not already satisfy under the configured ladders. StepUp is TERMINAL application-level step-up (it NEVER becomes a chained PoW — the application answers with its own step-up flow, e.g. MFA), Deny rejects the submission, and only a strictly-stronger non-StepUp/Deny post-solve action issues a signed one-shot CHAIN TICKET gating a second (stronger) challenge issuance. The chain is a SERVER-SIDE TRANSACTION OBLIGATION: the chain + its obligation mapping (keyed on the bounded pseudonymous obligation id of the (policy-epoch, scope, AUTHORITATIVE request-binding) triple) are created atomically, so a client cannot restart the transaction at stage 1 by discarding the ticket — a later challenge request for the same transaction AUTO-RESUMES the open chain. The chain completes only when the stage-2 challenge VERIFIES (issued -> verified, the TERMINAL state that clears the obligation); a ticket-bearing request is NEVER downgraded to an unchained issuance.')
                            ->addDefaultsIfNotSet()
                            ->children()
                                ->booleanNode('enabled')
                                    ->info('Enable selective chaining. When true, a valid verification whose post-solve reassessment demands a stronger stage returns the kiwi.chain_required violation carrying the signed chain ticket (violation parameter {{ chain_ticket }}); the application re-renders the widget with data-kiwi-chain-ticket=<ticket> and the next challenge request presents it for a one-shot stage-2 issuance. Requires risk.enabled AND a non-null risk.request_binding_authority (the chain is anchored on the AUTHORITATIVE transaction binding — never on an unexamined client string); the extension refuses the combination at compile time.')
                                    ->defaultFalse()
                                ->end()
                                ->integerNode('ttl_secs')
                                    ->info('Lifetime of a chain (state + ticket) in seconds (default 300, bounded 30..3600). The ticket expires server-side at issuedAt + ttl_secs; the chain state TTL matches.')
                                    ->defaultValue(300)
                                    ->min(30)
                                    ->max(3600)
                                ->end()
                                ->integerNode('reservation_lease_secs')
                                    ->info('The SHORT owner-scoped reservation lease of a stage-2 chain in seconds (default 15, bounded 5..60 AND strictly smaller than chaining.ttl_secs). A crashed issuance owner blocks retries for SECONDS, not minutes; the lease is further bounded by the chain record\'s OWN remaining TTL (the signed ticket expiry is the true bound).')
                                    ->defaultValue(15)
                                    ->min(5)
                                    ->max(60)
                                ->end()
                                ->scalarNode('hmac_secret')
                                    ->info('HMAC secret signing the chain tickets. MUST be a high-entropy secret of at least 32 bytes (%env(KIWI_RISK_SECRET)% recommended); a shorter literal secret is refused at compile time and an env-resolved secret is floor-checked when the ticket service is constructed (an env placeholder cannot be judged at build time). When null, the bundle derives it from the risk master_secret (which itself defaults to the captcha secret_key) — a dedicated chain secret is strongly recommended so a compromise of one never leaks the other.')
                                    ->defaultNull()
                                    ->validate()
                                        ->ifTrue(static fn ($v): bool => self::isShortSecret($v))
                                        ->thenInvalid('risk.chaining.hmac_secret must be a string of at least 32 bytes when configured (the core Config::MIN_SECRET_BYTES floor): a shorter ticket-signing key is not a rotation-grade secret. An %%env()%% placeholder is length-checked when the ticket service is constructed')
                                    ->end()
                                ->end()
                            ->end()
                            ->validate()
                                ->ifTrue(static fn (array $v): bool => $v['reservation_lease_secs'] >= $v['ttl_secs'])
                                ->thenInvalid('risk.chaining.reservation_lease_secs must be strictly smaller than risk.chaining.ttl_secs — the reservation lease is a SHORT claim, never the chain lifetime')
                            ->end()
                        ->end()
                        ->scalarNode('request_binding_authority')
                            ->info('OPTIONAL service id of a RequestBindingAuthorityInterface implementation — the AUTHORITATIVE transaction-binding resolver. When configured, the challenge controller resolves the transaction binding ONLY through the authority (resolve($request, $scope, $presented)): the client-presented request_binding field is a HINT, never a value the server signs unexamined, and a binding the authority cannot confirm for the transaction is refused (422 INVALID_REQUEST_BINDING). The authority resolution must be STABLE across one transaction (stage-1 issuance and stage-2 resumption) because the chain obligation is keyed on the authoritative binding. REQUIRED (non-null) when risk.chaining.enabled — a chain without an authoritative binding anchor cannot be a server-side transaction obligation; the extension refuses the combination at compile time.')
                            ->defaultNull()
                            ->cannotBeEmpty()
                        ->end()
                        ->arrayNode('siteverify_secrets')
                            ->info('PROVIDER-COMPATIBLE SITEVERIFY SECRETS: map of server-to-server secret -> EXPECTED SCOPE for the {prefix}/siteverify endpoint. Empty (default) DISABLES the endpoint. Each secret authenticates an application backend (never browsers — a browser must not see it) AND resolves the scope the verifier requires: a login page backend presents its own secret and a financial-action backend presents its secret, so the token scope is enforced server-side (the verifier rejects a weaker login token for the financial secret — no expectedScope=null for multi-scope deployments). `remoteip` is only honored after a valid secret.')
                            ->useAttributeAsKey('secret')
                            // The secrets ARE the map keys, so key
                            // normalization must stay off: a dash-bearing
                            // secret would otherwise be rewritten to
                            // underscores and authenticate against the
                            // wrong bytes, and numeric-string keys must
                            // never be coerced. PHP itself casts a
                            // canonical-decimal string key to int at array
                            // construction; the validation below rejects
                            // that shape with an actionable message instead
                            // of letting an integer secret key reach
                            // hash_equals() and fail every /siteverify
                            // request with a TypeError.
                            ->normalizeKeys(false)
                            ->validate()
                                ->ifTrue(static fn (array $v): bool => \array_filter(
                                    \array_keys($v),
                                    static fn ($k): bool => !\is_string($k) || \strlen((string) $k) < 32,
                                ) !== [])
                                ->thenInvalid('Siteverify secrets are the entire server-to-server authentication boundary — each key must be a string of at least 32 bytes. A purely numeric secret is coerced to an integer array key by PHP itself; choose a secret outside the canonical decimal shape (e.g. base64 with letters, or any 32 random bytes) so it stays a string key.')
                            ->end()
                            ->scalarPrototype()
                                ->validate()
                                    ->ifTrue(static fn (string $v): bool => preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $v) !== 1)
                                    ->thenInvalid('Siteverify expected scopes must match [A-Za-z0-9._:-]{1,128}.')
                                ->end()
                            ->end()
                            ->defaultValue([])
                        ->end()
                        ->arrayNode('hard_limits')
                            ->info('Cheap admission layer BEFORE the risk engine (long-lived-runtime-only, per process): in persistent workers the window is a real per-process emergency shield that gives floods an immediate 429 without touching Redis; under conventional PHP-FPM it is rebuilt per request, so it provides no temporal pre-Redis cap across requests.')
                            ->addDefaultsIfNotSet()
                            ->children()
                                ->integerNode('process_per_second')
                                    ->info('Per-PROCESS emergency cap protecting the process from overwhelming work when Redis/state controls fail (default 10000). The window lives in object memory: it is temporal only in a long-lived runtime (RoadRunner/Swoole/amphp or a single CLI process); under conventional PHP-FPM each request rebuilds the cap, so it provides no temporal pre-Redis cap across requests. Per-source throttling belongs to the distributed keyed layer — the risk-v1 source velocity signals plus the caller\'s own keyed rate limiter (fed back as SourceRateLimitHit). The process-local check runs BEFORE any Redis issuance limiter : a saturated window refuses with the 429 risk-denied response without a single Redis round trip.')
                                    ->defaultValue(10000)
                                    ->min(1)
                                ->end()
                            ->end()
                        ->end()
                        ->enumNode('client_ip_mode')
                            ->values(['direct', 'symfony_trusted_proxies', 'symfony_global'])
                            ->info('Trusted client-IP policy: "symfony_trusted_proxies" (default) trusts EXACTLY the risk.trusted_proxies list (an EMPTY list trusts nobody — Symfony global trusted-proxy state is never inherited implicitly); "direct" always uses the socket peer regardless of any application proxy configuration; "symfony_global" is the explicit opt-in that inherits Symfony\'s process-global trusted-proxy state. The controller, the validator and every risk signal derive the client IP through this policy, so the challenge binding tag, the rate-limit identity and the risk source pseudonym all see the same canonical IP.')
                            ->defaultValue('symfony_trusted_proxies')
                        ->end()
                        ->arrayNode('trusted_proxies')
                            ->info('CIDRs (or exact IPs) of the trusted reverse proxies . Only peers in this list may influence the canonical client IP via X-Forwarded-For / Forwarded (mode symfony_trusted_proxies); every other peer is the socket itself. When the list is empty, no peer is trusted — forwarding headers are ignored everywhere. In mode "direct" this list is unused.')
                            ->scalarPrototype()->end()
                            ->defaultValue([])
                        ->end()
                        ->booleanNode('reject_ambiguous_forwarding')
                            ->info('When a TRUSTED peer sends BOTH X-Forwarded-For AND Forwarded: true (the production default) rejects the request with HTTP 400 AMBIGUOUS_FORWARDING — a proxy sending both is misconfigured, the two headers can disagree, and the canonical IP becomes ambiguous (collapsing many users onto one proxy identity would otherwise weaken per-source rate limits and risk attribution). false logs the anomaly and proceeds with the socket peer. From an UNTRUSTED peer both headers are ignored entirely (never ambiguous, never an anomaly).')
                            ->defaultValue(true)
                        ->end()
                        ->scalarNode('trusted_tls_header')
                            ->info('OPTIONAL name of a TLS-classification header set by TRUSTED reverse-proxy/CDN infrastructure (e.g. "X-Tls-Class" carrying a coarse value like "tls13|http2"). When configured, the challenge controller reads ONLY this header, validates the value against the bounded pattern /^[a-z0-9_+:|:-]{1,64}$/i (a malformed value is ignored) — the 64-character bound and charset match the cross-language risk-v2 contract — and passes it to the risk-v2 client-context as a COARSE, server-attested TLS classification tag — never a raw fingerprint. This input is trusted ONLY from an explicitly trusted reverse proxy/CDN that STRIPS client-supplied values — never enable it without that, or a client can forge the classification. Only the coarse classification is stored (as the session first-seen record); no raw fingerprints are ever stored. Null (default) = the feature is off.')
                            ->defaultNull()
                        ->end()
                        ->arrayNode('trusted_tls_proxies')
                            ->info('CIDRs (or exact IPs) of the trusted edge proxies whose TLS-classification header (risk.trusted_tls_header) is honored. The header is read ONLY when the DIRECT peer of the request (REMOTE_ADDR — the immediate connection, checked with Symfony\'s IpUtils::checkIp) is inside this list; from every other peer the header is ignored (the request is assessed without a TLS tag). The direct peer must be the trusted proxy itself — the proxy must terminate the client connection and strip client-supplied header values. Empty (default) = the header is never read.')
                            ->scalarPrototype()->end()
                            ->defaultValue([])
                        ->end()
                        ->booleanNode('client_context')
                            ->info('OPT-IN coarse client-context collection: when true, the rendered widget container carries data-kiwi-risk-context="coarse" and the widget sends a deliberately coarse capability tag (viewport class, pointer class, language family, timezone class — no canvas/audio/font/GPU signals, no stable identifiers) with every challenge request. Default false: the widget collects no device-capability or screen-size signal in any mode. Refused under privacy_mode "strict" — enabling it requires the operator to deliberately enable coarse client context (privacy_mode "standard" plus this explicit opt-in).')
                            ->defaultFalse()
                        ->end()
                        ->enumNode('execution_challenge')
                            ->info('EXECUTIONCHALLENGEV1 GATE (enum "off" | "on", default "off"): whether issuance MAY arm the browser-execution dimension (the Cap-style layer, see kiwi_captcha.execution_key). "off" (default) = no execution program is ever issued (the byte-identical legacy path). "on" = issuance arms a deterministic execution program when a RISK TRIGGER passes (a non-Allow risk decision; with the risk engine disabled the gate itself is the trigger), and the driver must run it and present the execution digest — a missing/mismatched digest is the deterministic execution-mismatch verification failure. An armed issuance writes protocol v4 (the execution-capable canonical with the signed execution commitment). The gate on requires kiwi_captcha.execution_key — without it the gate is deliberately inert (no execution program is ever issued; the kiwicaptcha:doctor command flags the misconfiguration as a WARN) — AND the central security-policy floor ({kiwi:<ns>}:security-policy min_protocol_version) confirmed >= 4 — the two-phase protocol-v4 rollout gate: the floor establishes that every serving binary accepts protocol v4 before any node emits it; a floor below 4 (or unconfirmed) falls back to execution-unarmed emission with a once-per-process warning. The dimension is SUPPLEMENTARY EVIDENCE ONLY, never the sole acceptance boundary: the PoW proof and the record state machinery always gate. Off under the privacy_strict protection profile (the profile forces it off); on under high_abuse; available in balanced (default off).')
                            ->values(['off', 'on'])
                            ->defaultValue('off')
                        ->end()
                        ->integerNode('container_memory_mib')
                            ->info('Memory budget of the process container in MiB . When configured, /health/ready requires argon2_max_concurrent_verifications * max-adaptive-profile-memory (64 MiB — the risk profiles\' argon64 m_kib 65536 KiB) + 256 MiB headroom <= container_memory_mib; a violated invariant refuses startup (503 memory_budget_invariant). null (or a concurrency cap of 0 = unlimited) keeps the check skipped/documented — the invariant is only meaningful with a finite concurrency cap.')
                            ->defaultNull()
                            ->min(1)
                        ->end()
                        ->arrayNode('calibration')
                            ->info('Privacy-preserving aggregate calibration: score-bucket statistics (no identity, no IP, no pseudonym) with a bounded scope-bias adjustment. min_samples / max_adjustment / max_change_per_minute are passed to the Redis-backed AggregateCalibrator to bound the automatic adjustment; outcome_receipt_ttl_secs is the lifetime of the outcome/calibration receipts AND of the outcome ledger (the once-only confirmation/correction gate — long enough for fraud review / moderation / chargeback labels; it carries only score/scope/action/sample metadata, no identity); the short-lived nonce->decision handles use risk.nonce_to_decision_ttl_secs instead; retention_secs is accepted for backward compatibility with the former in-memory calibrator and is informational (the Redis-backed store uses the risk-v1 contract\'s fixed 24 h window).')
                            ->addDefaultsIfNotSet()
                            ->children()
                                ->booleanNode('enabled')->defaultFalse()->end()
                                ->integerNode('retention_secs')->defaultValue(86400)->min(3600)->end()
                                ->integerNode('min_samples')->defaultValue(1000)->min(10)->end()
                                ->integerNode('max_adjustment')->defaultValue(150)->min(0)->max(1000)->end()
                                ->integerNode('max_change_per_minute')->defaultValue(10)->min(1)->max(60)->end()
                                ->integerNode('outcome_receipt_ttl_secs')
                                    ->info('Lifetime of the outcome/calibration receipts AND of the outcome ledger ({kiwi:<ns>}:outcome:<decision_id> — the once-only confirmation/correction gate) in seconds. Long enough for fraud review / moderation / chargeback labels (default 86400 = 24 h); the payload contains only score/scope/action/sample metadata, never identity. The short-lived nonce->decision handles use risk.nonce_to_decision_ttl_secs instead.')
                                    ->defaultValue(86400)
                                    ->min(3600)
                                    ->max(604800)
                                ->end()
                                ->enumNode('mode')
                                    ->info('Label-selection contract: "complete" = every eligible outcome is labeled and fed to the calibrator; "random_sample" = Kiwi samples at assessment time (the receipt carries a "sampled" flag) and unsampled confirmations are consumed but NOT recorded (status 2 — the label can never select itself into the calibration population; the caller may still apply first-party reputation exactly once); "weighted" = the application supplies the inverse sampling probability per confirmation (RiskGateway::confirmDecisionOutcome($ppm) converts it to weight = 1_000_000/ppm) so labels with known selection bias are re-weighted into the population.')
                                    ->values(['complete', 'random_sample', 'weighted'])
                                    ->defaultValue('random_sample')
                                ->end()
                                ->integerNode('sampling_probability_ppm')
                                    ->info('Kiwi-side label inclusion probability in parts per million (default 100000 = 10%) for "random_sample" mode: each decision is sampled at assessment time and its receipt is marked; only sampled decisions can later be confirmed into the calibration aggregates. In "weighted" mode the application supplies the inverse probability per confirmation instead.')
                                    ->defaultValue(100000)
                                    ->min(1)
                                    ->max(1000000)
                                ->end()
                                ->floatNode('minimum_resolution_ratio')
                                    ->info('In random_sample mode, bias adjustment is suspended while total sampled decisions >= min_samples but resolved/total < this ratio — the label-reporting process must resolve a minimum fraction of the server-selected sample before the model may move (default 0.80; 0 disables the gate).')
                                    ->defaultValue(0.80)
                                    ->min(0.0)
                                    ->max(1.0)
                                ->end()
                                ->floatNode('false_positive_cost')
                                    ->info('Class-normalized calibration prices false positives vs false negatives: false_positive_cost is the per-unit cost of legitimate traffic scored as abusive (default 1.0).')
                                    ->defaultValue(1.0)
                                    ->min(0.1)
                                    ->max(10.0)
                                ->end()
                                ->floatNode('false_negative_cost')
                                    ->info('Class-normalized calibration prices false negatives vs false positives: false_negative_cost is the per-unit cost of abusive traffic scored as legitimate (default 2.0 — abuse that slips through costs twice as much as a false rejection).')
                                    ->defaultValue(2.0)
                                    ->min(0.1)
                                    ->max(10.0)
                                ->end()
                            ->end()
                        ->end()
                        ->integerNode('nonce_to_decision_ttl_secs')
                            ->info('TTL of the short-lived server-side mapping pairing a challenge nonce to its risk decision id ({kiwi:<ns>}:decision:<nonce>, JSON {"decision_id": ...}; NO IP, NO identity). Consumed once with GETDEL after a valid solve. Independent of the outcome lifetime: the handle only bridges the challenge solve window (default 300).')
                            ->defaultValue(300)
                            ->min(60)
                            ->max(3600)
                        ->end()
                        ->arrayNode('continuity_cookie')
                            ->info('First-party session continuity cookie: a random 16-byte nonce (hex, HttpOnly, SameSite=Strict) that links requests from the same browser into the risk engine\'s "session" signal. It carries NO identity — it is a fresh random value, and the engine only ever stores its keyed pseudonym.')
                            ->addDefaultsIfNotSet()
                            ->children()
                                ->scalarNode('name')
                                    ->defaultValue('__Host-kiwi-session')
                                    ->cannotBeEmpty()
                                ->end()
                                ->integerNode('ttl_secs')
                                    ->info("Cookie lifetime (default 30 minutes; the spec 15-30 minute window; 0 = session cookie, no Max-Age). This is the BROWSER cookie lifetime only: the server-side risk-state TTL is risk.session_state_ttl_secs and is always positive.")
                                    ->defaultValue(1800)
                                    ->min(0)
                                ->end()
                                ->scalarNode('path')
                                    ->defaultValue('/')
                                ->end()
                                ->enumNode('samesite')
                                    ->values(['lax', 'strict', 'none'])
                                    ->defaultValue('strict')
                                ->end()
                                ->booleanNode('http_only')
                                    ->defaultValue(true)
                                ->end()
                                ->enumNode('secure')
                                    ->info('Secure flag; null (default) = follow the request scheme (set when the request is HTTPS). A tri-state enum rather than a boolean node: the boolean normalization of some config-component releases collapses an explicit null to true, which would silently turn every scheme-derived deployment into an explicitly-secured one and silence the doctor warning.')
                                    ->values([true, false, null])
                                    ->defaultNull()
                                ->end()
                            ->end()
                            ->validate()
                                ->ifTrue(static fn (array $c): bool => str_starts_with((string) ($c['name'] ?? ''), '__Host-') && (string) ($c['path'] ?? '/') !== '/')
                                ->thenInvalid('risk.continuity_cookie: a __Host- prefixed name requires path: / — browsers refuse a __Host- cookie with any other path, silently eliminating session continuity')
                            ->end()
                            ->validate()
                                ->ifTrue(static function (array $c): bool {
                                    if ((string) ($c['samesite'] ?? 'strict') !== 'none') {
                                        return false;
                                    }
                                    // Effective Secure: explicit true, or the
                                    // __Host- prefix (whose browser contract
                                    // forces Secure regardless of the
                                    // configured/derived flag).
                                    return ($c['secure'] ?? null) !== true
                                        && !str_starts_with((string) ($c['name'] ?? ''), '__Host-');
                                })
                                ->thenInvalid('risk.continuity_cookie: samesite: none requires an effectively Secure cookie (secure: true, or a __Host- prefixed name) — modern browsers reject a SameSite=None cookie without Secure')
                            ->end()
                        ->end()
                        ->scalarNode('region')
                            ->info('Optional deployment region (e.g. "eu-central-1") baked into every issued challenge record and enforced by the verifier: a result token issued in one region is never redeemable elsewhere (Option A of the failover-replay mitigation — the FailoverReplay audit). When null, no region is recorded and verification never applies a region check.')
                            ->defaultNull()
                        ->end()
                        ->arrayNode('redis')
                            ->info('Redis hardening for the CHALLENGE storage (KiwiCaptcha\\Storage\\RedisStorage) — the failover-replay/replay-safety knobs. wait_replicas/wait_timeout_ms issue a verified WAIT after every durability-critical challenge-storage write — issuance, the pending-to-consumed transition, the deterministic-result commit, and the terminal delete-if-pending deletion — so each write has reached N replicas before the caller proceeds (async-replication failover can otherwise lose the write or resurrect a consumed/burned record from a stale replica). Supported for STANDALONE Redis connections only: a Predis Sentinel/replication aggregate and a Predis cluster aggregate are both refused by the storage constructor with wait_replicas > 0 (WAIT is connection-relative: a replication aggregate\'s failure retry executes the WAIT on a replacement connection whose write offset is empty, and a cluster aggregate cannot route a keyless WAIT). ttl_margin_secs extends the retention of challenge/replay-security state beyond the token validity window (must exceed max clock skew + failover margin — pair with a noeviction policy on the security Redis, see README).')
                            ->addDefaultsIfNotSet()
                            ->children()
                                ->integerNode('wait_replicas')
                                    ->info('WAIT numreplicas for every durability-critical challenge-storage write (default 0 = disabled): issuance, the pending-to-consumed transition, the deterministic-result commit, and the terminal delete-if-pending deletion each block until at least this many replicas acknowledged the write. Strengthens replay safety across async replication failover — a write acknowledged by the primary alone can be lost on failover, letting a consumed or burned challenge be replayed against a stale replica after promotion. Supported for STANDALONE Redis connections only: with a Predis Sentinel/replication aggregate or a Predis cluster aggregate the value must stay 0 (the storage constructor refuses both with wait_replicas > 0 — WAIT is connection-relative: a replication aggregate\'s failure retry executes the WAIT on a replacement connection whose write offset is empty, and a cluster aggregate cannot route a keyless WAIT by slot).\n\nHA REPLAY-SAFETY DEPLOYMENT PROFILE: WAIT is acknowledgement hardening, not consensus — it strengthens the durability contract but does NOT by itself guarantee single-use survives every failover. With wait_replicas = 0 (the default), a challenge consumed on the primary can still be replayed after a failover promotes a replica that never received the consume: atomic replay safety holds per Redis authority, but NOT across authority changes. A hardened deployment must choose one of: (A) no automatic promotion for the security Redis (fail closed during failure); (B) wait_replicas > 0 AND a promotion policy that only elects a replica acknowledged by the wait (a sufficiently caught-up replica); or (C) a security-state backend whose acknowledged-write contract itself gives the required durability/consensus property. Do not claim strict replay safety across arbitrary asynchronous failover with wait_replicas = 0.')
                                    ->defaultValue(0)
                                    ->min(0)
                                ->end()
                                ->integerNode('wait_timeout_ms')
                                    ->info('WAIT timeout in ms for the replicas acknowledged (default 100). Only meaningful when wait_replicas > 0.')
                                    ->defaultValue(100)
                                    ->min(1)
                                ->end()
                                ->integerNode('ttl_margin_secs')
                                    ->info('Extra retention on challenge/replay-security state beyond token validity, in seconds (default 60). The challenge record and every consumed-state guard must outlive token validity + max clock skew + failover margin, so a replayed/expired token can never land on a state that already expired and re-accepted it. The 60-second default exceeds ordinary clock skew and failover margins; set 0 only for single-clock test deployments that deliberately want no margin. Pair with a noeviction policy on the security Redis (see README).')
                                    ->defaultValue(60)
                                    ->min(0)
                                ->end()
                            ->end()
                        ->end()
                        ->integerNode('max_outstanding_challenges')
                            ->info('Anti-stockpiling bound: maximum UNSOLVED challenges a single source may hold at once (default 20, min 1). The outstanding accounting is an expiry-aware MEMBERSHIP, not a counter: every issuance atomically prunes expired members, ZADDs the nonce to the source membership ZSET ({kiwi:<ns>}:outstanding:<HMAC(canonical ip)>, member = nonce, score = the Redis-clock deadline) and the live membership ({kiwi:<ns>}:outstanding:global:live), and refuses when the LIVE count reaches the cap. A successful verification, cancellation or proven-not-handed-off issuance removes the nonce from both memberships (one-shot, nonce-authoritative). The memberships expire by their deadlines, and both keys carry a key-level EXPIREAT (latest member deadline + ttl margin) so an abandoned source key cannot accumulate. The challenge endpoint returns the 429 risk-denied response on exhaustion. Bounded memory: an attacker can never stockpile an unbounded number of live challenges for a single source or deployment.')
                            ->defaultValue(20)
                            ->min(1)
                        ->end()
                        ->integerNode('max_outstanding_challenges_global')
                            ->info('Deployment-wide anti-stockpiling cap on outstanding unsolved challenges (default 100000, min 1) — the {kiwi:<ns>}:outstanding:global:live membership ZSET holds every live challenge nonce scored at its Redis-clock deadline; expired members are pruned on every issuance and the cap counts the LIVE members. A source-level solve removes the nonce from the membership like any other release (global pressure is deployment-wide and identity-neutral). The key carries a key-level EXPIREAT (latest member deadline + ttl margin). Exhaustion returns the 429 risk-denied response.')
                            ->defaultValue(100000)
                            ->min(1)
                        ->end()
                        ->arrayNode('challenge_origin_allowlist')
                            ->info('Origin laundering defense: when NON-EMPTY, the challenge POST must carry an Origin header (or Referer-origin fallback) whose scheme+host+port exactly matches one allowlisted origin — otherwise the request is rejected with HTTP 403 origin_rejected BEFORE any CAPTCHA is issued (never a rate-limit hit, no state written). Requests with neither header cannot be matched and are rejected. Comparison is STRUCTURED NORMALIZATION : scheme/host/effective-port, host lowercased, default ports normalized (https 443 / http 80), trailing dots stripped, IDN hosts converted to punycode when ext-intl is available, IPv6 literals kept bracketed — so "https://example.com" matches "https://example.com:443", "https://EXAMPLE.COM." and "https://bücher.example" (as "xn--bcher-kva.example"), but never "https://example.com:444", "http://example.com" or "https://evil-example.com". Server-to-server integrations that cannot send an Origin keep enforce_origin=false (the Referer fallback or a bypassed check is the documented trusted mode). When non-empty, the challenge endpoint also emits `Content-Security-Policy: frame-ancestors <allowlisted origins, space-separated>` .')
                            ->scalarPrototype()->end()
                            ->defaultValue([])
                        ->end()
                        ->booleanNode('enforce_origin')
                            ->info('When true, challenge requests WITHOUT an Origin header — or carrying the literal "null" Origin (opaque/sandboxed origins) — are rejected with HTTP 403 origin_rejected, even when the allowlist is empty. When the allowlist is NON-EMPTY the (required) Origin must additionally be allowlisted (structured normalization). Browser-laundering defense: a framed/cross-site request either lacks a usable Origin or carries one that cannot match. Server-to-server integrations (no Origin header) MUST keep this false — the explicitly trusted mode.')
                            ->defaultValue(false)
                        ->end()
                        ->booleanNode('enforce_fetch_metadata')
                            ->info('When true, challenge requests whose Sec-Fetch-Site header is PRESENT and equals "cross-site" are rejected with HTTP 403 CROSS_SITE_REJECTED — a browser-laundering signal. Raw HTTP bots lack the header and are unaffected, so this is defense-in-depth only (never the security boundary).')
                            ->defaultValue(false)
                        ->end()
                        ->scalarNode('network_classifier_file')
                            ->info('Optional path to a CIDR classifier file ("cidr,flag1,flag2" per line; flags: reserved, hosting, proxy, tor, blocked). Sources in flagged blocks raise the network_risk signal: 600 for hosting, 650 for Tor exits, 750 for known proxies, 950 for reserved and 1000 for blocked. Default null = no network flags.')
                            ->defaultNull()
                        ->end()
                        ->scalarNode('request_binding')
                            ->info('OPTIONAL STATIC transaction binding : a fixed string (1..128 chars, no "|") baked (signed) into every issued challenge when the challenge request carries no request_binding field of its own. For DYNAMIC per-transaction bindings (recommended: a random nonce per page load) the application supplies the binding per request — the widget reads data-kiwi-request-binding, sends it with the challenge POST, carries it in the hidden kiwi_request_binding form field, and the controller/validator enforce it (a challenge bound to one transaction is never redeemable for another). Static binding is the fallback for server-side integrations that never send the field.')
                            ->defaultNull()
                        ->end()
                        ->arrayNode('health')
                            ->info('Rollback-resistant readiness : /health/live is always 200 while the process runs; /health/ready returns 200 only when the signing keys are configured, the security Redis answers a PING (probe cached ~1 s; transient probe timeouts are absorbed by the cache — a single blip never flips a healthy deployment, Argon queue fullness is NEVER consulted), and the CENTRAL security-policy state ({kiwi:<ns>}:security-policy hash: min_protocol_version, min_policy_epoch) is compatible — when the key is present, ready requires min_protocol_version <= 5 (this binary\'s max protocol: the identity-bearing rsw v5 canonical) and min_execution_version <= the binary execution max. A central min_policy_epoch above the risk.policy_version no longer takes the node out of the pool: issuance stamps the effective epoch max(configured, central), so the node follows a central bump, and the lag is logged as a warning instead of failing readiness. When the key is absent, the binary\'s own configuration is authoritative. Operators set the hash to protect mixed-version rolling deployments and rollbacks (see README).')
                            ->addDefaultsIfNotSet()
                            ->children()
                                ->booleanNode('enabled')->defaultTrue()->end()
                            ->end()
                        ->end()
                        ->arrayNode('outcomes')
                            ->info('The typed outcomes plane (application-reported outcomes onto risk events, the outcome ledger and long-memory marks). auto_bridge (default true) enables the Symfony security auto-bridge: a subscriber that translates LoginSuccessEvent into an authenticationSuccess report on the principal pseudonym, and LoginFailureEvent plus observable CheckPassportEvent errors into authenticationFailure reports on the target pseudonym (when the scope\'s target_field is configured) or the session pseudonym. The bridge never breaks authentication (every report is log-and-continue) and never carries a raw identifier into a handle. scope names the risk scope the auth events book under; the bridge arms only when the risk engine is on, the outcomes surface and the security event classes exist, and this scope is configured, so leaving it null keeps the bridge absent and an advisory names the missing knob.')
                            ->addDefaultsIfNotSet()
                            ->children()
                                ->booleanNode('auto_bridge')->defaultTrue()->end()
                                ->enumNode('trust_gate')
                                    ->info('The success-trust gate binding. store (default) uses the bridge-observed windowed failure ratio plus the target marks as evidence: session and source credit ride only an identity below failure_ratio_theta whose target carries no live mark. fail_closed refuses session and source credit unconditionally (no evidence, no credit). The principal credit is unconditional either way.')
                                    ->values(['store', 'fail_closed'])
                                    ->defaultValue('store')
                                ->end()
                                ->floatNode('failure_ratio_theta')
                                    ->info('The windowed failure-ratio ceiling of the store-backed gate: failures / (failures + successes) over the auth-outcome window must sit strictly below this value for session and source credit.')
                                    ->defaultValue(0.05)
                                    ->min(0.0)
                                    ->max(1.0)
                                ->end()
                                ->booleanNode('trust_request_id_header')
                                    ->info('Whether the bridge derives its idempotency id from the X-Request-Id header. False (the default) keeps the id server-side: the header is client-controlled, and one repeated value would collapse every authentication failure into a single deduplicated event. Set true only behind a fronting edge that overwrites the header on every request.')
                                    ->defaultFalse()
                                ->end()
                                ->scalarNode('scope')
                                    ->info('The risk scope name (a key of risk.scopes) whose policy the framework auth events book under, e.g. "login". Required for the auto-bridge to arm; null (default) leaves the bridge unregistered.')
                                    ->defaultNull()
                                    ->validate()
                                        ->ifTrue(static fn ($v): bool => \is_string($v) && preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $v) !== 1)
                                        ->thenInvalid('risk.outcomes.scope must be a scope name of 1-128 characters of [A-Za-z0-9._:-]')
                                    ->end()
                                ->end()
                        ->end()
                    ->end()
                        ->arrayNode('marks')
                            ->info('THE MARKS STAGE of the adaptive engine (long-memory attacker handling, change.md 3.3.3): when the engine is wired with a marks reader, every decision consults the deployment\'s long-memory marks on the requesting identity\'s own dimensions (session, principal, the ASN bucket) and on the presented login target. A live mark escalates the action to at least the maximum challenge rung (Argon64, capacity-aware); a mark combined with corroborating attacker evidence (bad proof, replay, malformed traffic or decoy evidence at the policy floor) denies for the remaining mark TTL; a target mark tops out at the interactive step-up so a victim can always finish logging in. The reader rides the risk state store (the canonical marks.lua surface), so this stage engages whenever the engine and its Redis client are on. Abuse_first and high_abuse wire it by default; compatibility keeps the plain pipeline. Null = the protection profile decides.')
                            ->addDefaultsIfNotSet()
                            ->children()
                                ->scalarNode('enabled')
                                    ->info('True wires the marks reader into the engine, false keeps the plain pipeline, null (default) derives from the protection profile (on everywhere except compatibility).')
                                    ->defaultNull()
                                    ->validate()
                                        ->ifTrue(static fn ($v): bool => $v !== null && !\is_bool($v))
                                        ->thenInvalid('risk.marks.enabled must be a boolean or null (null = the protection profile decides)')
                                    ->end()
                                ->end()
                            ->end()
                        ->end()
                        ->arrayNode('pricing')
                            ->info('THE CONTINUOUS PRICING STAGE of the adaptive engine (change.md 3.3.1/3.3.2): when the engine is wired with a price context, every decision is additionally priced as work = price of (risk score, per-scope value class, bucket trust, global pressure) and the continuous price is quantized onto the challenge ladder. The price may only RAISE the composed action; the plain policy floors keep applying underneath. The pressure term is gated by the session\'s bucket trust (trust.lua), so a trusted identity stays within one rung under a full-pressure storm while an unproven one takes the whole ramp. Abuse_first and high_abuse wire it by default; compatibility keeps the plain pipeline. Null = the protection profile decides.')
                            ->addDefaultsIfNotSet()
                            ->children()
                                ->scalarNode('enabled')
                                    ->info('True wires the price context into the engine, false keeps the plain pipeline, null (default) derives from the protection profile (on everywhere except compatibility).')
                                    ->defaultNull()
                                    ->validate()
                                        ->ifTrue(static fn ($v): bool => $v !== null && !\is_bool($v))
                                        ->thenInvalid('risk.pricing.enabled must be a boolean or null (null = the protection profile decides)')
                                    ->end()
                                ->end()
                            ->end()
                        ->end()
                        ->arrayNode('asn')
                            ->info('THE ASN DATASET of the trust and marks planes: a local, versioned IP-to-ASN dataset file (the free IPtoASN tsv shapes, "first_ip TAB last_ip TAB asn" per line, comments with #). No network call ever happens: the file is read once at boot into sorted interval tables (a rejected file fails the container build, never a silent empty table). The dataset resolves each request\'s ASN bucket: the bucket-local trust record (trust.lua) prices the request and the marks reader reads the bucket dimension. Null (default) = no dataset: the pricing stage reads zero bucket credit (fail closed, the price may only raise) and the marks reader drops the asn dimension; every other stage is unaffected.')
                            ->addDefaultsIfNotSet()
                            ->children()
                                ->scalarNode('dataset_path')
                                    ->info('Absolute path of the ASN dataset file. A literal path must exist and parse at container build (fail closed); an %%env()%% placeholder is opened when the service is constructed.')
                                    ->defaultNull()
                                ->end()
                            ->end()
                        ->end()
                        ->arrayNode('evidence')
                            ->info('THE PLANE-2 EVIDENCE STAGE of the adaptive engine (interaction_anomaly and solve_anomaly over the telemetry-v1 payload, plus the decoy escalation). The engine composes the stage automatically whenever an assessment carries evidence inputs (the token\'s telemetry payload, the measured solve facts); an absent or rejected payload is the neutral-unknown state and the stage may only raise the composed action. The telemetry knob is the BROWSER ARM SWITCH: it renders data-kiwi-telemetry on the widget container, and the driver\'s collector then attaches to the widget\'s host form and the solved token carries the coarse aggregate payload (event-class counts, one 4-bit entropy value, a focus-transition count, a paste ratio, the sample count; no raw coordinates, no key values, no timing series ever leave the page). Default: "minimal" under every protection profile, "full" under abuse_first and high_abuse. The payload is client-controlled and forgeable: probabilistic evidence for the engine, never the security boundary.')
                            ->addDefaultsIfNotSet()
                            ->children()
                                ->enumNode('telemetry')
                                    ->info('The telemetry mode rendered into data-kiwi-telemetry on the widget container: "minimal" and "full" arm the form-level collection (the driver-side mechanics are identical, the mode travels with the payload), "off" emits the neutral attribute and the token carries no payload. Null (default) derives from the protection profile: minimal under every profile, full under abuse_first and high_abuse; an explicit value in any config layer wins.')
                                    ->values(['minimal', 'full', 'off', null])
                                    ->defaultNull()
                                ->end()
                            ->end()
                        ->end()
                        ->scalarNode('explain')
                            ->info('THE NAMES-ONLY EXPLANATION SURFACE of the risk gateway (change.md 3.8.3): when true, every pre-issue assessment carries a DecisionExplanation (top reasons, identity dimension NAMES, chosen action, priced rung when pricing is composed) exposed through the gateway\'s currentDecisionExplanation() accessor, request-scoped beside the decision id. The explanation type has no path for pseudonym values: dimension names only, so a serialized explanation can never leak a hex digest. True by default under abuse_first / high_abuse (operator-visible decisions are part of the abuse posture); null (default) derives from the protection profile.')
                            ->defaultNull()
                            ->validate()
                                ->ifTrue(static fn ($v): bool => $v !== null && !\is_bool($v))
                                ->thenInvalid('kiwi_captcha.risk.explain must be a boolean or null (null = the protection profile decides)')
                            ->end()
                        ->end()
                        ->arrayNode('metrics')
                            ->info('The metrics exporter of the observability plane: GET {prefix}/metrics renders the deployment\'s aggregated counters as Prometheus text (decision counters by canonical scope id, action and band; outcome reports by kind; exporter scrapes). The endpoint carries its OWN secret, entirely separate from every other credential of the bundle: null (default) leaves the route unregistered (a direct call to a registered route answers 404 once an env-resolved secret resolves empty), a wrong or missing presented secret answers 401. Labels stay redacted: canonical scope ids, action names, score bands and outcome wire names only, never a raw scope string, IP, username or pseudonym.')
                            ->addDefaultsIfNotSet()
                            ->children()
                                ->scalarNode('secret')
                                    ->info('The exporter authentication secret (min 32 bytes, %env(KIWI_METRICS_SECRET)% recommended): accepted as an Authorization: Bearer credential or the secret query parameter, compared in constant time. Null (default) disables the endpoint (the route is not registered).')
                                    ->defaultNull()
                                    ->validate()
                                        ->ifTrue(static fn ($v): bool => self::isShortSecret($v))
                                        ->thenInvalid('risk.metrics.secret must be a string of at least 32 bytes when configured (the same floor as the siteverify secrets): the exporter secret is the entire authentication boundary of the metrics endpoint. An %%env()%% placeholder is length-checked when the controller is constructed')
                                    ->end()
                                ->end()
                            ->end()
                        ->end()
                        ->arrayNode('step_up')
                            ->info('THE STEP-UP PLANE (default off, nothing is registered when disabled): reference handlers for the application-level step-up the adaptive engine demands (the typed kiwi.post_solve_step_up_required violation). begin/complete run through the StepUpHandlerInterface contract: the begun challenge is a server-side state record in the risk Redis (single-use consumption, bounded TTL, attempt cap) plus a signed expiry-bounded ticket the client carries; a succeeded completion reports the stepUpCompleted outcome for the principal and the target pseudonyms through the outcomes plane, so a legitimate user is not stepped up twice. handlers.email_otp (a one-time passcode delivered through the application-bound sender service) and handlers.totp (RFC 6238, 30 s step, one-step window, per-principal replay guard, enrollment through the handler service) are the full reference handlers; handlers.webauthn is the phishing-resistant handler over the web-auth/webauthn-lib package: it refuses unenrolled principals during step-up (enrollment is a separate entry point gated on a completed step-up) and needs the configured rp_id and allowed_origins. handlers.custom maps application handler names to service ids implementing the interface. The StepUpController is exposed as a service; the application registers its own routes for begin_path/complete_path (the handlers render forms posting to the configured complete path).')
                            ->canBeEnabled()
                            ->children()
                                ->scalarNode('scope')
                                    ->info('The risk scope name (a key of risk.scopes) the step-up flow books under, e.g. "login". Required when the plane is enabled; the controller derives the challenge context under this scope.')
                                    ->defaultNull()
                                    ->validate()
                                        ->ifTrue(static fn ($v): bool => \is_string($v) && preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $v) !== 1)
                                        ->thenInvalid('risk.step_up.scope must be a scope name of 1-128 characters of [A-Za-z0-9._:-]')
                                    ->end()
                                ->end()
                                ->scalarNode('default_handler')
                                    ->info('The handler name the controller resolves when a request names none: one of email_otp, totp, webauthn or a handlers.custom key (the named handler must be enabled or registered).')
                                    ->defaultNull()
                                    ->validate()
                                        ->ifTrue(static fn ($v): bool => \is_string($v) && preg_match('/^[a-z0-9_]{1,64}$/D', $v) !== 1)
                                        ->thenInvalid('risk.step_up.default_handler must be a handler name of 1-64 characters of [a-z0-9_]')
                                    ->end()
                                ->end()
                                ->integerNode('challenge_ttl_secs')
                                    ->info('Lifetime of a begun step-up challenge record (and its signed ticket) in seconds (default 300, bounded 30..1800).')
                                    ->defaultValue(300)
                                    ->min(30)
                                    ->max(1800)
                                ->end()
                                ->integerNode('max_attempts')
                                    ->info('Verification attempts one challenge allows before it is dead (default 5, bounded 1..10; each wrong code counts once, atomically in the store).')
                                    ->defaultValue(5)
                                    ->min(1)
                                    ->max(10)
                                ->end()
                                ->booleanNode('allow_signup_bootstrap')
                                    ->info('Bootstrap path for the first factor: when true, a first enrollment (TOTP or WebAuthn) is allowed inside a freshly verified signup or recovery session without a prior step-up. Required for applications without email OTP; otherwise a user with no factor can never enroll one. Keep false when email OTP is available.')
                                    ->defaultFalse()
                                ->end()
                                ->scalarNode('hmac_secret')
                                    ->info('HMAC master of the step-up plane: the ticket signing key, the stored-code hash key and the completion-credit idempotency key all derive from it through purpose-separated HKDF derivations. MUST be a high-entropy secret of at least 32 bytes (%env(KIWI_RISK_SECRET)% recommended); a shorter literal is refused at compile time and an env-resolved secret is floor-checked when the services are constructed. When null (default) it derives from the risk master_secret (which itself defaults to the captcha secret_key) — a dedicated secret is recommended so a compromise of one never leaks the other.')
                                    ->defaultNull()
                                    ->validate()
                                        ->ifTrue(static fn ($v): bool => self::isShortSecret($v))
                                        ->thenInvalid('risk.step_up.hmac_secret must be a string of at least 32 bytes when configured (the same floor as secret_key): a shorter step-up master weakens the ticket signatures, the code hashes and the credit idempotency at once. An %%env()%% placeholder is length-checked when the step-up services are constructed')
                                    ->end()
                                ->end()
                                ->scalarNode('begin_path')
                                    ->info('The application-facing path the begin endpoint is registered at (default /kiwi/step-up/begin). The bundle registers no route; the application wires its own route to StepUpController::begin at this path (or sets this knob to its own path).')
                                    ->defaultValue('/kiwi/step-up/begin')
                                    ->validate()
                                        ->ifTrue(static fn ($v): bool => \is_string($v) && !self::isSafeStepUpPath($v))
                                        ->thenInvalid('risk.step_up.begin_path must be an absolute path: beginning with "/", no "//", no "." or ".." segments, no query, no fragment, no backslashes, no control characters')
                                    ->end()
                                ->end()
                                ->scalarNode('complete_path')
                                    ->info('The application-facing path the complete endpoint is registered at (default /kiwi/step-up/complete). The rendered forms post to this path; the application wires its own route to StepUpController::complete here (or sets this knob to its own path).')
                                    ->defaultValue('/kiwi/step-up/complete')
                                    ->validate()
                                        ->ifTrue(static fn ($v): bool => \is_string($v) && !self::isSafeStepUpPath($v))
                                        ->thenInvalid('risk.step_up.complete_path must be an absolute path: beginning with "/", no "//", no "." or ".." segments, no query, no fragment, no backslashes, no control characters')
                                    ->end()
                                ->end()
                                ->arrayNode('rate_limit')
                                    ->info('The begin bound: a store-backed fixed-window admission counter per principal pseudonym.')
                                    ->addDefaultsIfNotSet()
                                    ->children()
                                        ->integerNode('max_begins')
                                            ->info('Maximum challenges one principal may begin per window (default 3, bounded 1..20). A begin beyond the bound answers the 429 refusal with the window as the retry hint, fail-closed.')
                                            ->defaultValue(3)
                                            ->min(1)
                                            ->max(20)
                                        ->end()
                                        ->integerNode('window_secs')
                                            ->info('The admission window in seconds (default 900, bounded 60..3600).')
                                            ->defaultValue(900)
                                            ->min(60)
                                            ->max(3600)
                                        ->end()
                                    ->end()
                                ->end()
                                ->arrayNode('handlers')
                                    ->info('The handler registry inputs: the built-in reference handlers under their fixed names, plus the application\'s own handlers as name -> service id pairs (each service implements StepUpHandlerInterface; the registry refuses an unknown or non-implementing service at compile time).')
                                    ->addDefaultsIfNotSet()
                                    ->children()
                                        ->arrayNode('email_otp')
                                            ->info('The email one-time-passcode reference handler.')
                                            ->canBeEnabled()
                                            ->children()
                                                ->integerNode('digits')
                                                    ->info('The passcode length: 6 or 8 digits. Null (default) applies the policy default: 8 digits when the step-up scope carries the high or critical value class, 6 otherwise. An explicit value always wins.')
                                                    ->defaultNull()
                                                    ->validate()
                                                        ->ifTrue(static fn ($v): bool => $v !== null && !\in_array($v, [6, 8], true))
                                                        ->thenInvalid('risk.step_up.handlers.email_otp.digits must be 6 or 8')
                                                    ->end()
                                                ->end()
                                                ->scalarNode('sender')
                                                    ->info('Service id of the StepUpCodeSenderInterface the application binds (the code delivery: its mailer mapping the principal pseudonym to the address). Null (default) wires the logging dev sender — production must bind a real sender, the codes are the entire secret of this handler.')
                                                    ->defaultNull()
                                                ->end()
                                            ->end()
                                        ->end()
                                        ->arrayNode('totp')
                                            ->info('The RFC 6238 time-based one-time passcode reference handler (30 s step, in-bundle algorithm, no new composer dependency).')
                                            ->canBeEnabled()
                                            ->children()
                                                ->enumNode('algorithm')
                                                    ->info('The RFC 6238 hash: sha1 (the interoperable default every authenticator app speaks) or sha256 (longer secrets; check the app support first).')
                                                    ->values(['sha1', 'sha256'])
                                                    ->defaultValue('sha1')
                                                ->end()
                                                ->integerNode('digits')
                                                    ->info('The passcode length: 6 or 8 digits. Null (default) applies the policy default: 8 digits when the step-up scope carries the high or critical value class, 6 otherwise. An explicit value always wins.')
                                                    ->defaultNull()
                                                    ->validate()
                                                        ->ifTrue(static fn ($v): bool => $v !== null && !\in_array($v, [6, 8], true))
                                                        ->thenInvalid('risk.step_up.handlers.totp.digits must be 6 or 8')
                                                    ->end()
                                                ->end()
                                                ->integerNode('window')
                                                    ->info('Acceptance window in time-steps around the current one (default 1, bounded 0..2). The replay guard refuses a time-step that already verified, whatever the window.')
                                                    ->defaultValue(1)
                                                    ->min(0)
                                                    ->max(2)
                                                ->end()
                                            ->end()
                                        ->end()
                                        ->arrayNode('webauthn')
                                            ->info('The phishing-resistant handler over the web-auth/webauthn-lib package (enable with the package installed). The relying party id and the allowed origins come from configuration, never from the Host header: rp_id is the bare domain and every allowed_origin must be an absolute origin of that domain or one of its subdomains. Step-up itself never enrolls; the handler refuses an unenrolled principal and the application routes the enrollment entry points behind an authenticated session that has completed a step-up.')
                                            ->canBeEnabled()
                                            ->children()
                                                ->scalarNode('rp_id')
                                                    ->info('The WebAuthn relying party id: a bare domain like login.example.com (no scheme, no port, no path). Required when the handler is enabled.')
                                                    ->defaultNull()
                                                    ->validate()
                                                        ->ifTrue(static fn ($v): bool => $v !== null && (!\is_string($v) || preg_match('/^[a-z0-9.-]+$/D', $v) !== 1))
                                                        ->thenInvalid('risk.step_up.webauthn.rp_id must be a bare domain (no scheme, no port, no path)')
                                                    ->end()
                                                ->end()
                                                ->arrayNode('allowed_origins')
                                                    ->info('The absolute origins that may complete a ceremony (for example https://login.example.com). The presented origin must be one of them; the request Host header never decides it.')
                                                    ->scalarPrototype()
                                                        ->validate()
                                                            ->ifTrue(static fn ($v): bool => !\is_string($v) || preg_match('#^https?://[A-Za-z0-9.-]+(:[0-9]+)?$#D', $v) !== 1)
                                                            ->thenInvalid('risk.step_up.webauthn.allowed_origins entries must be absolute origins like https://login.example.com')
                                                        ->end()
                                                    ->end()
                                                    ->defaultValue([])
                                                ->end()
                                            ->end()
                                            ->validate()
                                                ->ifTrue(static fn (array $v): bool => ($v['enabled'] ?? false) && ($v['rp_id'] ?? null) === null)
                                                ->thenInvalid('risk.step_up.webauthn requires rp_id when the handler is enabled: the relying party id may never be derived from the request')
                                            ->end()
                                            ->validate()
                                                ->ifTrue(static fn (array $v): bool => ($v['enabled'] ?? false) && ($v['rp_id'] ?? null) !== null && (($v['allowed_origins'] ?? []) === []))
                                                ->thenInvalid('risk.step_up.webauthn requires at least one allowed origin when the handler is enabled')
                                            ->end()
                                        ->end()
                                        ->arrayNode('custom')
                                            ->info('Application handler services: map of handler name -> service id implementing StepUpHandlerInterface. The names join the registry next to the built-ins and are valid default_handler values.')
                                            ->normalizeKeys(false)
                                            ->scalarPrototype()
                                                ->cannotBeEmpty()
                                            ->end()
                                            ->defaultValue([])
                                            ->validate()
                                                ->ifTrue(static fn (array $v): bool => \array_filter(
                                                    \array_keys($v),
                                                    static fn ($k): bool => !\is_string($k) || preg_match('/^[a-z0-9_]{1,64}$/D', $k) !== 1,
                                                ) !== [])
                                                ->thenInvalid('risk.step_up.handlers.custom keys must be handler names of 1-64 characters of [a-z0-9_]')
                                            ->end()
                                        ->end()
                                    ->end()
                                ->end()
                            ->end()
                            ->validate()
                                ->ifTrue(static fn (array $v): bool => $v['enabled'] && $v['scope'] === null)
                                ->thenInvalid('risk.step_up.scope is required when the step-up plane is enabled — the controller derives every challenge context under a configured risk scope (add the scope to risk.scopes and name it here)')
                            ->end()
                            ->validate()
                                ->ifTrue(static function (array $v): bool {
                                    if (!$v['enabled'] || $v['default_handler'] === null) {
                                        return false;
                                    }
                                    $name = (string) $v['default_handler'];
                                    $available = [];
                                    foreach (['email_otp', 'totp', 'webauthn'] as $builtin) {
                                        if ($v['handlers'][$builtin]['enabled']) {
                                            $available[$builtin] = true;
                                        }
                                    }
                                    foreach (\array_keys($v['handlers']['custom']) as $custom) {
                                        $available[(string) $custom] = true;
                                    }

                                    return !isset($available[$name]);
                                })
                                ->thenInvalid('risk.step_up.default_handler must name an enabled handler: one of the enabled built-ins (email_otp, totp, webauthn) or a handlers.custom key')
                            ->end()
                        ->end()
                        ->arrayNode('agents')
                            ->info('VERIFIED AGENTS (RFC 9421 HTTP Message Signatures, plane 6): machine clients that authenticate a challenge request with an Ed25519 signature over the RFC 9421 signature base covering @method, @target-uri and the RFC 9530 content-digest (plus content-length whenever a body is present). A verified request skips the widget entirely for its allowed scopes (direct issue, no widget eligibility, no origin or risk-widget gates) and is priced at its price tier; its outcomes and marks attribute to the agent identity. Every agent names its key id, a rotation-capable list of Ed25519 public keys (base64 of the raw 32 bytes; every key verifies during the rotation window, and removing a key fails the agent within one container rebuild), the scopes it may request, per-minute and per-day quotas (sliding windows in the security Redis; an overrun answers 429 with Retry-After and escalates an abuse mark on the agent identity), its price tier and a contact. The signature parameters are enforced: alg must be exactly ed25519, the tag must be this plane\'s tag, created must sit inside the ±skew window (risk.agents_clock_skew_secs), expires is honored, and the nonce is single-use through a Redis ledger (fail-closed: an unverifiable nonce never verifies).')
                            // The agent names ARE the map keys, so key
                            // normalization must stay off: a
                            // dash-bearing agent name ("acme-bot")
                            // would otherwise be rewritten to
                            // underscores and the entry would be
                            // processed empty, silently disarming the
                            // agent.
                            ->normalizeKeys(false)
                            ->useAttributeAsKey('name')
                            ->arrayPrototype()
                                ->children()
                                    ->scalarNode('key_id')
                                        ->info('The RFC 9421 keyid parameter this agent signs with (1-128 characters of [A-Za-z0-9._-]). Two agents must never share a key id; the nonce ledger is keyed under it.')
                                        ->cannotBeEmpty()
                                        ->validate()
                                            ->ifTrue(static fn ($v): bool => \is_string($v) && preg_match('/^[A-Za-z0-9._-]{1,128}$/D', $v) !== 1)
                                            ->thenInvalid('risk.agents.<name>.key_id must be 1-128 characters of [A-Za-z0-9._-]')
                                        ->end()
                                    ->end()
                                    ->arrayNode('public_keys')
                                        ->info('The Ed25519 public keys of the agent, base64 of the raw 32 key bytes. More than one entry is the rotation window: every key verifies, and revocation is removing the entry (effective within one container rebuild).')
                                        ->requiresAtLeastOneElement()
                                        ->scalarPrototype()
                                            ->cannotBeEmpty()
                                        ->end()
                                        ->validate()
                                            ->ifTrue(static fn (array $v): bool => \count($v) !== \count(array_unique($v)))
                                            ->thenInvalid('risk.agents.<name>.public_keys must not repeat a key')
                                        ->end()
                                    ->end()
                                    ->arrayNode('allowed_scopes')
                                        ->info('The scopes this agent may request challenges for; anything else is refused with 403 and the typed agent scope code.')
                                        ->scalarPrototype()
                                            ->validate()
                                                ->ifTrue(static fn (string $v): bool => preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $v) !== 1)
                                                ->thenInvalid('risk.agents.<name>.allowed_scopes entries must match [A-Za-z0-9._:-]{1,128}.')
                                            ->end()
                                        ->end()
                                        ->defaultValue([])
                                    ->end()
                                    ->integerNode('per_minute')
                                        ->info('The per-minute challenge quota of the agent (a sliding 60 s window in the security Redis, bounded 1..100000).')
                                        ->defaultValue(60)
                                        ->min(1)
                                        ->max(100000)
                                    ->end()
                                    ->integerNode('per_day')
                                        ->info('The per-day challenge quota of the agent (a sliding 24 h window in the security Redis, bounded 1..10000000 and at least per_minute — a day cap below the minute cap is a contradiction).')
                                        ->defaultValue(10000)
                                        ->min(1)
                                        ->max(10000000)
                                    ->end()
                                    ->enumNode('price_tier')
                                        ->info('The pricing tier of the agent: low, standard, high or critical. The tier selects the challenge rung a verified request is issued and billed at (the interim tier pricing of the bundle, superseded by the core pricing stage when it lands).')
                                        ->values(['low', 'standard', 'high', 'critical'])
                                        ->defaultValue('standard')
                                    ->end()
                                    ->scalarNode('contact')
                                        ->info('The operator contact behind the agent (an email or a team handle, 1-320 bytes); it exists for quota-abuse outreach and never reaches a response.')
                                        ->cannotBeEmpty()
                                        ->validate()
                                            ->ifTrue(static fn ($v): bool => \is_string($v) && (\strlen($v) < 1 || \strlen($v) > 320))
                                            ->thenInvalid('risk.agents.<name>.contact must be 1-320 bytes')
                                        ->end()
                                    ->end()
                                ->end()
                                ->validate()
                                    ->ifTrue(static fn (array $v): bool => $v['per_day'] < $v['per_minute'])
                                    ->thenInvalid('risk.agents.<name>.per_day must be at least per_minute — a day quota below the minute quota is a contradiction')
                                ->end()
                            ->end()
                            ->validate()
                                ->ifTrue(static function (array $v): bool {
                                    $seen = [];
                                    foreach ($v as $agent) {
                                        $keyId = (string) ($agent['key_id'] ?? '');
                                        if (isset($seen[$keyId])) {
                                            return true;
                                        }
                                        $seen[$keyId] = true;
                                    }

                                    return false;
                                })
                                ->thenInvalid('risk.agents: two agents must never share one key_id — the key id is the lookup and the nonce-ledger identity; give each agent (or each rotation window) its own key_id')
                            ->end()
                            ->defaultValue([])
                        ->end()
                        ->integerNode('agents_clock_skew_secs')
                            ->info('The ± window in seconds the RFC 9421 created parameter of a verified-agent signature must sit inside (default 300, bounded 1..3600). Clock-skew tolerance and replay exposure move together: a wider window accepts signatures minted further in the past or future, while the single-use nonce ledger stays the replay bound.')
                            ->defaultValue(300)
                            ->min(1)
                            ->max(3600)
                        ->end()
                    ->end()
                    ->validate()
                        ->ifTrue(static fn (array $v): bool => ($v['chaining']['enabled'] ?? false)
                            && (!($v['enabled'] ?? false) || ($v['request_binding_authority'] ?? null) === null))
                        ->thenInvalid('risk.chaining.enabled requires risk.enabled=true AND a non-null risk.request_binding_authority — the chain is a server-side transaction obligation anchored on the AUTHORITATIVE binding, never on an unexamined client string')
                    ->end()
                    ->validate()
                        ->ifTrue(static fn (array $v): bool => ($v['step_up']['enabled'] ?? false)
                            && !($v['enabled'] ?? false))
                        ->thenInvalid('risk.step_up.enabled requires risk.enabled=true — the step-up plane stores its challenge records in the risk Redis and credits completions through the outcomes plane of the risk engine')
                    ->end()
                    ->validate()
                        ->ifTrue(static fn (array $v): bool => ($v['policy_rollout_min_epoch'] ?? null) !== null
                            && $v['policy_rollout_min_epoch'] >= $v['policy_version'])
                        ->thenInvalid('risk.policy_rollout_min_epoch must be strictly lower than risk.policy_version — the rollout window is [floor, expected] with the floor at the OLD epoch: a floor reaching the expected epoch is the strict contract itself (declare no window instead), and a floor above it would accept nothing (the window fails closed)')
                    ->end()
                    ->validate()
                        ->ifTrue(static fn (array $v): bool => ($v['agents'] ?? []) !== [] && !($v['enabled'] ?? false))
                        ->thenInvalid('risk.agents requires risk.enabled=true — the verified-agents plane keeps its nonce ledger and quota windows in the risk Redis and escalates overrun marks through the outcomes surface of the risk engine')
                    ->end()
                ->end()
                ->scalarNode('replay_durability')
                    ->info('THE AUTHORITY-CHANGE REPLAY POSTURE SWITCH (default best_effort): how the deployment treats the boundary between per-authority atomic replay safety and promotion of a stale replica. best_effort = the current boundary: single-authority atomicity with the documented stale-promotion window accepted as the deployment boundary (the doctor keeps the "Replication topology" WARN). operator_managed = the operator owns promotion eligibility (replication gating, catch-up rules, a promotion-eligibility gate on the failover manager) and acknowledges the invariant; the doctor reports PASS with the operator contract noted. fail_closed = the deployment refuses to rely on automatic failover: the bundle MUST NOT run with a Predis Sentinel/Cluster aggregate client under this posture, nor with a client it cannot prove safe. A literal value is validated here at build time; a %env()% placeholder is accepted and the RESOLVED posture is enforced by the runtime authority-transition guard when the Redis-backed services are constructed, because an env-resolved posture is invisible to every build-time lane (see docs/ha-authority.md). Single-node direct clients are fine under every posture.')
                    ->defaultValue('best_effort')
                    ->validate()
                        ->ifTrue(static function (mixed $v): bool {
                            // The empty string is the synthetic fixture
                            // Symfony's ValidateEnvPlaceholdersPass
                            // substitutes for an env-managed value when
                            // it re-processes this tree (string type
                            // fixture), so it must be tolerated here:
                            // the runtime guard receives the resolved
                            // posture at service construction.
                            if ($v === '') {
                                return false;
                            }
                            if (!\is_string($v)) {
                                return true;
                            }
                            if (preg_match('/^%env\([^%]+\)%$/D', $v) === 1
                                || preg_match('/^env_[a-f0-9]{16}_\w+_[a-f0-9]{32}$/iD', $v) === 1
                            ) {
                                return false;
                            }

                            return !\in_array($v, ['fail_closed', 'operator_managed', 'best_effort'], true);
                        })
                        ->thenInvalid('must be one of "fail_closed", "operator_managed", "best_effort" (a %%env()%% placeholder is accepted; the resolved posture is enforced by the runtime authority-transition guard)')
                    ->end()
                ->end()
                ->enumNode('ha_authority')
                    ->info('THE MECHANICAL AUTHORITY GUARD (default none): whether the bundle enforces a pinned serving authority for the storage/limiter/risk Redis client. none = the current boundary: no guard is wired and the authority is governed by the replay_durability posture alone. pinned_primary = the PinnedPrimaryAuthorityGuard is wired around the storage/limiter/risk client: initialize with `kiwicaptcha:ha-initialize` (which records the connected server identity, INFO role + run_id, as the write-once `{kiwi:<ns>}:authority:pin` key in the same Redis namespace) or provision ha_authority_expected with the operator-provisioned identity — production never auto-pins, so an uninitialized deployment refuses until the explicit bootstrap. The guard REFUSES every use when the authority changed (a promotion to a stale replica, a restarted primary with a new run_id) with a typed LogicException naming the pinned vs observed identity and the re-pin remediation. This is the mechanical enforcement that makes replay_durability "operator_managed" a real contract instead of an operator promise. Refused at container build time when the storage/limiter/risk client is a Predis Sentinel/Cluster aggregate or a phpredis client (only a Predis single-node direct client can be mechanically guarded), and when no Redis client is wired. See docs/ha-authority.md.')
                    ->values(['none', 'pinned_primary'])
                    ->defaultValue('none')
                ->end()
                ->integerNode('ha_authority_reverify_secs')
                    ->info('The pinned-primary guard verification cache window in seconds (default 5, min 1): the guard re-reads the serving authority (INFO + pin-key compare) at most every N seconds per process per connection object; within the window every non-security-final check passes without a round trip. A mutating security-final transition (consume, commit, chain or idempotency finalize) bypasses the window and re-verifies before every write (zero stale), and so does the verified-WAIT durability barrier (the causal fence write and the WAIT, which additionally assert the connection-generation equality before executing). A reconnect that replaces the connection object invalidates the cache. A smaller window detects an authority change sooner, a larger window costs less INFO traffic.')
                    ->defaultValue(5)
                    ->min(1)
                ->end()
                ->scalarNode('execution_key')
                    ->info('EXECUTIONCHALLENGEV1 KEYED-PRF KEY (string of at least 32 bytes, default null): the secret that generates the deterministic browser-execution programs (the Cap-style dimension, see ExecutionChallengeGenerator). Null (default) = execution challenges are never issued — arming without the key is refused. The key NEVER leaves the server: it only feeds the program generator; the browser digest uses the program blob itself as its content-derived key, so the deployment can rotate it without invalidating outstanding challenges. Requires the risk.execution_challenge gate to be on to have any effect; the gate on without a key is deliberately INERT (no execution program is ever issued) and the kiwicaptcha:doctor command flags it as a WARN.')
                    ->defaultNull()
                    ->validate()
                        ->ifTrue(static fn ($v): bool => self::isShortSecret($v))
                        ->thenInvalid('execution_key must be a string of at least 32 bytes when configured (the core Config::MIN_EXECUTION_KEY_BYTES floor): a shorter keyed-PRF key weakens the execution dimension and rotation safety. An %%env()%% placeholder is length-checked when the core Config is constructed')
                    ->end()
                ->end()
                ->integerNode('execution_version')
                    ->info('THE NODE\'S EXECUTION-PROGRAM VERSION CAP (1..'.ExecutionChallengeGenerator::MAX_EXECUTION_VERSION.', default 1): the operator-side ceiling of the grammar this deployment emits. The maximum tracks KiwiCaptcha\\ExecutionChallengeGenerator::MAX_EXECUTION_VERSION, so the deployable grammar can never lag the generator: version 5 adds the causal object-graph arms (fragment append, deep clone, reparent, attribute reflection, event-phase dispatch, text mutation, select-depth walking and URL canonicalization) and stays available only when all three rungs confirm it. A rung N above version 1 is emitted ONLY when every rung of the three-way gate is up for N: the client advertised execution_max_version >= N with the challenge request (the current widget driver does when the deployment configured the execution tier; an older driver never advertises), this cap is raised to at least N, AND the confirmed central security-policy floor ({kiwi:<ns>}:security-policy min_execution_version) is >= N. Below the confirmed rungs the issuance emits the strongest grammar the confirmed rungs admit — version 1, the construction-to-probe grammar every interpreter generation runs, when no rung is confirmed — so a mixed fleet of old binaries and stale open pages can never be handed a newer grammar. The cap defaults to 1: raising it is the explicit operator step that declares this node ready to write that rung\'s programs, mirroring risk.decoy_v3_enabled as a writer switch. The semantic spelling kiwi_captcha.execution_max_version is a canonicalized alias of this option: Symfony Config folds both names onto one processed value, and setting both to different values is refused. The legacy name stays valid through the one-major-version compatibility window. See operations.md "Execution versioning" for the rollout procedure.')
                    ->min(1)
                    ->max(ExecutionChallengeGenerator::MAX_EXECUTION_VERSION)
                    ->defaultValue(1)
                ->end()
                ->integerNode('execution_required_version')
                    ->info('THE SERVER-OWNED REQUIRED EXECUTION VERSION (1..'.ExecutionChallengeGenerator::MAX_EXECUTION_VERSION.', default 1): the tier a challenge MUST be solved at when the deployment arms the execution dimension. The client capability declaration is never an authority over this value: a client that advertises less than the required tier is refused with CLIENT_EXECUTION_VERSION_UNSUPPORTED, never downgraded to a weaker grammar. The safe transition: keep the default 1 while the fleet moves to the execution-version-2 generation (this node cap kiwi_captcha.execution_version = 2 everywhere and the central min_execution_version = 2), and only then raise this knob to 2 — at which point an old page that cannot solve version 2 must reload against current assets. The semantic spelling kiwi_captcha.execution_min_required_version is a canonicalized alias of this option: both names fold onto one processed value, and setting both to different values is refused. Under the high_abuse protection profile with risk.execution_challenge on, a required tier below the node cap is refused at compile time unless the deployment explicitly accepts the downgrade window with kiwi_captcha.execution_allow_downgrade: true (see operations.md "Execution versioning").')
                    ->min(1)
                    ->max(ExecutionChallengeGenerator::MAX_EXECUTION_VERSION)
                    ->defaultValue(1)
                ->end()
                ->booleanNode('execution_allow_downgrade')
                    ->info('THE EXPLICIT DOWNGRADE-WINDOW ESCAPE HATCH (default false): under the high_abuse protection profile with risk.execution_challenge on, the tree refuses kiwi_captcha.execution_required_version below kiwi_captcha.execution_version unless this flag is explicitly true — the strongest abuse profile must not silently serve the weakest experimental grammar to a client that cannot solve the stronger one. true accepts the documented downgrade window (the required tier below the node cap while the fleet transitions); the doctor then warns that the downgrade is permitted only through this flag. Non-high_abuse deployments and high_abuse deployments without the execution gate on are unaffected and may keep any required tier at or below the node cap.')
                    ->defaultFalse()
                ->end()
                ->variableNode('ha_authority_expected')
                    ->info('THE OPERATOR-PROVISIONED EXPECTED AUTHORITY IDENTITY (default null): the "role|run_id" identity the pinned-primary guard must observe, the same shape as the pin value (e.g. "master|5f8d..."). Two forms are accepted. The scalar string form applies the ONE identity to EVERY authority (storage and, when distinct, risk). The per-authority map form {"storage": "master|...", "risk": "master|..."} applies a DIFFERENT expected identity to each authority — a deployment whose storage Redis and risk Redis are different servers cannot share one run_id, and the map is the contract that says so; when only one Redis is used the storage entry covers the shared authority, and an authority without an entry falls back to the pin key (it must be initialized). When set, the guard compares the serving authority against this value INSTEAD of the `{kiwi:<ns>}:authority:pin:<suffix>` key — the configuration is the pin, so an immutable-identity deployment can skip the Redis pin entirely. The guard refuses when the serving identity differs, and kiwicaptcha:ha-initialize refuses when the configured identity disagrees with the connected server. Production never auto-pins: without this option the deployment must run kiwicaptcha:ha-initialize to record the pin before the guard serves. See docs/ha-authority.md.')
                    ->defaultNull()
                    ->validate()
                        ->ifTrue(static function (mixed $v): bool {
                            if ($v === null || $v === '') {
                                return false;
                            }
                            if (\is_string($v)) {
                                return preg_match('/^[^|]+\|[^|]+$/D', $v) !== 1;
                            }
                            if (\is_array($v)) {
                                foreach ($v as $authority => $identity) {
                                    if (!\in_array($authority, ['storage', 'risk'], true)
                                        || !\is_string($identity)
                                        || $identity === ''
                                        || preg_match('/^[^|]+\|[^|]+$/D', $identity) !== 1
                                    ) {
                                        return true;
                                    }
                                }

                                return false;
                            }

                            return true;
                        })
                        ->thenInvalid('must be either the identity shape "role|run_id" (the shorthand applying to EVERY authority) or a map {"storage": "role|run_id", "risk": "role|run_id"} naming only the storage/risk authorities, each value in the identity shape (the same shape as the pin value, e.g. "master|<run_id>")')
                    ->end()
                ->end()
                ->arrayNode('protocol_rollout')
                    ->info('THE EXPLICIT PROTOCOL ROLLOUT STATE (default mode "normal"): the deployment declares whether it is deliberately in a two-phase protocol migration. mode "normal" = no deliberate exception: under the high_abuse protection profile with risk.decoy_v3_enabled false (or risk.execution_challenge on without the confirmed v4 floor), the doctor FAILS the protocol-writer check (a forgotten override must not silently persist — the switch alone does not prove the deployment is intentionally deferring emission). mode "migration" = the deployment is deliberately in a two-phase rollout (v3/v4 emission deferred until the fleet floor is confirmed); the doctor records the same high_abuse deferral as a WARN (exit 0) while the profile stays active. Non-high_abuse paths are unaffected: protocol v2 emission passes regardless of the declared mode. See operations.md "Protocol v3 two-phase rollout" and "Protocol v4 execution rollout".')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->enumNode('mode')
                            ->values(['normal', 'migration'])
                            ->defaultValue('normal')
                        ->end()
                    ->end()
                ->end()
            ->end()
            // Cross-field rotation invariants over the signing key
            // identity (kid, secret_key, secrets_by_kid, revoked_kids),
            // validated here on the root node where all four are in
            // scope. Each combination below is a guaranteed-outage or
            // silently-weakened-security configuration, refused at
            // compile time instead of failing on the first challenge.
            // Each validate() call appends one rule (a single ExprBuilder
            // keeps only its last ifTrue/thenInvalid pair). The
            // secrets_by_kid keys are canonicalized to ints by the map
            // node's own rules first; the cross-field comparisons still
            // run through self::canonicalKid() so a textual alias can
            // never bypass them.
            ->validate()
                ->ifTrue(static fn (array $v): bool => \in_array($v['kid'], $v['revoked_kids'], true))
                ->thenInvalid('kiwi_captcha.kid must not appear in kiwi_captcha.revoked_kids: issuing under a revoked kid is a guaranteed outage, since every freshly issued challenge would fail verification with UnknownKid. Remove the kid from revoked_kids (revocation applies to superseded keys only) or bump kid to a new signing key id')
            ->end()
            ->validate()
                ->ifTrue(static function (array $v): bool {
                    foreach (\array_keys($v['secrets_by_kid']) as $historicalKid) {
                        if (self::canonicalKid($historicalKid) === (int) $v['kid']) {
                            return true;
                        }
                    }

                    return false;
                })
                ->thenInvalid('kiwi_captcha.secrets_by_kid must not contain the current kiwi_captcha.kid: a historical entry for the current signing key would make the verifier select the wrong secret. The current secret belongs in kiwi_captcha.secret_key, not in the historical map')
            ->end()
            ->validate()
                ->ifTrue(static function (array $v): bool {
                    foreach (\array_keys($v['secrets_by_kid']) as $historicalKid) {
                        $canonical = self::canonicalKid($historicalKid);
                        if ($canonical === null || $canonical > (int) $v['kid']) {
                            return true;
                        }
                    }

                    return false;
                })
                ->thenInvalid('every kiwi_captcha.secrets_by_kid key must be strictly below kiwi_captcha.kid: the map holds historical signing keys only, and a future key would silently extend the verifier rollback/forward guard (a record kid above the newest ring key) so no deployment should accept it. Bump kid above the newest historical key when rotating')
            ->end()
            // Cross-field Argon admission invariant: an explicit per-scope
            // concentration cap at or above the global cap can never bind
            // (the global cap admits fewer), so it provides no
            // anti-starvation and is refused here. The default (null)
            // derives the effective cap as max(1, global - 1) in the
            // extension, so the default configuration stays valid.
            ->validate()
                ->ifTrue(static fn (array $v): bool => $v['argon2_max_per_tenant'] !== null
                    && $v['argon2_max_concurrent_verifications'] > 0
                    && $v['argon2_max_per_tenant'] >= $v['argon2_max_concurrent_verifications'])
                ->thenInvalid('kiwi_captcha.argon2_max_per_tenant must be strictly below argon2_max_concurrent_verifications when the global cap is positive: a per-scope concentration cap at or above the global cap can never bind (the global cap admits fewer), so it provides no anti-starvation. Leave the option unset to derive max(1, global - 1) or set it strictly below the global cap')
            ->end()
            // Cross-field execution-versioning invariant: the node's
            // execution_version cap bounds the strongest grammar this
            // deployment can ever emit, and the server-owned required
            // tier refuses (never downgrades) a client below it, so a
            // required tier above the cap can never be satisfied:
            // every armed request would deterministically fail with
            // `CLIENT_EXECUTION_VERSION_UNSUPPORTED`. Refused here at
            // compile time instead of failing on the first request.
            // The defaults (both 1) stay valid.
            ->validate()
                ->ifTrue(static fn (array $v): bool => $v['execution_required_version'] > $v['execution_version'])
                ->thenInvalid('kiwi_captcha.execution_required_version must not exceed kiwi_captcha.execution_version (the node execution-program cap): the required tier is a solve mandate the node must be able to emit, and a client below it is refused with CLIENT_EXECUTION_VERSION_UNSUPPORTED, never downgraded — so a required tier above the cap makes every armed request deterministically fail. Raise kiwi_captcha.execution_version to at least the required tier (and confirm the fleet min_execution_version floor reaches it) or lower the required tier')
            ->end()
            // Cross-field high_abuse execution-versioning invariant: the
            // high_abuse protection profile arms the execution dimension
            // by default (risk.execution_challenge on) while the required
            // tier defaults to 1, so raising the node cap alone would put
            // the strongest abuse profile on a silently client-
            // downgradeable grammar. Refused here at compile time unless
            // the operator explicitly accepts the downgrade window with
            // kiwi_captcha.execution_allow_downgrade: true. balanced,
            // privacy_strict and profile-less deployments are unaffected:
            // their required tier stays operator-owned (the existing
            // required-tier at-or-below-cap rule above is their only
            // bound).
            ->validate()
                ->ifTrue(static fn (array $v): bool => \in_array($v['protection_profile'] ?? null, ['high_abuse', 'abuse_first'], true)
                    && ($v['risk']['execution_challenge'] ?? 'off') === 'on'
                    && $v['execution_required_version'] < $v['execution_version']
                    && !($v['execution_allow_downgrade'] ?? false))
                ->thenInvalid('kiwi_captcha.execution_required_version must not be below kiwi_captcha.execution_version under the high_abuse protection profile with risk.execution_challenge on: the profile arms the execution dimension by default, and a required tier below the node cap would let the strongest abuse profile silently hand the weaker grammar to any client that cannot solve the stronger one. Raise the required tier to the node cap (the hardened posture), or accept the deliberate downgrade window with an explicit kiwi_captcha.execution_allow_downgrade: true (see operations.md "Execution versioning")')
             ->end()
             // Namespace-migration invariant: the digest key version
             // changes every Redis key family at once, so it is only
             // accepted with the explicit drained-migration
             // acknowledgment. The security-policy and chain readers
             // still consult the legacy namespace as a safety net, but
             // the remaining state families (outstanding caps, decision
             // handles, dispositions, risk aggregates, limiter windows)
             // are not dual-read, so an unacknowledged switch would
             // silently abandon them.
             ->validate()
                 ->ifTrue(static function (array $v): bool {
                     $migration = $v['namespace_migration'] ?? 'none';
                     $version = $v['namespace_key_version'] ?? ($migration === 'fresh' ? RedisNamespace::VERSION_DIGEST : RedisNamespace::VERSION_LEGACY);

                     return $version === RedisNamespace::VERSION_DIGEST && $migration === 'none';
                 })
                 ->thenInvalid('kiwi_captcha.namespace_key_version 2 changes every derived Redis key family at once: set kiwi_captcha.namespace_migration to "migrating_v2" after quiescing the deployment and draining the pre-cutover state (outstanding challenges, nonce decision handles, post-solve dispositions, risk aggregates and calibration state, rate-limit and Argon admission windows), to "drained" once the migration is complete and the legacy namespace must no longer be read at all, or to "fresh" for a brand-new install with no pre-cutover state. The security-policy and chain readers consult the legacy namespace only while migrating_v2 is in effect, but the remaining families are not dual-read')
             ->end()
             // The v2 destinations (migrating_v2/drained/fresh) all select
             // the digest derivation: an explicit legacy version
             // contradicts the acknowledgment.
             ->validate()
                 ->ifTrue(static fn (array $v): bool => \in_array($v['namespace_migration'] ?? 'none', ['migrating_v2', 'drained', 'fresh'], true)
                     && ($v['namespace_key_version'] ?? null) === RedisNamespace::VERSION_LEGACY)
                 ->thenInvalid('kiwi_captcha.namespace_migration: migrating_v2/drained/fresh select the digest namespace derivation; namespace_key_version 1 (the legacy sanitized shape) contradicts them. Leave namespace_key_version unset (or set 2), or use namespace_migration: none for a deployment that stays on the legacy derivation')
             ->end();

        return $treeBuilder;
    }

    /**
     * The execution-versioning alias fold: the semantic names
     * kiwi_captcha.execution_max_version and
     * kiwi_captcha.execution_min_required_version are canonicalized
     * onto the legacy names execution_version and
     * execution_required_version before any other tree processing.
     * Symfony Config then merges both spellings of one concept into a
     * single value, no matter which layer carries which spelling.
     * Setting both spellings to different values is refused here: the
     * merge winner would otherwise depend on the spelling, never on
     * the operator. The legacy names stay valid through the
     * one-major-version compatibility window, so an existing
     * deployment never needs to touch its config.
     *
     * @return array<string, mixed>
     */
    private static function canonicalizeExecutionVersioningAliases(array $config): array
    {
        foreach ([
            'execution_version' => 'execution_max_version',
            'execution_required_version' => 'execution_min_required_version',
        ] as $canonical => $alias) {
            if (!\array_key_exists($alias, $config)) {
                continue;
            }
            $aliasValue = $config[$alias];
            if ($aliasValue !== null && \array_key_exists($canonical, $config)
                && $config[$canonical] !== null && $config[$canonical] !== $aliasValue
            ) {
                throw new InvalidConfigurationException(sprintf(
                    'kiwi_captcha.%s and kiwi_captcha.%s are aliases of the same execution-versioning option (the semantic name and the legacy name canonicalize to one value), but both are configured with different values (%s and %s): Symfony Config folds the aliases onto the single processed option, so the winner would silently depend on the spelling. Configure only one spelling, or set both to the same value',
                    $canonical,
                    $alias,
                    \is_scalar($config[$canonical]) ? (string) $config[$canonical] : \gettype($config[$canonical]),
                    \is_scalar($aliasValue) ? (string) $aliasValue : \gettype($aliasValue),
                ));
            }
            if ($aliasValue !== null) {
                $config[$canonical] = $aliasValue;
            }
            unset($config[$alias]);
        }

        return $config;
    }

    /**
     * The absolute-path grammar of the step-up endpoint knobs: begins
     * with "/", at least one segment, no empty ("//") or dot segments,
     * no backslashes, no query string, no fragment, no control bytes.
     */
    private static function isSafeStepUpPath(mixed $v): bool
    {
        if (!\is_string($v) || $v === '' || $v[0] !== '/' || \strlen($v) > 512) {
            return false;
        }
        if (str_contains($v, '\\') || str_contains($v, '?') || str_contains($v, '#') || str_contains($v, '%')) {
            return false;
        }
        if (preg_match('/[\x00-\x1F\x7F]/', $v) === 1) {
            return false;
        }
        $segments = explode('/', $v);
        for ($i = 1, $count = \count($segments); $i < $count; $i++) {
            if ($segments[$i] === '' || $segments[$i] === '.' || $segments[$i] === '..') {
                return false;
            }
        }

        return true;
    }

    /**
     * Canonical kid of a secrets_by_kid map key: a strictly-positive
     * canonical decimal integer within the signing kid range, or null for
     * anything else (text, leading zeros, out of range). The cross-field
     * rotation rules compare these canonical ints so a textual alias like
     * '02' can never bypass or collide with a numeric kid.
     */
    private static function canonicalKid(int|string $raw): ?int
    {
        if (\is_int($raw)) {
            $canonical = $raw;
        } elseif (preg_match('/^[1-9][0-9]*$/D', $raw) === 1) {
            $canonical = (int) $raw;
        } else {
            return null;
        }
        if ($canonical < 1 || $canonical > 4294967295) {
            return null;
        }

        return $canonical;
    }
}
