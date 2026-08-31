<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\DependencyInjection;

/**
 * SECURITY-MAINTAINER material: the protection-profile matrices are deep
 * design rationale, intentionally not published at the integration layer.
 * See docs/operations.md for the maintainer view and
 * docs/configuration.md "Protection profiles" for the operator contract.
 *
 * The profile is the LOWEST-precedence configuration layer. Symfony's
 * Processor normalizes and merges every config array in stack order, so
 * the profile defaults are prepended as the first array of the stack.
 * A later layer carrying only `protection_profile` can never inject
 * profile values that override explicit settings from an earlier layer;
 *  an explicit value in any layer always wins. The previous design
 *  expanded the profile inside the tree's per-array beforeNormalization,
 *  which made a later profile-only layer override earlier explicit
 *  settings (e.g. a base `rate_limit: 1` followed by a prod
 *  `protection_profile: high_abuse` silently became rate_limit 5).
 *
 *  Presence semantics govern the selection: the last layer containing
 *  the `protection_profile` key wins, so an explicit null in a later
 *  layer clears the profile (no derived defaults are prepended) and the
 *  visible field reports null in lockstep.
 *
 *  `balanced` is the current default configuration, so its defaults are
 *  empty: processing a balanced profile is a pure pass-through (the
 *  derived values equal the tree defaults byte-identically).
 */
final class ProtectionProfileDefaults
{
    /**
     * The protection-profile matrices. Each profile governs a bounded
     * set of safety-relevant knobs and carries safe derived defaults
     * for the knobs the operator did NOT set explicitly. The defaults
     * are prepended as the lowest-precedence layer, so an explicitly
     * configured knob in any config file always wins over the profile.
     * Every choice is documented in docs/configuration.md "Protection
     * profiles".
     *
     * Profile rationale:
     *  - balanced: the current defaults, explicitly documented as such.
     *    Picking it changes nothing: the derived values equal the tree
     *    defaults, so behavior is byte-identical to no profile.
     *  - privacy_strict: the strongest first-party privacy posture.
     *    binding_mode none drops even the nonce-bound IP tag, so no
     *    IP-derived state exists anywhere; every behavioral evidence
     *    surface stays off and the timing heuristic is disabled.
     *  - high_abuse: stronger abuse posture for public signup/login
     *    surfaces. Risk is enabled, requiring a Predis client and
     *    failing fast otherwise. The abuse-evidence weights rise so
     *    proven abuse outvotes trust signals sooner. Per-source limits
     *    tighten, aggregate issuance bounds widen, and the decoy
     *    surface arms (v3 emission behind the central floor). Chaining
     *    engages when the operator wired a binding authority.
     *    {@see finalize()} applies that conditional as an extension
     *    post-step, so the authority may now live in any layer, not
     *    only the layer carrying the profile.
     *  - compatibility: maximal integration compatibility. Algorithm
     *    sha256, a conservative TTL (300 s, Turnstile parity), binding
     *    off (IP churn behind NAT/mobile), risk and the decoy surface
     *    off (protocol v2 emission), no behavioral coupling.
     *  - ha_safe: the replay-safe HA posture. replay_durability
     *    operator_managed + ha_authority pinned_primary; every other
     *    derived default mirrors balanced (the tree defaults). The
     *    mechanical pinned-primary authority guard turns the
     *    operator_managed contract into a bundle-enforced guarantee:
     *    the deployment initializes the guard explicitly
     *    (kiwicaptcha:ha-initialize or ha_authority_expected; the
     *    production runtime never auto-pins), the guard refuses on any
     *    authority change, and the doctor reports its state. An explicit
     *    override of ha_authority or replay_durability in any layer
     *    wins (the doctor then FAILs the "HA authority" check when the
     *    profile promises pinned_primary but the effective posture
     *    dropped it, so the promise cannot silently weaken).
     *
     * @var array<string, array{root: array<string, mixed>, risk: array<string, mixed>}>
     */
    private const PROFILES = [
        'balanced' => [
            'root' => [
                'algorithm' => 'sha256',
                'difficulty_bits' => 18,
                'argon2_difficulty_bits' => 8,
                'argon_m_kib' => 0,
                'argon_t' => 3,
                'argon_p' => 1,
                'challenge_ttl_secs' => 120,
                'rate_limit' => 10,
                'rate_limit_global' => 500,
                'privacy_mode' => 'strict',
                'telemetry' => 'off',
                'enforce_telemetry' => false,
                'binding_mode' => 'nonce_ip_hmac',
            ],
            'risk' => [
                'enabled' => false,
                'decoy_v3_enabled' => false,
                'client_context' => false,
                'hard_limits' => ['process_per_second' => 10000],
                'max_outstanding_challenges' => 20,
                'max_outstanding_challenges_global' => 100000,
            ],
        ],
        'privacy_strict' => [
            'root' => [
                'algorithm' => 'sha256',
                'difficulty_bits' => 18,
                'argon2_difficulty_bits' => 8,
                'argon_m_kib' => 0,
                'argon_t' => 3,
                'argon_p' => 1,
                'challenge_ttl_secs' => 120,
                'rate_limit' => 10,
                'rate_limit_global' => 500,
                'privacy_mode' => 'strict',
                'telemetry' => 'off',
                'enforce_telemetry' => false,
                'min_duration_ms' => 0,
                'binding_mode' => 'none',
            ],
            'risk' => [
                'enabled' => false,
                'decoy_v3_enabled' => false,
                'client_context' => false,
                'hard_limits' => ['process_per_second' => 10000],
                'max_outstanding_challenges' => 20,
                'max_outstanding_challenges_global' => 100000,
            ],
        ],
        'high_abuse' => [
            'root' => [
                'algorithm' => 'sha256',
                'difficulty_bits' => 18,
                'argon2_difficulty_bits' => 8,
                'argon_m_kib' => 0,
                'argon_t' => 3,
                'argon_p' => 1,
                'challenge_ttl_secs' => 120,
                'rate_limit' => 5,
                'rate_limit_global' => 2000,
                'privacy_mode' => 'strict',
                'telemetry' => 'off',
                'enforce_telemetry' => false,
                'binding_mode' => 'nonce_ip_hmac',
                'resource_capacity' => ['issuance_per_second' => 2000],
            ],
            'risk' => [
                'enabled' => true,
                'decoy_v3_enabled' => true,
                'client_context' => false,
                'hard_limits' => ['process_per_second' => 5000],
                'max_outstanding_challenges' => 10,
                'max_outstanding_challenges_global' => 250000,
                'weights' => [
                    // The abuse-evidence weights rise so proven abuse
                    // outvotes trust signals sooner; the remaining ten
                    // weights stay at the contract defaults.
                    'bad_proof' => 320,
                    'malformed' => 340,
                    'replay' => 380,
                    'action_failure' => 160,
                ],
            ],
        ],
        'compatibility' => [
            'root' => [
                'algorithm' => 'sha256',
                'difficulty_bits' => 18,
                'argon2_difficulty_bits' => 8,
                'argon_m_kib' => 0,
                'argon_t' => 3,
                'argon_p' => 1,
                'challenge_ttl_secs' => 300,
                'rate_limit' => 10,
                'rate_limit_global' => 500,
                'privacy_mode' => 'strict',
                'telemetry' => 'off',
                'enforce_telemetry' => false,
                'binding_mode' => 'none',
            ],
            'risk' => [
                'enabled' => false,
                'decoy_v3_enabled' => false,
                'client_context' => false,
                'hard_limits' => ['process_per_second' => 10000],
                'max_outstanding_challenges' => 20,
                'max_outstanding_challenges_global' => 100000,
            ],
        ],
        'ha_safe' => [
            // The replay-safe HA posture: the mechanical authority
            // guard + the operator contract it makes real. Every other
            // knob mirrors balanced (the tree defaults) — including the
            // explicit risk defaults, because the risk node is
            // canBeEnabled(): a present-but-empty risk key would
            // silently default enabled to true, exactly what a
            // pass-through profile must never do.
            'root' => [
                'replay_durability' => 'operator_managed',
                'ha_authority' => 'pinned_primary',
            ],
            'risk' => [
                'enabled' => false,
                'decoy_v3_enabled' => false,
                'client_context' => false,
                'hard_limits' => ['process_per_second' => 10000],
                'max_outstanding_challenges' => 20,
                'max_outstanding_challenges_global' => 100000,
            ],
        ],
    ];

    private function __construct()
    {
    }

    /**
     * The final selected profile across the raw configuration stack:
     * the last layer containing the `protection_profile` key wins
     * (presence semantics, array_key_exists), so an explicit null is a
     * real selection. A later `protection_profile: null`, for example
     * a prod overlay clearing a dev compatibility profile, resets the
     * profile to none: the derived defaults of any earlier profile are
     * dropped. The invariant holds: the final visible
     * protection_profile field and the effective derived behavior
     * always correspond.
     *
     * @param array<int, array<string, mixed>> $configs
     */
    public static function selectedProfile(array $configs): ?string
    {
        $selected = null;
        foreach ($configs as $layer) {
            if (\is_array($layer) && \array_key_exists('protection_profile', $layer)) {
                $profile = $layer['protection_profile'];
                $selected = $profile === null ? null : (string) $profile;
            }
        }

        return $selected;
    }

    /**
     * The flat config-array defaults of a profile: root knobs plus the
     * `risk` subtree, in the same shape a config file would carry. The
     * result is the LOWEST-precedence layer: every key in it is a
     * derived default, so an explicit value in any config file always
     * wins during the Processor merge.
     *
     * `balanced` returns the empty array (a pure pass-through: its
     * derived values equal the tree defaults byte-identically). An
     * unknown profile name also returns the empty array — the tree's
     * enum validation refuses the unknown name during processing with a
     * proper configuration error, exactly like the historical
     * beforeNormalization behavior.
     *
     * @return array<string, mixed>
     */
    public static function defaultsFor(?string $profile): array
    {
        if ($profile === null || $profile === 'balanced') {
            return [];
        }
        $matrix = self::PROFILES[$profile] ?? null;
        if ($matrix === null) {
            return [];
        }

        return array_merge($matrix['root'], ['risk' => $matrix['risk']]);
    }

    /**
     * The processing stack for a raw configuration stack: the selected
     * profile's defaults first (lowest precedence), then the raw layers
     * in order (each later layer overrides the earlier ones, including
     * the profile defaults). With no profile (or balanced) the stack is
     * returned unchanged.
     *
     * @param array<int, array<string, mixed>> $configs
     *
     * @return array<int, array<string, mixed>>
     */
    public static function stack(array $configs): array
    {
        $defaults = self::defaultsFor(self::selectedProfile($configs));
        if ($defaults === []) {
            return $configs;
        }

        return array_merge([$defaults], $configs);
    }

    /**
     * Post-processing chaining postcondition (an extension post-step,
     * run after the Processor merge over the whole stack). The
     * high_abuse profile engages chained step-up only when the final
     * merged configuration carries a `risk.request_binding_authority`;
     * the chain anchor is the authoritative transaction binding, never
     * an unexamined client string. With the authority absent, chaining
     * stays at its tree default (false) — mirroring the historical
     * conditional semantics, with one deliberate improvement: the
     * authority may now live in any configuration layer, not only the
     * layer carrying the profile. An explicit
     * `risk.chaining.enabled` in any raw layer always wins (the
     * tree's own validation refuses the explicit combination without
     * an authority at compile time, so a configuration error is never
     * silently ignored).
     *
     * @param array<string, mixed>                $config     the processed configuration
     * @param array<int, array<string, mixed>> $rawConfigs the raw stack, for the explicit-setting scan
     *
     * @return array<string, mixed>
     */
    public static function finalize(array $config, array $rawConfigs): array
    {
        if (self::selectedProfile($rawConfigs) !== 'high_abuse'
            || ($config['risk']['request_binding_authority'] ?? null) === null
        ) {
            return $config;
        }
        foreach ($rawConfigs as $layer) {
            if (\is_array($layer) && isset($layer['risk']['chaining']['enabled'])) {
                return $config;
            }
        }
        $config['risk']['chaining']['enabled'] = true;

        return $config;
    }
}
