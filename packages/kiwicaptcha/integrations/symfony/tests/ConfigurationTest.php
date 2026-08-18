<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\DependencyInjection\Configuration;
use KiwiCaptcha\Config;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\Definition\Processor;

/**
 * The bundle's config tree must not contradict the core's protocol
 * constraints: difficulty_bits is bounded by the core's
 * Config::MAX_SHA_TARGET_BITS (20) so the bundle can never allow issuing an
 * unsolvable challenge.
 */
final class ConfigurationTest extends TestCase
{
    private function process(array $overrides = []): array
    {
        $config = array_merge([
            'secret_key' => str_repeat('a', 32),
        ], $overrides);

        return (new Processor())->processConfiguration(new Configuration(), [$config]);
    }

    public function testDifficultyBits21IsRejectedByTheTree(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $this->process(['difficulty_bits' => 21]);
    }

    public function testDifficultyBits24IsRejectedByTheTree(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $this->process(['difficulty_bits' => 24]);
    }

    public function testDifficultyBits20IsAccepted(): void
    {
        $processed = $this->process(['difficulty_bits' => 20]);

        self::assertSame(20, $processed['difficulty_bits']);
    }

    public function testTreeCeilingTracksCoreConstant(): void
    {
        self::assertSame(Config::MAX_SHA_TARGET_BITS, 20);
    }

    public function testRedisServiceDefaultsToNull(): void
    {
        $processed = $this->process();

        self::assertNull($processed['redis_service']);
        self::assertNull($processed['rate_limit_pepper']);
        self::assertNull($processed['rate_limit_cache']);
    }

    public function testArgonTreeBoundsMatchCoreUnconditionalBounds(): void
    {
        $processed = $this->process([
            'argon_m_kib' => 65536,
            'argon_t' => 1,
            'argon_p' => 1,
        ]);

        self::assertSame(65536, $processed['argon_m_kib']);
        self::assertSame(1, $processed['argon_t']);
        self::assertSame(1, $processed['argon_p']);

        // The core's CONDITIONAL Argon2id profile rules (t >= 3, p == 1,
        // m_kib >= 8 * p) are enforced by KiwiCaptcha\Config when the
        // extension builds it — the tree intentionally does not duplicate
        // them (see the Configuration comments). Prove the boundary cases
        // are tree-valid and left to the core:
        $this->process(['argon_t' => 2]);
        $this->process(['argon_p' => 2]);
        $this->process(['argon_m_kib' => 1]);
    }

    public function testAuditDefaultsArePrivacyFirst(): void
    {
        $processed = $this->process();

        self::assertSame('strict', $processed['privacy_mode']);
        self::assertSame('off', $processed['telemetry']);
        self::assertSame('nonce_ip_hmac', $processed['binding_mode']);
        self::assertTrue($processed['same_origin_only']);
        self::assertSame(10, $processed['rate_limit']);
        self::assertSame(500, $processed['rate_limit_global']);
        self::assertSame(60, $processed['rate_limit_window_secs']);
        self::assertSame('%kernel.project_dir%', $processed['argon2_semaphore_namespace']);
        self::assertFalse($processed['enforce_telemetry']);
        self::assertNull($processed['min_duration_ms']);
    }

    public function testPrivacyAndTelemetryEnumsAreValidated(): void
    {
        $this->expectException(\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException::class);
        $this->process(['telemetry' => 'bogus']);
    }

    public function testBindingModeAcceptsBothValues(): void
    {
        self::assertSame('none', $this->process(['binding_mode' => 'none'])['binding_mode']);
        self::assertSame('nonce_ip_hmac', $this->process(['binding_mode' => 'nonce_ip_hmac'])['binding_mode']);
    }

    public function testStandardPrivacyAllowsExplicitTelemetryAndTiming(): void
    {
        $processed = $this->process([
            'privacy_mode' => 'standard',
            'telemetry' => 'full',
            'min_duration_ms' => 250,
            'same_origin_only' => false,
        ]);

        self::assertSame('full', $processed['telemetry']);
        self::assertSame(250, $processed['min_duration_ms']);
        self::assertFalse($processed['same_origin_only']);
    }

    public function testChallengeTtlAboveProtocolCeilingIsRejectedByTree(): void
    {
        // The verifier declares lifetimes > MAX_TTL_SECS malformed; the
        // config tree must refuse them at configuration time.
        $this->expectException(\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException::class);
        $this->process(['challenge_ttl_secs' => 301]);
    }

    public function testChallengeTtlAtProtocolCeilingIsAccepted(): void
    {
        $config = $this->process(['challenge_ttl_secs' => 300]);
        self::assertSame(300, $config['challenge_ttl_secs']);
    }

    public function testCalibrationOutcomeReceiptTtlDefaultsAndBounds(): void
    {
        self::assertSame(86400, $this->process()['risk']['calibration']['outcome_receipt_ttl_secs'], 'outcome_receipt_ttl_secs defaults to the 24 h outcome/calibration receipt + outcome-ledger lifetime (long enough for fraud review / moderation / chargeback labels)');
        self::assertSame(3600, $this->process(['risk' => ['calibration' => ['outcome_receipt_ttl_secs' => 3600]]])['risk']['calibration']['outcome_receipt_ttl_secs']);
        self::assertSame(604800, $this->process(['risk' => ['calibration' => ['outcome_receipt_ttl_secs' => 604800]]])['risk']['calibration']['outcome_receipt_ttl_secs']);
    }

    public function testCalibrationOutcomeReceiptTtlBelowMinimumIsRejected(): void
    {
        $this->expectException(\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException::class);
        $this->process(['risk' => ['calibration' => ['outcome_receipt_ttl_secs' => 3599]]]);
    }

    public function testCalibrationOutcomeReceiptTtlAboveMaximumIsRejected(): void
    {
        $this->expectException(\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException::class);
        $this->process(['risk' => ['calibration' => ['outcome_receipt_ttl_secs' => 604801]]]);
    }

    public function testNonceToDecisionTtlDefaultsAndBounds(): void
    {
        self::assertSame(300, $this->process()['risk']['nonce_to_decision_ttl_secs'], 'nonce_to_decision_ttl_secs defaults to 300 (the short-lived challenge-nonce -> decision mapping, independent of the outcome lifetime)');
        self::assertSame(60, $this->process(['risk' => ['nonce_to_decision_ttl_secs' => 60]])['risk']['nonce_to_decision_ttl_secs']);
        self::assertSame(3600, $this->process(['risk' => ['nonce_to_decision_ttl_secs' => 3600]])['risk']['nonce_to_decision_ttl_secs']);
    }

    public function testNonceToDecisionTtlBelowMinimumIsRejected(): void
    {
        $this->expectException(\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException::class);
        $this->process(['risk' => ['nonce_to_decision_ttl_secs' => 59]]);
    }

    public function testNonceToDecisionTtlAboveMaximumIsRejected(): void
    {
        $this->expectException(\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException::class);
        $this->process(['risk' => ['nonce_to_decision_ttl_secs' => 3601]]);
    }

    public function testLegacyCalibrationReceiptTtlNodeIsGone(): void
    {
        $calibration = $this->process()['risk']['calibration'];
        self::assertArrayNotHasKey('receipt_ttl_secs', $calibration, 'the superseded receipt_ttl_secs node is replaced by outcome_receipt_ttl_secs + risk.nonce_to_decision_ttl_secs');
    }

    public function testHardLimitsUseSinglePerProcessCap(): void
    {
        $hardLimits = $this->process()['risk']['hard_limits'];

        self::assertArrayHasKey('process_per_second', $hardLimits, 'the hard limit is the single per-process cap');
        self::assertSame(10000, $hardLimits['process_per_second'], 'process_per_second defaults to 10000');
        self::assertArrayNotHasKey('source_per_second', $hardLimits, 'the two-window source cap is gone');
        self::assertArrayNotHasKey('global_per_second', $hardLimits, 'the two-window global cap is gone');

        self::assertSame(1, $this->process(['risk' => ['hard_limits' => ['process_per_second' => 1]]])['risk']['hard_limits']['process_per_second']);
        self::assertSame(250, $this->process(['risk' => ['hard_limits' => ['process_per_second' => 250]]])['risk']['hard_limits']['process_per_second']);
    }

    public function testHardLimitBelowOneIsRejected(): void
    {
        $this->expectException(\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException::class);
        $this->process(['risk' => ['hard_limits' => ['process_per_second' => 0]]]);
    }

    public function testUnknownScopeDefaultsToMinimum(): void
    {
        self::assertSame('minimum', $this->process()['risk']['unknown_scope']['mode'], 'unknown_scope.mode defaults to minimum (synthetic sha20 policy for scope typos)');

        self::assertSame('reject', $this->process(['risk' => ['unknown_scope' => ['mode' => 'reject']]])['risk']['unknown_scope']['mode']);
        self::assertSame('baseline', $this->process(['risk' => ['unknown_scope' => ['mode' => 'baseline']]])['risk']['unknown_scope']['mode']);
    }

    public function testResourceCapacityDefaultsToDeploymentWideIssuanceDenominator(): void
    {
        $capacity = $this->process()['resource_capacity'];

        self::assertSame(20000, $capacity['issuance_per_second'], 'issuance_per_second defaults to 20000 (deployment-wide, the shared Redis counter denominator)');
        self::assertSame(1, $this->process(['resource_capacity' => ['issuance_per_second' => 1]])['resource_capacity']['issuance_per_second']);
        self::assertSame(250, $this->process(['resource_capacity' => ['issuance_per_second' => 250]])['resource_capacity']['issuance_per_second']);
    }

    public function testResourceCapacityBelowOneIsRejected(): void
    {
        $this->expectException(\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException::class);
        $this->process(['resource_capacity' => ['issuance_per_second' => 0]]);
    }

    public function testCalibrationSamplingDefaultsToRandomSample(): void
    {
        $calibration = $this->process()['risk']['calibration'];

        self::assertSame('random_sample', $calibration['mode'], 'the label-selection contract defaults to random_sample (Kiwi samples at assessment time)');
        self::assertSame(100000, $calibration['sampling_probability_ppm'], 'sampling_probability_ppm defaults to 100000 (10%)');
    }

    public function testCalibrationSamplingModesAndBoundsAreValidated(): void
    {
        self::assertSame('complete', $this->process(['risk' => ['calibration' => ['mode' => 'complete']]])['risk']['calibration']['mode']);
        self::assertSame('weighted', $this->process(['risk' => ['calibration' => ['mode' => 'weighted']]])['risk']['calibration']['mode']);
        self::assertSame(1, $this->process(['risk' => ['calibration' => ['sampling_probability_ppm' => 1]]])['risk']['calibration']['sampling_probability_ppm']);
        self::assertSame(1000000, $this->process(['risk' => ['calibration' => ['sampling_probability_ppm' => 1000000]]])['risk']['calibration']['sampling_probability_ppm']);
    }

    public function testCalibrationSamplingInvalidValuesAreRejected(): void
    {
        $invalid = [
            ['risk' => ['calibration' => ['mode' => 'bogus']]],
            ['risk' => ['calibration' => ['sampling_probability_ppm' => 0]]],
            ['risk' => ['calibration' => ['sampling_probability_ppm' => 1000001]]],
        ];
        foreach ($invalid as $config) {
            try {
                $this->process($config);
                self::fail('invalid calibration sampling config must be rejected by the tree: '.json_encode($config));
            } catch (\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException) {
                self::assertTrue(true);
            }
        }
    }

    public function testCalibrationResolutionGateAndCostDefaults(): void
    {
        $calibration = $this->process()['risk']['calibration'];

        self::assertSame(0.80, $calibration['minimum_resolution_ratio'], 'minimum_resolution_ratio defaults to 0.80 (the label-reporting process must resolve 80% of the server-selected sample before the model may move)');
        self::assertSame(1.0, $calibration['false_positive_cost'], 'false_positive_cost defaults to 1.0');
        self::assertSame(2.0, $calibration['false_negative_cost'], 'false_negative_cost defaults to 2.0 (abuse that slips through costs twice a false rejection)');
    }

    public function testCalibrationResolutionGateAndCostBoundsAreValidated(): void
    {
        // Boundary values accepted.
        $this->process(['risk' => ['calibration' => ['minimum_resolution_ratio' => 0.0]]]);
        $this->process(['risk' => ['calibration' => ['minimum_resolution_ratio' => 1.0]]]);
        $this->process(['risk' => ['calibration' => ['false_positive_cost' => 0.1]]]);
        $this->process(['risk' => ['calibration' => ['false_positive_cost' => 10.0]]]);
        $this->process(['risk' => ['calibration' => ['false_negative_cost' => 0.1]]]);
        $this->process(['risk' => ['calibration' => ['false_negative_cost' => 10.0]]]);

        // Out-of-range values rejected.
        $invalid = [
            ['risk' => ['calibration' => ['minimum_resolution_ratio' => -0.01]]],
            ['risk' => ['calibration' => ['minimum_resolution_ratio' => 1.01]]],
            ['risk' => ['calibration' => ['false_positive_cost' => 0.05]]],
            ['risk' => ['calibration' => ['false_positive_cost' => 10.1]]],
            ['risk' => ['calibration' => ['false_negative_cost' => 0.05]]],
            ['risk' => ['calibration' => ['false_negative_cost' => 10.1]]],
        ];
        foreach ($invalid as $config) {
            try {
                $this->process($config);
                self::fail('out-of-range calibration knob must be rejected by the tree: '.json_encode($config));
            } catch (\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException) {
                self::assertTrue(true);
            }
        }

        // Explicit in-range values flow through.
        $calibration = $this->process(['risk' => ['calibration' => [
            'minimum_resolution_ratio' => 0.5,
            'false_positive_cost' => 2.5,
            'false_negative_cost' => 3.75,
        ]]])['risk']['calibration'];
        self::assertSame(0.5, $calibration['minimum_resolution_ratio']);
        self::assertSame(2.5, $calibration['false_positive_cost']);
        self::assertSame(3.75, $calibration['false_negative_cost']);
    }

    public function testArgon2MaxWaitersDefaultsAndBounds(): void
    {
        self::assertSame(64, $this->process()['argon2_max_waiters'], 'argon2_max_waiters defaults to 64 (bounded waiters guard of the Argon2 admission semaphore)');
        self::assertSame(1, $this->process(['argon2_max_waiters' => 1])['argon2_max_waiters']);
        self::assertSame(128, $this->process(['argon2_max_waiters' => 128])['argon2_max_waiters']);
    }

    public function testArgon2MaxWaitersBelowOneIsRejected(): void
    {
        $this->expectException(\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException::class);
        $this->process(['argon2_max_waiters' => 0]);
    }

    public function testRiskRegionDefaultsToNullAndAcceptsArbitraryString(): void
    {
        self::assertNull($this->process()['risk']['region'], 'risk.region defaults to null (no region baked into challenges)');
        self::assertSame('eu-central-1', $this->process(['risk' => ['region' => 'eu-central-1']])['risk']['region']);
    }

    public function testRiskAllowedScopesNode(): void
    {
        // allowed_scopes defaults to [] (accept any scope)
        // and accepts a list of identifier-alphabet names; hostile entries
        // are rejected at config load.
        self::assertSame([], $this->process()['risk']['allowed_scopes'], 'allowed_scopes defaults to empty (accept-any)');

        $processed = $this->process(['risk' => ['allowed_scopes' => ['login', 'signup', 'financial_action']]])['risk']['allowed_scopes'];
        self::assertSame(['login', 'signup', 'financial_action'], $processed);

        try {
            $this->process(['risk' => ['allowed_scopes' => ['bad scope!', 'x']]]);
            self::fail('an allowlist entry outside the identifier alphabet must be rejected');
        } catch (\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException) {
            // expected
        }
    }

    public function testSiteverifySecretsRequireStrongKeys(): void
    {
        // The siteverify secrets are the entire server-to-server
        // authentication boundary — configuration rejects weak keys.
        $processed = $this->process(['risk' => ['siteverify_secrets' => ['0123456789abcdef' => 'login']]])['risk']['siteverify_secrets'];
        self::assertSame(['0123456789abcdef' => 'login'], $processed);

        foreach ([['short' => 'login'], ['0123456789abcde' => 'login']] as $weak) {
            try {
                $this->process(['risk' => ['siteverify_secrets' => $weak]]);
                self::fail('a siteverify secret under 16 bytes must be rejected at config load');
            } catch (\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException) {
                // expected
            }
        }
    }

    public function testRiskRedisHardeningDefaults(): void
    {
        $redis = $this->process()['risk']['redis'];

        self::assertSame(0, $redis['wait_replicas'], 'wait_replicas defaults to 0 (WAIT disabled)');
        self::assertSame(100, $redis['wait_timeout_ms'], 'wait_timeout_ms defaults to 100');
        self::assertSame(0, $redis['ttl_margin_secs'], 'ttl_margin_secs defaults to 0 (no extra retention)');

        $redis = $this->process(['risk' => ['redis' => [
            'wait_replicas' => 2,
            'wait_timeout_ms' => 500,
            'ttl_margin_secs' => 30,
        ]]])['risk']['redis'];
        self::assertSame(2, $redis['wait_replicas']);
        self::assertSame(500, $redis['wait_timeout_ms']);
        self::assertSame(30, $redis['ttl_margin_secs']);
    }

    public function testRiskRedisBoundsAreValidated(): void
    {
        $invalid = [
            ['risk' => ['redis' => ['wait_replicas' => -1]]],
            ['risk' => ['redis' => ['wait_timeout_ms' => 0]]],
            ['risk' => ['redis' => ['ttl_margin_secs' => -1]]],
        ];
        foreach ($invalid as $config) {
            try {
                $this->process($config);
                self::fail('out-of-range risk.redis knob must be rejected by the tree: '.json_encode($config));
            } catch (\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException) {
                self::assertTrue(true);
            }
        }
    }

    public function testOutstandingChallengeCapsDefaultsAndBounds(): void
    {
        $risk = $this->process()['risk'];
        self::assertSame(20, $risk['max_outstanding_challenges'], 'max_outstanding_challenges defaults to 20 (anti-stockpiling per source)');
        self::assertSame(100000, $risk['max_outstanding_challenges_global'], 'max_outstanding_challenges_global defaults to 100000 (deployment-wide)');

        $risk = $this->process(['risk' => [
            'max_outstanding_challenges' => 5,
            'max_outstanding_challenges_global' => 999,
        ]])['risk'];
        self::assertSame(5, $risk['max_outstanding_challenges']);
        self::assertSame(999, $risk['max_outstanding_challenges_global']);
    }

    public function testOutstandingChallengeCapsBelowOneAreRejected(): void
    {
        foreach ([
            ['risk' => ['max_outstanding_challenges' => 0]],
            ['risk' => ['max_outstanding_challenges_global' => 0]],
        ] as $config) {
            try {
                $this->process($config);
                self::fail('outstanding cap below 1 must be rejected: '.json_encode($config));
            } catch (\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException) {
                self::assertTrue(true);
            }
        }
    }

    public function testOriginAllowlistDefaultsToEmptyAndAcceptsOrigins(): void
    {
        self::assertSame([], $this->process()['risk']['challenge_origin_allowlist'], 'challenge_origin_allowlist defaults to [] (origin laundering defense off)');

        $allowlist = $this->process(['risk' => ['challenge_origin_allowlist' => ['https://app.example.com', 'https://cdn.example.com']]])['risk']['challenge_origin_allowlist'];
        self::assertSame(['https://app.example.com', 'https://cdn.example.com'], $allowlist);
    }

    public function testEnforceFetchMetadataDefaultsToFalse(): void
    {
        self::assertFalse($this->process()['risk']['enforce_fetch_metadata'], 'enforce_fetch_metadata defaults to false (defense-in-depth only)');
        self::assertTrue($this->process(['risk' => ['enforce_fetch_metadata' => true]])['risk']['enforce_fetch_metadata']);
    }

    public function testArgon2MaxPerTenantDefaultsAndBounds(): void
    {
        self::assertSame(8, $this->process()['argon2_max_per_tenant'], 'argon2_max_per_tenant defaults to 8 (per-scope Argon budget)');
        self::assertSame(1, $this->process(['argon2_max_per_tenant' => 1])['argon2_max_per_tenant']);
        self::assertSame(25, $this->process(['argon2_max_per_tenant' => 25])['argon2_max_per_tenant']);
    }

    public function testArgon2MaxPerTenantBelowOneIsRejected(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->process(['argon2_max_per_tenant' => 0]);
    }

    public function testRiskPolicyVersionIsTheChallengeSecurityEpoch(): void
    {
        self::assertSame(1, $this->process()['risk']['policy_version'], 'risk.policy_version defaults to 1 (the CHALLENGE security-policy epoch — independent of the risk-v1 contract version)');
        self::assertSame(2, $this->process(['risk' => ['policy_version' => 2]])['risk']['policy_version'], 'bumping the epoch invalidates outstanding challenges');
    }

    public function testRiskPolicyVersionBelowOneIsRejected(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->process(['risk' => ['policy_version' => 0]]);
    }

    public function testRiskRequestBindingDefaultsToNullAndAcceptsAStaticBinding(): void
    {
        self::assertNull($this->process()['risk']['request_binding'], 'risk.request_binding defaults to null (no static transaction binding)');
        self::assertSame('static-txn', $this->process(['risk' => ['request_binding' => 'static-txn']])['risk']['request_binding']);
    }

    public function testEnforceOriginDefaultsToFalse(): void
    {
        self::assertFalse($this->process()['risk']['enforce_origin'], 'risk.enforce_origin defaults to false (server-to-server integrations cannot send an Origin)');
        self::assertTrue($this->process(['risk' => ['enforce_origin' => true]])['risk']['enforce_origin']);
    }

    public function testRiskHealthEnabledDefaultsToTrue(): void
    {
        self::assertTrue($this->process()['risk']['health']['enabled'], 'risk.health.enabled defaults to true (live/ready routes registered)');
        self::assertFalse($this->process(['risk' => ['health' => ['enabled' => false]]])['risk']['health']['enabled']);
    }

// ── trusted client-IP policy ──────────────────────────────────────────────

    public function testClientIpModeDefaultsToSymfonyTrustedProxies(): void
    {
        self::assertSame('symfony_trusted_proxies', $this->process()['risk']['client_ip_mode'], 'client_ip_mode defaults to symfony_trusted_proxies (Symfony\'s machinery ignores forwarding from untrusted peers)');
        self::assertSame('direct', $this->process(['risk' => ['client_ip_mode' => 'direct']])['risk']['client_ip_mode']);
    }

    public function testClientIpModeRejectsUnknownValues(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->process(['risk' => ['client_ip_mode' => 'header_trust']]);
    }

    public function testTrustedProxiesDefaultsToEmptyAndAcceptsCidrs(): void
    {
        self::assertSame([], $this->process()['risk']['trusted_proxies'], 'trusted_proxies defaults to [] (nobody is trusted)');

        $proxies = $this->process(['risk' => ['trusted_proxies' => ['10.0.0.0/8', '192.168.1.5']]])['risk']['trusted_proxies'];
        self::assertSame(['10.0.0.0/8', '192.168.1.5'], $proxies);
    }

    public function testRejectAmbiguousForwardingDefaultsToFalse(): void
    {
        self::assertFalse($this->process()['risk']['reject_ambiguous_forwarding'], 'reject_ambiguous_forwarding defaults to false (the anomaly is logged)');
        self::assertTrue($this->process(['risk' => ['reject_ambiguous_forwarding' => true]])['risk']['reject_ambiguous_forwarding']);
    }

// ── memory-budget readiness ───────────────────────────────────────────────

    public function testContainerMemoryMibDefaultsToNullAndAcceptsBudgets(): void
    {
        self::assertNull($this->process()['risk']['container_memory_mib'], 'container_memory_mib defaults to null (readiness invariant skipped)');
        self::assertSame(1024, $this->process(['risk' => ['container_memory_mib' => 1024]])['risk']['container_memory_mib']);
    }

    public function testContainerMemoryMibBelowOneIsRejected(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->process(['risk' => ['container_memory_mib' => 0]]);
    }

// ── server-configured public origin ───────────────────────────────────────

    public function testPublicBaseUrlDefaultsToNullAndAcceptsOrigins(): void
    {
        self::assertNull($this->process()['public_base_url'], 'public_base_url defaults to null (same-origin derived from the request)');
        self::assertSame('https://captcha.example.com', $this->process(['public_base_url' => 'https://captcha.example.com'])['public_base_url']);
    }

// ── max-stale fail-closed ─────────────────────────────────────────────────

    public function testSecurityEpochMaxStaleDefaultsAndBounds(): void
    {
        self::assertSame(60, $this->process()['risk']['security_epoch_max_stale_secs'], 'security_epoch_max_stale_secs defaults to 60 (the max-stale fail-closed window)');
        self::assertSame(10, $this->process(['risk' => ['security_epoch_max_stale_secs' => 10]])['risk']['security_epoch_max_stale_secs']);
        self::assertSame(3600, $this->process(['risk' => ['security_epoch_max_stale_secs' => 3600]])['risk']['security_epoch_max_stale_secs']);
    }

    public function testSecurityEpochMaxStaleBelowMinimumIsRejected(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->process(['risk' => ['security_epoch_max_stale_secs' => 9]]);
    }
}
