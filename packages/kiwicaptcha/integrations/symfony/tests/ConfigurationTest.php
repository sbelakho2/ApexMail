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
 * Config::MAX_SHA_target_bits (20) so the bundle can never allow issuing an
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

    public function testDifficultyBitsDefaultsTo18(): void
    {
        $processed = $this->process();

        self::assertSame(18, $processed['difficulty_bits'], 'difficulty_bits defaults to 18 — the ordinary SHA baseline (mean ≈ 262k hashes, p99 ≈ 1.21M, exhaustion within the 5,000,000-hash cap ≈ 5.2×10⁻⁹); 20 stays reachable as the elevated rung via risk escalation (Argon/StepUp above it), never a default that collapses the ladder');
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

        // The core's conditional Argon2id profile rules (t >= 3, p == 1,
        // m_kib >= 8 * p) are enforced by KiwiCaptcha\Config when the
        // extension builds it — the tree intentionally does not duplicate
        // them (see the Configuration comments). Prove the boundary cases
        // are tree-valid and left to the core:
        $this->process(['argon_t' => 2]);
        $this->process(['argon_p' => 2]);
        $this->process(['argon_m_kib' => 1]);
    }

    public function testRateLimitWindowSecsDefaultsAndBounds(): void
    {
        self::assertSame(60, $this->process()['rate_limit_window_secs'], 'rate_limit_window_secs defaults to 60');
        self::assertSame(1, $this->process(['rate_limit_window_secs' => 1])['rate_limit_window_secs']);
        self::assertSame(3600, $this->process(['rate_limit_window_secs' => 3600])['rate_limit_window_secs'], 'the one-hour maximum is accepted');
    }

    public function testRateLimitWindowSecsAboveTheOneHourMaximumIsRejected(): void
    {
        // The operational bound: the exact-ms global limiter prunes on
        // every admission, so an unbounded window would be a stale,
        // weakened limit — the tree refuses anything past one hour.
        $this->expectException(InvalidConfigurationException::class);
        $this->process(['rate_limit_window_secs' => 3601]);
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
        // The verifier declares lifetimes > MAX_TTL_secs malformed; the
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

        self::assertSame(500, $capacity['issuance_per_second'], 'issuance_per_second defaults to 500, aligned with the hard global limiter rate_limit_global 500 per rate_limit_window_secs 60 (the hard limiter is the binding constraint on the default deployment)');
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

    public function testChainingDefaultsAreOffWithBoundedTtl(): void
    {
        $processed = $this->process();

        self::assertFalse($processed['risk']['chaining']['enabled']);
        self::assertSame(300, $processed['risk']['chaining']['ttl_secs']);
        self::assertNull($processed['risk']['chaining']['hmac_secret']);
        self::assertSame(15, $processed['risk']['chaining']['reservation_lease_secs'], 'the SHORT reservation lease defaults to 15s');
        self::assertNull($processed['risk']['request_binding_authority'], 'no authority is wired by default');
        self::assertNull($processed['risk']['trusted_tls_header']);
    }

    public function testChainingAcceptsEnabledConfigWithBounds(): void
    {
        $processed = $this->process([
            'risk' => [
                'request_binding_authority' => 'app.binding_authority',
                'chaining' => ['enabled' => true, 'ttl_secs' => 60, 'hmac_secret' => str_repeat('c', 32)],
            ],
        ]);

        self::assertTrue($processed['risk']['chaining']['enabled']);
        self::assertSame(60, $processed['risk']['chaining']['ttl_secs']);
        self::assertSame(str_repeat('c', 32), $processed['risk']['chaining']['hmac_secret']);
        self::assertSame(15, $processed['risk']['chaining']['reservation_lease_secs']);
        self::assertSame('app.binding_authority', $processed['risk']['request_binding_authority'], 'a configured service id is accepted');
    }

    public function testChainingTtlBoundsAreEnforced(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->process(['risk' => ['chaining' => ['ttl_secs' => 29]]]);

        $this->process(['risk' => ['chaining' => ['ttl_secs' => 3601]]]);
    }

    public function testReservationLeaseSecsBoundsAreEnforced(): void
    {
        // The short lease is bounded 5..60 AND strictly smaller than the
        // chain lifetime (it is a short claim, never the chain lifetime).
        foreach ([4, 61] as $bad) {
            try {
                $this->process(['risk' => ['chaining' => ['reservation_lease_secs' => $bad]]]);
                self::fail('a reservation lease outside 5..60 must be refused: '.$bad);
            } catch (InvalidConfigurationException) {
                self::assertTrue(true);
            }
        }

        // A lease >= the chain TTL is refused (the compile-time
        // cross-field validation).
        try {
            $this->process(['risk' => ['chaining' => ['reservation_lease_secs' => 30, 'ttl_secs' => 30]]]);
            self::fail('a reservation lease equal to the chain lifetime must be refused');
        } catch (InvalidConfigurationException $e) {
            self::assertStringContainsString('reservation_lease_secs', $e->getMessage());
        }
        try {
            $this->process(['risk' => ['chaining' => ['reservation_lease_secs' => 60, 'ttl_secs' => 45]]]);
            self::fail('a reservation lease larger than the chain lifetime must be refused');
        } catch (InvalidConfigurationException) {
            self::assertTrue(true);
        }

        // The boundary values are accepted when below the TTL.
        $processed = $this->process(['risk' => ['chaining' => ['reservation_lease_secs' => 5, 'ttl_secs' => 300]]]);
        self::assertSame(5, $processed['risk']['chaining']['reservation_lease_secs']);
        $processed = $this->process(['risk' => ['chaining' => ['reservation_lease_secs' => 60, 'ttl_secs' => 300]]]);
        self::assertSame(60, $processed['risk']['chaining']['reservation_lease_secs']);
    }

    public function testChainingEnabledRequiresRiskEnabledAndTheBindingAuthority(): void
    {
        // chaining.enabled=true requires risk.enabled=true AND a non-null
        // risk.request_binding_authority — the chain is a server-side
        // transaction obligation anchored on the authoritative binding;
        // the refusal names both requirements at compile time.
        try {
            $this->process(['risk' => ['chaining' => ['enabled' => true]]]);
            self::fail('chaining.enabled without the binding authority must be refused');
        } catch (InvalidConfigurationException $e) {
            self::assertStringContainsString('risk.chaining.enabled requires risk.enabled=true AND a non-null risk.request_binding_authority', $e->getMessage());
        }

        try {
            $this->process(['risk' => ['enabled' => false, 'request_binding_authority' => 'app.binding_authority', 'chaining' => ['enabled' => true]]]);
            self::fail('chaining.enabled with risk disabled must be refused');
        } catch (InvalidConfigurationException $e) {
            self::assertStringContainsString('risk.chaining.enabled requires risk.enabled=true AND a non-null risk.request_binding_authority', $e->getMessage());
        }

        // The valid combination passes.
        $processed = $this->process(['risk' => ['request_binding_authority' => 'app.binding_authority', 'chaining' => ['enabled' => true]]]);
        self::assertTrue($processed['risk']['chaining']['enabled']);
    }

    public function testRequestBindingAuthorityAcceptsAndValidatesServiceIds(): void
    {
        // The authority is nullable; a configured value is a non-empty
        // service id.
        try {
            $this->process(['risk' => ['request_binding_authority' => '']]);
            self::fail('an empty request_binding_authority must be refused');
        } catch (InvalidConfigurationException) {
            self::assertTrue(true);
        }
        $processed = $this->process(['risk' => ['request_binding_authority' => 'app.binding_authority']]);
        self::assertSame('app.binding_authority', $processed['risk']['request_binding_authority']);
    }

    public function testTrustedTlsHeaderAcceptsHeaderNames(): void
    {
        $processed = $this->process(['risk' => ['trusted_tls_header' => 'X-Tls-Class']]);

        self::assertSame('X-Tls-Class', $processed['risk']['trusted_tls_header']);
    }

    public function testTrustedTlsProxiesDefaultsToEmptyAndAcceptsCidrs(): void
    {
        self::assertSame([], $this->process()['risk']['trusted_tls_proxies'], 'trusted_tls_proxies defaults to [] (the TLS header is never read)');

        $proxies = $this->process(['risk' => ['trusted_tls_proxies' => ['10.0.0.0/8', '192.168.1.5']]])['risk']['trusted_tls_proxies'];
        self::assertSame(['10.0.0.0/8', '192.168.1.5'], $proxies);
    }

    public function testRiskV2WeightsDefaultsAreTheContractDefaults(): void
    {
        $v2 = $this->process()['risk']['v2'];

        self::assertSame(200, $v2['honeypot_weight'], 'honeypot_weight defaults to the risk-v2 contract default (200)');
        self::assertSame(120, $v2['session_consistency_weight'], 'session_consistency_weight defaults to the risk-v2 contract default (120)');
        self::assertSame(80, $v2['tls_weight'], 'tls_weight defaults to the risk-v2 contract default (80)');
    }

    public function testRiskV2WeightsAcceptBoundedOverrides(): void
    {
        $v2 = $this->process(['risk' => ['v2' => [
            'honeypot_weight' => 300,
            'session_consistency_weight' => 40,
            'tls_weight' => 0,
        ]]])['risk']['v2'];
        self::assertSame(300, $v2['honeypot_weight']);
        self::assertSame(40, $v2['session_consistency_weight']);
        self::assertSame(0, $v2['tls_weight']);

        // The 0..1000 fixed-point bounds are compile-time.
        foreach ([-1, 1001] as $outOfRange) {
            try {
                $this->process(['risk' => ['v2' => ['honeypot_weight' => $outOfRange]]]);
                self::fail('an out-of-range v2 weight must be rejected by the tree: '.$outOfRange);
            } catch (InvalidConfigurationException) {
                self::assertTrue(true);
            }
        }
    }

    public function testChainingHmacSecretRequiresAtLeastSixteenBytesWhenConfigured(): void
    {
        // A configured secret below 16 bytes is refused at compile time;
        // the null fallback (master_secret -> secret_key) is unchanged.
        foreach (['short', '0123456789abcde'] as $weak) {
            try {
                $this->process(['risk' => ['request_binding_authority' => 'app.binding_authority', 'chaining' => ['enabled' => true, 'hmac_secret' => $weak]]]);
                self::fail('a chaining hmac_secret under 16 bytes must be rejected: '.$weak);
            } catch (InvalidConfigurationException) {
                self::assertTrue(true);
            }
        }
        $processed = $this->process(['risk' => ['request_binding_authority' => 'app.binding_authority', 'chaining' => ['enabled' => true, 'hmac_secret' => '0123456789abcdef']]])['risk']['chaining'];
        self::assertSame('0123456789abcdef', $processed['hmac_secret'], 'a 16-byte chaining secret is accepted');
    }

    public function testArgonEscalationLadderDefaultsToTheMonotonicThreeRungLadder(): void
    {
        self::assertSame([1, 4, 8], $this->process()['risk']['argon_escalation_target_bits'], 'argon_escalation_target_bits defaults to [1, 4, 8]');

        // Strictly increasing ladders inside the core ceiling are accepted.
        self::assertSame([1, 5, 10], $this->process(['risk' => ['argon_escalation_target_bits' => [1, 5, 10]]])['risk']['argon_escalation_target_bits']);
        self::assertSame([2, 4, 10], $this->process(['risk' => ['argon_escalation_target_bits' => [2, 4, 10]]])['risk']['argon_escalation_target_bits']);
        self::assertSame([1, 2, Config::MAX_ARGON2_TARGET_BITS], $this->process(['risk' => ['argon_escalation_target_bits' => [1, 2, Config::MAX_ARGON2_TARGET_BITS]]])['risk']['argon_escalation_target_bits']);
    }

    public function testArgonEscalationLadderNonMonotoneIsRejected(): void
    {
        foreach ([[1, 5, 5], [5, 5, 10], [1, 4, 3], [10, 9, 8], [1, 4, 4]] as $ladder) {
            try {
                $this->process(['risk' => ['argon_escalation_target_bits' => $ladder]]);
                self::fail('a non-monotone ladder must be refused at configuration time: '.json_encode($ladder));
            } catch (InvalidConfigurationException $e) {
                self::assertStringContainsString('1 <= rung1 < rung2 < rung3 <= '.Config::MAX_ARGON2_TARGET_BITS, $e->getMessage(), 'the refusal names the ladder constraint');
            }
        }
    }

    public function testArgonEscalationLadderOutOfRangeIsRejected(): void
    {
        foreach ([[0, 4, 8], [1, 4, 11], [1, 4, Config::MAX_ARGON2_TARGET_BITS + 1]] as $ladder) {
            try {
                $this->process(['risk' => ['argon_escalation_target_bits' => $ladder]]);
                self::fail('an out-of-range ladder must be refused at configuration time: '.json_encode($ladder));
            } catch (InvalidConfigurationException) {
                self::assertTrue(true);
            }
        }
    }

    public function testArgonEscalationLadderWrongEntryCountIsRejected(): void
    {
        foreach ([[1, 4], [1, 4, 8, 10], []] as $ladder) {
            try {
                $this->process(['risk' => ['argon_escalation_target_bits' => $ladder]]);
                self::fail('a ladder without EXACTLY 3 entries must be refused at configuration time: '.json_encode($ladder));
            } catch (InvalidConfigurationException) {
                self::assertTrue(true);
            }
        }
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
