<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\DependencyInjection\Configuration;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\ProtectionProfileDefaults;
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

        // The profile expansion is the extension's job (the profile is
        // the LOWEST-precedence configuration layer, prepended as the
        // first array of the processing stack), so the single-array
        // helper applies the same stack + chaining postcondition the
        // extension applies. This keeps the processed outcome of a
        // single-array config byte-identical to the historical
        // beforeNormalization expansion.
        $processed = (new Processor())->processConfiguration(
            new Configuration(),
            ProtectionProfileDefaults::stack([$config]),
        );

        return ProtectionProfileDefaults::finalize($processed, [$config]);
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

    public function testRedisDsnDefaultsToNullAndPassesThrough(): void
    {
        $processed = $this->process();

        self::assertNull($processed['redis_dsn'], 'redis_dsn defaults to null = every Redis-backed service keeps its existing wiring');
        self::assertSame('redis://127.0.0.1:6399/0', $this->process(['redis_dsn' => 'redis://127.0.0.1:6399/0'])['redis_dsn'], 'the tree accepts a plain redis:// DSN as a scalar');
        self::assertSame('rediss://user:pass@captcha.example.com:6380/2?prefix=kiwi', $this->process(['redis_dsn' => 'rediss://user:pass@captcha.example.com:6380/2?prefix=kiwi'])['redis_dsn'], 'a rediss:// DSN with credentials, database and query parameters passes through untouched');
    }

    public function testNonRedisRateLimitFallbackFlagsDefaultToFalse(): void
    {
        $processed = $this->process();

        self::assertFalse($processed['allow_nonredis_rate_limit_fallback'], 'the canonical flag defaults to false (production refuses the non-Redis fallback)');
        self::assertFalse($processed['allow_local_global_limit_fallback'], 'the deprecated alias defaults to false');
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

    public function testArgon2SaturationPressureCapDefaultsAndBounds(): void
    {
        self::assertNull($this->process()['argon2_saturation_pressure_cap'], 'argon2_saturation_pressure_cap defaults to null (resolved to 64 by the extension)');
        self::assertSame(1, $this->process(['argon2_saturation_pressure_cap' => 1])['argon2_saturation_pressure_cap']);
        self::assertSame(128, $this->process(['argon2_saturation_pressure_cap' => 128])['argon2_saturation_pressure_cap']);
    }

    public function testArgon2SaturationPressureCapBelowOneIsRejected(): void
    {
        $this->expectException(\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException::class);
        $this->process(['argon2_saturation_pressure_cap' => 0]);
    }

    public function testLegacyArgon2MaxWaitersNameStillProcesses(): void
    {
        // The deprecated alias keeps its own default (64) and its bounds:
        // an old config that only sets argon2_max_waiters stays valid and
        // the extension resolves it (OR semantics).
        self::assertSame(64, $this->process()['argon2_max_waiters'], 'the deprecated argon2_max_waiters alias keeps its default 64');
        self::assertSame(12, $this->process(['argon2_max_waiters' => 12])['argon2_max_waiters']);

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
        // The default is null: the extension derives the effective
        // per-scope concentration cap from the global cap as
        // max(1, global - 1), so with the default global cap of 2 the
        // derived cap is 1, and one scope can never monopolize both
        // slots.
        self::assertNull($this->process()['argon2_max_per_tenant'], 'argon2_max_per_tenant defaults to null (derived from the global cap by the extension)');
        self::assertSame(1, $this->process(['argon2_max_per_tenant' => 1])['argon2_max_per_tenant']);
        self::assertSame(25, $this->process(['argon2_max_concurrent_verifications' => 30, 'argon2_max_per_tenant' => 25])['argon2_max_per_tenant']);
    }

    public function testArgon2MaxPerTenantBelowOneIsRejected(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->process(['argon2_max_per_tenant' => 0]);
    }

    public function testArgon2MaxPerTenantAtOrAboveTheGlobalCapIsRefused(): void
    {
        // A per-scope concentration cap at or above the global cap can
        // never bind (the global cap admits fewer), so it provides no
        // anti-starvation — refused with the exact actionable message.
        try {
            $this->process(['argon2_max_concurrent_verifications' => 2, 'argon2_max_per_tenant' => 2]);
            self::fail('a per-scope cap equal to the global cap must be refused');
        } catch (InvalidConfigurationException $e) {
            self::assertSame(
                'Invalid configuration for path "kiwi_captcha": kiwi_captcha.argon2_max_per_tenant must be strictly below argon2_max_concurrent_verifications when the global cap is positive: a per-scope concentration cap at or above the global cap can never bind (the global cap admits fewer), so it provides no anti-starvation. Leave the option unset to derive max(1, global - 1) or set it strictly below the global cap',
                $e->getMessage(),
            );
        }
        try {
            $this->process(['argon2_max_concurrent_verifications' => 2, 'argon2_max_per_tenant' => 8]);
            self::fail('a per-scope cap above the global cap must be refused');
        } catch (InvalidConfigurationException $e) {
            self::assertSame(
                'Invalid configuration for path "kiwi_captcha": kiwi_captcha.argon2_max_per_tenant must be strictly below argon2_max_concurrent_verifications when the global cap is positive: a per-scope concentration cap at or above the global cap can never bind (the global cap admits fewer), so it provides no anti-starvation. Leave the option unset to derive max(1, global - 1) or set it strictly below the global cap',
                $e->getMessage(),
            );
        }

        // The default stays valid: null is never refused, and a cap with
        // an unlimited global (0) is still meaningful on its own.
        $this->process([]);
        self::assertSame(3, $this->process(['argon2_max_concurrent_verifications' => 0, 'argon2_max_per_tenant' => 3])['argon2_max_per_tenant']);
    }

    public function testArgon2MaxVerificationRuntimeMsDefaultsAndBounds(): void
    {
        // The deployment bound on a single verification derivation: below
        // the default lease (45000) by the 5000 ms safety margin, so the
        // default combination compiles (45000 > 30000 + 5000 = 35000).
        self::assertSame(30000, $this->process()['argon2_max_verification_runtime_ms'], 'argon2_max_verification_runtime_ms defaults to 30000 (below the default argon2_lease_ms 45000 by the 5000 ms safety margin)');
        self::assertSame(120000, $this->process(['argon2_max_verification_runtime_ms' => 120000])['argon2_max_verification_runtime_ms']);
    }

    public function testArgon2MaxVerificationRuntimeMsBelowOneSecondIsRejected(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->process(['argon2_max_verification_runtime_ms' => 999]);
    }

    public function testArgon2MaxVerificationRuntimeMsAboveTheFiveMinuteCeilingIsRejected(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->process(['argon2_max_verification_runtime_ms' => 300001]);
    }

    public function testStrictKidVerificationDefaultsToFalse(): void
    {
        self::assertFalse($this->process()['strict_kid_verification'], 'strict_kid_verification defaults to false (legacy any-kid single-secret semantics)');
        self::assertTrue($this->process(['strict_kid_verification' => true])['strict_kid_verification']);
    }

    public function testResumeClaimTtlSecsDefaultsAndBounds(): void
    {
        self::assertSame(60, $this->process()['resume_claim_ttl_secs'], 'resume_claim_ttl_secs defaults to 60 (the recovery-derivation claim lease)');
        self::assertSame(120, $this->process(['resume_claim_ttl_secs' => 120])['resume_claim_ttl_secs']);
    }

    public function testResumeClaimTtlSecsBelowTheOneMinuteFloorIsRejected(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->process(['resume_claim_ttl_secs' => 59]);
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

    public function testRejectAmbiguousForwardingDefaultsToTrue(): void
    {
        self::assertTrue($this->process()['risk']['reject_ambiguous_forwarding'], 'reject_ambiguous_forwarding defaults to true (ambiguity is rejected in production by default)');
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

    public function testDecoyV3EnabledDefaultsToFalse(): void
    {
        // The protocol-v3 writer switch: the default is
        // OFF, so a new deployment never emits v3 challenges (the
        // parent-revision verifiers reject them) until the operator
        // completes the two-phase rollout — deploy everywhere, raise the
        // central min_protocol_version floor to 3, then enable.
        self::assertFalse($this->process()['risk']['decoy_v3_enabled'], 'decoy_v3_enabled defaults to false (v2 emission)');
        self::assertTrue($this->process(['risk' => ['decoy_v3_enabled' => true]])['risk']['decoy_v3_enabled']);
        self::assertFalse($this->process(['risk' => ['decoy_v3_enabled' => false]])['risk']['decoy_v3_enabled']);
    }

// ── protection profiles ───────────────────────────────────────────────────

    public function testProtectionProfileDefaultsToNull(): void
    {
        $processed = $this->process();

        self::assertNull($processed['protection_profile'], 'protection_profile defaults to null = every knob at its individual default');
    }

    public function testProtectionProfileRejectsUnknownValues(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->process(['protection_profile' => 'bogus']);
    }

    public function testNullProfileIsByteIdenticalToNoProfile(): void
    {
        $plain = $this->process();
        $nullProfile = $this->process(['protection_profile' => null]);
        unset($plain['protection_profile'], $nullProfile['protection_profile']);

        // Key order follows the raw config order (the profile pass
        // injects absent keys), which is not semantically meaningful, so
        // the comparison is canonicalized recursively.
        self::assertSame(self::canonicalize($plain), self::canonicalize($nullProfile), 'a null protection_profile must leave every knob byte-identical to the profile-less config');
    }

    public function testBalancedProfileEqualsTheCurrentDefaults(): void
    {
        $plain = $this->process();
        $balanced = $this->process(['protection_profile' => 'balanced']);
        unset($plain['protection_profile'], $balanced['protection_profile']);

        self::assertSame(self::canonicalize($plain), self::canonicalize($balanced), 'balanced = the current defaults, explicitly documented as such: the derived values equal the tree defaults, so behavior is byte-identical to no profile');
    }

    /**
     * Recursively sort an array by key so two arrays with identical
     * values but different insertion order compare equal.
     *
     * @return array<mixed>
     */
    private static function canonicalize(array $array): array
    {
        foreach ($array as $key => $value) {
            if (\is_array($value)) {
                $array[$key] = self::canonicalize($value);
            }
        }
        \ksort($array);

        return $array;
    }

    public function testHighAbuseProfileFillsItsDerivedDefaults(): void
    {
        $processed = $this->process(['protection_profile' => 'high_abuse']);

        // Stricter per-source issuance limits.
        self::assertSame(5, $processed['rate_limit']);
        self::assertSame(10, $processed['risk']['max_outstanding_challenges']);
        // Wider aggregate issuance bounds, raised together (the hard
        // limiter and the resource-capacity denominator must scale in
        // lockstep, per the configuration docs).
        self::assertSame(2000, $processed['rate_limit_global']);
        self::assertSame(2000, $processed['resource_capacity']['issuance_per_second']);
        self::assertSame(250000, $processed['risk']['max_outstanding_challenges_global']);
        // Risk enabled with raised abuse-evidence weights + decoy surface.
        self::assertTrue($processed['risk']['enabled']);
        self::assertTrue($processed['risk']['decoy_v3_enabled']);
        self::assertSame(320, $processed['risk']['weights']['bad_proof']);
        self::assertSame(340, $processed['risk']['weights']['malformed']);
        self::assertSame(380, $processed['risk']['weights']['replay']);
        self::assertSame(160, $processed['risk']['weights']['action_failure']);
        // The remaining weights stay at the contract defaults.
        self::assertSame(\KiwiCaptcha\Risk\RiskWeights::DEFAULT_SOURCE_FAST, $processed['risk']['weights']['source_fast']);
        // Cheaper per-process emergency shield.
        self::assertSame(5000, $processed['risk']['hard_limits']['process_per_second']);
        // Chaining stays off without a binding authority (the tree would
        // refuse it anyway).
        self::assertFalse($processed['risk']['chaining']['enabled']);
    }

    public function testHighAbuseEngagesChainingWhenAnAuthorityIsWired(): void
    {
        $processed = $this->process([
            'protection_profile' => 'high_abuse',
            'risk' => ['request_binding_authority' => 'app.binding_authority'],
        ]);

        self::assertTrue($processed['risk']['chaining']['enabled'], 'high_abuse engages chained step-up when the authoritative binding resolver is wired in the same config');
    }

    public function testHighAbuseKeepsAnExplicitlyDisabledRiskLayerOff(): void
    {
        $processed = $this->process([
            'protection_profile' => 'high_abuse',
            'risk' => ['enabled' => false],
        ]);

        self::assertFalse($processed['risk']['enabled'], 'an explicitly configured risk.enabled=false wins over the profile');
        // The profile still fills the other risk defaults.
        self::assertTrue($processed['risk']['decoy_v3_enabled']);
    }

    public function testPrivacyStrictProfileFillsItsDerivedDefaults(): void
    {
        $processed = $this->process(['protection_profile' => 'privacy_strict']);

        self::assertSame('strict', $processed['privacy_mode']);
        self::assertSame('off', $processed['telemetry']);
        self::assertFalse($processed['enforce_telemetry']);
        self::assertFalse($processed['risk']['client_context']);
        self::assertSame(0, $processed['min_duration_ms'], 'the server-side solve-timing heuristic is off');
        self::assertSame('none', $processed['binding_mode'], 'no IP-derived binding tag at all — the strongest first-party posture');
        self::assertFalse($processed['risk']['enabled']);
        self::assertFalse($processed['risk']['decoy_v3_enabled']);
    }

    public function testCompatibilityProfileFillsItsDerivedDefaults(): void
    {
        $processed = $this->process(['protection_profile' => 'compatibility']);

        self::assertSame('sha256', $processed['algorithm']);
        self::assertSame(300, $processed['challenge_ttl_secs'], 'conservative TTL, Turnstile token-lifetime parity');
        self::assertSame('none', $processed['binding_mode'], 'binding off for IP churn behind NAT/mobile');
        self::assertFalse($processed['risk']['enabled']);
        self::assertFalse($processed['risk']['decoy_v3_enabled'], 'protocol v2 emission');
        self::assertFalse($processed['risk']['client_context']);
    }

    public function testProfileNeverOverridesAnExplicitlyConfiguredKnob(): void
    {
        // One explicit knob per profile: the explicit value must win.
        $highAbuse = $this->process([
            'protection_profile' => 'high_abuse',
            'challenge_ttl_secs' => 30,
            'rate_limit' => 100,
        ]);
        self::assertSame(30, $highAbuse['challenge_ttl_secs']);
        self::assertSame(100, $highAbuse['rate_limit']);

        $privacyStrict = $this->process([
            'protection_profile' => 'privacy_strict',
            'binding_mode' => 'nonce_ip_hmac',
            'min_duration_ms' => 500,
        ]);
        self::assertSame('nonce_ip_hmac', $privacyStrict['binding_mode']);
        self::assertSame(500, $privacyStrict['min_duration_ms']);

        $compatibility = $this->process([
            'protection_profile' => 'compatibility',
            'challenge_ttl_secs' => 60,
        ]);
        self::assertSame(60, $compatibility['challenge_ttl_secs']);
    }

    public function testProfileFillsRiskDefaultsButNeverAnExplicitRiskSubtreeKey(): void
    {
        $processed = $this->process([
            'protection_profile' => 'high_abuse',
            'risk' => [
                'decoy_v3_enabled' => false,
                'weights' => ['replay' => 900],
            ],
        ]);

        self::assertFalse($processed['risk']['decoy_v3_enabled'], 'an explicitly configured decoy_v3_enabled=false wins over the profile');
        self::assertSame(900, $processed['risk']['weights']['replay'], 'an explicitly configured weight wins');
        self::assertSame(320, $processed['risk']['weights']['bad_proof'], 'the profile still fills the weights the operator did not set');
        self::assertTrue($processed['risk']['enabled'], 'the profile still fills the absent risk.enabled');
    }

    public function testBalancedProfileFillsArgonDefaults(): void
    {
        $processed = $this->process(['protection_profile' => 'balanced']);

        self::assertSame('sha256', $processed['algorithm']);
        self::assertSame(18, $processed['difficulty_bits']);
        self::assertSame(8, $processed['argon2_difficulty_bits']);
        self::assertSame(0, $processed['argon_m_kib']);
        self::assertSame(3, $processed['argon_t']);
        self::assertSame(1, $processed['argon_p']);
        self::assertSame(120, $processed['challenge_ttl_secs']);
        self::assertSame('nonce_ip_hmac', $processed['binding_mode']);
    }

    public function testReplayDurabilityDefaultsToBestEffort(): void
    {
        $processed = $this->process();

        self::assertSame('best_effort', $processed['replay_durability'], 'the default posture is best_effort: the current single-authority boundary with the stale-promotion window accepted as the documented deployment boundary');
    }

    public function testReplayDurabilityAcceptsEveryPostureValue(): void
    {
        self::assertSame('best_effort', $this->process(['replay_durability' => 'best_effort'])['replay_durability']);
        self::assertSame('operator_managed', $this->process(['replay_durability' => 'operator_managed'])['replay_durability']);
        self::assertSame('fail_closed', $this->process(['replay_durability' => 'fail_closed'])['replay_durability']);
    }

    public function testReplayDurabilityRejectsUnknownValues(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $this->process(['replay_durability' => 'automatic']);
    }

    public function testHaAuthorityDefaultsToNoneAndAcceptsPinnedPrimary(): void
    {
        self::assertSame('none', $this->process()['ha_authority'], 'ha_authority defaults to none: the current boundary stays byte-identical');
        self::assertSame('none', $this->process(['ha_authority' => 'none'])['ha_authority']);
        self::assertSame('pinned_primary', $this->process(['ha_authority' => 'pinned_primary'])['ha_authority']);
    }

    public function testHaAuthorityRejectsUnknownValues(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $this->process(['ha_authority' => 'quorum']);
    }

    public function testHaAuthorityReverifySecsDefaultsAndBounds(): void
    {
        self::assertSame(5, $this->process()['ha_authority_reverify_secs'], 'the default verification cache window is 5 seconds');
        self::assertSame(1, $this->process(['ha_authority_reverify_secs' => 1])['ha_authority_reverify_secs']);
        $this->expectException(InvalidConfigurationException::class);
        $this->process(['ha_authority_reverify_secs' => 0]);
    }

    public function testHaAuthorityExpectedDefaultsNullAndValidatesTheIdentityShape(): void
    {
        self::assertNull($this->process()['ha_authority_expected'], 'no operator-provisioned expected identity by default');
        $expected = 'master|'.str_repeat('a', 40);
        self::assertSame($expected, $this->process(['ha_authority_expected' => $expected])['ha_authority_expected']);

        try {
            $this->process(['ha_authority_expected' => 'not-an-identity']);
            self::fail('an expected identity without the role|run_id shape must be refused');
        } catch (InvalidConfigurationException $e) {
            self::assertStringContainsString('role|run_id', $e->getMessage());
        }
    }

    public function testHaAuthorityExpectedPerAuthorityMapForm(): void
    {
        $storage = 'master|'.str_repeat('a', 40);
        $risk = 'master|'.str_repeat('b', 40);
        $map = ['storage' => $storage, 'risk' => $risk];
        self::assertSame($map, $this->process(['ha_authority_expected' => $map])['ha_authority_expected'], 'the per-authority map form passes through unchanged');

        // A partial map (one authority) is legal: the authority without
        // an entry falls back to the pin key.
        self::assertSame(
            ['storage' => $storage],
            $this->process(['ha_authority_expected' => ['storage' => $storage]])['ha_authority_expected'],
        );

        // The map form is validated like the scalar form: an unknown
        // authority name is refused.
        try {
            $this->process(['ha_authority_expected' => ['limiter' => $storage]]);
            self::fail('a map naming an unknown authority must be refused');
        } catch (InvalidConfigurationException $e) {
            self::assertStringContainsString('storage/risk', $e->getMessage());
        }

        // A map entry without the identity shape is refused too.
        try {
            $this->process(['ha_authority_expected' => ['storage' => 'not-an-identity']]);
            self::fail('a map entry without the role|run_id shape must be refused');
        } catch (InvalidConfigurationException $e) {
            self::assertStringContainsString('role|run_id', $e->getMessage());
        }
    }

    public function testProtocolRolloutDefaultsToNormal(): void
    {
        $processed = $this->process();

        self::assertSame('normal', $processed['protocol_rollout']['mode'], 'the default rollout mode is normal: no deliberate protocol-v3 migration exception is declared');
    }

    public function testProtocolRolloutAcceptsBothModes(): void
    {
        self::assertSame('normal', $this->process(['protocol_rollout' => ['mode' => 'normal']])['protocol_rollout']['mode']);
        self::assertSame('migration', $this->process(['protocol_rollout' => ['mode' => 'migration']])['protocol_rollout']['mode']);
    }

    public function testProtocolRolloutRejectsUnknownModes(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $this->process(['protocol_rollout' => ['mode' => 'experimental']]);
    }

    // ── Asset delivery tier (asset_mode) ──────────────────────────────────

    public function testAssetModeDefaultsToFiles(): void
    {
        self::assertSame('files', $this->process()['asset_mode'], 'the default is the recommended files tier: versioned immutable assets with SRI, lazy runtime + worker');
    }

    public function testAssetModeAcceptsBothTiers(): void
    {
        self::assertSame('files', $this->process(['asset_mode' => 'files'])['asset_mode']);
        self::assertSame('inline', $this->process(['asset_mode' => 'inline'])['asset_mode']);
    }

    public function testAssetModeRejectsUnknownTiers(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $this->process(['asset_mode' => 'cdn']);
    }
}
