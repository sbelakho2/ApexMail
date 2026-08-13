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

    public function testCalibrationReceiptTtlDefaultsAndBounds(): void
    {
        self::assertSame(300, $this->process()['risk']['calibration']['receipt_ttl_secs'], 'receipt_ttl_secs defaults to the audit receipt window (300)');
        self::assertSame(60, $this->process(['risk' => ['calibration' => ['receipt_ttl_secs' => 60]]])['risk']['calibration']['receipt_ttl_secs']);
        self::assertSame(86400, $this->process(['risk' => ['calibration' => ['receipt_ttl_secs' => 86400]]])['risk']['calibration']['receipt_ttl_secs']);
    }

    public function testCalibrationReceiptTtlBelowMinimumIsRejected(): void
    {
        $this->expectException(\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException::class);
        $this->process(['risk' => ['calibration' => ['receipt_ttl_secs' => 59]]]);
    }

    public function testCalibrationReceiptTtlAboveMaximumIsRejected(): void
    {
        $this->expectException(\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException::class);
        $this->process(['risk' => ['calibration' => ['receipt_ttl_secs' => 86401]]]);
    }

    public function testHardLimitsUseSinglePerProcessCap(): void
    {
        $hardLimits = $this->process()['risk']['hard_limits'];

        self::assertArrayHasKey('process_per_second', $hardLimits, 'the hard limit is the single per-process cap');
        self::assertSame(10000, $hardLimits['process_per_second'], 'process_per_second defaults to 10000');
        self::assertArrayNotHasKey('source_per_second', $hardLimits, 'the old two-window source cap is gone');
        self::assertArrayNotHasKey('global_per_second', $hardLimits, 'the old two-window global cap is gone');

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
}
