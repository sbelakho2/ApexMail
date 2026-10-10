<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use PHPUnit\Framework\TestCase;

/**
 * The store-configuration invariants at the lowest public API boundary,
 * driven by the shared cross-language vectors
 * (protocol/risk-v1/fixtures.json -> invalid_store_configuration): every
 * state/session/principal/dedupe/outcome TTL, epoch window and
 * hysteresis window must be a positive integer and every saturation must
 * be positive. The Symfony tree is the friendlier first error; this
 * constructor is the security validation a standalone package user
 * gets, and the Rust RedisRiskStateStore::with_options enforces the
 * identical vectors.
 */
final class RiskStoreConfigInvariantsTest extends TestCase
{
    /** @return array<string, mixed> */
    private function vectors(): array
    {
        $path = getenv('RISK_FIXTURES_PATH');
        if (!is_string($path) || $path === '') {
            $path = dirname(__DIR__).'/../../protocol/risk-v1/fixtures.json';
        }
        $fixtures = json_decode((string) file_get_contents($path), true, 8, JSON_THROW_ON_ERROR);
        self::assertIsArray($fixtures['invalid_store_configuration'] ?? null, 'the shared invalid-configuration vectors must exist');

        return $fixtures['invalid_store_configuration'];
    }

    public function testEveryInvalidConfigurationVectorIsRejected(): void
    {
        $vectors = $this->vectors();
        $defaults = $vectors['defaults'];
        $client = RedisRiskStateStore::createClient('redis://127.0.0.1:6399');

        $paramByKnob = [
            'state_ttl_secs' => 'stateTtlSecs',
            'dedupe_ttl_secs' => 'dedupeTtlSecs',
            'hysteresis_ms' => 'hysteresisMs',
            'session_ttl_secs' => 'sessionTtlSecs',
            'principal_ttl_secs' => 'principalTtlSecs',
            'outcome_ttl_secs' => 'outcomeTtlSecs',
        ];
        foreach ($vectors['vectors'] as $vector) {
            $knob = (string) $vector['knob'];
            $value = $vector['value'];
            $arguments = [
                'stateTtlSecs' => $defaults['state_ttl_secs'],
                'dedupeTtlSecs' => $defaults['dedupe_ttl_secs'],
                'hysteresisMs' => $defaults['hysteresis_ms'],
                'sessionTtlSecs' => $defaults['session_ttl_secs'],
                'principalTtlSecs' => $defaults['principal_ttl_secs'],
                'outcomeTtlSecs' => $defaults['outcome_ttl_secs'],
            ];
            if ($knob === 'saturation_0') {
                // Lua argv slot 0 is src_fast, exactly as the Rust vector
                // mutates saturations[0].
                $saturations = RedisRiskStateStore::DEFAULT_SATURATIONS;
                $saturations['src_fast'] = $value;
                $arguments['saturations'] = $saturations;
            } else {
                $arguments[$paramByKnob[$knob] ?? $knob] = $value;
            }

            try {
                new RedisRiskStateStore($client, ...['namespace' => 'inv'.bin2hex(random_bytes(4))] + $arguments);
                self::fail(sprintf('the invalid configuration vector %s (%s=%s) must be refused', $vector['name'], $knob, (string) $value));
            } catch (\InvalidArgumentException $e) {
                self::assertNotSame('', $e->getMessage(), $vector['name']);
            }
        }
    }

    public function testTheDefaultConfigurationIsAccepted(): void
    {
        // The defaults themselves are valid: the invariant is positivity,
        // not a spike of the defaults.
        $store = new RedisRiskStateStore(
            RedisRiskStateStore::createClient('redis://127.0.0.1:6399'),
            namespace: 'inv-ok'.bin2hex(random_bytes(4)),
        );
        self::assertInstanceOf(RedisRiskStateStore::class, $store);
    }

    public function testAPartialSaturationMapIsAcceptedAndOverlaidOnTheDefaults(): void
    {
        // The Symfony bundle wires only the channels its tree exposes, so a
        // partial map must stay valid: every read overlays it on
        // the contract defaults.
        $store = new RedisRiskStateStore(
            RedisRiskStateStore::createClient('redis://127.0.0.1:6399'),
            saturations: ['global' => 12345],
            namespace: 'inv-partial'.bin2hex(random_bytes(4)),
        );
        self::assertInstanceOf(RedisRiskStateStore::class, $store);
    }

    public function testAnUnknownSaturationKeyIsRefused(): void
    {
        // An unknown key would be silently ignored by the overlay, so it is
        // refused instead of pretending to tune a channel that does not
        // exist.
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('unknown key');
        new RedisRiskStateStore(
            RedisRiskStateStore::createClient('redis://127.0.0.1:6399'),
            saturations: ['principal_typo' => 10000],
            namespace: 'inv-unknown'.bin2hex(random_bytes(4)),
        );
    }
}
