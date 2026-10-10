<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\RiskWeights;
use PHPUnit\Framework\TestCase;

/**
 * Golden fixture parity: every protocol/risk-v1/fixtures.json vector must
 * reproduce expected_score exactly (byte-identical with the Rust side).
 */
final class FixturesParityTest extends TestCase
{
    private function fixturesPath(): string
    {
        $env = getenv('RISK_FIXTURES_PATH');
        if (is_string($env) && $env !== '') {
            return $env;
        }
        return dirname(__DIR__) . '/../../protocol/risk-v1/fixtures.json';
    }

    public function testEveryFixtureScoreMatchesExactly(): void
    {
        $path = $this->fixturesPath();
        self::assertFileExists($path, sprintf('Fixtures file not found at %s (set RISK_FIXTURES_PATH)', $path));
        $fixtures = json_decode((string) file_get_contents($path), true);
        self::assertIsArray($fixtures);
        self::assertSame('risk-v1', $fixtures['protocol']);

        $weights = RiskWeights::fromArray($fixtures['weights']);
        $scorer = new RiskScorer();

        foreach ($fixtures['fixtures'] as $i => $fixture) {
            $vector = SignalVector::fromArray($fixture['signals']);
            $score = $scorer->score((int) $fixtures['base_risk'], $vector, $weights);
            self::assertSame(
                $fixture['expected_score'],
                $score,
                sprintf('Fixture #%d score mismatch', $i)
            );
        }
    }

    public function testDefaultWeightsMatchContract(): void
    {
        $path = $this->fixturesPath();
        $fixtures = json_decode((string) file_get_contents($path), true);
        self::assertSame($fixtures['weights'], (new RiskWeights())->toArray());
    }

    public function testSignalVectorRoundTrip(): void
    {
        $path = $this->fixturesPath();
        $fixtures = json_decode((string) file_get_contents($path), true);
        $vector = SignalVector::fromArray($fixtures['fixtures'][0]['signals']);
        self::assertSame($fixtures['fixtures'][0]['signals'], $vector->toArray());
        $json = json_encode($fixtures['fixtures'][0]['signals']);
        self::assertSame($vector->toArray(), SignalVector::fromJson((string) $json)->toArray());
    }

    /**
     * Cross-language policy-parse parity: every policy_parse_rejects
     * vector in fixtures.json is a config both parsers must reject (the
     * Rust suite runs the identical cases — strict, fail-closed
     * global_floors semantics on both sides).
     */
    public function testPolicyParseRejectVectorsAreRejected(): void
    {
        $path = $this->fixturesPath();
        self::assertFileExists($path, sprintf('Fixtures file not found at %s (set RISK_FIXTURES_PATH)', $path));
        $fixtures = json_decode((string) file_get_contents($path), true);
        self::assertIsArray($fixtures);
        self::assertNotEmpty($fixtures['policy_parse_rejects'] ?? null, 'fixtures.json must carry policy_parse_rejects vectors');

        foreach ($fixtures['policy_parse_rejects'] as $case) {
            $config = $case['config'];
            try {
                RiskPolicy::fromConfig($config);
                self::fail(sprintf('policy config "%s" must be rejected', $case['name']));
            } catch (\InvalidArgumentException $e) {
                self::assertNotSame('', $e->getMessage());
            }
        }
    }
}
