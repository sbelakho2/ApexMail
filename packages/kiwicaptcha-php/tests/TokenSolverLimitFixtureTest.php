<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\DecodeError;
use KiwiCaptcha\SolutionToken;
use PHPUnit\Framework\TestCase;

/**
 * The shared solution-token boundary contract
 * (protocol/solution-token-v1/fixtures.json): the 20,000,000 solver hash
 * ceiling and the exact counter spellings both decoders accept. The
 * fixture comes from the PHP encoder. These assertions prove the PHP
 * decoder and encoder agree with the contract byte-for-byte; the Rust
 * token_limits integration test asserts the same fixture, so a drift on
 * either side fails in the language that moved.
 */
final class TokenSolverLimitFixtureTest extends TestCase
{
    /** @return array<string, mixed> */
    private static function fixture(): array
    {
        $path = \dirname(__DIR__).'/../../protocol/solution-token-v1/fixtures.json';
        $decoded = json_decode((string) file_get_contents($path), true, 8, JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);

        return $decoded;
    }

    public function testSolverCeilingMatchesTheFixtureAuthority(): void
    {
        $fixture = self::fixture();
        self::assertSame(20_000_000, $fixture['solver_max_hashes']);
        self::assertSame($fixture['solver_max_hashes'], SolutionToken::maxSolverCounter());
    }

    public function testAcceptedBoundaryCountersDecodeAndReencode(): void
    {
        $fixture = self::fixture();
        $nonce = $fixture['nonce_b64'];
        $duration = $fixture['duration_ms'];
        $telemetry = json_decode($fixture['telemetry_json'], true, 8, JSON_THROW_ON_ERROR);

        self::assertNotEmpty($fixture['accepted']);
        foreach ($fixture['accepted'] as $counter => $encoded) {
            $token = SolutionToken::decode($encoded);
            self::assertSame((int) $counter, $token->counter, "counter $counter must decode from the fixture token");
            // The encoder direction: exactly the same bytes, so PHP encode
            // and decode are both pinned to the shared fixture.
            self::assertSame(
                $encoded,
                SolutionToken::create($nonce, (int) $counter, $duration, $telemetry)->encode(),
                "counter $counter must re-encode byte-for-byte",
            );
        }
    }

    public function testRejectedBoundaryCountersAreRefused(): void
    {
        $fixture = self::fixture();
        self::assertNotEmpty($fixture['rejected']);
        foreach ($fixture['rejected'] as $counter => $encoded) {
            try {
                SolutionToken::decode($encoded);
                self::fail("counter $counter must be rejected as beyond the solver maximum");
            } catch (DecodeError $e) {
                self::assertSame(DecodeError::COUNTER_EXCEEDS_SOLVER_MAXIMUM, $e->getMessage());
            }
        }
    }

    public function testCrossLanguageTokenAboveTheHistoricalFiveMillionCeiling(): void
    {
        // 5,000,001 is a counter the 20M browser solver really can mint but
        // the historical 5M decoder refused; both languages must decode it.
        $fixture = self::fixture();
        $cross = $fixture['cross_language'];
        self::assertGreaterThan(5_000_000, $cross['counter']);
        self::assertLessThan($fixture['solver_max_hashes'], $cross['counter']);

        $token = SolutionToken::decode($cross['encoded']);
        self::assertSame($cross['counter'], $token->counter);

        $telemetry = json_decode($fixture['telemetry_json'], true, 8, JSON_THROW_ON_ERROR);
        self::assertSame(
            $cross['encoded'],
            SolutionToken::create($fixture['nonce_b64'], $cross['counter'], $fixture['duration_ms'], $telemetry)->encode(),
        );
    }
}
