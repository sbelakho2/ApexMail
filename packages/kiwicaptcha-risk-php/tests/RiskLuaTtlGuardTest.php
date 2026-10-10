<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use PHPUnit\Framework\TestCase;

/**
 * The ephemeral-TTL guards inside the canonical Lua scripts, against
 * real Redis. A non-positive state/session/principal/dedupe TTL must be
 * refused by the script itself, fail closed with a Lua error reply. It
 * must never be silently turned into a persistent risk hash by the
 * save() zero-skip. The store constructors enforce the same rule before
 * any script runs. The guard is the last line of defence for a caller
 * that invokes the scripts directly.
 */
final class RiskLuaTtlGuardTest extends TestCase
{
    /** @var \Predis\Client */
    private $client;

    protected function setUp(): void
    {
        $url = getenv('RISK_REDIS_URL');
        if (!is_string($url) || $url === '') {
            self::markTestSkipped('RISK_REDIS_URL not set; start redis with: docker run -d -p 6399:6379 redis:7-alpine');
        }
        $this->client = RedisRiskStateStore::createClient($url);
        $this->client->ping();
    }

    private static function riskV1Script(): string
    {
        $script = file_get_contents(dirname(__DIR__).'/resources/risk-v1.lua');
        self::assertIsString($script);

        return $script;
    }

    private static function assessV2Script(): string
    {
        $script = file_get_contents(dirname(__DIR__).'/resources/assess_v2.lua');
        self::assertIsString($script);

        return $script;
    }

    /**
     * The risk-v1 ARGV vector with the dedupe path disabled, so the TTL
     * guards are reached before any key access.
     *
     * @return list<string>
     */
    private static function riskV1Args(string $stateTtl, string $dedupeTtl, string $sessionTtl, string $principalTtl): array
    {
        return [
            '1',        // [1] PreIssue
            '1',        // [2] scope
            '1700000000000', // [3] now_ms (unused, TIME is authoritative)
            '',         // [4] event_id — '' disables dedupe, reaching the guards first
            $dedupeTtl, // [5]
            $stateTtl,  // [6]
            '60000',    // [7] hysteresis
            '8000', '100000', '6000', '4000', '3000', '2000', '6000', '10000', '70000', '10000', '10000', // [8..18]
            '0',        // [19] has_session
            '0',        // [20] has_principal
            $sessionTtl, // [21]
            $principalTtl, // [22]
        ];
    }

    public function testRiskV1RefusesNonPositiveStateSessionPrincipalAndDedupeTtls(): void
    {
        $script = self::riskV1Script();
        $cases = [
            'session_ttl_s' => self::riskV1Args('1800', '60', '0', '86400'),
            'state_ttl_s' => self::riskV1Args('0', '60', '1800', '86400'),
            'principal_ttl_s' => self::riskV1Args('1800', '60', '1800', '0'),
            'dedupe_ttl_s' => self::riskV1Args('1800', '0', '1800', '86400'),
        ];
        foreach ($cases as $needle => $args) {
            try {
                $this->client->eval($script, 0, ...$args);
                self::fail('a non-positive '.$needle.' must be refused by the script, not written as a persistent hash');
            } catch (\Throwable $e) {
                self::assertStringContainsString($needle, $e->getMessage(), 'the guard names the offending knob');
            }
        }
    }

    public function testRiskV1AcceptsPositiveTtlsAndStillReturnsTheVector(): void
    {
        $script = self::riskV1Script();
        $keys = [];
        for ($i = 1; $i <= 10; $i++) {
            $keys[] = '{kiwi:lua-guard'.bin2hex(random_bytes(3))."}:risk:k{$i}";
        }
        $result = $this->client->eval(
            $script,
            count($keys),
            ...array_merge($keys, self::riskV1Args('1800', '60', '1800', '86400')),
        );
        self::assertIsArray($result);
        self::assertCount(16, $result, 'the script still returns the full vector + level/cool/duplicate extras');
        // The identity-state keys (source/subnet/session/principal) must
        // never be persistent with a positive state TTL; the global
        // rolling state (KEYS[9]) is the one intentional no-expiry
        // record, so it is excluded here. The session/principal keys
        // (has_*=0) are not written at all.
        foreach ([0, 3, 6, 7] as $index) {
            $ttl = (int) $this->client->ttl($keys[$index]);
            self::assertNotSame(-1, $ttl, 'the identity-state key must carry a positive state TTL');
        }
        self::assertSame(-1, (int) $this->client->ttl($keys[8]), 'the global rolling state is the documented no-expiry record');
        $this->client->del($keys);
    }

    public function testAssessV2WithoutARegistrationDoesNotRequireTheOutcomeTtl(): void
    {
        // ARGV[25] is the registration marker: an absent (falsy) marker
        // must skip the optional outcome-TTL guard rather than trip it,
        // so an identity-bearing assessment without a registration still
        // runs instead of degrading to a zero score.
        $script = self::assessV2Script();
        $args = array_fill(0, 24, '0');
        $args[0] = '1';
        $args[1] = '1';
        $args[4] = '60';
        $args[5] = '1800';
        $args[6] = '0';
        $args[18] = '1';
        $args[19] = '0';
        $args[20] = '1800';
        $args[21] = '86400';
        try {
            $this->client->eval($script, 0, ...$args);
            self::addToAssertionCount(1);
        } catch (\Throwable $e) {
            self::assertStringNotContainsString('outcome_ttl_s', $e->getMessage());
        }
    }

    public function testAssessV2RefusesANonPositiveSessionTtl(): void
    {
        $script = self::assessV2Script();
        $args = array_fill(0, 24, '');
        $args[20] = '0'; // ARGV[21] zero-indexed
        try {
            $this->client->eval($script, 0, ...$args);
            self::fail('assess_v2 must refuse a zero session TTL instead of writing a persistent first-seen record');
        } catch (\Throwable $e) {
            self::assertStringContainsString('session_ttl_s', $e->getMessage());
        }
    }
}
