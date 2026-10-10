<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Security\ScopeIssuanceCap;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JsonRequest;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\Storage\ArrayStorage;
use PHPUnit\Framework\TestCase;

/**
 * Per-scope issuance cap: a Redis sliding-window log keyed by
 * {kiwi:<ns>}:issuance:<canonicalScopeId>:sw (one ZSET per scope,
 * one member per admitted issuance) bounds how many challenges a
 * scope may issue per 60 s. The prune + count + admit runs in one
 * atomic Lua script. The public site key and claimed origin can no longer create
 * unlimited billed verification work per scope. Any 60 s sliding
 * window admits at most the cap, so a burst straddling a minute
 * boundary yields exactly the cap, never twice the fixed-window
 * allowance. Once the live count reaches 80% of the cap a warning is
 * logged (at most once per scope per window): alert as the cap is
 * approached, before it starts refusing challenges.
 *
 * The key carries the server-owned canonical scope id: the configured
 * risk.scopes.<name>.id, the shared synthetic unknown-scope id, or
 * ScopeIssuanceCap::UNKNOWN_QUOTA_ID for every unresolved scope. The
 * raw attacker-controlled scope string is never a Redis key component
 * (nor a log line), and inventing scope names can never mint fresh
 * quota windows. The per-name HMAC form hmac_sha256(scope, K_scope) is
 * confined to the legacy allowSoftLegacy() path and is not a security
 * bound; K_scope comes from the bundle's master via hash_hkdf info
 * 'kiwi/v2/scope-rate'.
 */
final class ScopeIssuanceCapTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private int $nowSecs = 1_800_000_000;

    private function hmacKey(): string
    {
        return ScopeIssuanceCap::deriveScopeHmacKey(self::SECRET);
    }

    public function testCapIsEnforcedPerScopePerMinute(): void
    {
        $redis = new FakePredisClient();
        $cap = new ScopeIssuanceCap($redis, '{kiwi:t}:issuance:', 2, $this->hmacKey(), fn (): int => $this->nowSecs);

        self::assertTrue($cap->allow('login', 1), 'first issuance within the window');
        self::assertTrue($cap->allow('login', 1), 'second issuance within the window');
        self::assertFalse($cap->allow('login', 1), 'third issuance beyond the per-scope cap');
        self::assertTrue($cap->allow('signup', 2), 'a DIFFERENT scope has its own independent window');

        $key = '{kiwi:t}:issuance:1:sw';
        self::assertCount(2, $redis->zsets[$key] ?? [], 'the window keeps one member per admitted issuance (refusals add none)');
        self::assertSame(61_000, $redis->expirations[$key], 'the window ZSET carries the window + 1 s TTL');
        self::assertSame(61_000, $redis->expirations[$key.':seq'], 'the unique-member counter carries the same TTL');

        // The window slides: 60 s past the last admission the entries
        // have expired and the scope is admitted again — no minute
        // boundary reset, the entries simply age out.
        $this->nowSecs += 60;
        self::assertTrue($cap->allow('login', 1), 'a slid window admits again');
    }

    /**
     * The done-when of the sliding window: a boundary-straddling burst
     * yields exactly the cap, never twice. The fixed-window shape let a
     * late burst in one minute plus the next minute's fresh window
     * admit up to twice the cap; the sliding window admits at most the
     * cap in ANY 60 s interval.
     */
    public function testABoundaryStraddlingBurstYieldsExactlyTheCapNeverTwice(): void
    {
        $redis = new FakePredisClient();
        $nowMs = [59_999.0];
        // The injected clock returns epoch seconds; the test timeline is
        // written in ms (the closure divides), so the boundary points
        // stay readable.
        $clock = static function () use (&$nowMs): float {
            return $nowMs[0] / 1000.0;
        };
        $cap = new ScopeIssuanceCap($redis, '{kiwi:t}:issuance:', 3, $this->hmacKey(), $clock);

        $allowed = 0;
        foreach ([59_999.0, 59_999.0, 59_999.0, 60_001.0, 60_001.0, 60_001.0] as $t) {
            $nowMs[0] = $t;
            $allowed += $cap->allow('login', 1) ? 1 : 0;
        }
        self::assertSame(3, $allowed, '2C attempts spanning the minute boundary yield exactly C admissions');

        // Exactly 0 accepted until t advances past the first burst's
        // window: the t=59.999 s admissions expire at now-60 s = 119.999 s.
        $nowMs[0] = 119_998.0;
        self::assertFalse($cap->allow('login', 1), 't=119.998 s: the burst is still inside (now-60 s, now]');
        $nowMs[0] = 119_999.0;
        self::assertTrue($cap->allow('login', 1), 't=119.999 s: the burst left the window exactly at the cutoff');
    }

    /**
     * The window boundary is (now-60000, now]: an entry at exactly
     * now-window has expired — a t=60.000 s attempt does not count
     * t=0 entries.
     */
    public function testWindowEntriesExpireAtExactlyNowMinusWindow(): void
    {
        $redis = new FakePredisClient();
        $nowMs = [0.0];
        $clock = static function () use (&$nowMs): float {
            return $nowMs[0] / 1000.0;
        };
        $cap = new ScopeIssuanceCap($redis, '{kiwi:t}:issuance:', 1, $this->hmacKey(), $clock);

        self::assertTrue($cap->allow('login', 1), 'the t=0 admission fills the cap-1 window');
        $nowMs[0] = 59_999.0;
        self::assertFalse($cap->allow('login', 1), 't=59.999 s: the t=0 entry is still inside the window');
        $nowMs[0] = 60_000.0;
        self::assertTrue($cap->allow('login', 1), 't=60.000 s: the t=0 entry sits exactly at the cutoff and is removed');
    }

    /**
     * The approach alert: below 80% of the cap nothing is logged; the
     * 8th of 10 admissions warns exactly once for the window; a fresh
     * window warns again. The alert names the canonical scope id (never
     * the raw scope string), the live count and the cap.
     */
    public function testTheApproachAlertFiresOncePerWindowAtEightyPercent(): void
    {
        $redis = new FakePredisClient();
        $warnings = [];
        $logger = new class($warnings) extends \Psr\Log\NullLogger {
            /** @param list<array{message: string, context: array<string,mixed>}> $warnings */
            public function __construct(private array &$warnings)
            {
            }

            public function warning(string|\Stringable $message, array $context = []): void
            {
                $this->warnings[] = ['message' => (string) $message, 'context' => $context];
            }
        };
        $nowMs = [1_000.0];
        $clock = static function () use (&$nowMs): float {
            return $nowMs[0] / 1000.0;
        };
        $cap = new ScopeIssuanceCap($redis, '{kiwi:t}:issuance:', 10, $this->hmacKey(), $clock, $logger);

        for ($i = 0; $i < 7; $i++) {
            self::assertTrue($cap->allow('login', 42));
        }
        self::assertSame([], $warnings, 'below 80% of the cap nothing is logged');

        self::assertTrue($cap->allow('login', 42), 'the 8th admission reaches 80% of the cap');
        self::assertCount(1, $warnings, 'the approach alert fires at the 8th admission');
        self::assertStringContainsString('scope issuance cap approaching', $warnings[0]['message']);
        self::assertStringContainsString('being approached', $warnings[0]['message']);
        self::assertSame('42', (string) $warnings[0]['context']['scope'], 'the alert names the canonical scope id');
        self::assertSame(8, $warnings[0]['context']['count']);
        self::assertSame(10, $warnings[0]['context']['cap']);
        self::assertStringNotContainsString(
            'login',
            $warnings[0]['message'].' '.implode(' ', array_map(strval(...), $warnings[0]['context'])),
            'the raw scope must never appear in the alert',
        );

        self::assertTrue($cap->allow('login', 42), 'the 9th admission stays inside the cap');
        self::assertCount(1, $warnings, 'the alert fires at most once per scope per window');

        // A fresh window (the first burst slid out) alerts again on
        // approach: one warning per window, not one for the cap's life.
        $nowMs[0] = 61_001.0;
        for ($i = 0; $i < 7; $i++) {
            self::assertTrue($cap->allow('login', 42));
        }
        self::assertCount(1, $warnings, 'the fresh window stays quiet below 80%');
        self::assertTrue($cap->allow('login', 42));
        self::assertCount(2, $warnings, 'a new window logs the approach again');
    }

    /**
     * The security cap's canonical scope id is mandatory —
     * calling allow() without one is a compile-time/static-analysis error
     * (there is no nullable fallback that silently recreates the
     * per-name-HMAC attack surface).
     */
    public function testCanonicalScopeIdIsMandatoryForTheSecurityCap(): void
    {
        $redis = new FakePredisClient();
        $cap = new ScopeIssuanceCap($redis, '{kiwi:t}:issuance:', 2, $this->hmacKey(), fn (): int => $this->nowSecs);

        // ArgumentCountError: allow() requires (string $scope, int $canonicalScopeId).
        try {
            $cap->allow('login');
            self::fail('allow() must require the canonical scope id');
        } catch (\ArgumentCountError) {
            // expected
        }
        self::assertSame([], $redis->counters, 'an incomplete call must never touch Redis');
    }

    /**
     * The per-name HMAC form survives only as the
     * explicitly-named legacy soft-quota API — it hides bytes but does not
     * bound cardinality, and the name makes the distinction impossible to
     * miss.
     */
    public function testSoftLegacyApiIsExplicitlyNamedAndNonCardinalitySafe(): void
    {
        $redis = new FakePredisClient();
        $cap = new ScopeIssuanceCap($redis, '{kiwi:t}:issuance:', 2, $this->hmacKey(), fn (): int => $this->nowSecs);

        self::assertTrue($cap->allowSoftLegacy('login'));
        self::assertTrue($cap->allowSoftLegacy('login'));
        self::assertFalse($cap->allowSoftLegacy('login'), 'the legacy per-name window caps at 2/min');

        $key = '{kiwi:t}:issuance:'.hash_hmac('sha256', 'login', $this->hmacKey()).':sw';
        self::assertCount(2, $redis->zsets[$key] ?? [], 'the legacy window is the HMAC per-name form');
        // And the canonical form is a different window for the same scope
        // name — the two APIs never share keys.
        self::assertTrue($cap->allow('login', 1), 'the canonical window is independent of the legacy one');
    }

    /**
     * The window key carries the keyed scope pseudonym — the
     * raw scope string never appears in ANY Redis key the cap touches, and
     * distinct scopes map to distinct windows.
     */
    public function testRawScopeIsNeverARedisKeyComponent(): void
    {
        $redis = new FakePredisClient();
        $cap = new ScopeIssuanceCap($redis, '{kiwi:t}:issuance:', 10, $this->hmacKey(), fn (): int => $this->nowSecs);
        $cap->allowSoftLegacy('login');

        $expected = '{kiwi:t}:issuance:'.hash_hmac('sha256', 'login', $this->hmacKey()).':sw';
        self::assertCount(1, $redis->zsets[$expected] ?? [], "the window key is the HMAC'd-scope form");
        foreach ($redis->calls as $call) {
            foreach ((array) $call[1] as $arg) {
                if (\is_string($arg) && str_contains($arg, ':issuance:')) {
                    self::assertStringNotContainsString('login', $arg, 'the raw scope must never appear in an issuance key');
                }
            }
        }
        self::assertNotSame(
            $cap->scopeKey('login'),
            $cap->scopeKey('signup'),
            'distinct scopes must map to distinct keyed pseudonyms'
        );
        self::assertSame(
            $cap->scopeKey('login'),
            $cap->scopeKey('login'),
            'the keyed pseudonym is deterministic per scope'
        );
    }

    /**
     * When the caller supplies the risk policy's canonical
     * server-owned scope id, the quota keys on that identity — the
     * namespace is bounded by the server-owned set. Two spellings of one
     * scope share a window; the HMAC fallback is only for unscoped
     * calls.
     */
    public function testCanonicalScopeIdIsTheQuotaIdentity(): void
    {
        $redis = new FakePredisClient();
        $cap = new ScopeIssuanceCap($redis, '{kiwi:t}:issuance:', 2, $this->hmacKey(), fn (): int => $this->nowSecs);

        // Two attacker-chosen names that resolve to ONE server-owned scope
        // id share a single window — cardinality is bounded by the
        // server-owned set, not by the client's scope strings.
        self::assertTrue($cap->allow('login', 42));
        self::assertTrue($cap->allow('signup', 42));
        self::assertFalse($cap->allow('anything_else', 42), 'the canonical id collapses every alias into one window');

        $key = '{kiwi:t}:issuance:42:sw';
        self::assertCount(2, $redis->zsets[$key] ?? [], 'the window key is the canonical scope id, not the scope bytes');
        foreach ($redis->calls as $call) {
            foreach ((array) $call[1] as $arg) {
                if (\is_string($arg) && str_contains($arg, ':issuance:')) {
                    self::assertStringNotContainsString('login', $arg, 'the raw scope must never appear in an issuance key');
                    self::assertStringNotContainsString('signup', $arg, 'the raw scope must never appear in an issuance key');
                }
            }
        }

        // Distinct canonical ids still get independent windows.
        self::assertTrue($cap->allow('login', 7), 'a different server-owned scope id has its own window');
    }

    /**
     * The window clock comes from the Redis server clock and the cap
     * fails closed when that clock is unavailable. A time failure raises
     * instead of silently switching to each host's wall clock — around
     * window boundaries, skewed hosts would use different windows and
     * defeat the shared-window invariant.
     */
    public function testTheWindowFailsClosedWhenRedisTimeIsUnavailable(): void
    {
        $redis = new FakePredisClient();
        $cap = new ScopeIssuanceCap($redis, '{kiwi:t}:issuance:', 1, $this->hmacKey());

        $redis->timeUnavailable = true;
        try {
            $cap->allow('login', 42);
            self::fail('the cap must fail closed when Redis TIME is unavailable');
        } catch (\Exception) {
            // expected: the clock error propagates (no host-clock fallback)
        }
        self::assertSame([], $redis->counters, 'a failed clock must never open a quota window');

        $redis->timeUnavailable = false;
        self::assertTrue($cap->allow('login', 42), 'a healthy Redis clock still admits');
    }

    public function testDeriveScopeHmacKeyIsPurposeSeparated(): void
    {
        // The hkdf info tag 'kiwi/v2/scope-rate' must yield a key that
        // differs from the raw master and is deterministic across workers.
        $key = ScopeIssuanceCap::deriveScopeHmacKey(self::SECRET);
        self::assertSame(32, \strlen($key));
        self::assertSame($key, ScopeIssuanceCap::deriveScopeHmacKey(self::SECRET), 'derivation must be deterministic');
        self::assertNotSame($key, self::SECRET, 'the derived key must differ from the master');
        self::assertNotSame(
            $key,
            ScopeIssuanceCap::deriveScopeHmacKey(str_repeat('b', 32)),
            'a different master must derive a different key'
        );
    }

    public function testEnabledCapRequiresTheScopeHmacKey(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new ScopeIssuanceCap(new FakePredisClient(), '{kiwi:t}:issuance:', 5, '', fn (): int => $this->nowSecs);
    }

    public function testDisabledCapAlwaysAllows(): void
    {
        $cap = new ScopeIssuanceCap(null, '{kiwi:t}:issuance:', 5, '', fn (): int => $this->nowSecs);
        self::assertTrue($cap->allow('login', 1));
        $cap = new ScopeIssuanceCap(new FakePredisClient(), '{kiwi:t}:issuance:', 0, '', fn (): int => $this->nowSecs);
        self::assertTrue($cap->allow('login', 1), 'cap 0 = unlimited');
    }

    public function testRedisFailurePropagatesFailClosed(): void
    {
        $redis = new FakePredisClient();
        $redis->failCommand = 'EVAL';
        $cap = new ScopeIssuanceCap($redis, '{kiwi:t}:issuance:', 10, $this->hmacKey(), fn (): int => $this->nowSecs);

        try {
            $cap->allow('login', 1);
            self::fail('a Redis failure must fail closed (propagate), never silently unlimited');
        } catch (\Predis\Response\ServerException) {
            self::assertTrue(true);
        }
    }

    public function testControllerReturns429ScopeLimitedBeyondTheCap(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), $storage);
        $redis = new FakePredisClient();
        $cap = new ScopeIssuanceCap($redis, '{kiwi:t}:issuance:', 2, $this->hmacKey(), fn (): int => $this->nowSecs);
        $controller = new ChallengeController($issuer, scopeIssuanceCap: $cap);

        $first = json_decode((string) $controller->challenge($this->challengeRequest('login'))->getContent(), true);
        self::assertArrayHasKey('nonce', $first);
        self::assertSame(1, $this->storedCount($storage), 'the first issuance stores a challenge');

        $response = $controller->challenge($this->challengeRequest('login'));
        self::assertSame(200, $response->getStatusCode(), 'the second issuance is within the cap');

        $response = $controller->challenge($this->challengeRequest('login'));
        self::assertSame(429, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('SCOPE_LIMITED', $body['error']['code']);
        self::assertSame(2, $this->storedCount($storage), 'a capped request must not mint another challenge');
    }

    private function storedCount(ArrayStorage $storage): int
    {
        $prop = new \ReflectionProperty(ArrayStorage::class, 'records');

        return \count($prop->getValue($storage));
    }

    public function testUnresolvedScopesShareTheReservedWindow(): void
    {
        // Without a risk gateway every scope resolves to
        // the single reserved unknown_quota_ID — invented names share one
        // window instead of minting fresh per-name quotas.
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), $storage);
        $redis = new FakePredisClient();
        $cap = new ScopeIssuanceCap($redis, '{kiwi:t}:issuance:', 1, $this->hmacKey(), fn (): int => $this->nowSecs);
        $controller = new ChallengeController($issuer, scopeIssuanceCap: $cap);

        self::assertSame(200, $controller->challenge($this->challengeRequest('login'))->getStatusCode());
        self::assertSame(429, $controller->challenge($this->challengeRequest('login'))->getStatusCode(), 'login is capped at 1/min');
        self::assertSame(429, $controller->challenge($this->challengeRequest('signup'))->getStatusCode(), 'an unresolved scope shares the reserved quota window (never a fresh per-name window)');
        self::assertSame(429, $controller->challenge($this->challengeRequest('anything'))->getStatusCode(), 'every invented scope hits the SAME reserved bucket');
    }

    public function testDistinctCanonicalScopeIdsHaveIndependentWindows(): void
    {
        // The per-scope independence property holds for server-owned ids:
        // two configured scopes (ids 1 and 2) never share a window.
        $redis = new FakePredisClient();
        $cap = new ScopeIssuanceCap($redis, '{kiwi:t}:issuance:', 1, $this->hmacKey(), fn (): int => $this->nowSecs);

        self::assertTrue($cap->allow('login', 1));
        self::assertFalse($cap->allow('login', 1), 'scope id 1 is capped at 1/min');
        self::assertTrue($cap->allow('signup', 2), 'scope id 2 has its own independent window');
    }

    private function challengeRequest(string $scope): \Symfony\Component\HttpFoundation\Request
    {
        return JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], json_encode(['scope' => $scope]));
    }
}
