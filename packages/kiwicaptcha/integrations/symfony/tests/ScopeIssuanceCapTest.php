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
 * Per-scope issuance cap (audit #89): a Redis fixed-window counter
 * ({kiwi:<ns>}:issuance:<hex(hmac_sha256(scope, K_scope))>:<minute>, INCR +
 * EXPIRE 60 in one atomic Lua script) bounds how many challenges a scope
 * may issue per minute — the public site key + claimed origin can no longer
 * create unlimited billed verification work per scope.
 *
 * The RAW SCOPE STRING IS NEVER A REDIS KEY COMPONENT (audit #112): the
 * scope is attacker-controlled (bounded alphabet, unbounded cardinality),
 * so the window key carries hex(hmac_sha256(scope, K_scope)) where K_scope
 * is derived from the bundle's master with hash_hkdf info
 * 'kiwi/v2/scope-rate' (ScopeIssuanceCap::deriveScopeHmacKey).
 */
final class ScopeIssuanceCapTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private int $nowSecs = 1_800_000_000;

    private function hmacKey(): string
    {
        return ScopeIssuanceCap::deriveScopeHmacKey(self::SECRET);
    }

    /** The canonical audit #112 window key for a scope at the current minute. */
    private function windowKey(FakePredisClient $redis, string $scope): string
    {
        return '{kiwi:t}:issuance:'.hash_hmac('sha256', $scope, $this->hmacKey()).':'.intdiv($this->nowSecs, 60);
    }

    public function testCapIsEnforcedPerScopePerMinute(): void
    {
        $redis = new FakePredisClient();
        $cap = new ScopeIssuanceCap($redis, '{kiwi:t}:issuance:', 2, $this->hmacKey(), fn (): int => $this->nowSecs);

        self::assertTrue($cap->allow('login'), 'first issuance within the window');
        self::assertTrue($cap->allow('login'), 'second issuance within the window');
        self::assertFalse($cap->allow('login'), 'third issuance beyond the per-scope cap');
        self::assertTrue($cap->allow('signup'), 'a DIFFERENT scope has its own independent window');

        $key = $this->windowKey($redis, 'login');
        self::assertSame(3, $redis->counters[$key], 'the fixed-window counter counts every attempt');
        self::assertSame(60_000, $redis->expirations[$key], 'the first increment stamps the 60 s window TTL');

        // A new minute opens a fresh window.
        $this->nowSecs += 60;
        self::assertTrue($cap->allow('login'), 'a new minute resets the window');
    }

    /**
     * Audit #112: the window key carries the keyed scope pseudonym — the
     * raw scope string never appears in ANY Redis key the cap touches, and
     * distinct scopes map to distinct windows.
     */
    public function testRawScopeIsNeverARedisKeyComponent(): void
    {
        $redis = new FakePredisClient();
        $cap = new ScopeIssuanceCap($redis, '{kiwi:t}:issuance:', 10, $this->hmacKey(), fn (): int => $this->nowSecs);
        $cap->allow('login');

        $expected = '{kiwi:t}:issuance:'.hash_hmac('sha256', 'login', $this->hmacKey()).':'.intdiv($this->nowSecs, 60);
        self::assertSame(1, $redis->counters[$expected] ?? null, "the window key is the HMAC'd-scope form");
        foreach ($redis->calls as $call) {
            foreach ((array) $call[1] as $arg) {
                if (\is_string($arg) && str_contains($arg, ':issuance:')) {
                    self::assertStringNotContainsString('login', $arg, 'the raw scope must never appear in an issuance key (audit #112)');
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
     * Audit round 15: when the caller supplies the risk policy's canonical
     * SERVER-OWNED scope id, the quota keys on THAT identity — the
     * namespace is bounded by the server-owned set (two spellings of one
     * scope share a window; the HMAC fallback is only for unscoped calls).
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

        $key = '{kiwi:t}:issuance:42:'.intdiv($this->nowSecs, 60);
        self::assertSame(3, $redis->counters[$key], 'the window key is the canonical scope id, not the scope bytes');
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

    public function testDeriveScopeHmacKeyIsPurposeSeparated(): void
    {
        // The HKDF info tag 'kiwi/v2/scope-rate' must yield a key that
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
        self::assertTrue($cap->allow('login'));
        $cap = new ScopeIssuanceCap(new FakePredisClient(), '{kiwi:t}:issuance:', 0, '', fn (): int => $this->nowSecs);
        self::assertTrue($cap->allow('login'), 'cap 0 = unlimited');
    }

    public function testRedisFailurePropagatesFailClosed(): void
    {
        $redis = new FakePredisClient();
        $redis->failCommand = 'EVAL';
        $cap = new ScopeIssuanceCap($redis, '{kiwi:t}:issuance:', 10, $this->hmacKey(), fn (): int => $this->nowSecs);

        try {
            $cap->allow('login');
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

    public function testScopeCapDoesNotInterfereWithOtherScopes(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), $storage);
        $redis = new FakePredisClient();
        $cap = new ScopeIssuanceCap($redis, '{kiwi:t}:issuance:', 1, $this->hmacKey(), fn (): int => $this->nowSecs);
        $controller = new ChallengeController($issuer, scopeIssuanceCap: $cap);

        self::assertSame(200, $controller->challenge($this->challengeRequest('login'))->getStatusCode());
        self::assertSame(429, $controller->challenge($this->challengeRequest('login'))->getStatusCode(), 'login is capped at 1/min');
        self::assertSame(200, $controller->challenge($this->challengeRequest('signup'))->getStatusCode(), 'signup has its own window');
    }

    private function challengeRequest(string $scope): \Symfony\Component\HttpFoundation\Request
    {
        return JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], json_encode(['scope' => $scope]));
    }
}
