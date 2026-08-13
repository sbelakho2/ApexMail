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
 * ({kiwi:<ns>}:issuance:<scope>:<minute>, INCR + EXPIRE 60 in one atomic Lua
 * script) bounds how many challenges a scope may issue per minute — the
 * public site key + claimed origin can no longer create unlimited billed
 * verification work per scope.
 */
final class ScopeIssuanceCapTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private int $nowSecs = 1_800_000_000;

    public function testCapIsEnforcedPerScopePerMinute(): void
    {
        $redis = new FakePredisClient();
        $cap = new ScopeIssuanceCap($redis, '{kiwi:t}:issuance:', 2, fn (): int => $this->nowSecs);

        self::assertTrue($cap->allow('login'), 'first issuance within the window');
        self::assertTrue($cap->allow('login'), 'second issuance within the window');
        self::assertFalse($cap->allow('login'), 'third issuance beyond the per-scope cap');
        self::assertTrue($cap->allow('signup'), 'a DIFFERENT scope has its own independent window');

        $key = '{kiwi:t}:issuance:login:'.intdiv($this->nowSecs, 60);
        self::assertSame(3, $redis->counters[$key], 'the fixed-window counter counts every attempt');
        self::assertSame(60_000, $redis->expirations[$key], 'the first increment stamps the 60 s window TTL');

        // A new minute opens a fresh window.
        $this->nowSecs += 60;
        self::assertTrue($cap->allow('login'), 'a new minute resets the window');
    }

    public function testDisabledCapAlwaysAllows(): void
    {
        $cap = new ScopeIssuanceCap(null, '{kiwi:t}:issuance:', 5, fn (): int => $this->nowSecs);
        self::assertTrue($cap->allow('login'));
        $cap = new ScopeIssuanceCap(new FakePredisClient(), '{kiwi:t}:issuance:', 0, fn (): int => $this->nowSecs);
        self::assertTrue($cap->allow('login'), 'cap 0 = unlimited');
    }

    public function testRedisFailurePropagatesFailClosed(): void
    {
        $redis = new FakePredisClient();
        $redis->failCommand = 'EVAL';
        $cap = new ScopeIssuanceCap($redis, '{kiwi:t}:issuance:', 10, fn (): int => $this->nowSecs);

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
        $cap = new ScopeIssuanceCap($redis, '{kiwi:t}:issuance:', 2, fn (): int => $this->nowSecs);
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
        $cap = new ScopeIssuanceCap($redis, '{kiwi:t}:issuance:', 1, fn (): int => $this->nowSecs);
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
