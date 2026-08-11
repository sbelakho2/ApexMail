<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceRateLimiter;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\Storage\ArrayStorage;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpFoundation\Request;

/**
 * Per-IP issuance rate limiting: a sliding window per client IP (in-memory
 * single-process by default, or a PSR-6 pool for shared multi-process state),
 * enforced at the challenge endpoint with HTTP 429.
 */
final class RateLimiterTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private function controller(?IssuanceRateLimiter $limiter = null): ChallengeController
    {
        return new ChallengeController(new Issuer(
            new Config(secretKey: self::SECRET, targetBits: 8),
            new ArrayStorage(),
        ), $limiter);
    }

    private function post(ChallengeController $controller, string $ip, string $scope = 'login'): int
    {
        $response = $controller->challenge(Request::create(
            '/kiwi-captcha/challenge',
            'POST',
            [],
            [],
            [],
            ['REMOTE_ADDR' => $ip],
            json_encode(['scope' => $scope], JSON_THROW_ON_ERROR),
        ));

        return $response->getStatusCode();
    }

    public function testInMemoryLimiterAllowsLimitThenRejectsWith429(): void
    {
        $controller = $this->controller(new IssuanceRateLimiter(3, 60));

        self::assertSame(200, $this->post($controller, '198.51.100.7'));
        self::assertSame(200, $this->post($controller, '198.51.100.7'));
        self::assertSame(200, $this->post($controller, '198.51.100.7'));
        self::assertSame(429, $this->post($controller, '198.51.100.7'));
        self::assertSame(429, $this->post($controller, '198.51.100.7'));
    }

    public function testRateLimitIsPerClientIp(): void
    {
        $controller = $this->controller(new IssuanceRateLimiter(1, 60));

        self::assertSame(200, $this->post($controller, '198.51.100.7'));
        self::assertSame(429, $this->post($controller, '198.51.100.7'));
        self::assertSame(200, $this->post($controller, '198.51.100.8'));
    }

    public function testRateLimitedResponseIsJson(): void
    {
        $controller = $this->controller(new IssuanceRateLimiter(1, 60));
        $this->post($controller, '198.51.100.7');

        $response = $controller->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{}'));
        self::assertSame(429, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('RATE_LIMITED', $body['error']['code']);
    }

    public function testWindowExpiryAllowsRequestsAgain(): void
    {
        $now = 1_000.0;
        $limiter = new IssuanceRateLimiter(1, 60, null, static function () use (&$now): float {
            return $now;
        });
        $controller = $this->controller($limiter);

        self::assertSame(200, $this->post($controller, '198.51.100.7'));
        self::assertSame(429, $this->post($controller, '198.51.100.7'));

        $now += 61.0; // first hit falls out of the sliding window
        self::assertSame(200, $this->post($controller, '198.51.100.7'));
        self::assertSame(429, $this->post($controller, '198.51.100.7'));
    }

    public function testPsr6BackedLimiterSharesState(): void
    {
        $pool = new ArrayAdapter();
        $first = new IssuanceRateLimiter(3, 60, $pool);
        $second = new IssuanceRateLimiter(3, 60, $pool);

        self::assertTrue($first->allow('198.51.100.7'));
        self::assertTrue($first->allow('198.51.100.7'));
        self::assertTrue($second->allow('198.51.100.7'));
        self::assertFalse($first->allow('198.51.100.7'), 'limit is shared across limiter instances through the pool');
        self::assertTrue($first->allow('198.51.100.8'), 'other IPs are independent');
    }

    public function testRawIpIsNeverUsedAsAKey(): void
    {
        $pool = new ArrayAdapter();
        $pepper = 'rate-limit-pepper-for-tests';
        $limiter = new IssuanceRateLimiter(1, 60, $pool, null, $pepper);
        $limiter->allow('198.51.100.7');

        // The shared cache key is the peppered HMAC of the IP (hex digest) —
        // never the IP itself.
        $expectedKey = 'kiwi_rate_'.hash_hmac('sha256', '198.51.100.7', $pepper);
        self::assertTrue($pool->getItem($expectedKey)->isHit(), 'the state must live under the HMAC key');

        foreach (array_keys($pool->getValues()) as $key) {
            self::assertMatchesRegularExpression(
                '/^kiwi_rate_[0-9a-f]{64}$/',
                (string) $key,
                'rate-limit keys must be 64-hex HMAC digests of the client IP',
            );
            self::assertStringNotContainsString('198.51.100.7', (string) $key, 'raw IPs must never appear in stored keys');
        }
    }

    public function testInMemoryWindowIsSlidingNotFixed(): void
    {
        $now = 1_000.0;
        $limiter = new IssuanceRateLimiter(2, 60, null, static function () use (&$now): float {
            return $now;
        });
        $ip = '198.51.100.7';

        self::assertTrue($limiter->allow($ip), 'hit at t0');
        $now = 1_059.0; // t0 + window - ε
        self::assertTrue($limiter->allow($ip), 'hit at t0 + 59s');
        $now = 1_059.5;
        self::assertFalse($limiter->allow($ip), 't0 and t0+59s count TOGETHER: window is full');
        $now = 1_061.0; // t0 + window + ε
        self::assertTrue($limiter->allow($ip), 'the t0 hit has slid out of the window');
        $now = 1_061.5;
        self::assertFalse(
            $limiter->allow($ip),
            'sliding window: the two remaining hits (t0+59, t0+61) still fill the cap — a fixed [window_start, hits] bucket would have allowed this',
        );
    }

    public function testSharedWindowIsSlidingNotFixed(): void
    {
        // The PSR-6 path must implement a true sliding window too (the old
        // [window_start, hits] fixed bucket allowed boundary bursts to double
        // the rate).
        $pool = new ArrayAdapter();
        $now = 1_000.0;
        $limiter = new IssuanceRateLimiter(2, 60, $pool, static function () use (&$now): float {
            return $now;
        });
        $ip = '198.51.100.7';

        self::assertTrue($limiter->allow($ip), 'hit at t0');
        $now = 1_059.0;
        self::assertTrue($limiter->allow($ip), 'hit at t0 + 59s');
        $now = 1_059.5;
        self::assertFalse($limiter->allow($ip), 't0 and t0+59s count TOGETHER');
        $now = 1_061.0;
        self::assertTrue($limiter->allow($ip), 't0 has slid out');
        $now = 1_061.5;
        self::assertFalse($limiter->allow($ip), 'sliding window fills the cap; a fixed window would have allowed this');
    }

    public function testDisabledLimiterNeverRejects(): void
    {
        $controller = $this->controller(null);
        for ($i = 0; $i < 10; $i++) {
            self::assertSame(200, $this->post($controller, '198.51.100.7'));
        }
    }

    public function testRateLimitedRequestsDoNotStoreChallenges(): void
    {
        $limiter = new IssuanceRateLimiter(1, 60);
        $storage = new class(new ArrayStorage()) implements \KiwiCaptcha\StorageInterface {
            public int $stores = 0;

            public function __construct(private readonly \KiwiCaptcha\StorageInterface $inner)
            {
            }

            public function store(\KiwiCaptcha\ChallengeRecord $record): void
            {
                $this->stores++;
                $this->inner->store($record);
            }

            public function find(string $nonce): ?\KiwiCaptcha\ChallengeRecord
            {
                return $this->inner->find($nonce);
            }

            public function consume(string $nonce): ?\KiwiCaptcha\ChallengeRecord
            {
                return $this->inner->consume($nonce);
            }

            public function delete(string $nonce): void
            {
                $this->inner->delete($nonce);
            }
        };
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $controller = new ChallengeController($issuer, $limiter);

        self::assertSame(200, $this->post($controller, '198.51.100.7'));
        self::assertSame(429, $this->post($controller, '198.51.100.7'));

        self::assertSame(1, $storage->stores, 'the rate-limited request must never reach the issuer');
    }
}
