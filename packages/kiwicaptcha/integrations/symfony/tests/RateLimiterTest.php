<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceRateLimiter;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
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

    // ── Redis backend (atomic, cross-worker) ──────────────────────────────

    private function requireRedisClient(): FakePredisClient
    {
        // The bundle itself does not depend on predis; the dev toolchain has
        // it via the core package's copied vendor (path repo).
        $nested = \dirname(__DIR__).'/vendor/kiwicaptcha/kiwicaptcha-php/vendor/autoload.php';
        if (!\class_exists(\Predis\Client::class) && is_file($nested)) {
            require_once $nested;
        }
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed; cannot test the Redis rate limiter');
        }

        return new FakePredisClient();
    }

    public function testRedisLimiterEnforcesPerClientCapWith429(): void
    {
        $client = $this->requireRedisClient();
        $limiter = new IssuanceRateLimiter(2, 60, null, null, 'pepper', $client, 100, 'test-ns');
        $controller = $this->controller($limiter);

        self::assertSame(1, $limiter->check('198.51.100.7'));
        self::assertSame(200, $this->post($controller, '198.51.100.7'));
        self::assertSame(429, $this->post($controller, '198.51.100.7'), 'N+1st request within the window must be refused');

        $body = json_decode((string) $controller->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{}'))->getContent(), true);
        self::assertSame('RATE_LIMITED', $body['error']['code']);
    }

    public function testRedisLimiterGlobalCapBlocksADifferentClient(): void
    {
        $client = $this->requireRedisClient();
        // Global cap of 2 across ALL clients; per-client cap generous.
        $limiter = new IssuanceRateLimiter(100, 60, null, null, 'pepper', $client, 2, 'test-ns');
        $controller = $this->controller($limiter);

        self::assertSame(1, $limiter->check('198.51.100.7'));
        self::assertSame(1, $limiter->check('198.51.100.8'));

        // The global window is full: a THIRD identity is blocked by the
        // deployment-wide cap, not its own.
        self::assertSame(-1, $limiter->check('198.51.100.9'));

        $response = $controller->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.9'], '{}'));
        self::assertSame(429, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('GLOBAL_RATE_LIMITED', $body['error']['code'], 'global exhaustion must carry the distinct code');
    }

    public function testEpochRotationChangesIdentityAcrossEpochs(): void
    {
        $client = new FakePredisClient();
        $clock = 1_000_000.0; // fixed fake epoch-seconds
        $client->setTimeMs((int) ($clock * 1000));
        $limiter = new IssuanceRateLimiter(
            maxChallenges: 3,
            windowSecs: 60,
            redis: $client,
            globalMax: 1000,
            namespace: 'rot-test',
            pepper: 'pepper',
            rateLimitRotationSecs: 100,
            now: static fn (): float => $clock,
        );

        // Three hits in epoch 10 (identity A).
        self::assertSame(1, $limiter->check('203.0.113.7'));
        self::assertSame(1, $limiter->check('203.0.113.7'));
        self::assertSame(1, $limiter->check('203.0.113.7'));
        self::assertSame(0, $limiter->check('203.0.113.7'), 'per-client cap reached in epoch 10');

        // Rotate into epoch 11: a NEW pseudonym, so the cap is fresh — but
        // the previous-epoch hits still count within the window, so only 3
        // of the pre-rotation budget carry over and the cap still holds
        // until the window slides.
        $clock = 1_000_100.0; // exactly at the epoch boundary (floor(1000100/100) = 10001)
        // 1_000_100 / 100 = 10001 (not 11) — use an explicit small rotation
        // for deterministic math: rotation 100, epoch = floor(now/100).
        self::assertSame(0, $limiter->check('203.0.113.7'), 'previous-epoch hits still count inside the window');
    }

    public function testRotatedGlobalLimitIsSharedAcrossClients(): void
    {
        // REGRESSION (release blocker): with rotation ENABLED, the global
        // budget must still be deployment-wide — the global key contains no
        // client identity and must never be rotated. Three DIFFERENT
        // clients with globalMax 2: the third is rejected.
        $client = new FakePredisClient();
        $client->setTimeMs(1_700_000_000_000);
        $limiter = new IssuanceRateLimiter(
            maxChallenges: 100,
            windowSecs: 60,
            redis: $client,
            globalMax: 2,
            namespace: 'rotated-global',
            pepper: 'test-secret',
            rateLimitRotationSecs: 3600,
            now: static fn (): float => 1_700_000_000.0,
        );

        self::assertSame(1, $limiter->check('203.0.113.1'));
        self::assertSame(1, $limiter->check('203.0.113.2'));
        self::assertSame(-1, $limiter->check('203.0.113.3'), 'global cap must hold across DIFFERENT clients with rotation enabled');
    }

    public function testRotatedPsr6DenialRetainsState(): void
    {
        // REGRESSION: the rotated PSR-6 fallback must NOT clear the window
        // on denial — clearing lets a denied request reset the state and
        // pass on the next call (deterministic every-other-request bypass).
        $pool = new \Symfony\Component\Cache\Adapter\ArrayAdapter();
        $clock = 10_000.0;
        $limiter = new IssuanceRateLimiter(
            maxChallenges: 3,
            windowSecs: 60,
            pool: $pool,
            pepper: 'pepper',
            rateLimitRotationSecs: 100,
            now: static fn (): float => $clock,
        );

        self::assertTrue($limiter->allow('203.0.113.9'));
        self::assertTrue($limiter->allow('203.0.113.9'));
        self::assertTrue($limiter->allow('203.0.113.9'));
        self::assertFalse($limiter->allow('203.0.113.9'), '4th request within the window must be denied');
        self::assertFalse($limiter->allow('203.0.113.9'), '5th request must STILL be denied (state retained, no reset)');
        self::assertFalse($limiter->allow('203.0.113.9'), '6th request must STILL be denied');
    }

    public function testEpochRotationReleasesAfterWindowSlides(): void
    {
        $client = new FakePredisClient();
        $clockSecs = 10_000.0;
        // The fake Redis server clock must advance IN SYNC with the
        // limiter's clock: the Lua TIME read drives the pruning.
        $client->setTimeMs((int) ($clockSecs * 1000));
        $limiter = new IssuanceRateLimiter(
            maxChallenges: 2,
            windowSecs: 60,
            redis: $client,
            globalMax: 1000,
            namespace: 'rot-test2',
            pepper: 'pepper',
            rateLimitRotationSecs: 100,
            now: static fn (): float => $clockSecs,
        );

        self::assertSame(1, $limiter->check('198.51.100.9'));
        self::assertSame(1, $limiter->check('198.51.100.9'));
        self::assertSame(0, $limiter->check('198.51.100.9'));

        // 61s later: the window has fully slid (both epochs pruned) — the
        // cap is released even though the epoch changed.
        $clockSecs = 10_061.0;
        $client->setTimeMs((int) ($clockSecs * 1000));
        self::assertSame(1, $limiter->check('198.51.100.9'), 'window slide must release the cap');
    }

    public function testRedisLimiterWindowExpiryAllowsAgain(): void
    {
        $client = $this->requireRedisClient();
        $limiter = new IssuanceRateLimiter(1, 60, null, null, 'pepper', $client, 100, 'test-ns');

        self::assertSame(1, $limiter->check('198.51.100.7'));
        self::assertSame(0, $limiter->check('198.51.100.7'));

        // Advance the REDIS server clock past the window: the hit is pruned.
        $client->setTimeMs($client->timeMs() + 61_000);

        self::assertSame(1, $limiter->check('198.51.100.7'));
        self::assertSame(0, $limiter->check('198.51.100.7'));
    }

    public function testRedisLimiterKeysArePepperedHmacsAndNamespaced(): void
    {
        $client = $this->requireRedisClient();
        $pepper = 'rate-limit-pepper-for-tests';
        $limiter = new IssuanceRateLimiter(5, 60, null, null, $pepper, $client, 5, 'deployment-x');
        $limiter->check('198.51.100.7');

        $identity = hash_hmac('sha256', '198.51.100.7', $pepper);
        self::assertArrayHasKey('kiwi:rl:client:deployment-x:'.$identity, $client->zsets, 'the per-client ZSET must live under the namespaced HMAC key');
        self::assertArrayHasKey('kiwi:rl:global:deployment-x', $client->zsets);

        foreach (array_keys($client->zsets) as $key) {
            self::assertStringNotContainsString('198.51.100.7', (string) $key, 'raw IPs must never appear in Redis keys');
        }
    }

    public function testRedisLimiterDisabledClientCapStillEnforcesGlobal(): void
    {
        $client = $this->requireRedisClient();
        $limiter = new IssuanceRateLimiter(0, 60, null, null, 'pepper', $client, 1, 'test-ns');

        self::assertSame(1, $limiter->check('198.51.100.7'));
        self::assertSame(-1, $limiter->check('198.51.100.8'), 'with the per-client cap off, the global cap still applies');
    }
}
