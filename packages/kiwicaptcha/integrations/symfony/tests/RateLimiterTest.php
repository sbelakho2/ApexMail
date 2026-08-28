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
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JsonRequest;
use Symfony\Component\HttpFoundation\Request;

/**
 * Per-IP issuance rate limiting: a sliding window per client IP (in-memory
 * single-process by default, or a psr-6 pool for shared multi-process state),
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
        $response = $controller->challenge(JsonRequest::create(
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

        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{}'));
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

    public function testRawIpIsNeverUsedAsAKeyAndKeyStaysWithinPsr6Length(): void
    {
        $pool = new ArrayAdapter();
        $pepper = 'rate-limit-pepper-for-tests';
        $limiter = new IssuanceRateLimiter(1, 60, $pool, null, $pepper);
        $limiter->allow('198.51.100.7');

        // The shared cache key is 'kr_' + 60 hex of the peppered HMAC — 63
        // chars total, within the 64-character psr-6 portability floor (the
        // previous 'kiwi_rate_' + 64 hex = 74 chars exceeded it).
        foreach (array_keys($pool->getValues()) as $key) {
            self::assertMatchesRegularExpression(
                '/^kr_[0-9a-f]{60}$/',
                (string) $key,
                'rate-limit keys must be kr_ + 60 hex (63 chars, PSR-6 portable)',
            );
            self::assertLessThanOrEqual(64, strlen((string) $key), 'rate-limit keys must fit the PSR-6 64-char floor');
            self::assertStringNotContainsString('198.51.100.7', (string) $key, 'raw IPs must never appear in stored keys');
        }
    }

    public function testCanonicalIpPseudonymUnifiesEquivalentSpellings(): void
    {
        // The pseudonym is derived from canonical IP bytes: two textual
        // spellings of the same address must produce the same HMAC identity,
        // and IPv4-mapped IPv6 must equal the plain IPv4 form.
        $pool = new ArrayAdapter();
        $limiter = new IssuanceRateLimiter(1, 60, $pool, null, 'pepper');

        $limiter->allow('2001:db8::1');
        $keys1 = array_keys($pool->getValues());
        $pool->clear();

        $limiter->allow('2001:0db8:0:0:0:0:0:1');
        $keys2 = array_keys($pool->getValues());

        self::assertSame($keys1, $keys2, 'equivalent IPv6 spellings must map to the same pseudonym');

        $pool->clear();
        $limiter->allow('::ffff:192.168.1.5');
        $mapped = array_keys($pool->getValues());
        $pool->clear();
        $limiter->allow('192.168.1.5');
        self::assertSame($mapped, array_keys($pool->getValues()), 'IPv4-mapped IPv6 must equal the plain IPv4 pseudonym');
    }

    public function testGlobalOnlyModeCreatesNoClientKeys(): void
    {
        // maxChallenges = 0 disables the per-client control: with Redis, only
        // the deployment-global zset may exist — no client pseudonym at all.
        $client = new FakePredisClient();
        $limiter = new IssuanceRateLimiter(0, 60, redis: $client, globalMax: 2, namespace: 'global-only', pepper: 'p');
        self::assertSame(1, $limiter->check('203.0.113.1'));
        self::assertSame(1, $limiter->check('203.0.113.2'));
        self::assertSame(-1, $limiter->check('203.0.113.3'));

        foreach (array_keys($client->zsets) as $key) {
            self::assertStringStartsWith('{kiwi:rl:', (string) $key, 'no client key may exist in global-only mode');
            self::assertStringNotContainsString('client', (string) $key);
        }
    }

    public function testRotationShorterThanWindowIsRejected(): void
    {
        // A rotation < window would drop live hits from epochs older than
        // (current - 1) from the two-epoch accounting.
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('rate_limit_rotation_secs');
        new IssuanceRateLimiter(10, 120, rateLimitRotationSecs: 30);
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
        // The psr-6 path must implement a true sliding window too — the
        // [window_start, hits] fixed bucket would allow boundary bursts to
        // double the rate.
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

                        public function consumedState(string $nonce): ?\KiwiCaptcha\ConsumedRecord
            {
                return null;
            }

public function consume(string $nonce): ?\KiwiCaptcha\ConsumedRecord
            {
                return $this->inner->consume($nonce);
            }

            public function delete(string $nonce): void
            {
                $this->inner->delete($nonce);
            }

            public function commitResult(string $nonce, bool $valid, ?string $binding): bool
            {
                return $this->inner->commitResult($nonce, $valid, $binding);
            }
        };
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $controller = new ChallengeController($issuer, $limiter);

        self::assertSame(200, $this->post($controller, '198.51.100.7'));
        self::assertSame(429, $this->post($controller, '198.51.100.7'));

        self::assertSame(1, $storage->stores, 'the rate-limited request must never reach the issuer');
    }

    // ── Non-Redis global window (per-process / shared PSR-6) ─────────────

    public function testInMemoryGlobalCapBlocksDifferentClients(): void
    {
        // THE audit scenario: without Redis, a distributed attacker rotating
        // through many IPs must not escape the deployment-global cap — the
        // fallback window is per-process, but the cap still applies.
        $clock = 10_000.0;
        $limiter = new IssuanceRateLimiter(100, 60, null, static function () use (&$clock): float {
            return $clock;
        }, 'pepper', null, 2);

        self::assertSame(1, $limiter->check('198.51.100.7'), 'IP A admitted');
        self::assertSame(1, $limiter->check('198.51.100.8'), 'IP B admitted');
        self::assertSame(-1, $limiter->check('198.51.100.9'), 'IP C is denied by the global cap (-1), not the per-client cap');
        self::assertSame(-1, $limiter->check('198.51.100.10'), 'denied requests do not reset the window');

        // Per-client accounting is unchanged: one IP alone exhausts its own
        // cap and gets 0, not -1.
        $clock = 10_000.0;
        $perClient = new IssuanceRateLimiter(1, 60, null, static function () use (&$clock): float {
            return $clock;
        }, 'pepper', null, 2);
        self::assertSame(1, $perClient->check('198.51.100.7'));
        self::assertSame(0, $perClient->check('198.51.100.7'), 'per-client deny stays 0');
    }

    public function testInMemoryGlobalWindowSlides(): void
    {
        $clock = 10_000.0;
        $limiter = new IssuanceRateLimiter(100, 60, null, static function () use (&$clock): float {
            return $clock;
        }, 'pepper', null, 2);

        self::assertSame(1, $limiter->check('198.51.100.1'));
        self::assertSame(1, $limiter->check('198.51.100.2'));
        self::assertSame(-1, $limiter->check('198.51.100.3'));

        $clock += 61.0; // both admissions slid out of the window
        self::assertSame(1, $limiter->check('198.51.100.3'), 'the global window slid: the cap is free again');
        self::assertSame(1, $limiter->check('198.51.100.4'), 'a second admission still fits (cap 2)');
        self::assertSame(-1, $limiter->check('198.51.100.5'), 'the cap is full again');
    }

    public function testPsr6SharedGlobalCapBlocksAcrossClients(): void
    {
        $pool = new ArrayAdapter();
        $clock = 10_000.0;
        $limiter = new IssuanceRateLimiter(100, 60, $pool, static function () use (&$clock): float {
            return $clock;
        }, 'pepper', null, 2);

        self::assertSame(1, $limiter->check('198.51.100.1'));
        self::assertSame(1, $limiter->check('198.51.100.2'));
        self::assertSame(-1, $limiter->check('198.51.100.3'), 'the shared global window denies the third identity');
        self::assertSame(-1, $limiter->check('198.51.100.4'), 'denied requests do not reset the shared window');

        // The global window is exactly ONE dedicated item, distinct from
        // the per-client kr_ + 60-hex keys.
        $keys = array_keys($pool->getValues());
        self::assertContains('kr_global', $keys, 'the global window must be one dedicated shared item');
        foreach ($keys as $key) {
            if ($key === 'kr_global') {
                continue;
            }
            self::assertMatchesRegularExpression('/^kr_[0-9a-f]{60}$/', (string) $key, 'per-client keys keep the kr_ + 60-hex shape');
        }
        // Best-effort cross-worker semantics (concurrent readers can race
        // the non-atomic read-modify-write) are documented in the class
        // docblock — a generic PSR-6 pool cannot be tested for atomicity.
    }

    public function testPsr6SharedGlobalWindowSlides(): void
    {
        $pool = new ArrayAdapter();
        $clock = 10_000.0;
        $limiter = new IssuanceRateLimiter(100, 60, $pool, static function () use (&$clock): float {
            return $clock;
        }, 'pepper', null, 2);

        self::assertSame(1, $limiter->check('198.51.100.1'));
        self::assertSame(1, $limiter->check('198.51.100.2'));
        self::assertSame(-1, $limiter->check('198.51.100.3'));

        $clock += 61.0;
        self::assertSame(1, $limiter->check('198.51.100.3'), 'the shared global window slid: the cap is free');
    }

    public function testInMemoryGlobalOnlyModeEnforcesGlobalWindow(): void
    {
        // maxChallenges = 0, redis = null: the unpatched behavior allowed
        // unconditionally (the audit bug) — the global-only budget must
        // now be enforced as a real window.
        $clock = 10_000.0;
        $limiter = new IssuanceRateLimiter(0, 60, null, static function () use (&$clock): float {
            return $clock;
        }, 'pepper', null, 2);

        self::assertSame(1, $limiter->check('198.51.100.1'));
        self::assertSame(1, $limiter->check('198.51.100.2'));
        self::assertSame(-1, $limiter->check('198.51.100.3'), 'global-only: the third request hits the global cap');
        self::assertSame(-1, $limiter->check('198.51.100.4'), 'denied requests do not reset the window');

        $clock += 61.0;
        self::assertSame(1, $limiter->check('198.51.100.5'), 'window slide re-allows');
    }

    public function testPsr6GlobalOnlyModeWritesOnlyTheSharedGlobalItem(): void
    {
        $pool = new ArrayAdapter();
        $clock = 10_000.0;
        $limiter = new IssuanceRateLimiter(0, 60, $pool, static function () use (&$clock): float {
            return $clock;
        }, 'pepper', null, 2);

        self::assertSame(1, $limiter->check('198.51.100.1'));
        self::assertSame(1, $limiter->check('198.51.100.2'));
        self::assertSame(-1, $limiter->check('198.51.100.3'));

        self::assertSame(['kr_global'], array_keys($pool->getValues()), 'global-only mode must write exactly one shared global item and no client keys');
    }

    public function testGlobalOnlyModeIgnoresRotation(): void
    {
        // Rotation is a per-client pseudonym concern; with the per-client
        // limit disabled the global window must still be enforced across
        // the rotation boundary (rotation-independent by design). Rotation
        // equals the window (allowed): the boundary at t=10_020 falls
        // inside the window of the t=10_000 admission.
        $clock = 10_000.0;
        $limiter = new IssuanceRateLimiter(
            maxChallenges: 0,
            windowSecs: 60,
            now: static function () use (&$clock): float {
                return $clock;
            },
            pepper: 'pepper',
            globalMax: 1,
            rateLimitRotationSecs: 60,
        );

        self::assertSame(1, $limiter->check('203.0.113.1'), 'the first admission fills the global cap');
        $clock = 10_021.0; // rotated into the next epoch: floor(10021/60) = 167
        self::assertSame(-1, $limiter->check('203.0.113.2'), 'rotation must not reset the global window');
        $clock = 10_061.0; // the window slid past the admission
        self::assertSame(1, $limiter->check('203.0.113.2'), 'window slide re-allows');
    }

    public function testRotatedInMemoryGlobalCapIsSharedAcrossEpochs(): void
    {
        // With rotation enabled (no Redis), the global budget must stay
        // deployment-wide: rotating the client pseudonyms must NOT reset
        // the global window. Rotation equals the window (allowed): the
        // boundary at t=10_020 falls inside the window of the two
        // t=10_000 admissions.
        $clock = 10_000.0;
        $limiter = new IssuanceRateLimiter(
            maxChallenges: 100,
            windowSecs: 60,
            now: static function () use (&$clock): float {
                return $clock;
            },
            pepper: 'pepper',
            globalMax: 2,
            rateLimitRotationSecs: 60,
        );

        self::assertSame(1, $limiter->check('203.0.113.1'), 'epoch 166 admission');
        self::assertSame(1, $limiter->check('203.0.113.2'));

        // Cross the rotation boundary (epoch 167): the client pseudonyms
        // rotate, but the two global admissions still fill the cap.
        $clock = 10_021.0;
        self::assertSame(-1, $limiter->check('203.0.113.3'), 'rotation must not reset the global window');

        // The window slides past both admissions: the cap is free.
        $clock = 10_061.0;
        $slid = $limiter->check('203.0.113.3');
        self::assertSame(1, $slid, 'the global window slid past the rotation boundary');
    }

    public function testRotatedPsr6GlobalCapIsSharedAcrossEpochs(): void
    {
        $pool = new ArrayAdapter();
        $clock = 10_000.0;
        $limiter = new IssuanceRateLimiter(
            maxChallenges: 100,
            windowSecs: 60,
            pool: $pool,
            now: static function () use (&$clock): float {
                return $clock;
            },
            pepper: 'pepper',
            globalMax: 2,
            rateLimitRotationSecs: 60,
        );

        self::assertSame(1, $limiter->check('203.0.113.1'));
        self::assertSame(1, $limiter->check('203.0.113.2'));
        $clock = 10_021.0; // rotated into epoch 167
        self::assertSame(-1, $limiter->check('203.0.113.3'), 'the shared global window survives rotation');
        $clock = 10_061.0;
        self::assertSame(1, $limiter->check('203.0.113.3'));
    }

    public function testNoGlobalCapNeverConsultsTheGlobalWindow(): void
    {
        // Regression: globalMax = 0 (the default) must leave the non-Redis
        // behavior exactly as before — many different clients are all
        // admitted and no global state is ever kept.
        $clock = 10_000.0;
        $limiter = new IssuanceRateLimiter(100, 60, null, static function () use (&$clock): float {
            return $clock;
        }, 'pepper', null, 0);
        for ($i = 1; $i <= 5; $i++) {
            self::assertSame(1, $limiter->check('198.51.100.'.$i));
        }

        $pool = new ArrayAdapter();
        $limiter = new IssuanceRateLimiter(100, 60, $pool, static function () use (&$clock): float {
            return $clock;
        }, 'pepper', null, 0);
        for ($i = 1; $i <= 5; $i++) {
            self::assertSame(1, $limiter->check('198.51.100.'.$i));
        }
        self::assertArrayNotHasKey('kr_global', $pool->getValues(), 'no global cap -> no global item is ever written');
    }

    // ── Transactional fallback decisions ─────────────────────────────────

    public function testInMemoryGlobalSaturationDoesNotConsumeTheVictimAllowance(): void
    {
        // The hardening scenario: the former per-client-then-global
        // fallback appended the victim's hit before the global check
        // denied the request, so N denied attempts during global
        // saturation consumed N of the victim's personal allowance. The
        // combined decision must deny without writing anything.
        $clock = 10_000.0;
        $limiter = new IssuanceRateLimiter(2, 60, null, static function () use (&$clock): float {
            return $clock;
        }, 'pepper', null, 2);

        self::assertSame(1, $limiter->check('198.51.100.1'), 'attacker A admission');
        self::assertSame(1, $limiter->check('198.51.100.2'), 'attacker B admission fills the global cap');

        $clock = 10_040.0; // still inside the window of the two admissions
        $victim = '198.51.100.99';
        for ($i = 0; $i < 5; $i++) {
            self::assertSame(-1, $limiter->check($victim), 'the victim is denied by the GLOBAL cap, not by their own');
        }
        self::assertSame(-1, $limiter->check('198.51.100.3'), 'the global window is unchanged by the denied attempts: still full');

        // The global window expires (the t=10000 admissions slide out at
        // cutoff 10001), but the victim's would-be personal hits (at
        // 10040) would still be inside the window — so the full allowance
        // proves no personal hit was ever written.
        $clock = 10_061.0;
        self::assertSame(1, $limiter->check($victim), 'the victim still holds their FULL per-client allowance (2)');
        self::assertSame(1, $limiter->check($victim), 'a second victim admission still fits the personal cap');
        self::assertSame(0, $limiter->check($victim), 'the third victim request hits the per-client cap: the denied attempts consumed nothing');
    }

    public function testPsr6GlobalSaturationDoesNotConsumeTheVictimAllowance(): void
    {
        $pool = new ArrayAdapter();
        $clock = 10_000.0;
        $limiter = new IssuanceRateLimiter(2, 60, $pool, static function () use (&$clock): float {
            return $clock;
        }, 'pepper', null, 2);

        self::assertSame(1, $limiter->check('198.51.100.1'));
        self::assertSame(1, $limiter->check('198.51.100.2'));

        $clock = 10_040.0;
        $victim = '198.51.100.99';
        for ($i = 0; $i < 5; $i++) {
            self::assertSame(-1, $limiter->check($victim), 'the victim is denied by the shared GLOBAL cap');
        }

        // The denied attempts must write nothing: no per-client item for
        // the victim (the pool holds exactly the two admitted clients
        // plus the one global item) and no global hit. Read misses leave
        // null entries, so filter them out before counting.
        $values = array_filter($pool->getValues(), static fn ($v): bool => $v !== null);
        self::assertCount(3, $values, 'denied attempts must not create a victim client item');
        self::assertCount(2, unserialize($values['kr_global'])['t'], 'denied attempts must not add a global hit');
        self::assertSame(-1, $limiter->check('198.51.100.3'), 'the shared global window is still full');

        $clock = 10_061.0;
        self::assertSame(1, $limiter->check($victim), 'the victim still holds their FULL per-client allowance');
        self::assertSame(1, $limiter->check($victim));
        self::assertSame(0, $limiter->check($victim), 'the denied attempts consumed nothing of the personal window');
    }

    public function testRotatedInMemoryGlobalSaturationDoesNotConsumeTheVictimAllowance(): void
    {
        $clock = 10_000.0;
        $limiter = new IssuanceRateLimiter(
            maxChallenges: 2,
            windowSecs: 60,
            now: static function () use (&$clock): float {
                return $clock;
            },
            pepper: 'pepper',
            globalMax: 2,
            rateLimitRotationSecs: 60,
        );

        self::assertSame(1, $limiter->check('198.51.100.1'));
        self::assertSame(1, $limiter->check('198.51.100.2'));

        // 10040 is epoch 167 while the admissions sit in epoch 166: the
        // victim's would-be hits would land in the current-epoch
        // pseudonym and survive until 10100 — well past the global-window
        // expiry at 10060.
        $clock = 10_040.0;
        $victim = '198.51.100.99';
        for ($i = 0; $i < 5; $i++) {
            self::assertSame(-1, $limiter->check($victim), 'the victim is denied by the global cap across the rotation boundary');
        }
        self::assertSame(-1, $limiter->check('198.51.100.3'), 'the global window survives the denied attempts');

        $clock = 10_061.0;
        self::assertSame(1, $limiter->check($victim), 'the victim still holds their FULL per-client allowance: the epoch-167 hits were never written');
        self::assertSame(1, $limiter->check($victim));
        self::assertSame(0, $limiter->check($victim));
    }

    public function testRotatedPsr6GlobalSaturationDoesNotConsumeTheVictimAllowance(): void
    {
        $pool = new ArrayAdapter();
        $clock = 10_000.0;
        $limiter = new IssuanceRateLimiter(
            maxChallenges: 2,
            windowSecs: 60,
            pool: $pool,
            now: static function () use (&$clock): float {
                return $clock;
            },
            pepper: 'pepper',
            globalMax: 2,
            rateLimitRotationSecs: 60,
        );

        self::assertSame(1, $limiter->check('198.51.100.1'));
        self::assertSame(1, $limiter->check('198.51.100.2'));

        $clock = 10_040.0;
        $victim = '198.51.100.99';
        for ($i = 0; $i < 5; $i++) {
            self::assertSame(-1, $limiter->check($victim), 'the victim is denied by the shared global cap across the rotation boundary');
        }

        $values = array_filter($pool->getValues(), static fn ($v): bool => $v !== null);
        self::assertCount(3, $values, 'denied attempts must not create a victim client item in either epoch');
        self::assertCount(2, unserialize($values['kr_global'])['t'], 'denied attempts must not add a global hit');
        self::assertSame(-1, $limiter->check('198.51.100.3'), 'the shared global window is still full');

        $clock = 10_061.0;
        self::assertSame(1, $limiter->check($victim), 'the victim still holds their FULL per-client allowance');
        self::assertSame(1, $limiter->check($victim));
        self::assertSame(0, $limiter->check($victim));
    }

    public function testHitAtExactCutoffIsPrunedOnTheNextCheck(): void
    {
        // Redis prunes timestamps <= now - window (inclusive); the
        // fallback prune predicates must retain only ts > cutoff (strictly
        // greater), so an admission at exactly now - windowSecs has slid
        // out at the boundary instant. Per-client path, local and PSR-6.
        $clock = 10_000.0;
        $local = new IssuanceRateLimiter(1, 60, null, static function () use (&$clock): float {
            return $clock;
        }, 'pepper');
        self::assertSame(1, $local->check('198.51.100.7'), 'hit at t');
        $clock = 10_060.0; // exactly t + window: cutoff == t
        self::assertSame(1, $local->check('198.51.100.7'), 'the hit at the exact cutoff is pruned, matching the Redis inclusive prune');
        self::assertSame(0, $local->check('198.51.100.7'), 'the fresh hit refills the cap');

        $pool = new ArrayAdapter();
        $clock = 10_000.0;
        $shared = new IssuanceRateLimiter(1, 60, $pool, static function () use (&$clock): float {
            return $clock;
        }, 'pepper');
        self::assertSame(1, $shared->check('198.51.100.7'));
        $clock = 10_060.0;
        self::assertSame(1, $shared->check('198.51.100.7'), 'PSR-6: the exact-cutoff hit is pruned');
        self::assertSame(0, $shared->check('198.51.100.7'));
    }

    public function testGlobalHitAtExactCutoffIsPrunedOnTheNextCheck(): void
    {
        $clock = 10_000.0;
        $local = new IssuanceRateLimiter(100, 60, null, static function () use (&$clock): float {
            return $clock;
        }, 'pepper', null, 1);
        self::assertSame(1, $local->check('198.51.100.1'), 'the admission fills the global cap');
        $clock = 10_060.0;
        self::assertSame(1, $local->check('198.51.100.2'), 'the exact-cutoff global hit is pruned');
        self::assertSame(-1, $local->check('198.51.100.3'), 'the fresh global hit refills the cap');

        $pool = new ArrayAdapter();
        $clock = 10_000.0;
        $shared = new IssuanceRateLimiter(100, 60, $pool, static function () use (&$clock): float {
            return $clock;
        }, 'pepper', null, 1);
        self::assertSame(1, $shared->check('198.51.100.1'));
        $clock = 10_060.0;
        self::assertSame(1, $shared->check('198.51.100.2'), 'PSR-6: the exact-cutoff global hit is pruned');
        self::assertSame(-1, $shared->check('198.51.100.3'));
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

        $body = json_decode((string) $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{}'))->getContent(), true);
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

        // The global window is full: a third identity is blocked by the
        // deployment-wide cap, not its own.
        self::assertSame(-1, $limiter->check('198.51.100.9'));

        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.9'], '{}'));
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
        $clock = 1_000_100.0; // exactly at the epoch boundary: floor(1000100/100) = 10001
        // 1_000_100 / 100 = 10001 (not 11) — use an explicit small rotation
        // for deterministic math: rotation 100, epoch = floor(now/100).
        self::assertSame(0, $limiter->check('203.0.113.7'), 'previous-epoch hits still count inside the window');
    }

    public function testRotatedGlobalLimitIsSharedAcrossClients(): void
    {
        // regression (release blocker): with rotation enabled, the global
        // budget must still be deployment-wide — the global key contains no
        // client identity and must never be rotated. Three different
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
        // regression: the rotated psr-6 fallback must NOT clear the window
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
        // The fake Redis server clock must advance IN sync with the
        // limiter's clock: the Lua time read drives the pruning.
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

        // Advance the redis server clock past the window: the hit is pruned.
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

        // The identity is the peppered HMAC of the canonical IP bytes
        // (inet_pton with IPv4-mapped normalization) — the same
        // canonicalization used for challenge binding.
        $identity = hash_hmac('sha256', \KiwiCaptcha\Issuer::canonicalIpFamily('198.51.100.7'), $pepper);
        self::assertArrayHasKey('{kiwi:rl:deployment-x}:client:'.$identity, $client->zsets, 'the per-client ZSET must live under the namespaced canonical-HMAC key');
        self::assertArrayHasKey('{kiwi:rl:deployment-x}:global', $client->zsets);

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

    public function testExactMsGlobalCardinalityStaysBoundedByTheGlobalCap(): void
    {
        // The deployment-global limiter stores one exact-time member per
        // admitted request: ten thousand admissions within one window must
        // never grow the global ZSET beyond the global cap (the 1001st
        // admission is refused), and every member carries its exact
        // admission millisecond as the score.
        $client = new FakePredisClient();
        $clock = 1_000_000_000.0; // epoch seconds
        $client->setTimeMs($clock * 1000);
        $limiter = new IssuanceRateLimiter(
            maxChallenges: 0,
            windowSecs: 60,
            redis: $client,
            globalMax: 1000,
            namespace: 'bounded-global',
            pepper: 'pepper',
            now: static fn (): float => $clock,
        );

        $allowed = 0;
        for ($i = 0; $i < 10_000; $i++) {
            // Distinct exact-ms admissions inside one window: the 1001st
            // must be refused — the member count is bounded by the cap,
            // never by the window or the request volume.
            $client->setTimeMs($clock * 1000 + $i);
            if ($limiter->check('198.51.100.'.($i % 250 + 1)) === 1) {
                $allowed++;
            }
        }

        $globalKey = '{kiwi:rl:bounded-global}:global';
        self::assertArrayHasKey($globalKey, $client->zsets, 'the global key must exist');
        self::assertSame(1000, $allowed, 'exactly the cap\'s worth of admissions are allowed');
        self::assertSame(1000, $client->zcard($globalKey), 'the global ZSET never exceeds the cap — one exact-time member per admission');
        self::assertSame(9_000, 10_000 - $allowed, 'every admission beyond the cap is refused');
        foreach ($client->zsets[$globalKey] as $member => $score) {
            self::assertGreaterThanOrEqual($clock * 1000, $score, 'every member is scored at its exact admission ms');
            self::assertLessThanOrEqual($clock * 1000 + 999, $score, 'every member is scored at its exact admission ms');
        }
    }

    public function testExactMsGlobalBoundaryRequestIsCountedAtTheCutoffEdge(): void
    {
        // THE adversarial exact-ms boundary: a request at T fills the
        // global cap. A request at T + 900ms (still inside the window)
        // must be counted — the member's timestamp is exact, so a
        // millisecond-precision window cannot slip a request past a
        // second-granular bucket. A request at T + W + 100ms (window plus
        // 100ms) must NOT be counted — the member has slid out at
        // millisecond precision.
        $client = new FakePredisClient();
        $t0Ms = 1_000_000_000_500.0; // the exact admission ms (T)
        $client->setTimeMs($t0Ms);
        $limiter = new IssuanceRateLimiter(
            maxChallenges: 0,
            windowSecs: 60,
            redis: $client,
            globalMax: 1,
            namespace: 'exact-boundary-global',
            pepper: 'pepper',
            now: static fn (): float => $t0Ms / 1000,
        );
        self::assertSame(1, $limiter->check('198.51.100.7'), 'the first admission fills the global cap');
        $globalKey = '{kiwi:rl:exact-boundary-global}:global';
        self::assertCount(1, $client->zsets[$globalKey], 'exactly one member exists after the first admission');
        $member = array_key_first($client->zsets[$globalKey]);
        self::assertSame($t0Ms, $client->zsets[$globalKey][$member], 'the member is scored at its exact admission ms');

        // Each probe runs against its own namespace, seeded with exactly
        // the member the limiter wrote (asserted above), so the probe
        // itself never disturbs the state under test: it only observes
        // whether the T request still counts toward the cap.
        $probe = static function (float $atMs, string $namespace, int $expected, string $why) use ($client, $member, $t0Ms): void {
            $key = '{kiwi:rl:'.$namespace.'}:global';
            $client->zsets[$key] = [$member => $t0Ms];
            $client->setTimeMs($atMs);
            $probeLimiter = new IssuanceRateLimiter(
                maxChallenges: 0,
                windowSecs: 60,
                redis: $client,
                globalMax: 1,
                namespace: $namespace,
                pepper: 'pepper',
                now: static fn (): float => $atMs / 1000,
            );
            self::assertSame($expected, $probeLimiter->check('198.51.100.8'), $why);
        };

        // T + 900ms: still inside the window — the exact-ms member is
        // counted and the probe is refused.
        $probe($t0Ms + 900.0, 'exact-edge-in', -1, 'a request 900ms after T is still counted — the exact-ms member is in the window');

        // cutoff - epsilon: still counted.
        $probe($t0Ms + 60_000.0 - 1.0, 'exact-edge-cutoff-min', -1, 'a request at cutoff minus 1ms still counts the T member');

        // cutoff exactly: the member at the exact cutoff has slid out.
        $probe($t0Ms + 60_000.0, 'exact-edge-cutoff', 1, 'a request at the exact cutoff does not count the T member');

        // cutoff + epsilon: out.
        $probe($t0Ms + 60_000.0 + 1.0, 'exact-edge-cutoff-plus', 1, 'a request 1ms past the cutoff does not count the T member');

        // T + W + 100ms (window plus 100ms): out.
        $probe($t0Ms + 60_100.0, 'exact-edge-past', 1, 'a request at T + W + 100ms does not count the T member');
    }

    public function testExactMsGlobalPruneDropsSlidOutMembers(): void
    {
        // A burst of two admissions at T fills the cap; the window then
        // slides past T (the cutoff reaches T exactly): both members are
        // pruned by the same `ZREMRANGEBYSCORE` on the next admission, so
        // the cap is free — no slid-out member lingers.
        $client = new FakePredisClient();
        $clock = 1_000_000_000.0;
        $client->setTimeMs($clock * 1000);
        $limiter = new IssuanceRateLimiter(
            maxChallenges: 0,
            windowSecs: 60,
            redis: $client,
            globalMax: 2,
            namespace: 'exact-burst',
            pepper: 'pepper',
            now: static fn (): float => $clock,
        );
        $globalKey = '{kiwi:rl:exact-burst}:global';
        self::assertSame(1, $limiter->check('198.51.100.1'));
        self::assertSame(1, $limiter->check('198.51.100.2'));
        self::assertSame(2, $client->zcard($globalKey), 'two admissions = two exact-time members');
        self::assertSame(-1, $limiter->check('198.51.100.3'), 'the cap is full while both members are inside the window');

        // The window slides so the cutoff reaches T exactly (exclusive
        // edge): both burst members are pruned and the cap is free.
        $clock = 1_000_000_060.0;
        $client->setTimeMs($clock * 1000);
        self::assertSame(1, $limiter->check('198.51.100.3'), 'both slid-out members are pruned — the cap is free');
        self::assertSame(1, $client->zcard($globalKey), 'the admission leaves exactly its own member');
    }
}
