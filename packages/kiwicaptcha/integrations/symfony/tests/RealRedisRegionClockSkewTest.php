<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor;
use BelConsulting\KiwiCaptchaBundle\Security\RedisAdmissionSemaphore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JsonRequest;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\PartitionedPredisClient;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptcha;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Validator\ConstraintValidatorFactory;
use Symfony\Component\Validator\Validation;

/**
 * Region clock skew and coordinated policy changes against one shared
 * Redis authority.
 *
 * Two admission-gate instances share the server-side lease set. The
 * lease deadline is stamped from Redis TIME, so both regions see the
 * same liveness at any moment. Two security-epoch monitors share the
 * central policy hash with different last-known timestamps. Each region
 * fails closed on a stale policy once its own window elapses. A region
 * whose policy Redis is partitioned refuses to serve once its max-stale
 * window is exceeded.
 *
 * Runs in the real-Redis CI lane, which publishes `KC_REDIS_URL` and
 * `TEST_REDIS_URL` and sets `KIWI_REQUIRE_REAL_REDIS_TESTS=1`; with the
 * flag on, a missing Redis fails the suite instead of skipping.
 */
final class RealRedisRegionClockSkewTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const ISSUED_AT = 1_800_000_000;

    private \Predis\Client $client;

    protected function setUp(): void
    {
        $url = RedisTestUrl::resolve();
        if ($url === null) {
            $this->failIfRealRedisRequired('no KC_REDIS_URL/TEST_REDIS_URL is set');
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis region suite runs in the CI Redis-service lane');
        }
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        try {
            $this->client = new \Predis\Client($url, ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
            $this->client->ping();
        } catch (\Throwable $e) {
            $this->failIfRealRedisRequired('no Redis is reachable at the configured URL');
            self::markTestSkipped('Redis unreachable: '.$e->getMessage());
        }
        $this->client->flushdb();
    }

    /**
     * Fail the suite instead of skipping when the real-Redis CI lane
     * loses its environment.
     */
    private function failIfRealRedisRequired(string $why): void
    {
        $flag = getenv('KIWI_REQUIRE_REAL_REDIS_TESTS');
        if (\is_string($flag) && $flag !== '' && $flag !== '0') {
            self::fail('KIWI_REQUIRE_REAL_REDIS_TESTS is set but '.$why.' — the real-Redis region suite must run in the real-Redis CI lane');
        }
    }

    /**
     * A mutable clock holder for the monitor's nowMs seam.
     */
    private function clockHolder(float $ms): object
    {
        return new class($ms) {
            public float $ms;

            public function __construct(float $ms)
            {
                $this->ms = $ms;
            }

            public function __invoke(): float
            {
                return $this->ms;
            }
        };
    }

    private function tokenFor(\KiwiCaptcha\Challenge $challenge): string
    {
        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            ++$counter;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;

        return SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
    }

    public function testArgonAdmissionLeaseIsServerClockAnchoredAndIdenticalAcrossRegions(): void
    {
        $ns = 'skew-'.bin2hex(random_bytes(4));
        $semA = new RedisAdmissionSemaphore($this->client, 1, $ns, leaseMs: 1000);
        $semB = new RedisAdmissionSemaphore($this->client, 1, $ns, leaseMs: 1000);

        $leaseA = $semA->acquire();
        self::assertIsString($leaseA, 'the first region acquires the only slot');
        self::assertSame(1, $semA->usage(), 'the shared authority reports one live lease');
        self::assertSame(1, $semB->usage(), 'both regions see the same live count');

        // The other region is refused while the lease is live. The lease
        // liveness is decided inside the acquire script on Redis TIME,
        // so a region clock can neither free a held slot nor see one.
        self::assertNull($semB->acquire(), 'the second region is refused while the lease is live');
        self::assertNull($semA->acquire(), 'the first region is refused too');

        // The lease deadline is anchored at the server clock: the
        // sorted-set score equals Redis TIME plus the lease lifetime.
        $time = $this->client->time();
        $score = (float) $this->client->zscore('kiwicaptcha:argon2:leases:'.$ns, $leaseA);
        $serverNowMs = (int) $time[0] * 1000 + (int) ((int) $time[1] / 1000);
        self::assertLessThanOrEqual($serverNowMs + 1000 + 1500, $score, 'the score is the server clock plus the lease lifetime');
        self::assertGreaterThanOrEqual($serverNowMs + 1000 - 1500, $score, 'the score is the server clock plus the lease lifetime');

        // Once Redis TIME passes the deadline, the expired lease is
        // reaped for every region and the second region admits.
        sleep(3);
        $leaseB = $semB->acquire();
        self::assertIsString($leaseB, 'the expired lease frees the slot for the other region');
        $semB->release($leaseB);
        self::assertSame(0, $semA->usage(), 'the release empties the shared lease set');
    }

    public function testCoordinatedEpochBumpFailsClosedAcrossTwoRegionsOnSharedRedis(): void
    {
        $ns = 'epoch-'.bin2hex(random_bytes(4));
        $storage = new RedisStorage($this->client, 'epoch-'.$ns.'-');
        $issuer1 = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0, policyVersion: 1), $storage, now: static fn (): int => self::ISSUED_AT);
        $oldTokenA = $this->tokenFor($issuer1->issue('login', '198.51.100.7'));
        $oldTokenB = $this->tokenFor($issuer1->issue('login', '198.51.100.7'));
        $oldTokenC = $this->tokenFor($issuer1->issue('login', '198.51.100.7'));
        $oldTokenD = $this->tokenFor($issuer1->issue('login', '198.51.100.7'));

        $verifierA = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $verifierB = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $clockA = $this->clockHolder(0.0);
        $clockB = $this->clockHolder(1500.0);
        $monitorA = new SecurityEpochMonitor($verifierA, $this->client, $ns, 1, 1, $clockA);
        $monitorB = new SecurityEpochMonitor($verifierB, $this->client, $ns, 1, 1, $clockB);

        // Both regions confirm the central epoch 1 at their own
        // last-known timestamps.
        self::assertSame(1, $monitorA->currentEpoch(), 'region A observes the central epoch at T0');
        self::assertSame(1, $monitorB->currentEpoch(), 'region B observes the central epoch at its own T0 plus 1500ms');
        self::assertTrue($verifierA->verify($oldTokenA, self::SECRET, 'login', '198.51.100.7')->isOk(), 'an epoch-1 record verifies on region A before the bump');
        self::assertTrue($verifierB->verify($oldTokenB, self::SECRET, 'login', '198.51.100.7')->isOk(), 'an epoch-1 record verifies on region B before the bump');

        // The coordinated bump lands in the shared central hash.
        $this->client->hset(sprintf('{kiwi:%s}:security-policy', $ns), SecurityEpochMonitor::MIN_POLICY_EPOCH_FIELD, '2');

        // Region A refreshes first, its window elapsed, and fails closed
        // on the stale policy immediately.
        $clockA->ms = 2000.0;
        self::assertSame(2, $monitorA->currentEpoch(), 'region A observes the bump');
        self::assertSame(VerifyError::WrongPolicyVersion, $verifierA->verify($oldTokenC, self::SECRET, 'login', '198.51.100.7')->error, 'region A fails closed on the stale policy');

        // Region B is still inside its window: the last-known epoch 1
        // keeps serving until its own refresh, the bounded revocation
        // latency.
        $clockB->ms = 2000.0;
        self::assertSame(1, $monitorB->currentEpoch(), 'region B still serves its last-known epoch inside its window');
        self::assertTrue($verifierB->verify($oldTokenD, self::SECRET, 'login', '198.51.100.7')->isOk(), 'region B verifies under the last-known epoch inside its window');

        // Region B's window elapses: it refreshes, observes the bump and
        // fails closed on the stale policy like region A.
        $clockB->ms = 3000.0;
        self::assertSame(2, $monitorB->currentEpoch(), 'region B observes the bump once its window elapses');
        self::assertSame(VerifyError::WrongPolicyVersion, $verifierB->verify($oldTokenD, self::SECRET, 'login', '198.51.100.7')->error, 'region B fails closed on the stale policy');

        // After the refresh both regions accept the new epoch.
        $issuer2 = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0, policyVersion: 2), $storage, now: static fn (): int => self::ISSUED_AT);
        $newTokenA = $this->tokenFor($issuer2->issue('login', '198.51.100.7'));
        $newTokenB = $this->tokenFor($issuer2->issue('login', '198.51.100.7'));
        self::assertTrue($verifierA->verify($newTokenA, self::SECRET, 'login', '198.51.100.7')->isOk(), 'region A accepts the new epoch after the refresh');
        self::assertTrue($verifierB->verify($newTokenB, self::SECRET, 'login', '198.51.100.7')->isOk(), 'region B accepts the new epoch after the refresh');
    }

    public function testPartitionedRegionServesWithinWindowAndFailsClosedPastIt(): void
    {
        $ns = 'part-'.bin2hex(random_bytes(4));
        $storage = new RedisStorage($this->client, 'part-'.$ns.'-');
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0, policyVersion: 1), $storage, now: static fn (): int => self::ISSUED_AT);
        $token = $this->tokenFor($issuer->issue('login', '198.51.100.7'));
        $token2 = $this->tokenFor($issuer->issue('login', '198.51.100.7'));

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $partitioned = new PartitionedPredisClient((string) RedisTestUrl::resolve());
        $clock = $this->clockHolder(0.0);
        $monitor = new SecurityEpochMonitor($verifier, $partitioned, $ns, 1, 1, $clock, maxStaleSecs: 10);

        self::assertSame(1, $monitor->currentEpoch(), 'the region confirms the central epoch at T0');
        self::assertFalse($monitor->isStale(), 'right after a successful read the region is fresh');
        self::assertTrue($verifier->verify($token, self::SECRET, 'login', '198.51.100.7')->isOk(), 'an epoch-1 record verifies before the bump');

        // The bump lands while this region's policy Redis is partitioned.
        $this->client->hset(sprintf('{kiwi:%s}:security-policy', $ns), SecurityEpochMonitor::MIN_POLICY_EPOCH_FIELD, '2');
        $partitioned->failReads = true;

        // Inside the max-stale window the cached max keeps serving and
        // the region is not stale, the bounded outage tolerance.
        $clock->ms = 1000.0;
        self::assertSame(1, $monitor->currentEpoch(), 'the cached max serves during the partition');
        self::assertFalse($monitor->isStale(), 'inside the max-stale window the region is not stale');

        // Past the window the region is stale. The caller fails closed
        // and never verifies under the possibly-revoked epoch.
        $clock->ms = 15000.0;
        self::assertTrue($monitor->isStale(), 'past the max-stale window the region is stale');

        $stack = new RequestStack();
        $stack->push(JsonRequest::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $validator = new KiwiCaptchaValidator($verifier, $stack, self::SECRET, epochMonitor: $monitor);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engineValidator = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token2;
        $meta = $engineValidator->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engineValidator->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $violations[0]->getCode(), 'a stale region fails verification closed with temporary_unavailable');

        // The issuance path refuses too: 503 `SERVICE_UNAVAILABLE`.
        $controller = new ChallengeController($issuer, epochMonitor: $monitor);
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
        self::assertSame(503, $response->getStatusCode(), 'a stale region refuses issuance with 503');
        self::assertSame('SERVICE_UNAVAILABLE', json_decode((string) $response->getContent(), true)['error']['code']);

        // The partition heals: the next refresh observes the bump, the
        // max-stale deadline refreshes and the epoch-1 record fails
        // closed in this region too.
        $partitioned->failReads = false;
        $clock->ms = 16000.0;
        self::assertSame(2, $monitor->currentEpoch(), 'a recovered read observes the bump');
        self::assertFalse($monitor->isStale(), 'a successful read refreshes the max-stale deadline');
        self::assertSame(VerifyError::WrongPolicyVersion, $verifier->verify($token2, self::SECRET, 'login', '198.51.100.7')->error, 'an epoch-1 record fails closed after recovery');
    }
}
