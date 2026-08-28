<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JsonRequest;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptcha;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Validator\ConstraintValidatorFactory;
use Symfony\Component\Validator\Validation;

/**
 * Bounded-revocation-latency security epoch: the monitor reads the
 * central {kiwi:<ns>}:security-policy hash's min_policy_epoch, keeps a
 * monotonic in-process max (ignoring a regressed central value), serves
 * the last-observed max on Redis failure, and feeds the verifier's
 * expected policy epoch per verification. A central bump revokes
 * old-version challenges within one cache window.
 */
final class SecurityEpochMonitorTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const POLICY_KEY = '{kiwi:test-ns}:security-policy';

    private int $clockMs = 0;

    private function clock(): float
    {
        return (float) $this->clockMs;
    }

    private function setCentralEpoch(FakePredisClient $redis, int $epoch): void
    {
        $redis->hset(self::POLICY_KEY, SecurityEpochMonitor::MIN_POLICY_EPOCH_FIELD, (string) $epoch);
    }

    /**
     * A verifier + issuer sharing one ArrayStorage; the issuer stamps the
     * configured policy epoch into every challenge record.
     */
    private function pair(int $policyVersion): array
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120, policyVersion: $policyVersion), $storage);
        $verifier = new Verifier($storage, null, null, false, null, $policyVersion);

        return [$issuer, $verifier, $storage];
    }

    /**
     * Issue + solve a challenge in pure PHP (fast 8-bit difficulty) and
     * return the solution token.
     */
    private function solveChallenge(Issuer $issuer): string
    {
        $challenge = $issuer->issue('login', '198.51.100.7');
        // The server-measured minimum-duration floor applies at verification
        // (the server timing) — sleep past it like every other
        // round-trip test.
        usleep(((int) $challenge->minDurationMs + 10) * 1000);
        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;

        return \KiwiCaptcha\SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
    }

    public function testCentralBumpRejectsOldVersionChallengesWithinTheCacheTtl(): void
    {
        [$issuer, $verifier] = $this->pair(1);
        $beforeToken = $this->solveChallenge($issuer);
        $oldToken = $this->solveChallenge($issuer);

        // The central policy bumps the epoch to 2.
        $redis = new FakePredisClient();
        $this->setCentralEpoch($redis, 2);
        $monitor = new SecurityEpochMonitor(
            $verifier,
            $redis,
            'test-ns',
            1,
            1,
            $this->clock(...),
        );

        // Before the monitor observes the bump, an old-version challenge is
        // still valid (the verifier's configured epoch 1 is in force).
        self::assertTrue($verifier->verify($beforeToken, self::SECRET, 'login', '198.51.100.7')->isOk());

        // One monitor refresh (cache window 1 s) observes the bump and
        // rotates the verifier: within the cache TTL a pending old-version
        // challenge is rejected.
        self::assertSame(2, $monitor->currentEpoch());
        $outcome = $verifier->verify($oldToken, self::SECRET, 'login', '198.51.100.7');
        self::assertFalse($outcome->isOk());
        self::assertSame(VerifyError::WrongPolicyVersion, $outcome->error, 'a challenge issued under epoch 1 must die on a verifier observing epoch 2');
    }

    public function testFreshVersionChallengesVerifyAfterTheBump(): void
    {
        // The deployment rotates: issuance now stamps epoch 2.
        [$newIssuer, $verifier] = $this->pair(2);
        $newToken = $this->solveChallenge($newIssuer);

        $redis = new FakePredisClient();
        $this->setCentralEpoch($redis, 2);
        $monitor = new SecurityEpochMonitor($verifier, $redis, 'test-ns', 2, 1, $this->clock(...));
        $monitor->currentEpoch();

        $outcome = $verifier->verify($newToken, self::SECRET, 'login', '198.51.100.7');
        self::assertTrue($outcome->isOk(), 'challenges issued under the CURRENT epoch must verify');
    }

    public function testEpochBumpNeverDisablesTheIssuerExpectation(): void
    {
        // The security boundary the audit found: the monitor previously
        // rotated the shared verifier with rotateDeploymentExpectations()
        // carrying a null issuer, so a central epoch bump silently
        // disabled issuer enforcement on every later verification. The
        // monitor now mutates only the policy epoch. The verifier starts
        // with issuer=prod (the construction-time wiring); the central
        // epoch rises 1 -> 2; a current-epoch record issued for a foreign
        // deployment (issuer=staging) still fails WrongIssuer, and a
        // current-epoch prod record still verifies.
        $storage = new ArrayStorage();
        $stagingIssuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120, policyVersion: 2, issuer: 'staging'), $storage);
        $prodIssuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120, policyVersion: 2, issuer: 'prod'), $storage);
        $foreignToken = $this->solveChallenge($stagingIssuer);
        $ownToken = $this->solveChallenge($prodIssuer);

        $verifier = new Verifier($storage, null, null, false, null, 1, 'prod');

        $redis = new FakePredisClient();
        $this->setCentralEpoch($redis, 1);
        $monitor = new SecurityEpochMonitor($verifier, $redis, 'test-ns', 1, 1, $this->clock(...));
        self::assertSame(1, $monitor->currentEpoch());

        // The central epoch rises to 2: the monitor applies only the epoch.
        $this->setCentralEpoch($redis, 2);
        $this->clockMs = 2000; // past the cache window -> a re-read happens
        self::assertSame(2, $monitor->currentEpoch());

        // The current-epoch foreign record: the epoch check passes (2 == 2)
        // but the issuer check still fails — the compartment never
        // disappeared after the bump.
        $outcome = $verifier->verify($foreignToken, self::SECRET, 'login', '198.51.100.7');
        self::assertFalse($outcome->isOk());
        self::assertSame(VerifyError::WrongIssuer, $outcome->error, 'a current-epoch staging record must still fail WrongIssuer after the epoch bump (the issuer boundary survives)');

        // The control: a current-epoch prod record still verifies.
        self::assertTrue($verifier->verify($ownToken, self::SECRET, 'login', '198.51.100.7')->isOk(), 'the rotation must not break the normal prod path');
    }

    public function testRegressedCentralValueIsIgnoredByTheMonotonicGuard(): void
    {
        [$issuer, $verifier] = $this->pair(1);
        $revokedToken = $this->solveChallenge($issuer);
        $stillRevokedToken = $this->solveChallenge($issuer);

        $redis = new FakePredisClient();
        $this->setCentralEpoch($redis, 3);
        $monitor = new SecurityEpochMonitor($verifier, $redis, 'test-ns', 1, 1, $this->clock(...));
        self::assertSame(3, $monitor->currentEpoch());
        self::assertSame(VerifyError::WrongPolicyVersion, $verifier->verify($revokedToken, self::SECRET, 'login', '198.51.100.7')->error, 'the bump revokes epoch-1 challenges');

        // The central value regresses to 1 (a misconfigured rollback of the
        // policy hash): the monotonic guard must keep the observed max 3.
        $this->setCentralEpoch($redis, 1);
        $this->clockMs = 2000; // past the cache window -> a re-read happens
        self::assertSame(3, $monitor->currentEpoch(), 'a regressed central value must never weaken the observed max');
        self::assertSame(3, $monitor->observedMax());

        $outcome = $verifier->verify($stillRevokedToken, self::SECRET, 'login', '198.51.100.7');
        self::assertFalse($outcome->isOk(), 'challenges revoked by epoch 3 stay revoked after the regression');
        self::assertSame(VerifyError::WrongPolicyVersion, $outcome->error);
    }

    public function testRedisDownServesTheLastObservedMax(): void
    {
        [$issuer, $verifier] = $this->pair(1);
        $revokedToken = $this->solveChallenge($issuer);
        $stillRevokedToken = $this->solveChallenge($issuer);

        $redis = new FakePredisClient();
        $this->setCentralEpoch($redis, 2);
        $monitor = new SecurityEpochMonitor($verifier, $redis, 'test-ns', 1, 1, $this->clock(...));
        self::assertSame(2, $monitor->currentEpoch());
        self::assertSame(VerifyError::WrongPolicyVersion, $verifier->verify($revokedToken, self::SECRET, 'login', '198.51.100.7')->error, 'the bump revokes epoch-1 challenges');

        // Redis goes down: the monitor serves the last-observed max 2 — the
        // revocation stays in force, it can never weaken.
        $redis->failCommand = '*';
        $this->clockMs = 2000;
        self::assertSame(2, $monitor->currentEpoch(), 'a Redis outage must serve the last-observed epoch, never a weaker one');
        self::assertSame(2, $monitor->observedMax());

        $outcome = $verifier->verify($stillRevokedToken, self::SECRET, 'login', '198.51.100.7');
        self::assertSame(VerifyError::WrongPolicyVersion, $outcome->error, 'the last-observed max stays enforced while Redis is down');
    }

    public function testCacheWindowBoundsTheCentralReads(): void
    {
        [$issuer, $verifier] = $this->pair(1);
        $redis = new FakePredisClient();
        $this->setCentralEpoch($redis, 2);
        $monitor = new SecurityEpochMonitor($verifier, $redis, 'test-ns', 1, 1, $this->clock(...));

        $hgetBefore = $this->hgetCount($redis);
        self::assertSame(2, $monitor->currentEpoch());
        self::assertSame($hgetBefore + 1, $this->hgetCount($redis), 'the first refresh reads the central state');

        // Within the cache window (1 s) no further read happens and the
        // observed epoch stays in force — bounded revocation latency, no
        // per-verification Redis round trip.
        self::assertSame(2, $monitor->currentEpoch());
        self::assertSame($hgetBefore + 1, $this->hgetCount($redis), 'a refresh inside the cache window must not re-read Redis');

        // Past the window the central value is re-read.
        $this->setCentralEpoch($redis, 5);
        $this->clockMs = 1100;
        self::assertSame(5, $monitor->currentEpoch());
        self::assertSame($hgetBefore + 2, $this->hgetCount($redis), 'past the cache window the central value is re-read');
    }

    public function testAbsentCentralKeyServesTheConfiguredEpoch(): void
    {
        [$issuer, $verifier] = $this->pair(1);
        $token = $this->solveChallenge($issuer);

        $monitor = new SecurityEpochMonitor($verifier, new FakePredisClient(), 'test-ns', 1, 1, $this->clock(...));
        self::assertSame(1, $monitor->currentEpoch(), 'without a central key the configured epoch is authoritative');

        $outcome = $verifier->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertTrue($outcome->isOk());
    }

    public function testMonitorWithoutRedisIsANoOp(): void
    {
        [, $verifier] = $this->pair(1);
        $monitor = new SecurityEpochMonitor($verifier, null, 'test-ns', 1, 1, $this->clock(...));
        self::assertSame(1, $monitor->currentEpoch());
        self::assertSame(0, $monitor->observedMax());
    }

    /**
     * The validator path ("the validator + any verification path
     * use the monitor's current epoch"): a monitor observing the bump makes
     * an old-version solve fail with the collapsed invalid_or_expired
     * violation, and the monitor's refresh happens per verification.
     */
    public function testValidatorEnforcesTheMonitoredEpochPerVerification(): void
    {
        [$issuer, $verifier] = $this->pair(1);
        $oldToken = $this->solveChallenge($issuer);
        usleep(10 * 1000); // clear the min-duration floor

        $redis = new FakePredisClient();
        $this->setCentralEpoch($redis, 2);
        $monitor = new SecurityEpochMonitor($verifier, $redis, 'test-ns', 1, 1, $this->clock(...));

        $stack = new RequestStack();
        $stack->push(JsonRequest::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $validator = new KiwiCaptchaValidator($verifier, $stack, self::SECRET, epochMonitor: $monitor);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engineValidator = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();

        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $oldToken;
        $meta = $engineValidator->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $violations = $engineValidator->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $violations[0]->getCode(), 'the monitored epoch must be enforced per verification (collapsed public code)');
    }

    // ── Max-stale fail-closed ─────────────────────────────────────────────

    /**
     * Within the max-stale window (now <= last_success +
     * risk.security_epoch_max_stale_secs) a Redis outage is NOT stale — the
     * cached max keeps serving and the revocation stays in force.
     */
    public function testWithinTheMaxStaleWindowTheCachedMaxStillServes(): void
    {
        [$issuer, $verifier] = $this->pair(1);
        $revokedToken = $this->solveChallenge($issuer);

        $redis = new FakePredisClient();
        $this->setCentralEpoch($redis, 2);
        $monitor = new SecurityEpochMonitor($verifier, $redis, 'test-ns', 1, 1, $this->clock(...), maxStaleSecs: 60);
        self::assertSame(2, $monitor->currentEpoch(), 'the central bump is observed at T0');
        self::assertFalse($monitor->isStale(), 'right after a successful read the monitor is fresh');

        // Redis dies at T0+5 s; at T0+30 s (well inside the 60 s window) the
        // cached max 2 is still served AND the monitor is not stale.
        $redis->failCommand = '*';
        $this->clockMs = 30_000;
        self::assertSame(2, $monitor->currentEpoch(), 'the cached max keeps serving during the outage');
        self::assertFalse($monitor->isStale(), 'within the max-stale window the outage is NOT stale');
        self::assertSame(
            VerifyError::WrongPolicyVersion,
            $verifier->verify($revokedToken, self::SECRET, 'login', '198.51.100.7')->error,
            'the cached revocation stays in force within the window'
        );
    }

    /**
     * Once now > last_success + max_stale the monitor IS stale —
     * the cached epoch may be outdated (an emergency revocation could have
     * landed while the node could not read) — and every caller fails closed.
     */
    public function testPastTheMaxStaleWindowTheMonitorIsStale(): void
    {
        [$issuer, $verifier] = $this->pair(1);

        $redis = new FakePredisClient();
        $this->setCentralEpoch($redis, 2);
        $monitor = new SecurityEpochMonitor($verifier, $redis, 'test-ns', 1, 1, $this->clock(...), maxStaleSecs: 60);
        self::assertSame(2, $monitor->currentEpoch(), 'the central bump is observed at T0');

        $redis->failCommand = '*';
        $this->clockMs = 90_000; // last_success 0 + 60 s < 90 s
        self::assertSame(2, $monitor->currentEpoch(), 'the cached max is still the enforced epoch');
        self::assertTrue($monitor->isStale(), 'past last_success + max_stale the monitor is stale');

        // A successful read refreshes the deadline: the outage ends at
        // T0+90 s, the next refresh confirms the central state and the
        // monitor is fresh again.
        $redis->failCommand = null;
        $this->setCentralEpoch($redis, 3);
        $this->clockMs = 91_000;
        self::assertSame(3, $monitor->currentEpoch(), 'a recovered read observes the newest bump');
        self::assertFalse($monitor->isStale(), 'a successful read refreshes the max-stale deadline');
    }

    public function testNeverSucceededReadIsImmediatelyStale(): void
    {
        [, $verifier] = $this->pair(1);
        $redis = new FakePredisClient();
        $redis->failCommand = '*';
        $monitor = new SecurityEpochMonitor($verifier, $redis, 'test-ns', 1, 1, $this->clock(...), maxStaleSecs: 60);
        self::assertSame(1, $monitor->currentEpoch(), 'the configured epoch is the enforced floor');
        self::assertTrue(
            $monitor->isStale(),
            'a monitor with a Redis client that NEVER succeeded a central read is stale immediately (an unobserved central policy is never trusted to be current)'
        );
    }

    public function testMonitorWithoutRedisIsNeverStale(): void
    {
        [, $verifier] = $this->pair(1);
        $monitor = new SecurityEpochMonitor($verifier, null, 'test-ns', 1, 1, $this->clock(...), maxStaleSecs: 60);
        $this->clockMs = 3_600_000;
        self::assertFalse(
            $monitor->isStale(),
            'no central state by design (null Redis) is a configured posture, never a stale failure'
        );
    }

    public function testMaxStaleBelowTenSecondsIsRefused(): void
    {
        [, $verifier] = $this->pair(1);
        $this->expectException(\InvalidArgumentException::class);
        new SecurityEpochMonitor($verifier, null, 'test-ns', 1, 1, $this->clock(...), maxStaleSecs: 9);
    }

    /**
     * The validator fails verification closed with the distinct
     * temporary_unavailable violation when the monitor is stale — the token
     * is NOT burned (retryable), the server refuses to trust its own cache.
     */
    public function testValidatorFailsClosedWithTemporaryUnavailableWhenStale(): void
    {
        [$issuer, $verifier] = $this->pair(1);
        $token = $this->solveChallenge($issuer);
        usleep(10 * 1000); // clear the min-duration floor

        $redis = new FakePredisClient();
        $this->setCentralEpoch($redis, 2);
        $monitor = new SecurityEpochMonitor($verifier, $redis, 'test-ns', 1, 1, $this->clock(...), maxStaleSecs: 60);
        $monitor->currentEpoch(); // observe the central state at T0

        // Within the window a verification still runs (and the cached
        // revocation is enforced — the epoch-1 token fails as invalid).
        $stack = new RequestStack();
        $stack->push(JsonRequest::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $validator = new KiwiCaptchaValidator($verifier, $stack, self::SECRET, epochMonitor: $monitor);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engineValidator = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engineValidator->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        self::assertSame(
            KiwiCaptcha::INVALID_OR_EXPIRED_ERROR,
            $engineValidator->validate($dto)[0]?->getCode(),
            'within the window the cached revocation applies (epoch-1 token dies)'
        );

        // Past the window with Redis still down: verification fails closed
        // with temporary_unavailable — never invalid_or_expired (the token
        // is not burned) and never a guessed success.
        $redis->failCommand = '*';
        $this->clockMs = 90_000;
        $violations = $engineValidator->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(
            KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR,
            $violations[0]->getCode(),
            'a stale security state fails verification closed with temporary_unavailable'
        );
    }

    /**
     * The challenge controller refuses issuance with 503
     * service_unavailable when the monitor is stale — within the window the
     * cached max still serves (issuance keeps working).
     */
    public function testControllerRefusesIssuanceWith503WhenStale(): void
    {
        [$issuer, $verifier] = $this->pair(1);
        $redis = new FakePredisClient();
        $this->setCentralEpoch($redis, 2);
        $monitor = new SecurityEpochMonitor($verifier, $redis, 'test-ns', 1, 1, $this->clock(...), maxStaleSecs: 60);
        $controller = new \BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController($issuer, epochMonitor: $monitor);

        // Within the window: issuance works.
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode(), 'within the max-stale window issuance keeps serving');

        // Past the window with Redis down: 503 service_unavailable.
        $redis->failCommand = '*';
        $this->clockMs = 90_000;
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
        self::assertSame(503, $response->getStatusCode(), 'a stale security state refuses issuance with 503');
        self::assertSame('SERVICE_UNAVAILABLE', json_decode((string) $response->getContent(), true)['error']['code']);
    }

    private function hgetCount(FakePredisClient $redis): int
    {
        $count = 0;
        foreach ($redis->calls as $call) {
            if ($call[0] === 'HGET') {
                $count++;
            }
        }

        return $count;
    }
}
