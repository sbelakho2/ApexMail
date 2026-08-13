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
 * Bounded-revocation-latency security epoch (audit #81): the monitor reads
 * the central {kiwi:<ns>}:security-policy hash's min_policy_epoch with a
 * SHORT cache, keeps a MONOTONIC in-process max (a regressed central value
 * is ignored), serves the last-observed max on Redis failure, and feeds the
 * verifier's expected policy epoch per verification — so a central bump
 * revokes old-version challenges within one cache window.
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
        // (audit #47's server timing) — sleep past it like every other
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
        // rotates the verifier: within the cache TTL a PENDING old-version
        // challenge is REJECTED.
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

        // The central value REGRESSES to 1 (a misconfigured rollback of the
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
     * The VALIDATOR path (audit #81: "the validator + any verification path
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
