<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\SiteVerifyController;
use BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisSiteVerifyIdempotencyStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * REAL-REDIS matrix of the UNCOMMITTED-RESULT recovery (the defect shape):
 * the atomic pending→consumed transition EXECUTES on the real Redis
 * storage and the operation identity lands atomically with the state flip,
 * but the reply is lost BEFORE the derivation/commit — consumed_result
 * stays null forever for the ordinary verifier. A same-key retry takes
 * over the expired lease and the takeover gate proves the identity (the
 * consumed record's OWN operation identity equals the retry's
 * fingerprint): the derivation is RESUMED and committed via
 * Verifier::resumeConsumedOperation(). Every negative tail — a different
 * UUID, a different backend secret, a no-key first redemption, a changed
 * remoteip, admission exhaustion — must NEVER resume.
 */
final class RealRedisSiteVerifyRecoveryTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';
    private const SITEVERIFY_SECRET = 'compat-secret-42';

    /** @return \Predis\Client|null null when Redis is unreachable */
    private function redisOrSkip(): ?\Predis\Client
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        try {
            $probe = new \Predis\Client('tcp://127.0.0.1:6399', ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
            $probe->ping();

            return $probe;
        } catch (\Throwable) {
            self::markTestSkipped('no Redis at 127.0.0.1:6399 — start one for the recovery matrix');
        }
    }

    /**
     * The "lost reply" seam: consumeWithOperationIdentity() DELEGATES to
     * the real Redis storage — the transition executes and the identity
     * lands atomically with the state flip — and the response is then
     * lost. Everything else delegates.
     */
    private function lostConsumeReplyStorage(\KiwiCaptcha\AtomicStorageInterface $inner): \KiwiCaptcha\AtomicStorageInterface
    {
        return new class($inner) implements \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyRecoveryCapableStorageInterface {
            public function __construct(private readonly \KiwiCaptcha\AtomicStorageInterface $inner)
            {
            }

            public function store(\KiwiCaptcha\ChallengeRecord $record): void
            {
                $this->inner->store($record);
            }

            public function find(string $nonce): ?\KiwiCaptcha\ChallengeRecord
            {
                return $this->inner->find($nonce);
            }

            public function consumedState(string $nonce): ?\KiwiCaptcha\ConsumedRecord
            {
                return $this->inner->consumedState($nonce);
            }

            public function consume(string $nonce): ?\KiwiCaptcha\ConsumedRecord
            {
                return $this->inner->consume($nonce);
            }

            public function consumeWithOperationIdentity(string $nonce, ?string $operationIdentity): ?\KiwiCaptcha\ConsumedRecord
            {
                // The transition EXECUTES (the identity lands atomically
                // with the state flip) — and the response is then lost.
                $this->inner->consumeWithOperationIdentity($nonce, $operationIdentity);

                throw new \RuntimeException('consume reply lost after the transition');
            }

            public function commitResult(string $nonce, bool $valid, ?string $binding): bool
            {
                return $this->inner->commitResult($nonce, $valid, $binding);
            }

            public function delete(string $nonce): void
            {
                $this->inner->delete($nonce);
            }
        };
    }

    /** @return array{0: string, 1: \KiwiCaptcha\Challenge, 2: string} [token, challenge, nonce] */
    private function issueSha(RedisStorage $storage, int $ttlSecs = 120): array
    {
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: $ttlSecs), $storage);
        $challenge = $issuer->issue('login', '127.0.0.1');
        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;
        usleep(($challenge->minDurationMs + 10) * 1000);

        return [SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode(), $challenge, $challenge->nonce];
    }

    /** @return array{0: string, 1: \KiwiCaptcha\Challenge} [token, challenge] */
    private function issueArgon(RedisStorage $storage): array
    {
        $issuer = new Issuer(new Config(
            secretKey: self::SECRET,
            algorithm: PoWAlgorithm::Argon2id,
            mKib: 64,
            t: 3,
            p: 1,
            argon2TargetBits: 4,
            ttlSecs: 120,
        ), $storage);
        $challenge = $issuer->issue('login', '127.0.0.1');
        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = sodium_crypto_pwhash(32, $challenge->prefix.$counter, $saltBytes, 3, 64 * 1024, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;
        usleep(($challenge->minDurationMs + 10) * 1000);

        return [SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode(), $challenge];
    }

    private function expectedCanonicalSuccess(RedisStorage $storage, string $nonce): string
    {
        $record = $storage->find($nonce);
        self::assertNotNull($record);

        return (string) json_encode([
            'action' => null,
            'cdata' => null,
            'challenge_ts' => gmdate('Y-m-d\TH:i:s\Z', $record->issuedAt),
            'error-codes' => [],
            'hostname' => $record->hostname,
            'success' => true,
        ], JsonResponse::DEFAULT_ENCODING_OPTIONS);
    }

    public function testValidShaConsumeReplyLostThenSameKeyRetryResumesOriginalSuccess(): void
    {
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }
        $storage = new RedisStorage($probe);
        [$token, , $nonce] = $this->issueSha($storage);
        $uuid = 'c0ffee00-0000-4000-8000-000000000001';
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $idemKey = '{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuid;
        $probe->del([$idemKey]);

        // A SHORT fixed store lease (1s) keeps the takeover instant; the
        // waiter bound (5s) exceeds it (the construction invariant).
        $store = new RedisSiteVerifyIdempotencyStore($probe, 'kiwicaptcha', 1);
        $lost = $this->lostConsumeReplyStorage($storage);

        try {
            $owner = new SiteVerifyController(new Verifier($lost), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $lost, null, null, $store, null, 5.0);
            $ownerResponse = $owner->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame(503, $ownerResponse->getStatusCode(), 'the lost consume reply must map to the retryable 503 internal-error');
            self::assertSame(['internal-error'], json_decode((string) $ownerResponse->getContent(), true)['error-codes']);
            self::assertNull($store->stored($backendId, $uuid), 'the lost reply must NOT finalize the claim');
            $consumed = $storage->consumedState($nonce);
            self::assertNotNull($consumed, 'the transition EXECUTED on real Redis');
            self::assertSame(
                hash('sha256', $backendId."\0".$uuid."\0".hash('sha256', $token)."\0"."ip:127.0.0.1"),
                $consumed->operationIdentity,
                'the operation identity lands atomically with the real-Redis state flip',
            );
            self::assertNull($consumed->consumedResult, 'consumed_result stays null — the ordinary verifier would say ConsumeIndeterminate forever');

            // Wait out the 1s lease (Redis TIME is the lease clock).
            usleep(2_500_000);

            // The same-key retry takes over and RESUMES the derivation.
            $retry = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 5.0);
            $retryResponse = $retry->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            $retryBody = json_decode((string) $retryResponse->getContent(), true);
            self::assertSame(true, $retryBody['success'] ?? null, 'the identity-proven retry must RESUME and succeed: '.(string) $retryResponse->getContent());
            self::assertSame([], $retryBody['error-codes'] ?? null);
            self::assertSame($this->expectedCanonicalSuccess($storage, $nonce), (string) $retryResponse->getContent(), 'the retry receives the ORIGINAL canonical success bytes');
            $after = $storage->consumedState($nonce);
            self::assertNotNull($after?->consumedResult, 'the resumed derivation must be committed');
            self::assertSame(true, $after->consumedResult->valid);

            // A same-UUID retry now returns the stored canonical bytes
            // (COMPLETE_SAME) — never a re-derivation.
            $replay = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 5.0);
            $replayResponse = $replay->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame((string) $retryResponse->getContent(), (string) $replayResponse->getContent(), 'a same-UUID retry reproduces the identical canonical response');
        } finally {
            $probe->del([$idemKey, 'kiwicaptcha:'.$nonce]);
        }
    }

    public function testEpochBumpedClaimKeysDifferFromTheStaticEpochKeys(): void
    {
        // The monitor's effective epoch (central min_policy_epoch = 1)
        // moves the ENTIRE idempotency namespace: the owner's claim, the
        // consumed operation identity and the retry's takeover all live
        // under the epoch-1 backend identity — the static epoch-0 keys
        // are never created. The lost-reply recovery still works
        // end-to-end under the bumped namespace.
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }
        $storage = new RedisStorage($probe);
        [$token, , $nonce] = $this->issueSha($storage);
        $uuid = 'c0ffee00-0000-4000-8000-0000000000e1';
        $staticBackendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $effectiveBackendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|1');
        self::assertNotSame($staticBackendId, $effectiveBackendId, 'precondition: the effective epoch must differ from the static one');
        $staticKey = '{kiwicaptcha}:siteverify-idem:'.$staticBackendId.':'.$uuid;
        $effectiveKey = '{kiwicaptcha}:siteverify-idem:'.$effectiveBackendId.':'.$uuid;
        $probe->del([$effectiveKey, $staticKey]);

        // A SHORT fixed store lease (1s) keeps the takeover instant; the
        // waiter bound (5s) exceeds it (the construction invariant).
        $store = new RedisSiteVerifyIdempotencyStore($probe, 'kiwicaptcha', 1);
        $lost = $this->lostConsumeReplyStorage($storage);

        // The central security-policy state (epoch 1) feeds the real
        // monitor; the static configured epoch stays 0, so any claim
        // under the static key would prove the monitor is NOT wired.
        $policyRedis = new FakePredisClient();
        $policyRedis->hset('{kiwi:test-ns}:security-policy', SecurityEpochMonitor::MIN_POLICY_EPOCH_FIELD, '1');

        try {
            $ownerVerifier = new Verifier($lost);
            $ownerMonitor = new SecurityEpochMonitor($ownerVerifier, $policyRedis, 'test-ns', 1);
            $owner = new SiteVerifyController($ownerVerifier, self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $lost, null, null, $store, null, 5.0, 0, null, $ownerMonitor);
            $ownerResponse = $owner->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame(503, $ownerResponse->getStatusCode(), 'the lost consume reply must map to the retryable 503 internal-error');
            self::assertNull($store->stored($effectiveBackendId, $uuid), 'the lost reply must NOT finalize the claim');
            $consumed = $storage->consumedState($nonce);
            self::assertNotNull($consumed, 'the transition EXECUTED on real Redis');
            self::assertSame(
                hash('sha256', $effectiveBackendId."\0".$uuid."\0".hash('sha256', $token)."\0"."ip:127.0.0.1"),
                $consumed->operationIdentity,
                'the operation identity lands atomically with the real-Redis state flip under the EFFECTIVE-epoch backend identity',
            );
            self::assertNull($consumed->consumedResult, 'consumed_result stays null — the ordinary verifier would say ConsumeIndeterminate forever');
            self::assertNotNull($probe->get($effectiveKey), 'the pending claim must live under the effective-epoch key');
            self::assertNull($probe->get($staticKey), 'the static-epoch key must never be created');

            // Wait out the 1s lease (Redis TIME is the lease clock).
            usleep(2_500_000);

            // The same-key retry (its own monitor observing the same
            // central epoch) claims under the SAME effective-epoch key,
            // takes over and RESUMES the derivation.
            $retryVerifier = new Verifier($storage);
            $retryMonitor = new SecurityEpochMonitor($retryVerifier, $policyRedis, 'test-ns', 1);
            $retry = new SiteVerifyController($retryVerifier, self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 5.0, 0, null, $retryMonitor);
            $retryResponse = $retry->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            $retryBody = json_decode((string) $retryResponse->getContent(), true);
            self::assertSame(true, $retryBody['success'] ?? null, 'the identity-proven retry must RESUME and succeed under the effective-epoch namespace: '.(string) $retryResponse->getContent());
            self::assertSame([], $retryBody['error-codes'] ?? null);
            self::assertSame($this->expectedCanonicalSuccess($storage, $nonce), (string) $retryResponse->getContent(), 'the retry receives the ORIGINAL canonical success bytes');
            $after = $storage->consumedState($nonce);
            self::assertNotNull($after?->consumedResult, 'the resumed derivation must be committed');
            self::assertSame(true, $after->consumedResult->valid);
            self::assertNotNull($probe->get($effectiveKey), 'the completed claim stays under the effective-epoch key');
            self::assertNull($probe->get($staticKey), 'the static-epoch key stays untouched after the recovery');
        } finally {
            $probe->del([$effectiveKey, $staticKey, 'kiwicaptcha:'.$nonce]);
        }
    }

    public function testInvalidShaConsumeReplyLostResumesDeterministicInsufficientWork(): void
    {
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }
        $storage = new RedisStorage($probe);
        [$token, , $nonce] = $this->issueSha($storage);
        $record = $storage->find($nonce);
        self::assertNotNull($record);
        $saltBytes = base64_decode($record->salt, true);
        $wrong = 0;
        while (Verifier::leadingZeroBits(hash('sha256', $record->prefix.$wrong.$saltBytes, true)) >= $record->targetBits) {
            $wrong++;
        }
        $wrongToken = SolutionToken::create($nonce, $wrong, 5000, [])->encode();
        self::assertNotSame($token, $wrongToken);

        $uuid = 'c0ffee00-0000-4000-8000-000000000002';
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $idemKey = '{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuid;
        $probe->del([$idemKey]);
        $store = new RedisSiteVerifyIdempotencyStore($probe, 'kiwicaptcha', 1);
        $lost = $this->lostConsumeReplyStorage($storage);

        try {
            $owner = new SiteVerifyController(new Verifier($lost), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $lost, null, null, $store, null, 5.0);
            $ownerResponse = $owner->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $wrongToken, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame(503, $ownerResponse->getStatusCode());
            self::assertNull($store->stored($backendId, $uuid), 'the lost reply must NOT finalize the claim');
            $consumed = $storage->consumedState($nonce);
            self::assertNotNull($consumed, 'the lost-reply 503 must come from the EXECUTED transition — the record must be consumed');
            self::assertSame(
                hash('sha256', $backendId."\0".$uuid."\0".hash('sha256', $wrongToken)."\0"."ip:127.0.0.1"),
                $consumed->operationIdentity,
                'the identity lands atomically with the state flip',
            );
            self::assertNull($consumed->consumedResult, 'consumed_result must be null — the derivation never ran');

            usleep(2_500_000);
            $retry = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 5.0);
            $retryResponse = $retry->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $wrongToken, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            $retryBody = json_decode((string) $retryResponse->getContent(), true);
            self::assertSame(false, $retryBody['success'] ?? null, 'the resumed derivation must deterministically fail the wrong counter');
            self::assertSame(['invalid-input-response'], $retryBody['error-codes'] ?? null, 'insufficient work maps to the invalid-response vocabulary');
            $after = $storage->consumedState($nonce);
            self::assertNotNull($after?->consumedResult, 'the resumed invalid outcome must be committed');
            self::assertSame(false, $after->consumedResult->valid);
            $stored = $store->stored($backendId, $uuid);
            self::assertIsArray($stored, 'a failed resumed verification is ALSO finalized');
            self::assertSame(['invalid-input-response'], $stored['error-codes'] ?? null);

            // A same-UUID retry reproduces the identical canonical failure.
            $again = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 5.0);
            $againResponse = $again->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $wrongToken, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame($retryBody, json_decode((string) $againResponse->getContent(), true), 'a same-UUID retry reproduces the identical canonical failure');
        } finally {
            $probe->del([$idemKey, 'kiwicaptcha:'.$nonce]);
        }
    }

    public function testArgonConsumeReplyLostResumesOriginalSuccess(): void
    {
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }
        $storage = new RedisStorage($probe);
        [$token, $challenge] = $this->issueArgon($storage);
        $nonce = $challenge->nonce;
        $uuid = 'c0ffee00-0000-4000-8000-000000000003';
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $idemKey = '{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuid;
        $probe->del([$idemKey]);
        $store = new RedisSiteVerifyIdempotencyStore($probe, 'kiwicaptcha', 1);
        $lost = $this->lostConsumeReplyStorage($storage);

        try {
            $owner = new SiteVerifyController(new Verifier($lost), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $lost, null, null, $store, null, 5.0);
            $ownerResponse = $owner->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame(503, $ownerResponse->getStatusCode(), 'the lost Argon consume reply maps to the retryable 503');
            $consumed = $storage->consumedState($nonce);
            self::assertNotNull($consumed, 'the lost-reply 503 must come from the EXECUTED transition — the record must be consumed');
            self::assertSame(
                hash('sha256', $backendId."\0".$uuid."\0".hash('sha256', $token)."\0"."ip:127.0.0.1"),
                $consumed->operationIdentity,
            );
            self::assertNull($consumed->consumedResult, 'precondition: nothing committed yet');

            usleep(2_500_000);
            $retry = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 5.0);
            $retryResponse = $retry->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            $retryBody = json_decode((string) $retryResponse->getContent(), true);
            self::assertSame(true, $retryBody['success'] ?? null, 'the Argon resume must derive and commit the original success: '.(string) $retryResponse->getContent());
            self::assertSame($this->expectedCanonicalSuccess($storage, $nonce), (string) $retryResponse->getContent());
            $after = $storage->consumedState($nonce);
            self::assertNotNull($after?->consumedResult);
            self::assertSame(true, $after->consumedResult->valid);
        } finally {
            $probe->del([$idemKey, 'kiwicaptcha:'.$nonce]);
        }
    }

    /**
     * THE adversarial expiry sequence on real Redis: a valid token is
     * consumed by an owner whose derivation CROSSES the signed expiry —
     * the ordinary verify() then returns Expired from its post-derive
     * final revalidation WITHOUT committing a result — and the owner
     * CRASHES before finalizing its idempotency record. A same-UUID
     * retry takes over and RESUMES the resultless derivation: the resume
     * re-checks the signed expiry BEFORE deriving, so the deterministic
     * Expired outcome is reproduced (timeout-or-duplicate) — NEVER a
     * post-deadline Valid. Nothing is ever committed, and every further
     * same-UUID retry reproduces the identical canonical failure.
     */
    public function testResultlessResumePastSignedExpiryIsDeterministicallyExpired(): void
    {
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }
        // The retained-state horizon: the storage's ttl_margin_secs keeps
        // the consumed record readable past the signed expiry (the
        // recovery-window margin the container enforces at compile time).
        $storage = new RedisStorage($probe, 'kiwicaptcha:', 0, 100, (int) SiteVerifyController::IDEMPOTENCY_WAIT_SECS);
        [$token, , $nonce] = $this->issueSha($storage, ttlSecs: 5);
        $record = $storage->find($nonce);
        self::assertNotNull($record);
        $uuid = 'c0ffee00-0000-4000-8000-000000000004';
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $idemKey = '{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuid;
        $probe->del([$idemKey]);
        // A SHORT fixed store lease (1s) keeps the takeover instant; the
        // waiter bound (5s) exceeds it (the construction invariant).
        $store = new RedisSiteVerifyIdempotencyStore($probe, 'kiwicaptcha', 1);

        // The owner's derivation CROSSES the signed expiry: the verifier
        // clock reads pre-expiry at the cheap phase and post-expiry at
        // the POST-DERIVE final revalidation — exactly the
        // Expired-without-commit outcome the ordinary verify() produces
        // when the derivation crosses expiresAt.
        $calls = 0;
        $ownerClock = static function () use (&$calls, $record): int {
            $calls++;
            return $calls === 1 ? $record->expiresAt - 1 : $record->expiresAt + 100;
        };
        // The finalize-crash decorator: the owner's finalize never lands
        // (process death between the Expired outcome and the claim
        // finalization) — the entry stays PENDING for the takeover.
        $crashingStore = new class($store) implements \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore {
            public function __construct(private readonly \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore $inner)
            {
            }

            public function leaseSeconds(): int
            {
                return $this->inner->leaseSeconds();
            }

            public function claim(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null): array
            {
                return $this->inner->claim($backendId, $idempotencyKey, $responseHash, $ttlSeconds, $remoteipFingerprint, $leaseSeconds);
            }

            public function takeover(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null): array
            {
                return $this->inner->takeover($backendId, $idempotencyKey, $responseHash, $ttlSeconds, $remoteipFingerprint, $leaseSeconds);
            }

            public function renew(string $backendId, string $idempotencyKey, string $owner): bool
            {
                return $this->inner->renew($backendId, $idempotencyKey, $owner);
            }

            public function finalize(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonicalResponse): void
            {
                // The owner's finalize never lands (process death).
            }

            public function stored(string $backendId, string $idempotencyKey): ?array
            {
                return $this->inner->stored($backendId, $idempotencyKey);
            }
        };

        try {
            $owner = new SiteVerifyController(new Verifier($storage, now: $ownerClock), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $crashingStore, null, 5.0);
            $ownerResponse = $owner->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            $ownerBody = json_decode((string) $ownerResponse->getContent(), true);
            self::assertSame(false, $ownerBody['success'] ?? null, 'the owner whose derivation crossed the signed expiry must get the deterministic Expired outcome');
            self::assertSame(['timeout-or-duplicate'], $ownerBody['error-codes'] ?? null);
            $consumed = $storage->consumedState($nonce);
            self::assertNotNull($consumed, 'the owner\'s transition EXECUTED on real Redis');
            self::assertSame(
                hash('sha256', $backendId."\0".$uuid."\0".hash('sha256', $token)."\0"."ip:127.0.0.1"),
                $consumed->operationIdentity,
                'the operation identity lands atomically with the real-Redis state flip',
            );
            self::assertNull($consumed->consumedResult, 'the Expired outcome is NEVER committed — the record stays consumed-without-result');
            self::assertNull($store->stored($backendId, $uuid), 'the owner crashed BEFORE finalizing the idempotency record');

            // Wait past the signed expiry (5s TTL) AND the 1s lease.
            sleep(7);

            // The same-key retry takes over and RESUMES: the resultless
            // resume re-checks the signed expiry BEFORE deriving — the
            // deterministic Expired outcome, NEVER a post-deadline Valid.
            $retry = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 5.0);
            $retryResponse = $retry->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            $retryBody = json_decode((string) $retryResponse->getContent(), true);
            self::assertSame(false, $retryBody['success'] ?? null, 'the identity-proven retry must reproduce the deterministic Expired outcome — never success: '.(string) $retryResponse->getContent());
            self::assertSame(['timeout-or-duplicate'], $retryBody['error-codes'] ?? null, 'the expired resultless resume maps to the duplicate vocabulary');
            $after = $storage->consumedState($nonce);
            self::assertNull($after?->consumedResult, 'the expired resume must NOT commit anything on real Redis');

            // A same-UUID retry reproduces the identical canonical
            // failure — the redemption can never become successful again.
            $replay = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 5.0);
            $replayResponse = $replay->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame($retryBody, json_decode((string) $replayResponse->getContent(), true), 'a same-UUID retry reproduces the identical canonical failure');
            self::assertSame(false, $retryBody['success'] ?? null, 'the adversarial sequence must NEVER yield success after the signed deadline');
        } finally {
            $probe->del([$idemKey, 'kiwicaptcha:'.$nonce]);
        }
    }

    public function testDifferentUuidCannotResumeAndWinnerStillRecovers(): void
    {
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }
        $storage = new RedisStorage($probe);
        [$token, , $nonce] = $this->issueSha($storage);
        $uuidA = 'c0ffee00-0000-4000-8000-000000000005';
        $uuidB = 'c0ffee00-0000-4000-8000-000000000006';
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $idemKeyA = '{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuidA;
        $idemKeyB = '{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuidB;
        $probe->del([$idemKeyA, $idemKeyB]);
        $store = new RedisSiteVerifyIdempotencyStore($probe, 'kiwicaptcha', 1);
        $lost = $this->lostConsumeReplyStorage($storage);

        try {
            $owner = new SiteVerifyController(new Verifier($lost), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $lost, null, null, $store, null, 5.0);
            $ownerResponse = $owner->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidA,
            ]));
            self::assertSame(503, $ownerResponse->getStatusCode());
            $consumed = $storage->consumedState($nonce);
            self::assertNotNull($consumed);
            self::assertSame(hash('sha256', $backendId."\0".$uuidA."\0".hash('sha256', $token)."\0"."ip:127.0.0.1"), $consumed->operationIdentity);
            self::assertNull($consumed->consumedResult);

            // UUID B: fresh claim -> ConsumeIndeterminate -> 503 (no
            // finalize). Then B's retry takes over B's own pending claim:
            // the identity gate refuses (the record carries A's identity)
            // and the resume never runs.
            $bFirst = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 5.0);
            $bFirstResponse = $bFirst->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidB,
            ]));
            self::assertSame(503, $bFirstResponse->getStatusCode(), 'B cannot derive a consumed-without-result record');
            usleep(2_500_000);
            $bRetry = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 5.0);
            $bRetryResponse = $bRetry->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidB,
            ]));
            self::assertSame(503, $bRetryResponse->getStatusCode(), 'a different UUID must NEVER resume the winner\'s derivation');
            self::assertNull($storage->consumedState($nonce)?->consumedResult, 'B\'s refused takeover must not commit anything — A\'s recovery evidence survives');

            // A's own retry still resumes the original success.
            usleep(2_500_000);
            $aRetry = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 5.0);
            $aRetryResponse = $aRetry->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidA,
            ]));
            self::assertSame(true, json_decode((string) $aRetryResponse->getContent(), true)['success'] ?? null, 'the winner\'s same-key retry still resumes after B\'s refused attempts');
        } finally {
            $probe->del([$idemKeyA, $idemKeyB, 'kiwicaptcha:'.$nonce]);
        }
    }

    public function testDifferentBackendSecretCannotResume(): void
    {
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }
        $storage = new RedisStorage($probe);
        [$token, , $nonce] = $this->issueSha($storage);
        $secret1 = 'secret-one-'.str_repeat('a', 16);
        $secret2 = 'secret-two-'.str_repeat('b', 16);
        $uuid = 'c0ffee00-0000-4000-8000-000000000007';
        $backendId1 = hash('sha256', $secret1.'|login|0');
        $backendId2 = hash('sha256', $secret2.'|login|0');
        $idemKey1 = '{kiwicaptcha}:siteverify-idem:'.$backendId1.':'.$uuid;
        $idemKey2 = '{kiwicaptcha}:siteverify-idem:'.$backendId2.':'.$uuid;
        $probe->del([$idemKey1, $idemKey2]);
        $store = new RedisSiteVerifyIdempotencyStore($probe, 'kiwicaptcha', 1);
        $lost = $this->lostConsumeReplyStorage($storage);

        try {
            $owner = new SiteVerifyController(new Verifier($lost), self::SECRET, [$secret1 => 'login'], $lost, null, null, $store, null, 5.0);
            $ownerResponse = $owner->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => $secret1, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame(503, $ownerResponse->getStatusCode());
            $consumed = $storage->consumedState($nonce);
            self::assertNotNull($consumed, 'the lost-reply 503 must come from the EXECUTED transition — the record must be consumed');
            self::assertSame(hash('sha256', $backendId1."\0".$uuid."\0".hash('sha256', $token)."\0"."ip:127.0.0.1"), $consumed->operationIdentity);
            self::assertNull($consumed->consumedResult, 'consumed_result must be null — the derivation never ran');

            // Secret 2: fresh claim in secret-2's namespace -> Consume-
            // Indeterminate -> 503; after the lease expiry secret-2's
            // retry takes over its own claim — the fingerprint binds the
            // backendId, so it differs from the record's identity (secret
            // 1's): never a resume.
            $s2First = new SiteVerifyController(new Verifier($storage), self::SECRET, [$secret2 => 'login'], $storage, null, null, $store, null, 5.0);
            $s2FirstResponse = $s2First->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => $secret2, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame(503, $s2FirstResponse->getStatusCode());
            usleep(2_500_000);
            $s2Retry = new SiteVerifyController(new Verifier($storage), self::SECRET, [$secret2 => 'login'], $storage, null, null, $store, null, 5.0);
            $s2RetryResponse = $s2Retry->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => $secret2, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame(503, $s2RetryResponse->getStatusCode(), 'a same-scope backend secret can never resume another backend\'s redemption');
            self::assertNull($storage->consumedState($nonce)?->consumedResult);
        } finally {
            $probe->del([$idemKey1, $idemKey2, 'kiwicaptcha:'.$nonce]);
        }
    }

    public function testSameUuidChangedRemoteipConflicts(): void
    {
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }
        $storage = new RedisStorage($probe);
        [$token, , $nonce] = $this->issueSha($storage);
        $uuid = 'c0ffee00-0000-4000-8000-000000000008';
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $idemKey = '{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuid;
        $probe->del([$idemKey]);
        $store = new RedisSiteVerifyIdempotencyStore($probe, 'kiwicaptcha', 1);
        $lost = $this->lostConsumeReplyStorage($storage);

        try {
            $owner = new SiteVerifyController(new Verifier($lost), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $lost, null, null, $store, null, 5.0);
            $ownerResponse = $owner->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame(503, $ownerResponse->getStatusCode());
            self::assertNotNull($storage->consumedState($nonce), 'the lost-reply 503 must come from the EXECUTED transition — the record must be consumed');
            self::assertNull($storage->consumedState($nonce)?->consumedResult, 'consumed_result must be null');

            // Same UUID + changed remoteip: CONFLICT at the claim layer —
            // the fingerprint includes the IP, so the entry is bound to
            // the ORIGINAL remoteip and the retry can never join.
            $conflict = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 5.0);
            $conflictResponse = $conflict->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '203.0.113.9', 'idempotency_key' => $uuid,
            ]));
            self::assertSame(400, $conflictResponse->getStatusCode(), 'a changed remoteip under the same UUID must CONFLICT');
            self::assertSame(['bad-request'], json_decode((string) $conflictResponse->getContent(), true)['error-codes']);
        } finally {
            $probe->del([$idemKey, 'kiwicaptcha:'.$nonce]);
        }
    }

    public function testNoKeyFirstRedemptionThenKeyedReplayCannotResume(): void
    {
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }
        $storage = new RedisStorage($probe);
        [$token, , $nonce] = $this->issueSha($storage);
        $uuidB = 'c0ffee00-0000-4000-8000-000000000009';
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $idemKeyB = '{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuidB;
        $probe->del([$idemKeyB]);
        $store = new RedisSiteVerifyIdempotencyStore($probe, 'kiwicaptcha', 1);

        // The no-key path uses the PLAIN consume: the transition executes
        // WITHOUT any identity — and the reply is lost.
        $lostNoKey = new class($storage) implements \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyRecoveryCapableStorageInterface {
            public function __construct(private readonly \KiwiCaptcha\AtomicStorageInterface $inner)
            {
            }

            public function store(\KiwiCaptcha\ChallengeRecord $record): void
            {
                $this->inner->store($record);
            }

            public function find(string $nonce): ?\KiwiCaptcha\ChallengeRecord
            {
                return $this->inner->find($nonce);
            }

            public function consumedState(string $nonce): ?\KiwiCaptcha\ConsumedRecord
            {
                return $this->inner->consumedState($nonce);
            }

            public function consume(string $nonce): ?\KiwiCaptcha\ConsumedRecord
            {
                $this->inner->consume($nonce);

                throw new \RuntimeException('consume reply lost after the transition');
            }

            public function consumeWithOperationIdentity(string $nonce, ?string $operationIdentity): ?\KiwiCaptcha\ConsumedRecord
            {
                return $this->inner->consumeWithOperationIdentity($nonce, $operationIdentity);
            }

            public function commitResult(string $nonce, bool $valid, ?string $binding): bool
            {
                return $this->inner->commitResult($nonce, $valid, $binding);
            }

            public function delete(string $nonce): void
            {
                $this->inner->delete($nonce);
            }
        };

        try {
            $owner = new SiteVerifyController(new Verifier($lostNoKey), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $lostNoKey, null, null, $store, null, 5.0);
            $ownerResponse = $owner->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1',
            ]));
            self::assertSame(503, $ownerResponse->getStatusCode());
            self::assertNull($storage->consumedState($nonce)?->operationIdentity, 'the no-key redemption records NO operation identity');

            // The keyed replay: fresh claim, the identity is null so the
            // gate refuses, and the ordinary verify stays
            // ConsumeIndeterminate — 503, never a resume.
            $keyed = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 5.0);
            $keyedResponse = $keyed->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidB,
            ]));
            self::assertSame(503, $keyedResponse->getStatusCode(), 'a keyed replay of a no-key redemption must NEVER resume');
            self::assertNull($store->stored($backendId, $uuidB), 'the keyed replay must not finalize anything');
            self::assertNull($storage->consumedState($nonce)?->consumedResult);
        } finally {
            $probe->del([$idemKeyB, 'kiwicaptcha:'.$nonce]);
        }
    }

    public function testArgonAdmissionUnavailableDuringResumeThenRetrySucceeds(): void
    {
        \BelConsulting\KiwiCaptchaBundle\Security\InProcessArgonGate::resetForTests();
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            \BelConsulting\KiwiCaptchaBundle\Security\InProcessArgonGate::resetForTests();

            return;
        }
        try {
            $storage = new RedisStorage($probe);
            [$token, $challenge] = $this->issueArgon($storage);
            $nonce = $challenge->nonce;
            $uuid = 'c0ffee00-0000-4000-8000-00000000000a';
            $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
            $idemKey = '{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuid;
            $probe->del([$idemKey]);
            $store = new RedisSiteVerifyIdempotencyStore($probe, 'kiwicaptcha', 1);
            $lost = $this->lostConsumeReplyStorage($storage);

            $owner = new SiteVerifyController(new Verifier($lost), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $lost, null, null, $store, null, 5.0);
            $ownerResponse = $owner->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame(503, $ownerResponse->getStatusCode());
            $consumed = $storage->consumedState($nonce);
            self::assertNotNull($consumed, 'the lost-reply 503 must come from the EXECUTED transition — the record must be consumed');
            self::assertSame(
                hash('sha256', $backendId."\0".$uuid."\0".hash('sha256', $token)."\0"."ip:127.0.0.1"),
                $consumed->operationIdentity,
            );
            self::assertNull($consumed->consumedResult, 'precondition: nothing committed yet');

            // The retry resumes with a SATURATED admission gate: the
            // resumed Argon derivation is refused (CapacityExceeded ->
            // 503 internal-error) WITHOUT committing or finalizing.
            usleep(2_500_000);
            $gate = new \BelConsulting\KiwiCaptchaBundle\Security\InProcessArgonGate(1);
            $outsideLease = $gate->acquire();
            self::assertIsString($outsideLease);
            $gated = new SiteVerifyController(new Verifier($storage, $gate), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 5.0);
            $gatedResponse = $gated->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame(503, $gatedResponse->getStatusCode(), 'admission exhaustion during the resume must map to the retryable 503');
            self::assertSame(['internal-error'], json_decode((string) $gatedResponse->getContent(), true)['error-codes']);
            self::assertNull($storage->consumedState($nonce)?->consumedResult, 'admission rejection must NOT commit anything');
            self::assertNull($store->stored($backendId, $uuid), 'the admission rejection must NOT finalize');

            // Capacity freed: the next same-key retry resumes to the
            // ORIGINAL success.
            usleep(2_500_000);
            $gate->release($outsideLease);
            $retry = new SiteVerifyController(new Verifier($storage, $gate), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 5.0);
            $retryResponse = $retry->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame(true, json_decode((string) $retryResponse->getContent(), true)['success'] ?? null, 'with admission capacity available the resume must succeed: '.(string) $retryResponse->getContent());
            self::assertNotNull($storage->consumedState($nonce)?->consumedResult);
        } finally {
            \BelConsulting\KiwiCaptchaBundle\Security\InProcessArgonGate::resetForTests();
            $probe->del([$idemKey, 'kiwicaptcha:'.$nonce]);
        }
    }

    public function testCommitReplyLostReadsBackTheStoredResult(): void
    {
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }
        $storage = new RedisStorage($probe);
        [$token, , $nonce] = $this->issueSha($storage);
        $uuid = 'c0ffee00-0000-4000-8000-00000000000b';
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $idemKey = '{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuid;
        $probe->del([$idemKey]);
        $store = new RedisSiteVerifyIdempotencyStore($probe, 'kiwicaptcha', 1);
        $lost = $this->lostConsumeReplyStorage($storage);

        try {
            $owner = new SiteVerifyController(new Verifier($lost), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $lost, null, null, $store, null, 5.0);
            $ownerResponse = $owner->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame(503, $ownerResponse->getStatusCode());
            $consumed = $storage->consumedState($nonce);
            self::assertNotNull($consumed, 'the lost-reply 503 must come from the EXECUTED transition — the record must be consumed');
            self::assertSame(
                hash('sha256', $backendId."\0".$uuid."\0".hash('sha256', $token)."\0"."ip:127.0.0.1"),
                $consumed->operationIdentity,
            );
            self::assertNull($consumed->consumedResult, 'precondition: nothing committed yet');

            // The retry's RESUME hits a lost COMMIT reply: the commit
            // executes on real Redis and the reply is then lost — the
            // read-after-failed-commit resolves the stored result.
            $lostCommit = new class($storage) implements \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyRecoveryCapableStorageInterface {
                public function __construct(private readonly \KiwiCaptcha\AtomicStorageInterface $inner)
                {
                }

                public function store(\KiwiCaptcha\ChallengeRecord $record): void
                {
                    $this->inner->store($record);
                }

                public function find(string $nonce): ?\KiwiCaptcha\ChallengeRecord
                {
                    return $this->inner->find($nonce);
                }

                public function consumedState(string $nonce): ?\KiwiCaptcha\ConsumedRecord
                {
                    return $this->inner->consumedState($nonce);
                }

                public function consume(string $nonce): ?\KiwiCaptcha\ConsumedRecord
                {
                    return $this->inner->consume($nonce);
                }

                public function consumeWithOperationIdentity(string $nonce, ?string $operationIdentity): ?\KiwiCaptcha\ConsumedRecord
                {
                    return $this->inner->consumeWithOperationIdentity($nonce, $operationIdentity);
                }

                public function commitResult(string $nonce, bool $valid, ?string $binding): bool
                {
                    // The commit EXECUTES (the result lands) — and the
                    // reply is then lost.
                    $result = $this->inner->commitResult($nonce, $valid, $binding);

                    throw new \RuntimeException('commit reply lost after the commit');
                }

                public function delete(string $nonce): void
                {
                    $this->inner->delete($nonce);
                }
            };
            usleep(2_500_000);
            $retry = new SiteVerifyController(new Verifier($lostCommit), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $lostCommit, null, null, $store, null, 5.0);
            $retryResponse = $retry->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            $retryBody = json_decode((string) $retryResponse->getContent(), true);
            self::assertSame(true, $retryBody['success'] ?? null, 'the read-after-failed-commit must resolve the winner\'s stored result: '.(string) $retryResponse->getContent());
            self::assertSame($this->expectedCanonicalSuccess($storage, $nonce), (string) $retryResponse->getContent(), 'the retry receives the ORIGINAL canonical success bytes');
            $after = $storage->consumedState($nonce);
            self::assertNotNull($after?->consumedResult, 'the commit really landed on real Redis');
            self::assertSame(true, $after->consumedResult->valid);
        } finally {
            $probe->del([$idemKey, 'kiwicaptcha:'.$nonce]);
        }
    }

    public function testTwoRecoveryAttemptsResolveOneDeterministicRetainedResult(): void
    {
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }
        $storage = new RedisStorage($probe);
        [$token, , $nonce] = $this->issueSha($storage);
        $uuid = 'c0ffee00-0000-4000-8000-00000000000c';
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $idemKey = '{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuid;
        $probe->del([$idemKey]);
        $store = new RedisSiteVerifyIdempotencyStore($probe, 'kiwicaptcha', 1);
        $lost = $this->lostConsumeReplyStorage($storage);
        $fingerprint = hash('sha256', $backendId."\0".$uuid."\0".hash('sha256', $token)."\0"."ip:127.0.0.1");

        try {
            $owner = new SiteVerifyController(new Verifier($lost), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $lost, null, null, $store, null, 5.0);
            $ownerResponse = $owner->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame(503, $ownerResponse->getStatusCode());
            $consumed = $storage->consumedState($nonce);
            self::assertNotNull($consumed, 'the lost-reply 503 must come from the EXECUTED transition — the record must be consumed');
            self::assertSame($fingerprint, $consumed->operationIdentity);
            self::assertNull($consumed->consumedResult, 'consumed_result must be null — the derivation never ran');

            usleep(2_500_000);
            // Attempt A: the takeover wins and resumes (commits).
            $retryA = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 5.0);
            $retryAResponse = $retryA->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            $retryABody = json_decode((string) $retryAResponse->getContent(), true);
            self::assertSame(true, $retryABody['success'] ?? null, 'recovery attempt A resumes and commits: '.(string) $retryAResponse->getContent());

            // Attempt B — a second verifier over the same real store: the
            // committed result resolves the SAME outcome (fast path, no
            // re-derivation), and the claim layer returns the identical
            // stored bytes.
            $direct = (new Verifier($storage))->resumeConsumedOperation($token, self::SECRET, $fingerprint, 'login', '127.0.0.1');
            self::assertTrue($direct->isOk(), sprintf('the second verifier resolves the retained result, got %s', $direct->code()));
            self::assertSame($nonce, $direct->nonce());
            $retryB = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 5.0);
            $retryBResponse = $retryB->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame((string) $retryAResponse->getContent(), (string) $retryBResponse->getContent(), 'both recovery attempts see the IDENTICAL deterministic result');
            $after = $storage->consumedState($nonce);
            self::assertNotNull($after?->consumedResult, 'exactly ONE deterministic result is retained');
            self::assertSame(true, $after->consumedResult->valid);
        } finally {
            $probe->del([$idemKey, 'kiwicaptcha:'.$nonce]);
        }
    }
}
