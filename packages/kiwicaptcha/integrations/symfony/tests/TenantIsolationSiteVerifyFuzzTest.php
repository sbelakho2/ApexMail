<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\SiteVerifyController;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\IdempotencyClaim;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisSiteVerifyIdempotencyStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * SiteVerify backend-compartment fuzzing on one real Redis: each
 * configured provider secret owns an idempotency namespace derived
 * from its secret, its expected scope, the security-policy epoch and
 * the deployment security-context digest. Two secrets on one Redis
 * must never share idempotency state, and a rotated secret or a
 * rotated security context must move the namespace instead of
 * replaying cached bytes.
 *
 * Properties under test: a same-key collision across secrets resolves
 * in separate namespaces, the namespace key sets are disjoint, and a
 * cross-secret retry with the same key and token evaluates fresh: the
 * consumed token fails while the cached success stays untouched.
 * A rotated digest or epoch likewise starts a fresh logical
 * operation.
 *
 * Runs when `KC_REDIS_URL` or `TEST_REDIS_URL` is set; the
 * `KIWI_REQUIRE_REAL_REDIS_TESTS` flag turns a missing environment
 * into a hard failure in the dedicated real-Redis lane.
 */
final class TenantIsolationSiteVerifyFuzzTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const SECRET_A = 'provider-secret-alpha-01';

    private const SECRET_B = 'provider-secret-beta-02';

    private const SCOPE_A = 'login';

    private const SCOPE_B = 'register';

    private const NS = 'iso-siteverify';

    private \Predis\Client $client;

    private RedisStorage $storage;

    private RedisSiteVerifyIdempotencyStore $store;

    protected function setUp(): void
    {
        $url = RedisTestUrl::resolve();
        if ($url === null) {
            $this->failIfRealRedisRequired('no Redis test URL (KC_REDIS_URL / TEST_REDIS_URL) is set');
            self::markTestSkipped('no Redis test URL (KC_REDIS_URL / TEST_REDIS_URL) — real-Redis SiteVerify isolation fuzz skipped');
        }
        if (!\class_exists(\Predis\Client::class)) {
            $this->failIfRealRedisRequired('predis/predis is not installed');
            self::markTestSkipped('predis/predis not installed');
        }
        try {
            $probe = new \Predis\Client($url, ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
            $probe->ping();
        } catch (\Throwable $e) {
            $this->failIfRealRedisRequired('Redis is unreachable at the configured URL');
            self::markTestSkipped('Redis unreachable: '.$e->getMessage());
        }
        $probe->flushdb();
        $this->client = $probe;
        $this->storage = new RedisStorage($probe, 'iso-siteverify:');
        $this->store = new RedisSiteVerifyIdempotencyStore($probe, self::NS);
    }

    private function failIfRealRedisRequired(string $why): void
    {
        $flag = getenv('KIWI_REQUIRE_REAL_REDIS_TESTS');
        if (\is_string($flag) && $flag !== '' && $flag !== '0') {
            self::fail('KIWI_REQUIRE_REAL_REDIS_TESTS is set but '.$why.' — the SiteVerify isolation fuzz must run in the real-Redis CI lane');
        }
    }

    /** @return array{0: string, 1: string} [token, nonce] */
    private function issueAndSolve(string $scope): array
    {
        $issuer = new Issuer(
            new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120),
            $this->storage,
        );
        $challenge = $issuer->issue($scope, '127.0.0.1');
        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;
        usleep(($challenge->minDurationMs + 10) * 1000);

        return [SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode(), $challenge->nonce];
    }

    private function controller(int $policyVersion = 0, ?string $digest = null, array $secrets = [self::SECRET_A => self::SCOPE_A, self::SECRET_B => self::SCOPE_B]): SiteVerifyController
    {
        return new SiteVerifyController(
            new Verifier($this->storage),
            self::SECRET,
            $secrets,
            $this->storage,
            null,
            null,
            $this->store,
            null,
            2.0,
            $policyVersion,
            $digest,
        );
    }

    private function siteverifyRequest(array $fields): Request
    {
        return Request::create(
            '/kiwi-captcha/siteverify',
            'POST',
            [],
            [],
            [],
            ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'],
            (string) http_build_query($fields),
        );
    }

    /** @return array{success: bool, error-codes: list<string>|null} */
    private function body(SiteVerifyController $controller, array $fields): array
    {
        $response = $controller->siteverify($this->siteverifyRequest($fields));
        $data = json_decode((string) $response->getContent(), true, flags: JSON_THROW_ON_ERROR);

        return [
            'success' => ($data['success'] ?? null) === true,
            'error-codes' => $data['error-codes'] ?? null,
        ];
    }

    private function backendId(string $secret, string $scope, int $epoch, ?string $digest): string
    {
        return hash('sha256', $secret.'|'.$scope.'|'.$epoch.'|'.($digest ?? ''));
    }

    private function idempotencyKeys(string $idempotencyKey): array
    {
        return $this->client->keys('{'.self::NS.'}:siteverify-idem:*:'.$idempotencyKey);
    }

    public function testCrossSecretSameKeyNeverSharesIdempotencyState(): void
    {
        $controller = $this->controller();
        $uuid = 'f47ac10b-58cc-4372-a567-0e02b2c3d479';

        [$tokenA] = $this->issueAndSolve(self::SCOPE_A);
        $first = $this->body($controller, [
            'secret' => self::SECRET_A,
            'response' => $tokenA,
            'remoteip' => '127.0.0.1',
            'idempotency_key' => $uuid,
        ]);
        self::assertTrue($first['success'], 'the first redemption under secret A must succeed');

        $retryA = $this->body($controller, [
            'secret' => self::SECRET_A,
            'response' => $tokenA,
            'remoteip' => '127.0.0.1',
            'idempotency_key' => $uuid,
        ]);
        self::assertTrue($retryA['success'], 'the same-key retry under secret A must replay the cached success');

        // A fresh token under the other secret and the same key must
        // evaluate in the B namespace: the login-scoped token fails the
        // register scope there, and it must never see the A cached
        // success.
        [$tokenB] = $this->issueAndSolve(self::SCOPE_A);
        $crossSecret = $this->body($controller, [
            'secret' => self::SECRET_B,
            'response' => $tokenB,
            'remoteip' => '127.0.0.1',
            'idempotency_key' => $uuid,
        ]);
        self::assertFalse($crossSecret['success'], 'a cross-secret same-key request must evaluate fresh and fail');

        $keys = $this->idempotencyKeys($uuid);
        self::assertCount(2, $keys, 'the same idempotency key under two secrets must own two literal keys');
        self::assertNotSame($keys[0], $keys[1], 'the two backend namespaces must be disjoint literals');

        $retryA2 = $this->body($controller, [
            'secret' => self::SECRET_A,
            'response' => $tokenA,
            'remoteip' => '127.0.0.1',
            'idempotency_key' => $uuid,
        ]);
        self::assertTrue($retryA2['success'], 'the B request must leave the A namespace untouched');
    }

    public function testStoreLevelSameKeyAcrossSecretsIsClaimedTwice(): void
    {
        $idA = $this->backendId(self::SECRET_A, self::SCOPE_A, 0, null);
        $idB = $this->backendId(self::SECRET_B, self::SCOPE_B, 0, null);
        self::assertNotSame($idA, $idB, 'the backend identity must differ across secrets');

        $uuid = 'f47ac10b-58cc-4372-a567-0e02b2c3d480';
        [$claimA, $ownerA] = $this->store->claim($idA, $uuid, hash('sha256', 'response-A'), 300, 'fp');
        self::assertSame(IdempotencyClaim::Claimed, $claimA, 'the A namespace must claim the key');
        self::assertIsString($ownerA);

        [$claimB, $ownerB] = $this->store->claim($idB, $uuid, hash('sha256', 'response-B'), 300, 'fp');
        self::assertSame(
            IdempotencyClaim::Claimed,
            $claimB,
            'the B namespace must claim the same key independently; a shared namespace would conflict on a different response hash',
        );
        self::assertIsString($ownerB);

        self::assertTrue(
            $this->store->finalize($idA, $uuid, hash('sha256', 'response-A'), $ownerA, ['success' => true]),
            'the A owner must finalize its own namespace',
        );
        self::assertIsArray($this->store->stored($idA, $uuid), 'the A namespace must hold the finalized record');
        self::assertNull($this->store->stored($idB, $uuid), 'the B namespace must remain untouched');

        $keys = $this->idempotencyKeys($uuid);
        self::assertCount(2, $keys, 'each backend namespace must own its literal key');
    }

    public function testRotatedSecurityContextSeparatesNamespaces(): void
    {
        $digestA = hash('sha256', 'deployment-A');
        $digestB = hash('sha256', 'deployment-B');
        $controllerA = $this->controller(digest: $digestA);
        $uuid = 'f47ac10b-58cc-4372-a567-0e02b2c3d481';

        [$tokenA] = $this->issueAndSolve(self::SCOPE_A);
        $first = $this->body($controllerA, [
            'secret' => self::SECRET_A,
            'response' => $tokenA,
            'remoteip' => '127.0.0.1',
            'idempotency_key' => $uuid,
        ]);
        self::assertTrue($first['success'], 'the deployment A context must succeed');

        // A rotated digest moves the namespace: the same key and the
        // same consumed token under B evaluate fresh, so the consumed
        // token fails instead of replaying the A cached success.
        $controllerB = $this->controller(digest: $digestB);
        $rotated = $this->body($controllerB, [
            'secret' => self::SECRET_A,
            'response' => $tokenA,
            'remoteip' => '127.0.0.1',
            'idempotency_key' => $uuid,
        ]);
        self::assertFalse($rotated['success'], 'a rotated security context must never replay the cached success');

        $keys = $this->idempotencyKeys($uuid);
        self::assertCount(2, $keys, 'the rotated digest must own a separate literal key');
    }

    public function testPolicyEpochSeparatesNamespaces(): void
    {
        $uuid = 'f47ac10b-58cc-4372-a567-0e02b2c3d482';
        $idEpoch0 = $this->backendId(self::SECRET_A, self::SCOPE_A, 0, null);
        $idEpoch2 = $this->backendId(self::SECRET_A, self::SCOPE_A, 2, null);
        self::assertNotSame($idEpoch0, $idEpoch2, 'the backend identity must differ across policy epochs');

        [$claim0, $owner0] = $this->store->claim($idEpoch0, $uuid, hash('sha256', 'epoch-0'), 300, 'fp');
        self::assertSame(IdempotencyClaim::Claimed, $claim0);
        self::assertTrue($this->store->finalize($idEpoch0, $uuid, hash('sha256', 'epoch-0'), $owner0, ['success' => true]));

        [$claim2, $owner2] = $this->store->claim($idEpoch2, $uuid, hash('sha256', 'epoch-2'), 300, 'fp');
        self::assertSame(
            IdempotencyClaim::Claimed,
            $claim2,
            'a policy-epoch bump must start a fresh logical operation for the same key',
        );
        self::assertIsString($owner2);
        self::assertNull($this->store->stored($idEpoch2, $uuid), 'the new epoch namespace must be untouched');

        $keys = $this->idempotencyKeys($uuid);
        self::assertCount(2, $keys, 'each epoch must own its literal key');
    }
}
