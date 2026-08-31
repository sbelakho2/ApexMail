<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\SiteVerifyController;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\IdempotencyClaim;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisSiteVerifyIdempotencyStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyRecoveryCapableStorageInterface;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Adversarial fault injection over the provider-compatible Siteverify
 * surface with real Redis: idempotency-key brute force, forged and
 * malformed provider bodies, secret and epoch rotation with a malicious
 * replay, and the claimed-then-abandoned takeover path.
 *
 * Every scenario asserts the fail-closed contract of the whole chain:
 * exactly one logical redemption, deterministic responses, and a 500
 * that never escapes.
 *
 * Runs in the real-Redis CI lane.
 */
final class RealRedisAdversarialSiteVerifyFaultInjectionTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const SITEVERIFY_SECRET = 'compat-secret-42';

    private const NAMESPACE = 'kiwicaptcha';

    private \Predis\Client $client;

    protected function setUp(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis not installed');
        }
        $url = RedisTestUrl::resolve();
        if ($url === null) {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis suites run in the CI Redis-service job');
        }
        $this->client = new \Predis\Client($url, ['timeout' => 10.0, 'read_write_timeout' => 10.0]);
        try {
            $this->client->ping();
        } catch (\Throwable $e) {
            self::markTestSkipped('Redis unreachable at '.$url.': '.$e->getMessage());
        }
        $this->client->flushdb();
    }

    // ── helpers ─────────────────────────────────────────────────────────

    private function siteverifyRequest(array $fields, string $contentType = 'application/x-www-form-urlencoded'): Request
    {
        $body = $contentType === 'application/json' ? json_encode($fields, JSON_THROW_ON_ERROR) : http_build_query($fields);

        return Request::create('/kiwi-captcha/siteverify', 'POST', [], [], [], ['CONTENT_TYPE' => $contentType], (string) $body);
    }

    private function rawJsonRequest(string $body): Request
    {
        return Request::create('/kiwi-captcha/siteverify', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'], $body);
    }

    private function remoteipFingerprint(?string $remoteIp): string
    {
        $trimmed = $remoteIp !== null ? trim($remoteIp) : '';
        if ($trimmed === '') {
            return 'no-ip';
        }
        $binary = @inet_pton($trimmed);
        $canonical = null;
        if ($binary !== false) {
            if (\strlen($binary) === 16 && str_starts_with($binary, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff")) {
                $binary = substr($binary, 12);
            }
            $canonical = (string) inet_ntop($binary);
        }
        $canonical ??= $trimmed;

        return hash_hmac('sha256', 'siteverify-idem-ip-v1|'.$canonical, self::SECRET);
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

    /** @param array<string, string> $secrets */
    private function controller(RedisStorage $storage, ?RedisSiteVerifyIdempotencyStore $idem = null, float $waitSecs = 0.5, int $policyVersion = 0, ?string $securityContextDigest = null, array $secrets = [self::SITEVERIFY_SECRET => 'login']): SiteVerifyController
    {
        return new SiteVerifyController(new Verifier($storage), self::SECRET, $secrets, $storage, null, null, $idem, null, $waitSecs, $policyVersion, $securityContextDigest);
    }

    private function idemKey(string $backendId, string $uuid): string
    {
        return sprintf('{%s}:siteverify-idem:%s:%s', self::NAMESPACE, $backendId, $uuid);
    }

    private function backendId(string $secret, int $epoch = 0, ?string $digest = null): string
    {
        return hash('sha256', $secret.'|login|'.$epoch.'|'.$digest);
    }

    private function operationFingerprint(string $backendId, string $uuid, string $token, ?string $remoteIp = '127.0.0.1', ?string $binding = null): string
    {
        return hash('sha256', $backendId."\0".$uuid."\0".hash('sha256', $token)."\0".$this->remoteipFingerprint($remoteIp)."\0".($binding ?? "\0no-binding"));
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

    private function lostConsumeReplyStorage(\KiwiCaptcha\AtomicStorageInterface $inner): SiteVerifyRecoveryCapableStorageInterface
    {
        return new class($inner) implements SiteVerifyRecoveryCapableStorageInterface {
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
                // The transition executes and the identity lands
                // atomically with the state flip, then the reply is lost.
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

            public function deleteIfPending(string $nonce): \KiwiCaptcha\DeleteIfPendingResult
            {
                return $this->inner->deleteIfPending($nonce);
            }
        };
    }

    // ── 1. idempotency-key brute force ───────────────────────────────────

    public function testIdempotencyKeyBruteForceOneTokenManyKeysExactlyOneRedemption(): void
    {
        $storage = new RedisStorage($this->client);
        [$token, , $nonce] = $this->issueSha($storage);
        $idem = new RedisSiteVerifyIdempotencyStore($this->client, self::NAMESPACE, 3);
        $controller = $this->controller($storage, $idem);
        $backendId = $this->backendId(self::SITEVERIFY_SECRET);

        $keys = [];
        for ($i = 0; $i < 10; ++$i) {
            $keys[] = sprintf('aaaaaaaa-%04d-4b2c-8c3d-0000000000%02d', $i, $i);
        }

        $winnerBody = null;
        $winnerKey = null;
        $loserBodies = [];
        try {
            foreach ($keys as $key) {
                $response = $controller->siteverify($this->siteverifyRequest([
                    'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $key,
                ]));
                self::assertLessThan(500, $response->getStatusCode(), 'a brute-force racer must never answer a 5xx: '.$key);
                $body = (string) $response->getContent();
                if (($this->json($body)['success'] ?? false) === true) {
                    self::assertNull($winnerBody, 'exactly one brute-force key can win');
                    $winnerBody = $body;
                    $winnerKey = $key;
                } else {
                    $loserBodies[] = $body;
                }
            }
            self::assertSame($keys[0], $winnerKey, 'the first key wins the single logical redemption');
            self::assertCount(9, $loserBodies, 'every other key is a deterministic loser');
            foreach ($loserBodies as $body) {
                self::assertSame($loserBodies[0], $body, 'every loser body is byte-identical');
            }
            self::assertSame(['timeout-or-duplicate'], $this->json($loserBodies[0])['error-codes'] ?? null, 'the loser vocabulary is deterministic');

            // Every key finalized a deterministic stored outcome: the
            // winner's canonical success, each loser's duplicate failure.
            foreach ($keys as $i => $key) {
                $stored = $idem->stored($backendId, $key);
                self::assertIsArray($stored, 'the key must finalize a stored result');
                if ($i === 0) {
                    self::assertTrue($stored['success'] ?? false, 'the winner key stores the canonical success');
                } else {
                    self::assertFalse($stored['success'] ?? true, 'a loser key never stores a success');
                    self::assertSame(['timeout-or-duplicate'], $stored['error-codes'] ?? null);
                }
            }

            // Exactly one logical redemption: one committed result, and
            // the consumed record carries the winner's operation identity.
            $consumed = $storage->consumedState($nonce);
            self::assertNotNull($consumed, 'the token is consumed exactly once');
            self::assertNotNull($consumed->consumedResult, 'the winner committed the result');
            self::assertTrue($consumed->consumedResult->valid);
            self::assertSame(
                $this->operationFingerprint($backendId, $keys[0], $token),
                $consumed->operationIdentity,
                'the consumed record carries the winner fingerprint',
            );
            self::assertSame($this->expectedCanonicalSuccess($storage, $nonce), $winnerBody, 'the winner answers the canonical success');
        } finally {
            foreach ($keys as $key) {
                $this->client->del([$this->idemKey($backendId, $key)]);
            }
            $this->client->del([self::NAMESPACE.':'.$nonce]);
        }
    }

    // ── 2. forged and malformed provider bodies ──────────────────────────

    public function testForgedProviderBodiesAreDeterministicNever500(): void
    {
        $storage = new RedisStorage($this->client);
        $idem = new RedisSiteVerifyIdempotencyStore($this->client, self::NAMESPACE, 3);
        $controller = $this->controller($storage, $idem);

        // Every case answers the same deterministic bytes on a repeat and
        // never a status at or above 500. Each case builds a fresh
        // request, because the bounded body read consumes the stream.
        $cases = [
            'array-shaped response' => [
                fn (): Request => $this->rawJsonRequest('{"secret":"'.self::SITEVERIFY_SECRET.'","response":["not-a-token"]}'),
                200,
                'missing-input-response',
            ],
            'array-shaped secret' => [
                fn (): Request => $this->rawJsonRequest('{"secret":["x"],"response":"tok"}'),
                200,
                'missing-input-secret',
            ],
            'duplicate JSON keys' => [
                fn (): Request => $this->rawJsonRequest('{"secret":"'.self::SITEVERIFY_SECRET.'","secret":"x","response":"y"}'),
                400,
                'bad-request',
            ],
            'duplicate form parameters' => [
                fn (): Request => Request::create('/kiwi-captcha/siteverify', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'], 'secret='.self::SITEVERIFY_SECRET.'&secret=other&response=z'),
                400,
                'bad-request',
            ],
            'depth-bomb JSON' => [
                fn (): Request => $this->rawJsonRequest('{"secret":'.str_repeat('[', 33).str_repeat(']', 33).',"secret":"'.self::SITEVERIFY_SECRET.'","response":"x"}'),
                400,
                'bad-request',
            ],
            'oversized response token' => [
                fn (): Request => $this->rawJsonRequest('{"secret":"'.self::SITEVERIFY_SECRET.'","response":"'.str_repeat('a', 9000).'"}'),
                200,
                'invalid-input-response',
            ],
            'oversized body' => [
                fn (): Request => $this->rawJsonRequest('{"secret":"'.self::SITEVERIFY_SECRET.'","response":"'.str_repeat('a', 17_000).'"}'),
                413,
                'bad-request',
            ],
        ];
        foreach ($cases as $context => [$build, $expectedStatus, $expectedCode]) {
            $first = $controller->siteverify($build());
            self::assertLessThan(500, $first->getStatusCode(), $context.' must never answer 5xx');
            self::assertSame($expectedStatus, $first->getStatusCode(), $context.' status');
            self::assertSame($expectedCode, $this->json((string) $first->getContent())['error-codes'][0] ?? null, $context.' code');
            $second = $controller->siteverify($build());
            self::assertSame((string) $first->getContent(), (string) $second->getContent(), $context.' must be byte-deterministic');
        }

        // A valid bound token with an array-shaped remoteip: the IP is
        // treated as absent, so the bound challenge fails closed with the
        // provider invalid-response vocabulary.
        [$token] = $this->issueSha($storage);
        $remoteIpCase = fn (): Request => $this->rawJsonRequest('{"secret":"'.self::SITEVERIFY_SECRET.'","response":"'.$token.'","remoteip":["203.0.113.7"]}');
        $first = $controller->siteverify($remoteIpCase());
        self::assertSame(200, $first->getStatusCode(), 'the array-shaped remoteip must not surface as the retryable 503');
        self::assertSame(['invalid-input-response'], $this->json((string) $first->getContent())['error-codes'] ?? null);
        $second = $controller->siteverify($remoteIpCase());
        self::assertSame((string) $first->getContent(), (string) $second->getContent());

        // A valid token with an array-shaped idempotency key: the key is
        // treated as absent and the redemption is a plain unkeyed one.
        [$token2] = $this->issueSha($storage);
        $keyCase = fn (): Request => $this->rawJsonRequest('{"secret":"'.self::SITEVERIFY_SECRET.'","response":"'.$token2.'","remoteip":"127.0.0.1","idempotency_key":["x"]}');
        $first = $controller->siteverify($keyCase());
        self::assertSame(200, $first->getStatusCode());
        self::assertSame(true, $this->json((string) $first->getContent())['success'] ?? null, 'the array-shaped key is no key');
        $second = $controller->siteverify($keyCase());
        self::assertSame(['timeout-or-duplicate'], $this->json((string) $second->getContent())['error-codes'] ?? null, 'the consumed token answers the duplicate vocabulary');

        // A valid token with an array-shaped request binding: the binding
        // is dropped, so the bound challenge verifies against its IP and
        // the redemption still succeeds deterministically.
        [$token3] = $this->issueSha($storage);
        $bindingCase = fn (): Request => $this->rawJsonRequest('{"secret":"'.self::SITEVERIFY_SECRET.'","response":"'.$token3.'","remoteip":"127.0.0.1","request_binding":["txn-x"]}');
        $first = $controller->siteverify($bindingCase());
        self::assertSame(200, $first->getStatusCode());
        self::assertSame(true, $this->json((string) $first->getContent())['success'] ?? null, 'the array-shaped binding is inert');
        $second = $controller->siteverify($bindingCase());
        self::assertSame(['timeout-or-duplicate'], $this->json((string) $second->getContent())['error-codes'] ?? null, 'the consumed token answers the duplicate vocabulary');
    }

    public function testDecoyArmedEnvelopeWithArrayShapedDecoyFieldsIsDeterministic(): void
    {
        $storage = new RedisStorage($this->client);
        $idem = new RedisSiteVerifyIdempotencyStore($this->client, self::NAMESPACE, 3);
        $controller = $this->controller($storage, $idem);
        [$token, , $nonce] = $this->issueSha($storage);
        $backendId = $this->backendId(self::SITEVERIFY_SECRET);
        $uuid = 'bbbbbbbb-0001-4b2c-8c3d-000000000101';

        // The envelope carries array-shaped decoy-shaped fields next to
        // the genuine redemption fields; the parse must ignore them.
        $envelope = fn (): Request => $this->rawJsonRequest('{"secret":"'.self::SITEVERIFY_SECRET.'","response":"'.$token.'","remoteip":"127.0.0.1","idempotency_key":"'.$uuid.'","honeypot":["a","b"],"decoy_field_xyz":[],"billing_address_line":["x"]}');
        try {
            $first = $controller->siteverify($envelope());
            self::assertSame(200, $first->getStatusCode(), 'the decoy-armed envelope must not break the genuine redemption');
            self::assertSame(true, $this->json((string) $first->getContent())['success'] ?? null);
            $stored = $idem->stored($backendId, $uuid);
            self::assertIsArray($stored, 'the keyed redemption finalizes');
            self::assertSame(true, $stored['success'] ?? false);

            // The same-key retry replays the identical stored bytes.
            $retry = $controller->siteverify($envelope());
            self::assertSame((string) $first->getContent(), (string) $retry->getContent(), 'the decoy-armed retry returns the stored outcome');
            self::assertSame($this->expectedCanonicalSuccess($storage, $nonce), (string) $first->getContent());
        } finally {
            $this->client->del([$this->idemKey($backendId, $uuid), self::NAMESPACE.':'.$nonce]);
        }
    }

    // ── 3. rotation mid-flight with a malicious replay ───────────────────

    public function testSecretRotationMidFlightMaliciousReplayFailsClosedAndTheOriginalContextRecovers(): void
    {
        $storage = new RedisStorage($this->client);
        [$token, , $nonce] = $this->issueSha($storage);
        $secret1 = 'secret-one-'.str_repeat('a', 16);
        $secret2 = 'secret-two-'.str_repeat('b', 16);
        $uuid = 'cccccccc-0002-4b2c-8c3d-000000000202';
        $backendId1 = $this->backendId($secret1);
        $backendId2 = $this->backendId($secret2);
        $idemKey1 = $this->idemKey($backendId1, $uuid);
        $idemKey2 = $this->idemKey($backendId2, $uuid);
        $idem = new RedisSiteVerifyIdempotencyStore($this->client, self::NAMESPACE, 1);
        $lost = $this->lostConsumeReplyStorage($storage);

        try {
            // The legitimate owner under secret 1: consume executed, the
            // reply lost, the entry pending under backend-1.
            $owner = new SiteVerifyController(new Verifier($lost), self::SECRET, [$secret1 => 'login'], $lost, null, null, $idem, null, 0.5);
            $ownerResponse = $owner->siteverify($this->siteverifyRequest([
                'secret' => $secret1, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame(503, $ownerResponse->getStatusCode(), 'the lost reply is the retryable 503');
            $consumed = $storage->consumedState($nonce);
            self::assertNotNull($consumed);
            self::assertSame($this->operationFingerprint($backendId1, $uuid, $token), $consumed->operationIdentity, 'the identity lands under backend-1');

            // The malicious replay with the rotated backend secret 2: a
            // fresh namespace, the resultless consumed record refuses the
            // reconstruction, nothing is finalized, never a 500.
            $attacker = $this->controller($storage, $idem, 0.5, 0, null, [$secret2 => 'login']);
            $malicious = $attacker->siteverify($this->siteverifyRequest([
                'secret' => $secret2, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame(503, $malicious->getStatusCode(), 'the rotated retry must fail closed');
            self::assertSame(['internal-error'], $this->json((string) $malicious->getContent())['error-codes']);
            self::assertNull($idem->stored($backendId2, $uuid), 'the rotated namespace finalizes nothing');
            self::assertNull($storage->consumedState($nonce)?->consumedResult, 'the record stays resultless');

            // The same malicious replay under a different key is refused
            // with the same deterministic fail-closed response.
            $uuidOther = 'cccccccc-0002-4b2c-8c3d-000000000203';
            $idemKeyOther = $this->idemKey($backendId2, $uuidOther);
            $otherReplay = $attacker->siteverify($this->siteverifyRequest([
                'secret' => $secret2, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidOther,
            ]));
            self::assertSame(503, $otherReplay->getStatusCode(), 'a different-key rotated replay must fail closed too');
            self::assertSame(['internal-error'], $this->json((string) $otherReplay->getContent())['error-codes']);
            self::assertNull($idem->stored($backendId2, $uuidOther), 'the different-key replay finalizes nothing');

            // After the lease expires the same-context retry (secret 1)
            // takes over its own pending claim and resumes the original
            // success: the rotation isolated the namespaces, it never
            // destroyed the recovery evidence.
            $this->waitForLeaseExpiry($idemKey1);
            $recovery = $this->controller($storage, $idem, 0.5, 0, null, [$secret1 => 'login']);
            $recoveryResponse = $recovery->siteverify($this->siteverifyRequest([
                'secret' => $secret1, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame(200, $recoveryResponse->getStatusCode());
            self::assertSame(true, $this->json((string) $recoveryResponse->getContent())['success'] ?? null, 'the secret-1 context still recovers its success');
            self::assertSame($this->expectedCanonicalSuccess($storage, $nonce), (string) $recoveryResponse->getContent());
            self::assertNull($idem->stored($backendId2, $uuid), 'the secret-2 namespace stays untouched');

            // The attacker replays under secret 2 after the recovery: the
            // secret-1 success never leaks through the rotated backend.
            $lateReplay = $attacker->siteverify($this->siteverifyRequest([
                'secret' => $secret2, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            $lateBody = $this->json((string) $lateReplay->getContent());
            self::assertSame(200, $lateReplay->getStatusCode());
            self::assertFalse($lateBody['success'] ?? null, 'the rotated backend must never surface the secret-1 success');
            self::assertSame(['timeout-or-duplicate'], $lateBody['error-codes'] ?? null);
        } finally {
            $this->client->del([$idemKey1, $idemKey2, self::NAMESPACE.':'.$nonce]);
        }
    }

    public function testPolicyEpochRotationMaliciousReplayFailsClosedNeverTheCachedSuccess(): void
    {
        $storage = new RedisStorage($this->client);
        $idem = new RedisSiteVerifyIdempotencyStore($this->client, self::NAMESPACE, 3);

        // A token minted under policy epoch 0.
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120, policyVersion: 0), $storage);
        $challenge = $issuer->issue('login', '127.0.0.1');
        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
        $uuid = 'dddddddd-0003-4b2c-8c3d-000000000303';
        $backendId0 = $this->backendId(self::SITEVERIFY_SECRET, 0);
        $backendId1 = $this->backendId(self::SITEVERIFY_SECRET, 1);
        $idemKey0 = $this->idemKey($backendId0, $uuid);
        $idemKey1 = $this->idemKey($backendId1, $uuid);

        try {
            $verifier0 = new Verifier($storage);
            $verifier0->setExpectedPolicyVersion(0);
            $controller0 = new SiteVerifyController($verifier0, self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $idem, null, 0.5, 0);
            $first = $controller0->siteverify($this->siteverifyRequest([
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame(200, $first->getStatusCode());
            self::assertSame(true, $this->json((string) $first->getContent())['success'] ?? null);
            self::assertSame(true, ($idem->stored($backendId0, $uuid)['success'] ?? false) === true, 'the epoch-0 namespace caches the success');

            // The epoch rotates to 1; the malicious replay with the same
            // key lands in the epoch-1 namespace and the signed epoch-0
            // record fails closed.
            $verifier1 = new Verifier($storage);
            $verifier1->setExpectedPolicyVersion(1);
            $controller1 = new SiteVerifyController($verifier1, self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $idem, null, 0.5, 1);
            $malicious = $controller1->siteverify($this->siteverifyRequest([
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            $maliciousBody = $this->json((string) $malicious->getContent());
            self::assertSame(200, $malicious->getStatusCode());
            self::assertFalse($maliciousBody['success'] ?? null, 'the epoch-rotated replay must never return the cached success');
            self::assertSame(['invalid-input-response'], $maliciousBody['error-codes'] ?? null, 'the signed-epoch mismatch is the hard provider verdict');
            $stored1 = $idem->stored($backendId1, $uuid);
            self::assertIsArray($stored1, 'the rotated replay finalizes its own deterministic failure');
            self::assertFalse($stored1['success'] ?? true);
            self::assertSame(true, ($idem->stored($backendId0, $uuid)['success'] ?? false) === true, 'the epoch-0 cached success stays untouched');
            self::assertNotNull($storage->consumedState($challenge->nonce)?->consumedResult, 'the epoch-0 redemption committed exactly once');
        } finally {
            $this->client->del([$idemKey0, $idemKey1, self::NAMESPACE.':'.$challenge->nonce]);
        }
    }

    // ── 4. the claimed-then-abandoned takeover ───────────────────────────

    public function testClaimedThenAbandonedRecordReplayedWithTheSameKeyResolvesDeterministically(): void
    {
        $storage = new RedisStorage($this->client);
        [$token, , $nonce] = $this->issueSha($storage);
        $uuid = 'eeeeeeee-0004-4b2c-8c3d-000000000404';
        $backendId = $this->backendId(self::SITEVERIFY_SECRET);
        $idemKey = $this->idemKey($backendId, $uuid);
        $idem = new RedisSiteVerifyIdempotencyStore($this->client, self::NAMESPACE, 1);
        $fingerprint = $this->operationFingerprint($backendId, $uuid, $token);

        try {
            // The claim is made and the token consumed, then the owner
            // abandons the work: the entry stays pending, the consumed
            // record stays resultless, the reply never arrives.
            [$claim] = $idem->claim($backendId, $uuid, hash('sha256', $token), 300, $this->remoteipFingerprint('127.0.0.1'));
            self::assertSame(IdempotencyClaim::Claimed, $claim);
            self::assertNotNull($storage->consumeWithOperationIdentity($nonce, $fingerprint), 'the abandoned owner consumed the token');
            self::assertNull($storage->consumedState($nonce)?->consumedResult);

            // The same-key replay inside the live lease polls the pending
            // entry and answers the retryable 503 within the waiter bound.
            $controller = $this->controller($storage, $idem, 0.5);
            $early = $controller->siteverify($this->siteverifyRequest([
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame(503, $early->getStatusCode(), 'the live-lease replay is the retryable pending error');
            self::assertSame(['internal-error'], $this->json((string) $early->getContent())['error-codes']);
            self::assertNull($storage->consumedState($nonce)?->consumedResult, 'the early replay commits nothing');

            // After the lease expires the takeover path resumes the
            // identity-proven derivation and finalizes exactly once.
            $this->waitForLeaseExpiry($idemKey);
            $taker = $controller->siteverify($this->siteverifyRequest([
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame(200, $taker->getStatusCode(), 'the takeover replay must resolve: '.(string) $taker->getContent());
            self::assertSame(true, $this->json((string) $taker->getContent())['success'] ?? null);
            self::assertSame($this->expectedCanonicalSuccess($storage, $nonce), (string) $taker->getContent());
            $consumed = $storage->consumedState($nonce);
            self::assertNotNull($consumed?->consumedResult, 'exactly one committed result');
            self::assertSame(true, $consumed->consumedResult->valid);

            // A later same-key observer returns the stored bytes.
            $observer = $controller->siteverify($this->siteverifyRequest([
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame((string) $taker->getContent(), (string) $observer->getContent(), 'every observer resolves to the same bytes');
        } finally {
            $this->client->del([$idemKey, self::NAMESPACE.':'.$nonce]);
        }
    }

    // ── shared helpers ───────────────────────────────────────────────────

    /** @return array<string, mixed> */
    private function json(string $body): array
    {
        return json_decode($body, true, 8, JSON_THROW_ON_ERROR);
    }

    /**
     * Wait until the pending entry's lease has expired in Redis time
     * (bounded, deterministic under suite load).
     */
    private function waitForLeaseExpiry(string $idemKey): void
    {
        $waitClient = new \Predis\Client(RedisTestUrl::resolve(), ['timeout' => 10.0, 'read_write_timeout' => 10.0]);
        try {
            $deadline = microtime(true) + 45;
            while (true) {
                $raw = $waitClient->get($idemKey);
                if ($raw === null) {
                    // The claim entry carries a 300s TTL: an absent key is
                    // an anomaly, so fail fast instead of polling out the
                    // whole bound.
                    self::fail('the claim entry vanished before the takeover window could open');
                }
                $rec = json_decode((string) $raw, true, 8, JSON_THROW_ON_ERROR);
                $leaseExpiresAt = (int) ($rec['lease_expires_at'] ?? 0);
                $redisSec = (int) ($waitClient->time()[0]);
                if ($redisSec > $leaseExpiresAt) {
                    return;
                }
                if (microtime(true) >= $deadline) {
                    self::fail('the claim lease never expired — the takeover window was not established');
                }
                usleep(50_000);
            }
        } finally {
            $waitClient->disconnect();
        }
    }
}
