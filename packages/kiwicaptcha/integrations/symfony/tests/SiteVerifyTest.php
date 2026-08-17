<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\SiteVerifyController;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\IdempotencyClaim;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadata;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\ArraySiteVerifyMetadataStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\ArraySiteVerifyIdempotencyStore;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * Round 24: provider-compatible Siteverify golden tests. The endpoint calls
 * the EXACT SAME atomic verifier as the native path and returns the
 * provider-shaped JSON (`success`, `challenge_ts`, `hostname`,
 * `error-codes`).
 */
final class SiteVerifyTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';
    private const SITEVERIFY_SECRET = 'compat-secret-42';

    private function controller(
        array $secrets = [self::SITEVERIFY_SECRET => 'login'],
        ?\BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadataStore $metadataStore = null,
        ?\BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore $idempotencyStore = null,
        ?ArrayStorage $storage = null,
    ): SiteVerifyController {
        $storage ??= new ArrayStorage();
        $verifier = new Verifier($storage);

        return new SiteVerifyController($verifier, self::SECRET, $secrets, $storage, null, $metadataStore, $idempotencyStore);
    }

    private function issuedToken(ArrayStorage $storage, string $scope = 'login', ?string $remoteIp = '127.0.0.1'): array
    {
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $storage);
        $challenge = $issuer->issue($scope, $remoteIp);
        $solution = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits);
        // The timing floor applies server-side (issuance -> verify); the
        // tests must clear minDurationMs like the existing suite does.
        usleep(($challenge->minDurationMs + 10) * 1000);

        return [SolutionToken::create($challenge->nonce, $solution, 5000, [])->encode(), $challenge->nonce];
    }

    private function solve(string $prefix, string $salt, int $targetBits): int
    {
        $saltBytes = base64_decode($salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $targetBits);

        return $counter - 1;
    }

    private function solveSolution(\KiwiCaptcha\ChallengeRecord $record): string
    {
        $saltBytes = base64_decode($record->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $record->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $record->targetBits);

        return \KiwiCaptcha\SolutionToken::create($record->nonce, $counter - 1, 5000, [])->encode();
    }

    public function testDisabledWithoutConfiguredSecret(): void
    {
        $storage = new ArrayStorage();
        $verifier = new Verifier($storage);
        $controller = new SiteVerifyController($verifier, self::SECRET, [], $storage);
        $response = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', ['response' => 'x', 'secret' => 'x']));
        self::assertSame(404, $response->getStatusCode());
    }

    public function testOversizedBodyIsRefusedBeforeParsing(): void
    {
        $controller = $this->controller();
        $request = Request::create('/kiwi-captcha/siteverify', 'POST', [], [], [], [], json_encode(['response' => str_repeat('x', 32 * 1024)]));
        $response = $controller->siteverify($request);
        self::assertSame(413, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('bad-request', $body['error-codes'][0] ?? null);
    }

    public function testInvalidSecretIsRejectedWithProviderCode(): void
    {
        $response = $this->controller()->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', ['response' => 'x', 'secret' => 'wrong']));
        self::assertSame(200, $response->getStatusCode());
        $json = json_decode((string) $response->getContent(), true);
        self::assertFalse($json['success']);
        self::assertSame(['invalid-input-secret'], $json['error-codes']);
    }

    public function testMissingResponseIsRejected(): void
    {
        $response = $this->controller()->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', ['secret' => self::SITEVERIFY_SECRET]));
        self::assertSame(['missing-input-response'], json_decode((string) $response->getContent(), true)['error-codes']);
    }

    public function testValidTokenReturnsProviderShapeWithHostnameAndTs(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $storage);
        $challenge = $issuer->issue('login', '203.0.113.7', null, 'login.example');
        $solution = $this->solveSolution($storage->find($challenge->nonce));
        // The server-measured timing floor applies: the solve must appear
        // to take at least min_duration_ms (mirrors the bundle's flow
        // tests).
        usleep(((int) $challenge->minDurationMs + 10) * 1000);
        $verifier = new Verifier($storage);
        $controller = new SiteVerifyController($verifier, self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage);

        // Form-encoded, with the end-user IP supplied by the trusted backend.
        $response = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'response' => $solution,
            'secret' => self::SITEVERIFY_SECRET,
            'remoteip' => '203.0.113.7',
        ]));
        self::assertSame(200, $response->getStatusCode());
        $json = json_decode((string) $response->getContent(), true);
        self::assertTrue($json['success']);
        self::assertSame([], $json['error-codes']);
        self::assertSame('login.example', $json['hostname'], 'the issuance Host is returned as hostname');
        self::assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/', $json['challenge_ts']);

        // JSON-encoded body works identically — with a FRESH token (the
        // round-26 replay boundary rejects the already-consumed one).
        $challenge2 = $issuer->issue('login', '203.0.113.7', null, 'login.example');
        $solution2 = $this->solveSolution($storage->find($challenge2->nonce));
        usleep(((int) $challenge2->minDurationMs + 10) * 1000);
        $jsonResponse = $controller->siteverify(Request::create(
            '/kiwi-captcha/siteverify',
            'POST',
            [],
            [],
            [],
            ['CONTENT_TYPE' => 'application/json'],
            json_encode(['response' => $solution2, 'secret' => self::SITEVERIFY_SECRET, 'remoteip' => '203.0.113.7']),
        ));
        self::assertTrue(json_decode((string) $jsonResponse->getContent(), true)['success']);
    }

    public function testReplayResolvesToTheStoredDeterministicOutcome(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $storage);
        $challenge = $issuer->issue('login', '203.0.113.7', null, null);
        $solution = $this->solveSolution($storage->find($challenge->nonce));
        usleep(((int) $challenge->minDurationMs + 10) * 1000);
        $verifier = new Verifier($storage);
        $controller = new SiteVerifyController($verifier, self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage);

        $first = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', ['response' => $solution, 'secret' => self::SITEVERIFY_SECRET, 'remoteip' => '203.0.113.7']));
        self::assertTrue(json_decode((string) $first->getContent(), true)['success']);

        // Round 26 (P1): the COMPATIBILITY boundary distinguishes the first
        // redemption from replays. A repeated Siteverify redemption of the
        // same nonce MUST NOT report success again — it returns the
        // provider vocabulary for a consumed token. (The native verifier's
        // deterministic-result retry semantics stay internal.)
        $replay = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', ['response' => $solution, 'secret' => self::SITEVERIFY_SECRET, 'remoteip' => '203.0.113.7']));
        $json = json_decode((string) $replay->getContent(), true);
        self::assertFalse($json['success'], 'a replayed response must not succeed again');
        self::assertSame(['timeout-or-duplicate'], $json['error-codes']);
    }

    public function testCrossSecretScopeEscalationIsRejected(): void
    {
        // Round 26 (P1): the secret resolves the EXPECTED SCOPE — a login
        // token presented to the financial secret is rejected, so a weaker
        // challenge can never satisfy a stronger backend's Siteverify.
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $storage);
        $challenge = $issuer->issue('login', '203.0.113.7');
        $solution = $this->solveSolution($storage->find($challenge->nonce));
        usleep(((int) $challenge->minDurationMs + 10) * 1000);
        $verifier = new Verifier($storage);
        $controller = new SiteVerifyController($verifier, self::SECRET, [
            'secret-login' => 'login',
            'secret-admin' => 'admin_login',
        ], $storage);

        $ok = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', ['response' => $solution, 'secret' => 'secret-login', 'remoteip' => '203.0.113.7']));
        self::assertTrue(json_decode((string) $ok->getContent(), true)['success']);

        // The SAME login token against the admin secret: WrongScope.
        $rejected = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', ['response' => $solution, 'secret' => 'secret-admin', 'remoteip' => '203.0.113.7']));
        $json = json_decode((string) $rejected->getContent(), true);
        self::assertFalse($json['success']);
        self::assertSame(['invalid-input-response'], $json['error-codes']);
    }

    public function testHostnameSurvivesARedisSerializeDeserializeRoundTrip(): void
    {
        // Round 26 (P1): hostname must survive a real serialize -> Redis ->
        // deserialize cycle (ArrayStorage would mask a fromArray() drop).
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        try {
            $redis = new \Predis\Client('tcp://127.0.0.1:6399', ['timeout' => 1.0, 'read_write_timeout' => 1.0]);
            $redis->ping();
        } catch (\Throwable) {
            self::markTestSkipped('no Redis at 127.0.0.1:6399');
        }
        $nonce = base64_encode(random_bytes(32));
        $storage = new \KiwiCaptcha\Storage\RedisStorage($redis);
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $storage);
        try {
            $challenge = $issuer->issue('login', '203.0.113.7', null, 'login.example');
            $solution = $this->solveSolution($storage->find($challenge->nonce));
            usleep(((int) $challenge->minDurationMs + 10) * 1000);
            $verifier = new Verifier($storage);
            $controller = new SiteVerifyController($verifier, self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage);
            $response = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'response' => $solution,
                'secret' => self::SITEVERIFY_SECRET,
                'remoteip' => '203.0.113.7',
            ]));
            $json = json_decode((string) $response->getContent(), true);
            self::assertTrue($json['success']);
            self::assertSame('login.example', $json['hostname'], 'hostname must survive the Redis round-trip');
        } finally {
            $redis->del('kiwicaptcha:'.$nonce);
        }
    }

    public function testExpiredTokenReturnsTimeoutOrDuplicate(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 1), $storage);
        $challenge = $issuer->issue('login', '203.0.113.7');
        $solution = $this->solveSolution($storage->find($challenge->nonce));
        // Wait past the 1s TTL (the record keeps its valid signature — the
        // expiration must come from the server clock, not from re-signing).
        usleep(1_500_000);
        $verifier = new Verifier($storage);
        $controller = new SiteVerifyController($verifier, self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage);
        $response = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', ['response' => $solution, 'secret' => self::SITEVERIFY_SECRET, 'remoteip' => '203.0.113.7']));
        $json = json_decode((string) $response->getContent(), true);
        self::assertFalse($json['success']);
        self::assertSame(['timeout-or-duplicate'], $json['error-codes']);
    }


    // ── Round 30 (P1): provider metadata + idempotency semantics ──────

    public function testMissingSecretMapsToMissingInputSecret(): void
    {
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage);
        $controller = $this->controller();
        $response = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', ['response' => $token]));
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('missing-input-secret', $body['error-codes'][0] ?? null);
    }

    public function testWrongSecretMapsToInvalidInputSecret(): void
    {
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage);
        $controller = $this->controller();
        $response = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', ['secret' => str_repeat('x', 24), 'response' => $token]));
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('invalid-input-secret', $body['error-codes'][0] ?? null);
    }

    public function testMalformedIdempotencyKeyIsRejectedBeforeTheVerifier(): void
    {
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage);
        $controller = $this->controller(secrets: [self::SITEVERIFY_SECRET => 'login'], idempotencyStore: new ArraySiteVerifyIdempotencyStore());
        $response = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET,
            'response' => $token,
            'idempotency_key' => 'not-a-uuid',
        ]));
        self::assertSame(400, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('bad-request', $body['error-codes'][0] ?? null);
    }

    public function testOversizedResponseTokenIsRejectedBeforeDecoding(): void
    {
        $storage = new ArrayStorage();
        $controller = $this->controller();
        $response = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET,
            'response' => str_repeat('A', 9000),
        ]));
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('invalid-input-response', $body['error-codes'][0] ?? null);
    }

    public function testRequestSuppliedActionIsIgnoredAndServerBoundMetadataIsReturned(): void
    {
        // The full trust chain: metadata bound at ISSUANCE (sidecar) is
        // returned on verification; a forged request action/cdata is
        // ignored (it is not even parsed anymore).
        $storage = new ArrayStorage();
        [$token, $nonce] = $this->issuedToken($storage);
        $metadataStore = new ArraySiteVerifyMetadataStore();
        $metadataStore->store($nonce, new SiteVerifyMetadata('checkout', 'order_19382', 'login'), 300);
        $controller = $this->controller(metadataStore: $metadataStore, storage: $storage);

        $response = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET,
            'response' => $token,
            'remoteip' => '127.0.0.1',
            'action' => 'admin',   // forged — must be ignored
            'cdata' => 'forged',   // forged — must be ignored
        ]));
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame(true, $body['success'] ?? null, 'metadata test body: '.(string) $response->getContent());
        self::assertSame('checkout', $body['action'] ?? null);
        self::assertSame('order_19382', $body['cdata'] ?? null);
    }

    public function testIdempotentRetryReturnsTheIdenticalCanonicalResponse(): void
    {
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage);
        $store = new ArraySiteVerifyIdempotencyStore();
        $controller = $this->controller(idempotencyStore: $store, storage: $storage);
        $uuid = '123e4567-e89b-42d3-a456-426614174000';

        $first = json_decode((string) $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]))->getContent(), true);
        self::assertSame(true, $first['success'] ?? null);

        $second = json_decode((string) $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]))->getContent(), true);
        self::assertSame($first, $second, 'a same-key retry must return the IDENTICAL canonical response');

        // Same token + a DIFFERENT key -> timeout-or-duplicate (no idempotency).
        $third = json_decode((string) $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => '223e4567-e89b-42d3-a456-426614174000',
        ]))->getContent(), true);
        self::assertSame(false, $third['success'] ?? null);
        self::assertSame('timeout-or-duplicate', $third['error-codes'][0] ?? null);
    }

    public function testSameKeyWithDifferentTokenIsRejected(): void
    {
        $storage = new ArrayStorage();
        [$tokenA] = $this->issuedToken($storage);
        [$tokenB] = $this->issuedToken($storage);
        $store = new ArraySiteVerifyIdempotencyStore();
        $controller = $this->controller(idempotencyStore: $store);
        $uuid = '323e4567-e89b-42d3-a456-426614174000';

        $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $tokenA, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        $second = json_decode((string) $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $tokenB, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]))->getContent(), true);
        self::assertSame('bad-request', $second['error-codes'][0] ?? null, 'same key + different token must be rejected');
    }

    public function testFailedVerificationFinalizesTheSameCanonicalFailure(): void
    {
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage);
        $store = new ArraySiteVerifyIdempotencyStore();
        $controller = $this->controller(idempotencyStore: $store);
        $uuid = '423e4567-e89b-42d3-a456-426614174000';
        // A WRONG remoteip makes the bound verification fail.
        $first = json_decode((string) $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '203.0.113.9', 'idempotency_key' => $uuid,
        ]))->getContent(), true);
        self::assertSame(false, $first['success'] ?? null);
        // Retry with the correct remoteip and the SAME key -> the SAME
        // canonical failure (idempotency freezes the outcome).
        $second = json_decode((string) $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]))->getContent(), true);
        self::assertSame($first, $second);
    }

    public function testIdempotencyNamespacesDoNotCollideAcrossSecrets(): void
    {
        // Different configured secrets (backends) share the same UUID
        // WITHOUT colliding: each backend's namespace is separate, so each
        // claims and succeeds with its own token.
        $storage = new ArrayStorage();
        [$tokenA] = $this->issuedToken($storage);
        [$tokenB] = $this->issuedToken($storage);
        $store = new ArraySiteVerifyIdempotencyStore();
        $uuid = '523e4567-e89b-42d3-a456-426614174000';
        $controllerA = $this->controller(secrets: ['secret-A-'.str_repeat('a', 16) => 'login'], idempotencyStore: $store, storage: $storage);
        $controllerB = $this->controller(secrets: ['secret-B-'.str_repeat('b', 16) => 'login'], idempotencyStore: $store, storage: $storage);
        $first = json_decode((string) $controllerA->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => 'secret-A-'.str_repeat('a', 16), 'response' => $tokenA, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]))->getContent(), true);
        self::assertSame(true, $first['success'] ?? null);
        $second = json_decode((string) $controllerB->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => 'secret-B-'.str_repeat('b', 16), 'response' => $tokenB, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]))->getContent(), true);
        self::assertSame(true, $second['success'] ?? null, 'different backends must not collide on the same UUID');
    }

    // ── Round 31 (P2): the owner lease + atomic takeover ───────────────

    public function testTakeoverReturnsTookOverToExactlyOneWaiterAfterLeaseExpiry(): void
    {
        $now = 1_700_000_000;
        $clock = static function () use (&$now): int {
            return $now;
        };
        $store = new ArraySiteVerifyIdempotencyStore($clock);
        $backendId = hash('sha256', self::SITEVERIFY_SECRET);
        $uuid = '623e4567-e89b-42d3-a456-426614174000';
        $hash = 'response-hash';

        [$claim, $owner] = $store->claim($backendId, $uuid, $hash, 300);
        self::assertSame(IdempotencyClaim::Claimed, $claim);
        self::assertNotNull($owner);

        [$second] = $store->claim($backendId, $uuid, $hash, 300);
        self::assertSame(IdempotencyClaim::PendingSame, $second);

        // While the owner's lease is valid the takeover attempt is a no-op.
        [$whileHeld] = $store->takeover($backendId, $uuid, $hash, 300);
        self::assertSame(IdempotencyClaim::StillPending, $whileHeld);

        // Expire the lease: exactly ONE caller may win the takeover; the
        // loser must see the record unchanged (the winner's refreshed
        // lease keeps it pending).
        $now += 31;
        [$first, $newOwner] = $store->takeover($backendId, $uuid, $hash, 300);
        self::assertSame(IdempotencyClaim::TookOver, $first);
        self::assertNotNull($newOwner);
        [$secondTakeover] = $store->takeover($backendId, $uuid, $hash, 300);
        self::assertSame(IdempotencyClaim::StillPending, $secondTakeover, 'the loser sees StillPending — the winner refreshed the lease');
    }

    public function testFinalizeByTheOldOwnerIsRefusedAfterTakeover(): void
    {
        $now = 1_700_000_000;
        $clock = static function () use (&$now): int {
            return $now;
        };
        $store = new ArraySiteVerifyIdempotencyStore($clock);
        $backendId = hash('sha256', self::SITEVERIFY_SECRET);
        $uuid = '723e4567-e89b-42d3-a456-426614174000';
        $hash = 'response-hash';

        [$claim, $oldOwner] = $store->claim($backendId, $uuid, $hash, 300);
        self::assertSame(IdempotencyClaim::Claimed, $claim);

        $now += 31;
        [$takeover, $newOwner] = $store->takeover($backendId, $uuid, $hash, 300);
        self::assertSame(IdempotencyClaim::TookOver, $takeover);

        // The crashed owner's finalize must be a no-op after the takeover.
        $store->finalize($backendId, $uuid, $hash, $oldOwner, ['success' => true]);
        self::assertNull($store->stored($backendId, $uuid), 'the old owner cannot finalize after the takeover');

        // The takeover winner finalizes with ITS token.
        $store->finalize($backendId, $uuid, $hash, $newOwner, ['success' => true]);
        self::assertSame(['success' => true], $store->stored($backendId, $uuid));
    }

    public function testMalformedTokenFinalizesTheClaimDeterministically(): void
    {
        $storage = new ArrayStorage();
        $store = new ArraySiteVerifyIdempotencyStore();
        $controller = $this->controller(idempotencyStore: $store, storage: $storage);
        $uuid = '823e4567-e89b-42d3-a456-426614174000';
        $backendId = hash('sha256', self::SITEVERIFY_SECRET);
        $malformed = 'not-a-valid-solution-token';

        $first = (string) $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $malformed, 'idempotency_key' => $uuid,
        ]))->getContent();
        $body = json_decode($first, true);
        self::assertFalse($body['success'] ?? true);
        self::assertSame(['invalid-input-response'], $body['error-codes'] ?? null);

        // A same-key retry reproduces the IDENTICAL canonical failure.
        $second = (string) $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $malformed, 'idempotency_key' => $uuid,
        ]))->getContent();
        self::assertSame($first, $second, 'a same-key malformed retry must return the identical canonical failure');
        self::assertSame(['invalid-input-response'], json_decode($second, true)['error-codes'] ?? null);

        // The claim was FINALIZED: the store exposes the failure.
        $stored = $store->stored($backendId, $uuid);
        self::assertIsArray($stored);
        self::assertFalse($stored['success'] ?? true);
        self::assertSame(['invalid-input-response'], $stored['error-codes'] ?? null);
    }
}

