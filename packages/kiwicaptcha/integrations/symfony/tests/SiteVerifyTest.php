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
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * Provider-compatible Siteverify golden tests. The endpoint calls the EXACT
 * SAME atomic verifier as the native path and returns the provider-shaped
 * JSON (`success`, `challenge_ts`, `hostname`, `error-codes`).
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
        float $waitSecs = 90.0,
        ?\BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyRedemptionGuard $redemptionGuard = null,
    ): SiteVerifyController {
        $storage ??= new ArrayStorage();
        $verifier = new Verifier($storage);

        return new SiteVerifyController($verifier, self::SECRET, $secrets, $storage, null, $metadataStore, $idempotencyStore, null, $waitSecs, redemptionGuard: $redemptionGuard);
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
        // replay boundary rejects the already-consumed one).
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

        // The COMPATIBILITY boundary distinguishes the first
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
        // The secret resolves the EXPECTED SCOPE — a login
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
        // Hostname must survive a real serialize -> Redis ->
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


    // ── Provider metadata + idempotency semantics ─────────────────────

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

    public function testSameFingerprintRetryReturnsTheIdenticalCanonicalResponse(): void
    {
        // The idempotency fingerprint covers backend identity + response
        // hash + canonicalized remoteip; the SAME key + token + remoteip
        // stays the normal retry path (complete -> identical bytes).
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage);
        $store = new ArraySiteVerifyIdempotencyStore();
        $controller = $this->controller(idempotencyStore: $store, storage: $storage);
        $uuid = 'b23e4567-e89b-42d3-a456-426614174000';

        $first = (string) $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]))->getContent();
        self::assertSame(true, json_decode($first, true)['success'] ?? null);
        $second = (string) $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]))->getContent();
        self::assertSame($first, $second, 'same key + token + remoteip is the normal retry path: identical canonical bytes');
    }

    public function testChangedRemoteipConflictsWhileTheEntryIsPending(): void
    {
        // remoteip materially changes verification under IP binding, so the
        // claim fingerprint binds it: while the entry is PENDING, a request
        // with the SAME key + token but a DIFFERENT remoteip must CONFLICT
        // — it can neither join the pending entry nor overtake it.
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage);
        $store = new ArraySiteVerifyIdempotencyStore();
        $controller = $this->controller(idempotencyStore: $store, storage: $storage);
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $uuid = '923e4567-e89b-42d3-a456-426614174000';

        // The owner claims with remoteip 127.0.0.1 and stalls: the entry
        // stays PENDING under fingerprint 'ip:127.0.0.1'.
        [$claim] = $store->claim($backendId, $uuid, hash('sha256', $token), 300, 'ip:127.0.0.1');
        self::assertSame(IdempotencyClaim::Claimed, $claim);

        $response = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '203.0.113.9', 'idempotency_key' => $uuid,
        ]));
        self::assertSame(400, $response->getStatusCode());
        self::assertSame(['bad-request'], json_decode((string) $response->getContent(), true)['error-codes']);
    }

    public function testChangedRemoteipConflictsAfterTheEntryIsComplete(): void
    {
        // Same conflict AFTER completion: the stored fingerprint is
        // authoritative, so a changed remoteip can never receive the stored
        // outcome of a verification bound to another IP.
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage);
        $store = new ArraySiteVerifyIdempotencyStore();
        $controller = $this->controller(idempotencyStore: $store, storage: $storage);
        $uuid = 'a23e4567-e89b-42d3-a456-426614174000';

        $first = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        self::assertSame(200, $first->getStatusCode());

        $second = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '203.0.113.9', 'idempotency_key' => $uuid,
        ]));
        self::assertSame(400, $second->getStatusCode());
        self::assertSame(['bad-request'], json_decode((string) $second->getContent(), true)['error-codes']);
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
        // Retry with the SAME remoteip and the SAME key -> the SAME
        // canonical failure (idempotency freezes the outcome; the
        // fingerprint binds the remoteip, so the retry must repeat it).
        $second = json_decode((string) $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '203.0.113.9', 'idempotency_key' => $uuid,
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

    // ── The owner lease + atomic takeover ───────────────────────────────

    public function testTakeoverReturnsTookOverToExactlyOneWaiterAfterLeaseExpiry(): void
    {
        $now = 1_700_000_000;
        $clock = static function () use (&$now): int {
            return $now;
        };
        // A SHORT configurable lease makes the expiry instant in the test.
        $store = new ArraySiteVerifyIdempotencyStore($clock, 3);
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $uuid = '623e4567-e89b-42d3-a456-426614174000';
        $hash = 'response-hash';
        $fingerprint = 'ip:127.0.0.1';

        [$claim, $owner] = $store->claim($backendId, $uuid, $hash, 300, $fingerprint);
        self::assertSame(IdempotencyClaim::Claimed, $claim);
        self::assertNotNull($owner);

        [$second] = $store->claim($backendId, $uuid, $hash, 300, $fingerprint);
        self::assertSame(IdempotencyClaim::PendingSame, $second);

        // While the owner's lease is valid the takeover attempt is a no-op.
        [$whileHeld] = $store->takeover($backendId, $uuid, $hash, 300, $fingerprint);
        self::assertSame(IdempotencyClaim::StillPending, $whileHeld);

        // Expire the lease: exactly ONE caller may win the takeover; the
        // loser must see the record unchanged (the winner's refreshed
        // lease keeps it pending).
        $now += 4;
        [$first, $newOwner] = $store->takeover($backendId, $uuid, $hash, 300, $fingerprint);
        self::assertSame(IdempotencyClaim::TookOver, $first);
        self::assertNotNull($newOwner);
        [$secondTakeover] = $store->takeover($backendId, $uuid, $hash, 300, $fingerprint);
        self::assertSame(IdempotencyClaim::StillPending, $secondTakeover, 'the loser sees StillPending — the winner refreshed the lease');
    }

    public function testFinalizeByTheDisplacedOwnerIsRefusedAfterTakeover(): void
    {
        $now = 1_700_000_000;
        // The clock ticks one second per store call: the stalled owner's
        // lease expires while the waiter polls, so the atomic takeover
        // wins deterministically within the waiter's bound.
        $clock = static function () use (&$now): int {
            return ++$now;
        };
        $store = new ArraySiteVerifyIdempotencyStore($clock, 3);
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $uuid = '723e4567-e89b-42d3-a456-426614174000';
        $hash = 'response-hash';
        $fingerprint = 'ip:127.0.0.1';

        [$claim, $oldOwner] = $store->claim($backendId, $uuid, $hash, 300, $fingerprint);
        self::assertSame(IdempotencyClaim::Claimed, $claim);

        $now += 4;
        [$takeover, $newOwner] = $store->takeover($backendId, $uuid, $hash, 300, $fingerprint);
        self::assertSame(IdempotencyClaim::TookOver, $takeover);

        // The displaced owner's finalize must be a no-op after the takeover.
        $store->finalize($backendId, $uuid, $hash, $oldOwner, ['success' => true]);
        self::assertNull($store->stored($backendId, $uuid), 'a displaced owner cannot finalize after the takeover');

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
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
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

    public function testOwnerStallDoesNotVerifyWithoutOwnership(): void
    {
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage);
        $counting = new class($storage) implements \KiwiCaptcha\AtomicStorageInterface {
            public int $consumes = 0;

            public function __construct(private readonly \KiwiCaptcha\StorageInterface $inner)
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
                return null;
            }

public function consume(string $nonce): ?\KiwiCaptcha\ConsumedRecord
            {
                $this->consumes++;

                return $this->inner->consume($nonce);
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
        $verifier = new Verifier($counting);
        $now = 1_700_000_000;
        // The clock ticks one second per store call: the stalled owner's
        // lease expires while the waiter polls, so the atomic takeover
        // wins deterministically within the waiter's bound.
        $clock = static function () use (&$now): int {
            return ++$now;
        };
        $store = new ArraySiteVerifyIdempotencyStore($clock, 3);
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $uuid = 'a3e4567e-e89b-42d3-a456-426614174000';
        $hash = hash('sha256', $token);
        $fingerprint = 'ip:127.0.0.1';

        // The stalled owner claims the entry and never finalizes.
        [$claim] = $store->claim($backendId, $uuid, $hash, 300, $fingerprint);
        self::assertSame(IdempotencyClaim::Claimed, $claim);

        // A stalled owner (claims, never finalizes) is taken over
        // atomically once its lease expires: the waiter's hard bound must
        // exceed the lease (enforced at construction), so the waiter
        // polls through the lease expiry, wins the takeover, verifies and
        // finalizes with the takeover owner token.
        $winner = new SiteVerifyController($verifier, self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $counting, null, null, $store, null, 5.0);
        $won = $winner->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        $wonBody = json_decode((string) $won->getContent(), true);
        self::assertSame(true, $wonBody['success'] ?? null, 'waiter body: '.(string) $won->getContent());
        self::assertSame(1, $counting->consumes, 'the token was consumed exactly once, by the takeover winner');
        self::assertSame($wonBody, $store->stored($backendId, $uuid), 'the takeover winner finalizes its canonical response');
    }

    public function testWaiterBoundMustExceedTheOwnerLease(): void
    {
        // The lease-ordering invariant is enforced: a waiter bound that
        // does not exceed the owner lease makes the crash-recovery
        // takeover unreachable and is refused at construction.
        $storage = new ArrayStorage();
        $store = new ArraySiteVerifyIdempotencyStore(static fn (): int => 1_700_000_000, 60);
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('must exceed the owner lease');
        new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 30.0);
    }

    public function testDefaultLeaseOrderingInvariant(): void
    {
        // The default ordering must satisfy: owner lease < waiter bound <
        // challenge lifetime — otherwise the crash-recovery path is
        // unreachable under defaults (a waiter would give up before the
        // lease expires, or the retained consumed record would expire
        // before a takeover).
        self::assertLessThan(SiteVerifyController::IDEMPOTENCY_WAIT_SECS, SiteVerifyIdempotencyStore::LEASE_SECONDS, 'the waiter bound must exceed the owner lease');
        self::assertLessThan(120, SiteVerifyController::IDEMPOTENCY_WAIT_SECS, 'the waiter bound must stay inside the default challenge lifetime');
        self::assertGreaterThan(30, SiteVerifyIdempotencyStore::LEASE_SECONDS, 'the lease must exceed any supported verification window with margin');
    }

    public function testLeaseRenewalPreventsOvertake(): void
    {
        $now = 1_700_000_000;
        $clock = static function () use (&$now): int {
            return $now;
        };
        $store = new ArraySiteVerifyIdempotencyStore($clock, 3);
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $uuid = 'b3e4567e-e89b-42d3-a456-426614174000';
        $hash = 'response-hash';
        $fingerprint = 'ip:127.0.0.1';

        [$claim, $owner] = $store->claim($backendId, $uuid, $hash, 300, $fingerprint);
        self::assertSame(IdempotencyClaim::Claimed, $claim);

        // The owner's verification outlasts most of the lease window; the
        // owner renews the lease before it expires.
        $now += 2;
        self::assertTrue($store->renew($backendId, $uuid, $owner), 'the current owner renews a still-pending lease');

        // The waiter's takeover attempt is refused: the renewed lease is
        // still held.
        [$takeover] = $store->takeover($backendId, $uuid, $hash, 300, $fingerprint);
        self::assertSame(IdempotencyClaim::StillPending, $takeover, 'the renewed lease blocks the takeover of a live owner');

        // A foreign owner token cannot renew (ownership is bound to the
        // current owner token).
        self::assertFalse($store->renew($backendId, $uuid, 'foreign-owner-token'));

        // Once the RENEWED lease expires, the takeover succeeds.
        $now += 4;
        [$later, $newOwner] = $store->takeover($backendId, $uuid, $hash, 300, $fingerprint);
        self::assertSame(IdempotencyClaim::TookOver, $later, 'a takeover succeeds only after the renewed lease expires');
        self::assertNotNull($newOwner);

        // A complete entry can no longer be renewed.
        $store->finalize($backendId, $uuid, $hash, $newOwner, ['success' => true]);
        self::assertFalse($store->renew($backendId, $uuid, $newOwner), 'a completed entry cannot be renewed');
    }

    // ── Malformed remoteip + fingerprint identity ──────────────────────

    public function testMalformedRemoteipIsRejectedAsBadRequest(): void
    {
        // A malformed remoteip (e.g. a forwarding-header list like
        // "203.0.113.4, 10.0.0.4") must be rejected as a NORMAL provider
        // bad-request — the core's IP canonicalization must never throw
        // past the boundary as a 500.
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage);
        $controller = $this->controller(storage: $storage);

        $response = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET,
            'response' => $token,
            'remoteip' => '203.0.113.4, 10.0.0.4',
        ]));
        self::assertSame(400, $response->getStatusCode());
        self::assertSame(['bad-request'], json_decode((string) $response->getContent(), true)['error-codes']);
    }

    public function testMalformedRemoteipIsRejectedBeforeIdempotencyClaim(): void
    {
        // Same rejection on the IDEMPOTENT path: the malformed IP is
        // refused BEFORE any claim is made, so no entry may be created
        // (or joined) under a malformed remoteip.
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage);
        $store = new ArraySiteVerifyIdempotencyStore();
        $controller = $this->controller(idempotencyStore: $store, storage: $storage);
        $uuid = 'c23e4567-e89b-42d3-a456-426614174000';

        $response = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET,
            'response' => $token,
            'remoteip' => '203.0.113.4, 10.0.0.4',
            'idempotency_key' => $uuid,
        ]));
        self::assertSame(400, $response->getStatusCode());
        self::assertSame(['bad-request'], json_decode((string) $response->getContent(), true)['error-codes']);
        self::assertNull($store->stored(hash('sha256', self::SITEVERIFY_SECRET.'|login|0'), $uuid), 'no idempotency entry may exist under a malformed remoteip');
    }

    public function testMappedV6RemoteipFingerprintIsTheSameIdentityAsPlainIpv4(): void
    {
        // The verifier deliberately normalizes IPv4-mapped IPv6
        // (::ffff:192.0.2.1) to the SAME identity as the plain IPv4
        // spelling (the core's Issuer::canonicalIpFamily()); the
        // idempotency fingerprint must mirror that exactly, so the two
        // spellings of one address are the SAME claim — a same-key retry
        // under the mapped spelling returns the identical canonical bytes
        // instead of CONFLICTING.
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage, 'login', '192.0.2.1');
        $store = new ArraySiteVerifyIdempotencyStore();
        $controller = $this->controller(idempotencyStore: $store, storage: $storage);
        $uuid = 'd23e4567-e89b-42d3-a456-426614174000';

        $first = (string) $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '192.0.2.1', 'idempotency_key' => $uuid,
        ]))->getContent();
        self::assertSame(true, json_decode($first, true)['success'] ?? null);

        $second = (string) $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '::ffff:192.0.2.1', 'idempotency_key' => $uuid,
        ]))->getContent();
        self::assertSame($first, $second, 'the mapped-v6 spelling is the SAME identity: identical canonical bytes, not a conflict');
    }

    // ── The complete finalize / takeover identity ──────────────────────

    public function testFinalizeWithWrongResponseHashIsANoOp(): void
    {
        // finalize must authorize BOTH the owner token AND the response
        // hash bound in the record: a finalize with the correct owner but
        // a WRONG hash is a no-op and the entry stays pending.
        $store = new ArraySiteVerifyIdempotencyStore();
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $uuid = 'e23e4567-e89b-42d3-a456-426614174000';
        $hash = 'response-hash';
        $fingerprint = 'ip:127.0.0.1';

        [$claim, $owner] = $store->claim($backendId, $uuid, $hash, 300, $fingerprint);
        self::assertSame(IdempotencyClaim::Claimed, $claim);
        self::assertNotNull($owner);

        $store->finalize($backendId, $uuid, 'wrong-hash', $owner, ['success' => true]);
        self::assertNull($store->stored($backendId, $uuid), 'a wrong-hash finalize must not complete the entry');

        $store->finalize($backendId, $uuid, $hash, $owner, ['success' => true]);
        self::assertSame(['success' => true], $store->stored($backendId, $uuid));
    }

    public function testTakeoverWithWrongRemoteipFingerprintIsRefused(): void
    {
        // takeover must enforce the COMPLETE claim identity itself: the
        // remoteip fingerprint is bound in the record, so a takeover with
        // the correct response hash but a DIFFERENT fingerprint is
        // refused even after the lease has expired.
        $now = 1_700_000_000;
        $clock = static function () use (&$now): int {
            return $now;
        };
        $store = new ArraySiteVerifyIdempotencyStore($clock, 3);
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $uuid = 'f23e4567-e89b-42d3-a456-426614174000';
        $hash = 'response-hash';

        [$claim] = $store->claim($backendId, $uuid, $hash, 300, 'ip:127.0.0.1');
        self::assertSame(IdempotencyClaim::Claimed, $claim);

        // The lease expires, but the fingerprint still does not match.
        $now += 4;
        [$takeover] = $store->takeover($backendId, $uuid, $hash, 300, 'ip:203.0.113.9');
        self::assertSame(IdempotencyClaim::StillPending, $takeover, 'a different remoteip fingerprint must never take over');

        // The correct fingerprint takes over after the expired lease.
        [$second] = $store->takeover($backendId, $uuid, $hash, 300, 'ip:127.0.0.1');
        self::assertSame(IdempotencyClaim::TookOver, $second);
    }


    /**
     * Crash recovery for a token submitted LATE in its lifetime: the
     * owner consumes + commits the token but dies before finalizing; the
     * signed challenge expires; the retry (same key) takes over after the
     * owner's lease and must RECONSTRUCT the original committed success —
     * a fresh verification would now answer Expired (timeout-or-duplicate),
     * violating the identical-canonical-response promise. The owner lease
     * is the store's FIXED configured lease (the per-token derivation is
     * gone): the test configures a SHORT store lease (3s) + a waiter
     * bound above it (5s) so the takeover happens quickly, and the
     * retained-state recovery covers the reconstruction after the signed
     * expiry.
     */
    public function testLateTokenCrashRecoveryReconstructsTheOriginalSuccessAfterExpiry(): void
    {
        $storage = new ArrayStorage();
        // A token with a SHORT lifetime: the owner verifies it ~1s after
        // issuance (remaining ~4s); the fixed 3s store lease expires
        // before the signed expiry, so the takeover happens quickly and
        // the reconstruction then works AFTER the signed expiry (the
        // retained-state margin covers it).
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 5), $storage);
        $challenge = $issuer->issue('login', '127.0.0.1');
        $solution = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits);
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = SolutionToken::create($challenge->nonce, $solution, 5000, [])->encode();
        // A SHORT fixed store lease (3s) with a waiter bound above it
        // (5s — the construction invariant) makes the takeover quick.
        $store = new ArraySiteVerifyIdempotencyStore(static fn (): int => time(), 3);
        // The NONCE-LEVEL redemption guard is SHARED across the owner
        // and the retry: the retry is the SAME logical operation (same
        // key + hash), so it is recovery-eligible.
        $guard = new \BelConsulting\KiwiCaptchaBundle\SiteVerify\ArraySiteVerifyRedemptionGuard();
        // The "crash" seam: finalize() is a no-op for the owner, exactly
        // like a process dying between the core commit and the Siteverify
        // finalize. Everything else delegates.
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
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $uuid = 'e4f5a6b7-8c9d-4eaf-b012-3c4d5e6f7081';

        // The owner claims, verifies (committed success) and "dies"
        // WITHOUT finalizing.
        $owner = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $crashingStore, null, 5.0, redemptionGuard: $guard);
        $ownerResponse = $owner->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        $ownerBody = json_decode((string) $ownerResponse->getContent(), true);
        self::assertSame(true, $ownerBody['success'] ?? null);
        // The owner consumed + committed but never finalized: the entry is
        // still pending with a committed core result.
        self::assertNull($store->stored($backendId, $uuid), 'the owner crashed before the Siteverify finalize');

        // Wait past the signed expiry (ttl 5s) and the fixed 3s lease.
        sleep(7);
        $waiter = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $crashingStore, null, 5.0, redemptionGuard: $guard);
        $retry = $waiter->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        $retryBody = json_decode((string) $retry->getContent(), true);
        self::assertSame(true, $retryBody['success'] ?? null, 'the retry must reconstruct the ORIGINAL committed success after the signed expiry: '.(string) $retry->getContent());
        self::assertSame($ownerBody, $retryBody, 'the identical canonical response promise holds even for a late-lifetime crash');
    }

    // ── The NONCE-LEVEL redemption guard ───────────────────────────────

    /**
     * THE decisive regression: a used token must NEVER become successful
     * again through a different idempotency UUID. The first logical
     * operation (UUID A) redeems the token; a replay under a NEW UUID B
     * is a DIFFERENT logical operation and is answered with
     * timeout-or-duplicate, AND its claim is FINALIZED as CompleteSame
     * (the canonical duplicate); after B's owner lease expires, a retry
     * with B must STILL be timeout-or-duplicate — the entry returns the
     * stored duplicate immediately and can never be reconstructed as a
     * success.
     */
    public function testDifferentUuidForAConsumedTokenCanNeverBecomeSuccessfulAgain(): void
    {
        $storage = new ArrayStorage();
        [$token, $nonce] = $this->issuedToken($storage);
        $now = 1_700_000_000;
        $clock = static function () use (&$now): int {
            return $now;
        };
        // A SHORT configured store lease (3s) keeps the lease-expiry step
        // instant; the waiter bound (5s) exceeds it (the construction
        // invariant).
        $store = new ArraySiteVerifyIdempotencyStore($clock, 3);
        $guard = new \BelConsulting\KiwiCaptchaBundle\SiteVerify\ArraySiteVerifyRedemptionGuard();
        $controller = $this->controller(idempotencyStore: $store, storage: $storage, waitSecs: 5.0, redemptionGuard: $guard);
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $uuidA = '123e4567-e89b-42d3-a456-42661417401a';
        $uuidB = '123e4567-e89b-42d3-a456-42661417401b';

        // 1. The ORIGINAL logical operation: UUID A redeems the token once.
        $first = json_decode((string) $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidA,
        ]))->getContent(), true);
        self::assertSame(true, $first['success'] ?? null);

        // The redemption guard recorded A's response hash as the ORIGINAL
        // redemption (first write wins).
        self::assertSame(hash('sha256', $token), $guard->originalHash($backendId, $nonce));

        // 2. A DIFFERENT UUID for the SAME (already-redeemed) token is a
        // DIFFERENT logical operation: timeout-or-duplicate — and its
        // claim is FINALIZED as CompleteSame with the canonical duplicate
        // (never left pending for a later takeover).
        $second = json_decode((string) $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidB,
        ]))->getContent(), true);
        self::assertSame(false, $second['success'] ?? null);
        self::assertSame(['timeout-or-duplicate'], $second['error-codes'] ?? null);
        $storedB = $store->stored($backendId, $uuidB);
        self::assertIsArray($storedB, 'the duplicate-detecting claim must be finalized as CompleteSame');
        self::assertFalse($storedB['success'] ?? true);
        self::assertSame(['timeout-or-duplicate'], $storedB['error-codes'] ?? null);

        // 3. B's owner lease expires (the defect window: a pending entry
        // could otherwise be taken over and reconstructed).
        $now += 4;

        // 4. The retry with UUID B must STILL be timeout-or-duplicate —
        // a consumed token can never become successful again through a
        // different idempotency UUID.
        $retry = json_decode((string) $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidB,
        ]))->getContent(), true);
        self::assertSame(false, $retry['success'] ?? null, 'a consumed token must NEVER become successful again through a different idempotency UUID');
        self::assertSame(['timeout-or-duplicate'], $retry['error-codes'] ?? null);
    }

    /**
     * The crash-window variant of the decisive regression: the first
     * B-replay detects the duplicate but the finalize does NOT land (a
     * process dies between detect and finalize — the claim stays
     * PENDING). After B's lease expires, the retry with B takes over its
     * own pending claim — but the takeover's redemption guard carries NO
     * original-redemption record for this nonce (the original logical
     * operation registered under the first controller's guard), so the
     * takeover is NOT recovery-eligible: the ordinary verify returns
     * timeout-or-duplicate for the consumed token, never a reconstructed
     * success. The guard is the structural backstop of the
     * crash-between-detect-and-finalize window.
     */
    public function testCrashWindowDuplicateFinalizeIsBackstoppedByTheRedemptionGuard(): void
    {
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage);
        $now = 1_700_000_000;
        $clock = static function () use (&$now): int {
            return $now;
        };
        $store = new ArraySiteVerifyIdempotencyStore($clock, 3);
        // The "crash" seam: finalize() never lands — exactly like a
        // process dying between detecting the duplicate and finalizing
        // the claim. Everything else delegates.
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
                // The finalize never lands (crash between detect and finalize).
            }

            public function stored(string $backendId, string $idempotencyKey): ?array
            {
                return $this->inner->stored($backendId, $idempotencyKey);
            }
        };
        $controller = $this->controller(idempotencyStore: $crashingStore, storage: $storage, waitSecs: 5.0);
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $uuidA = '123e4567-e89b-42d3-a456-42661417401c';
        $uuidB = '123e4567-e89b-42d3-a456-42661417401d';

        // 1. UUID A redeems the token (the original logical operation).
        $first = json_decode((string) $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidA,
        ]))->getContent(), true);
        self::assertSame(true, $first['success'] ?? null);

        // 2. UUID B detects the duplicate (timeout-or-duplicate) but the
        // finalize never lands: claim B is STILL PENDING.
        $second = json_decode((string) $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidB,
        ]))->getContent(), true);
        self::assertSame(false, $second['success'] ?? null);
        self::assertSame(['timeout-or-duplicate'], $second['error-codes'] ?? null);
        self::assertNull($store->stored($backendId, $uuidB), 'the finalize crashed between detect and landing — claim B stays pending');

        // 3. B's lease expires while the entry is STILL PENDING — the
        // exact window where a takeover would reconstruct the success.
        $now += 4;

        // 4. The retry with B (a FRESH controller, carrying no
        // original-redemption record in its redemption guard) takes over
        // its own pending claim — but the guard blocks the recovery (B
        // is NOT the nonce's original logical operation): the ordinary
        // verify returns timeout-or-duplicate for the consumed token.
        $retryController = $this->controller(idempotencyStore: $crashingStore, storage: $storage, waitSecs: 5.0);
        $retry = json_decode((string) $retryController->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidB,
        ]))->getContent(), true);
        self::assertSame(false, $retry['success'] ?? null, 'the guard must block the recovery of a different-UUID claim: '.(string) json_encode($retry));
        self::assertSame(['timeout-or-duplicate'], $retry['error-codes'] ?? null);
    }

    // ── The idempotency store's raw operations inside the hardened boundary ──

    public function testThrowingIdempotencyStoreClaimMapsToInternalError(): void
    {
        // The claim is a raw store operation (a Redis outage): a throwing
        // claim must degrade to the retryable provider error (503
        // internal-error) — nothing has been consumed yet, so a retry is
        // safe. It must never escape as a 500.
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage);
        $throwing = new class implements \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore {
            public function claim(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null): array
            {
                throw new \RuntimeException('idempotency store outage');
            }

            public function leaseSeconds(): int
            {
                return 60;
            }

            public function finalize(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonicalResponse): void
            {
            }

            public function stored(string $backendId, string $idempotencyKey): ?array
            {
                return null;
            }

            public function takeover(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null): array
            {
                return [IdempotencyClaim::StillPending, null];
            }

            public function renew(string $backendId, string $idempotencyKey, string $owner): bool
            {
                return false;
            }
        };
        $controller = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $throwing);

        $response = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET,
            'response' => $token,
            'remoteip' => '127.0.0.1',
            'idempotency_key' => '123e4567-e89b-42d3-a456-42661417401e',
        ]));
        self::assertSame(503, $response->getStatusCode(), 'a throwing claim must map to 503 internal-error, never a 500');
        self::assertSame(['internal-error'], json_decode((string) $response->getContent(), true)['error-codes']);
    }

    public function testThrowingFinalizeAfterConsumptionReturnsInternalErrorAndStaysReconstructable(): void
    {
        // The finalize runs AFTER the core consumed+committed the token:
        // a throwing finalize must NOT become a 500 — the response is the
        // retryable 503 internal-error, the entry stays PENDING, and a
        // same-key retry takes over and reconstructs the committed
        // outcome (retryability is preserved).
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage);
        $now = 1_700_000_000;
        $clock = static function () use (&$now): int {
            return $now;
        };
        $inner = new ArraySiteVerifyIdempotencyStore($clock, 3);
        $finalizeThrowing = new class($inner) implements \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore {
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
                throw new \RuntimeException('finalize outage');
            }

            public function stored(string $backendId, string $idempotencyKey): ?array
            {
                return $this->inner->stored($backendId, $idempotencyKey);
            }
        };
        $guard = new \BelConsulting\KiwiCaptchaBundle\SiteVerify\ArraySiteVerifyRedemptionGuard();
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $uuid = '123e4567-e89b-42d3-a456-42661417401f';

        // The verification SUCCEEDS (the token is consumed+committed by
        // the core), but the finalize throws: 503 internal-error, never a
        // 500, and the entry stays pending.
        $owner = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $finalizeThrowing, null, 5.0, redemptionGuard: $guard);
        $ownerResponse = $owner->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        self::assertSame(503, $ownerResponse->getStatusCode(), 'a throwing finalize after consumption must map to 503 internal-error, never a 500');
        self::assertSame(['internal-error'], json_decode((string) $ownerResponse->getContent(), true)['error-codes']);
        self::assertNull($inner->stored($backendId, $uuid), 'the finalize failed — the entry stays pending');

        // Expire the owner's lease: a same-key retry takes over and
        // reconstructs the committed outcome via the retained state.
        $now += 4;
        $retry = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $inner, null, 5.0, redemptionGuard: $guard);
        $retryResponse = $retry->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        $retryBody = json_decode((string) $retryResponse->getContent(), true);
        self::assertSame(true, $retryBody['success'] ?? null, 'the same-key retry must reconstruct the committed outcome: '.(string) $retryResponse->getContent());
        self::assertSame([], $retryBody['error-codes'] ?? null);
    }

    public function testNonIdempotentRequestNeverTouchesTheIdempotencyStore(): void
    {
        // The idempotency machinery is strictly key-gated: a request
        // WITHOUT an idempotency_key never claims, never waits and never
        // finalizes — even a store whose claim() throws cannot affect it.
        // The challenge storage's own failure is handled INSIDE the
        // verifier (StorageUnavailable -> provider bad-request
        // vocabulary), never as a 500.
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage);
        $throwing = new class($storage) implements \KiwiCaptcha\AtomicStorageInterface {
            public function __construct(private readonly \KiwiCaptcha\StorageInterface $inner)
            {
            }

            public function store(\KiwiCaptcha\ChallengeRecord $record): void
            {
                $this->inner->store($record);
            }

            public function find(string $nonce): ?\KiwiCaptcha\ChallengeRecord
            {
                throw new \RuntimeException('storage outage');
            }

            public function consumedState(string $nonce): ?\KiwiCaptcha\ConsumedRecord
            {
                throw new \RuntimeException('storage outage');
            }

            public function consume(string $nonce): ?\KiwiCaptcha\ConsumedRecord
            {
                throw new \RuntimeException('storage outage');
            }

            public function commitResult(string $nonce, bool $valid, ?string $binding): bool
            {
                throw new \RuntimeException('storage outage');
            }

            public function delete(string $nonce): void
            {
                $this->inner->delete($nonce);
            }
        };
        $throwingIdem = new class implements \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore {
            public function claim(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null): array
            {
                throw new \RuntimeException('idempotency store outage');
            }

            public function leaseSeconds(): int
            {
                return 60;
            }

            public function finalize(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonicalResponse): void
            {
            }

            public function stored(string $backendId, string $idempotencyKey): ?array
            {
                return null;
            }

            public function takeover(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null): array
            {
                return [IdempotencyClaim::StillPending, null];
            }

            public function renew(string $backendId, string $idempotencyKey, string $owner): bool
            {
                return false;
            }
        };
        $controller = new SiteVerifyController(new Verifier($throwing), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $throwing, null, null, $throwingIdem);

        $response = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET,
            'response' => $token,
            'remoteip' => '127.0.0.1',
        ]));
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame(200, $response->getStatusCode(), 'the non-idempotent path never touches the idempotency store; the verifier handles its own storage failure');
        self::assertFalse($body['success'] ?? true);
        self::assertSame(['bad-request'], $body['error-codes'] ?? null, 'the verifier degrades its storage failure to the provider bad-request vocabulary');
    }
}

