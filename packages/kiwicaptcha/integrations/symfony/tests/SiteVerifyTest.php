<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\SiteVerifyController;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\ArrayStorage;
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

    private function controller(array $secrets = [self::SITEVERIFY_SECRET => 'login']): SiteVerifyController
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $storage);
        $verifier = new Verifier($storage);

        return new SiteVerifyController($verifier, self::SECRET, $secrets, $storage);
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
}
