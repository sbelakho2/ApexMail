<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * End-to-end flow through the bundle's own wiring: issue a challenge via the
 * controller, solve it locally (pure PHP), and verify via the local Verifier.
 */
final class ChallengeFlowTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private function issuer(): Issuer
    {
        return new Issuer(new Config(
            secretKey: self::SECRET,
            algorithm: PoWAlgorithm::Sha256,
            targetBits: 8, // fast solve for tests
            ttlSecs: 120,
        ), new ArrayStorage());
    }

    public function testChallengeControllerIssuesValidChallenge(): void
    {
        $controller = new ChallengeController($this->issuer());
        $request = Request::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}');

        $response = $controller->challenge($request);
        self::assertSame(200, $response->getStatusCode());

        $data = json_decode((string) $response->getContent(), true);
        self::assertSame('sha256', $data['algorithm']);
        self::assertSame(8, $data['targetBits']);
        self::assertSame('login', $data['prefix'] !== '' ? 'login' : 'login');
        self::assertNotEmpty($data['nonce']);
        self::assertNotEmpty($data['prefix']);
        // The prefix binds the signed challenge.
        self::assertStringContainsString($data['challenge'], $data['prefix']);
    }

    public function testControllerRejectsInvalidScope(): void
    {
        $controller = new ChallengeController($this->issuer());
        $request = Request::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"bad|scope"}');

        $response = $controller->challenge($request);
        self::assertSame(422, $response->getStatusCode());
        self::assertStringContainsString('INVALID_SCOPE', (string) $response->getContent());
    }

    public function testFullRoundTrip(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(
            secretKey: self::SECRET,
            algorithm: PoWAlgorithm::Sha256,
            targetBits: 8,
            ttlSecs: 120,
        ), $storage);
        $verifier = new Verifier($storage);
        $controller = new ChallengeController($issuer);

        // Issue
        $request = Request::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}');
        $challenge = json_decode((string) $controller->challenge($request)->getContent(), true);
        $this->waitOutMinDuration((float) $challenge['minDurationMs']);

        // Solve in pure PHP (8 bits — fast)
        $counter = 0;
        $saltBytes = base64_decode($challenge['salt'], true);
        do {
            $hash = hash('sha256', $challenge['prefix'].$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge['targetBits']);
        --$counter;

        $token = \KiwiCaptcha\SolutionToken::create($challenge['nonce'], $counter, 5000, ['wd' => false])->encode();

        // Verify locally
        $outcome = $verifier->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertTrue($outcome->isOk(), sprintf('expected valid, got %s', $outcome->code()));

        // Single-use: replay fails
        $replay = $verifier->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertSame(\KiwiCaptcha\VerifyError::RecordNotFound, $replay->error);

        // Wrong scope fails
        $storage2 = new ArrayStorage();
        $issuer2 = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage2);
        $verifier2 = new Verifier($storage2);
        $ch2 = json_decode((string) (new ChallengeController($issuer2))->challenge(
            Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}')
        )->getContent(), true);
        $c2 = 0;
        do {
            $h = hash('sha256', $ch2['prefix'].$c2.base64_decode($ch2['salt'], true), true);
            $c2++;
        } while (Verifier::leadingZeroBits($h) < $ch2['targetBits']);
        --$c2;
        $t2 = \KiwiCaptcha\SolutionToken::create($ch2['nonce'], $c2, 5000, [])->encode();
        $wrongScope = $verifier2->verify($t2, self::SECRET, 'signup', '198.51.100.7');
        self::assertSame(\KiwiCaptcha\VerifyError::WrongScope, $wrongScope->error);
    }

    public function testArgon2ChallengeIssuesAndVerifiesLocally(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(
            secretKey: self::SECRET,
            algorithm: PoWAlgorithm::Argon2id,
            mKib: 64,
            t: 3, // libsodium-representable
            p: 1,
            argon2TargetBits: 4,
            ttlSecs: 120,
        ), $storage);
        $verifier = new Verifier($storage);

        $challenge = $issuer->issue('login', '198.51.100.7');
        self::assertSame('argon2id', $challenge->algorithm->value);
        $this->waitOutMinDuration((float) $challenge->minDurationMs);

        // Solve via libsodium (same parameters as the verifier)
        $counter = 0;
        do {
            $h = sodium_crypto_pwhash(
                32,
                $challenge->prefix.$counter,
                base64_decode($challenge->salt, true),
                $challenge->t,
                $challenge->mKib * 1024 * 1024,
                SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13,
            );
            $counter++;
        } while (Verifier::leadingZeroBits($h) < $challenge->targetBits);
        --$counter;

        $token = \KiwiCaptcha\SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
        $outcome = $verifier->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertTrue($outcome->isOk(), sprintf('expected valid, got %s', $outcome->code()));
    }

    /**
     * The core enforces the minimum solve duration with a server-measured
     * clock; tests issue and verify in the same process, so wait out the
     * floor before submitting.
     */
    private function waitOutMinDuration(float $minDurationMs): void
    {
        usleep(((int) $minDurationMs + 10) * 1000);
    }

    public function testWrongSecretKeyRejected(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $verifier = new Verifier($storage);

        $challenge = $issuer->issue('login', '198.51.100.7');
        $token = \KiwiCaptcha\SolutionToken::create($challenge->nonce, 1, 5000, [])->encode();
        $outcome = $verifier->verify($token, str_repeat('a', 32), 'login', '198.51.100.7');
        self::assertSame(\KiwiCaptcha\VerifyError::BadSignature, $outcome->error);
    }

    public function testCrossOriginRequestRejectedWith403(): void
    {
        $controller = new ChallengeController($this->issuer());
        $request = Request::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://evil.example'], '{"scope":"login"}');

        $response = $controller->challenge($request);
        self::assertSame(403, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('CROSS_ORIGIN_DENIED', $body['error']['code']);
    }

    public function testSameOriginRequestIsAllowed(): void
    {
        $controller = new ChallengeController($this->issuer());
        $request = Request::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'http://localhost'], '{"scope":"login"}');

        self::assertSame(200, $controller->challenge($request)->getStatusCode());
    }

    public function testNoOriginHeaderIsAllowed(): void
    {
        $controller = new ChallengeController($this->issuer());
        $request = Request::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}');

        self::assertSame(200, $controller->challenge($request)->getStatusCode());
    }

    public function testSameOriginCheckCanBeDisabled(): void
    {
        $controller = new ChallengeController($this->issuer(), null, false);
        $request = Request::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://evil.example'], '{"scope":"login"}');

        self::assertSame(200, $controller->challenge($request)->getStatusCode(), 'same_origin_only=false must allow cross-origin');
    }

    public function testCrossOriginRejectionDoesNotStoreAChallenge(): void
    {
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

            public function consume(string $nonce): ?\KiwiCaptcha\ChallengeRecord
            {
                return $this->inner->consume($nonce);
            }

            public function delete(string $nonce): void
            {
                $this->inner->delete($nonce);
            }
        };
        $controller = new ChallengeController(new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage));
        $request = Request::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://evil.example'], '{"scope":"login"}');

        $controller->challenge($request);
        self::assertSame(0, $storage->stores, 'cross-origin rejection must happen before any state is written');
    }

    public function testSuccessResponseCarriesPrivateDocumentHeaders(): void
    {
        $controller = new ChallengeController($this->issuer());
        $response = $controller->challenge(Request::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));

        self::assertSame('max-age=0, no-store, private', $response->headers->get('Cache-Control'));
        self::assertSame('no-cache', $response->headers->get('Pragma'));
        self::assertSame('no-referrer', $response->headers->get('Referrer-Policy'));
        self::assertSame('nosniff', $response->headers->get('X-Content-Type-Options'));
    }
}
