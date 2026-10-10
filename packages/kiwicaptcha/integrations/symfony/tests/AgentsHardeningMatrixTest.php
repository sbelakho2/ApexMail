<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\Agents\AgentDefinition;
use BelConsulting\KiwiCaptchaBundle\Security\Agents\AgentGateResult;
use BelConsulting\KiwiCaptchaBundle\Security\Agents\AgentNonceStore;
use BelConsulting\KiwiCaptchaBundle\Security\Agents\AgentRegistry;
use BelConsulting\KiwiCaptchaBundle\Security\Agents\AgentSignatureVerifier;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\AgentSigner;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * The hardening matrix of the RFC 9421 verifier: the failure shapes
 * that must answer a typed refusal (never a 500, never a silent
 * verification) once the covered-component, signature-length,
 * created-window, nonce-TTL and origin-pinning rules are enforced.
 */
final class AgentsHardeningMatrixTest extends TestCase
{
    private const KEY_ID = 'acme-bot-2026q4';
    private const URI = 'http://localhost/kiwi/challenge';
    private const ORIGIN = 'http://localhost';
    private const SKEW = 300;
    private const NOW = 1_770_000_100;

    protected function setUp(): void
    {
        if (!\function_exists('sodium_crypto_sign_verify_detached')) {
            self::markTestSkipped('ext-sodium is required');
        }
    }

    /**
     * The content-digest is a required covered component even for an
     * empty body: the request that drops the header keeps only length
     * integrity and is refused, and the empty body still needs the
     * digest of the zero-length bytes.
     */
    public function testMissingContentDigestIsRefusedEvenForEmptyBodies(): void
    {
        $verifier = $this->verifier();

        // Body present, digest header stripped after signing.
        $body = '{"scope":"login"}';
        $withDigest = $this->signedRequest($body);
        $stripped = Request::create(self::URI, 'POST', [], [], [], array_filter(
            $this->serverOf($withDigest),
            static fn (string $key): bool => $key !== 'HTTP_CONTENT_DIGEST',
            ARRAY_FILTER_USE_KEY,
        ), $body);
        self::assertSame(
            AgentSignatureVerifier::CODE_INVALID,
            $verifier->verify($stripped, $body)->errorCode(),
            'a body-bearing request without content-digest must be refused',
        );

        // Empty body: still requires the digest of the empty bytes.
        $empty = $this->signedRequest('');
        $emptyServer = $this->serverOf($empty);
        unset($emptyServer['HTTP_CONTENT_DIGEST'], $emptyServer['CONTENT_LENGTH']);
        $emptyStripped = Request::create(self::URI, 'POST', [], [], [], $emptyServer, '');
        self::assertSame(
            AgentSignatureVerifier::CODE_INVALID,
            $verifier->verify($emptyStripped, '')->errorCode(),
            'an empty body without content-digest must be refused',
        );

        // And the covered list without content-digest is a coverage
        // refusal before any crypto runs.
        $unsignedDigest = $this->signedRequest($body, covered: ['@method', '@target-uri', 'content-length']);
        self::assertSame(
            AgentSignatureVerifier::CODE_COVERAGE_INVALID,
            $verifier->verify($unsignedDigest, $body)->errorCode(),
        );
    }

    /**
     * A Signature member that is not exactly 64 decoded bytes is
     * refused as malformed — before sodium is ever called (a sodium
     * call with a wrong-length signature would be a 500, not a 401).
     */
    public function testBadSignatureLengthIsRefusedWithoutSodium(): void
    {
        $verifier = $this->verifier();
        $body = '{"scope":"login"}';
        $request = $this->signedRequest($body);
        $server = $this->serverOf($request);
        // Keep the Signature-Input, replace the Signature member with
        // a well-formed base64 of 3 bytes.
        $server['HTTP_SIGNATURE'] = 'sig1=:AAEC:';
        $short = Request::create(self::URI, 'POST', [], [], [], $server, $body);
        self::assertSame(
            AgentSignatureVerifier::CODE_MALFORMED,
            $verifier->verify($short, $body)->errorCode(),
            'a 3-byte signature must be refused as malformed',
        );

        $server['HTTP_SIGNATURE'] = 'sig1=::';
        $empty = Request::create(self::URI, 'POST', [], [], [], $server, $body);
        self::assertSame(
            AgentSignatureVerifier::CODE_MALFORMED,
            $verifier->verify($empty, $body)->errorCode(),
        );
    }

    /**
     * The created parameter may not sit more than the skew window in
     * the future — the bound that keeps the nonce TTL (derived from
     * created + skew) finite.
     */
    public function testCreatedTooFarInTheFutureIsRefused(): void
    {
        $verifier = $this->verifier();
        $body = '{"scope":"login"}';
        $future = $this->signedRequest($body, createdOffset: self::SKEW + 1);
        self::assertSame(AgentSignatureVerifier::CODE_SKEW, $verifier->verify($future, $body)->errorCode());

        $wayBack = $this->signedRequest($body, createdOffset: -(self::SKEW + 1));
        self::assertSame(AgentSignatureVerifier::CODE_SKEW, $verifier->verify($wayBack, $body)->errorCode());

        // The exact edge is admitted.
        $edge = $this->signedRequest($body, createdOffset: self::SKEW);
        self::assertTrue($verifier->verify($edge, $body)->isVerified());
    }

    /**
     * The nonce TTL math: it must cover the whole acceptance window
     * min(expires, created + skew). It must never fall below the floor,
     * and it must never stretch past twice the skew window plus the margin.
     */
    public function testNonceTtlCoversTheAcceptanceWindowWithFloorAndCeiling(): void
    {
        // A short acceptance window: the floor applies (300 s).
        $redis = new FakePredisClient();
        $body = '{"scope":"login"}';
        $request = $this->signedRequest($body, nonce: 'ttl-floor', createdOffset: -10, expiresOffset: -290);
        self::assertTrue($this->verifier($redis)->verify($request, $body)->isVerified());
        $stored = $redis->expirations['{kiwi:test}:agent-nonce:'.self::KEY_ID.':ttl-floor'] ?? null;
        self::assertSame(300 * 1000, $stored, 'the nonce TTL floor is 300 s');

        // The ordinary case: created now, expires now + 300 → the
        // acceptance window ends at created + skew = now + 300, TTL =
        // 360 (window + margin), under the ceiling.
        $redis = new FakePredisClient();
        $request = $this->signedRequest($body, nonce: 'ttl-window');
        self::assertTrue($this->verifier($redis)->verify($request, $body)->isVerified());
        $stored = $redis->expirations['{kiwi:test}:agent-nonce:'.self::KEY_ID.':ttl-window'] ?? null;
        self::assertSame(360 * 1000, $stored, 'the TTL covers min(expires, created + skew) plus the margin');

        // A far-future expires with created at the future edge: the
        // ceiling (2 × skew + margin = 660 s) caps the TTL.
        $redis = new FakePredisClient();
        $request = $this->signedRequest($body, nonce: 'ttl-ceiling', createdOffset: self::SKEW, expiresOffset: 100_000);
        self::assertTrue($this->verifier($redis)->verify($request, $body)->isVerified());
        $stored = $redis->expirations['{kiwi:test}:agent-nonce:'.self::KEY_ID.':ttl-ceiling'] ?? null;
        self::assertSame(660 * 1000, $stored, 'the TTL ceiling is 2 × skew + margin');
    }

    /**
     * The verifier fails closed when the deployment never configured
     * its public origin: @target-uri can then never be pinned, so no
     * signature verifies (the Host header must not decide it).
     */
    public function testUnconfiguredPublicOriginRefusesEverySignature(): void
    {
        $registry = AgentRegistry::fromConfig(['acme-bot' => [
            'key_id' => self::KEY_ID,
            'public_keys' => [$this->signer()->publicKeyBase64()],
            'allowed_scopes' => ['login'],
            'per_minute' => 10,
            'per_day' => 100,
            'price_tier' => 'standard',
            'contact' => 'ops@acme.example',
        ]]);
        $verifier = new AgentSignatureVerifier(
            $registry,
            new AgentNonceStore(new FakePredisClient(), '{kiwi:test}:'),
            self::SKEW,
            static fn (): int => self::NOW,
            null,
        );
        $body = '{"scope":"login"}';
        $result = $verifier->verify($this->signedRequest($body), $body);
        self::assertFalse($result->isVerified());
        self::assertSame(AgentSignatureVerifier::CODE_ORIGIN_UNCONFIGURED, $result->errorCode());
    }

    /**
     * @param list<string> $covered
     */
    private function signedRequest(
        string $body,
        int $createdOffset = 0,
        int $expiresOffset = 0,
        ?string $nonce = null,
        array $covered = ['@method', '@target-uri', 'content-digest', 'content-length'],
    ): Request {
        $signer = $this->signer();
        $created = self::NOW + $createdOffset;
        $expires = self::NOW + 300 + $expiresOffset;
        $nonce ??= 'hard-'.bin2hex(random_bytes(6));
        $digest = AgentSigner::contentDigest($body);
        $parameters = [
            'created' => $created,
            'expires' => $expires,
            'nonce' => $nonce,
            'keyid' => self::KEY_ID,
            'alg' => 'ed25519',
            'tag' => 'kiwi-agents-v1',
        ];
        $values = [
            '@method' => 'POST',
            '@target-uri' => self::URI,
            'content-digest' => $digest,
            'content-length' => (string) \strlen($body),
        ];
        $base = AgentSigner::signatureBase($covered, $parameters, $values);
        $headers = $signer->signedHeaders($covered, $parameters, $base);

        $server = [
            'CONTENT_TYPE' => 'application/json',
            'REMOTE_ADDR' => '203.0.113.10',
            'HTTP_CONTENT_DIGEST' => $digest,
            'HTTP_SIGNATURE_INPUT' => $headers['Signature-Input'],
            'HTTP_SIGNATURE' => $headers['Signature'],
        ];
        if ($body !== '') {
            $server['CONTENT_LENGTH'] = (string) \strlen($body);
        }

        return Request::create(self::URI, 'POST', [], [], [], $server, $body);
    }

    private function serverOf(Request $request): array
    {
        return [
            'CONTENT_TYPE' => (string) $request->headers->get('CONTENT_TYPE', 'application/json'),
            'CONTENT_LENGTH' => (string) $request->headers->get('CONTENT_LENGTH', ''),
            'REMOTE_ADDR' => (string) $request->server->get('REMOTE_ADDR', '203.0.113.10'),
            'HTTP_CONTENT_DIGEST' => (string) $request->headers->get('CONTENT-DIGEST', ''),
            'HTTP_SIGNATURE_INPUT' => (string) $request->headers->get('SIGNATURE-INPUT', ''),
            'HTTP_SIGNATURE' => (string) $request->headers->get('SIGNATURE', ''),
        ];
    }

    private function verifier(?FakePredisClient $redis = null): AgentSignatureVerifier
    {
        return new AgentSignatureVerifier(
            AgentRegistry::fromConfig(['acme-bot' => [
                'key_id' => self::KEY_ID,
                'public_keys' => [$this->signer()->publicKeyBase64()],
                'allowed_scopes' => ['login'],
                'per_minute' => 10,
                'per_day' => 100,
                'price_tier' => 'standard',
                'contact' => 'ops@acme.example',
            ]]),
            new AgentNonceStore($redis ?? new FakePredisClient(), '{kiwi:test}:'),
            self::SKEW,
            static fn (): int => self::NOW,
            self::ORIGIN,
        );
    }

    private function signer(): AgentSigner
    {
        return new AgentSigner(AgentSigner::seed('hardening-matrix'));
    }
}
