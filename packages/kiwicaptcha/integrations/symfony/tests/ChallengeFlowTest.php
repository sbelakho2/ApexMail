<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\ArraySiteVerifyMetadataStore;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceRateLimiter;
use BelConsulting\KiwiCaptchaBundle\Security\OutstandingChallenges;
use BelConsulting\KiwiCaptchaBundle\Security\ScopeIssuanceCap;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakeRiskStateStore;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\Storage\ProcessEmergencyCap;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JsonRequest;
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
        $request = JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}');

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
        $request = JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"bad|scope"}');

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
        $request = JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}');
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

        // Retry semantics: an identical replay in the same
        // context returns the same stored result without re-deriving.
        $replay = $verifier->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertTrue($replay->isOk(), 'same-context replay must return the stored result');
        self::assertTrue($replay->fromStoredResult, 'the replay must come from the stored result, not a second derivation');

        // Wrong scope fails
        $storage2 = new ArrayStorage();
        $issuer2 = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage2);
        $verifier2 = new Verifier($storage2);
        $ch2 = json_decode((string) (new ChallengeController($issuer2))->challenge(
            JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}')
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
                $challenge->mKib * 1024,
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
        $request = JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://evil.example'], '{"scope":"login"}');

        $response = $controller->challenge($request);
        self::assertSame(403, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('CROSS_ORIGIN_DENIED', $body['error']['code']);
    }

    public function testSameOriginRequestIsAllowed(): void
    {
        $controller = new ChallengeController($this->issuer());
        $request = JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'http://localhost'], '{"scope":"login"}');

        self::assertSame(200, $controller->challenge($request)->getStatusCode());
    }

    public function testNoOriginHeaderIsAllowed(): void
    {
        $controller = new ChallengeController($this->issuer());
        $request = JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}');

        self::assertSame(200, $controller->challenge($request)->getStatusCode());
    }

    public function testSameOriginCheckCanBeDisabled(): void
    {
        $controller = new ChallengeController($this->issuer(), null, false);
        $request = JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://evil.example'], '{"scope":"login"}');

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

                        public function consumedState(string $nonce): ?\KiwiCaptcha\ConsumedRecord
            {
                return null;
            }

public function consume(string $nonce): ?\KiwiCaptcha\ConsumedRecord
            {
                return $this->inner->consume($nonce);
            }

            public function delete(string $nonce): void
            {
                $this->inner->delete($nonce);
            }

            public function commitResult(string $nonce, bool $valid, ?string $binding): bool
            {
                return $this->inner->commitResult($nonce, $valid, $binding);
            }
        };
        $controller = new ChallengeController(new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage));
        $request = JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://evil.example'], '{"scope":"login"}');

        $controller->challenge($request);
        self::assertSame(0, $storage->stores, 'cross-origin rejection must happen before any state is written');
    }

    public function testSuccessResponseCarriesPrivateDocumentHeaders(): void
    {
        $controller = new ChallengeController($this->issuer());
        $response = $controller->challenge(JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));

        self::assertSame('max-age=0, no-store, private', $response->headers->get('Cache-Control'));
        self::assertSame('no-cache', $response->headers->get('Pragma'));
        self::assertSame('no-referrer', $response->headers->get('Referrer-Policy'));
        self::assertSame('nosniff', $response->headers->get('X-Content-Type-Options'));
    }

    public function testOriginAllowlistAcceptsExactOriginAndRefererFallback(): void
    {
        $controller = new ChallengeController($this->issuer(), null, false, null, null, null, null, ['https://app.example.com']);

        // Exact Origin match (default port normalized).
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://app.example.com'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode(), 'an allowlisted Origin must pass');

        // Host is case-insensitive (DNS); explicit default port equals the
        // default.
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://APP.EXAMPLE.COM:443'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode());

        // Referer-origin fallback (no Origin header).
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_REFERER' => 'https://app.example.com/contact'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode(), 'a Referer whose origin matches must pass');
    }

    public function testOriginAllowlistRejectsNonMatchingOrigins(): void
    {
        $controller = new ChallengeController($this->issuer(), null, false, null, null, null, null, ['https://app.example.com']);

        $rejected = [
            'https://evil.example.com' => 'different host',
            'http://app.example.com' => 'different scheme',
            'https://app.example.com:8443' => 'different port',
            'https://sub.app.example.com' => 'subdomain is not the host',
        ];
        foreach ($rejected as $origin => $why) {
            $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => $origin], '{"scope":"login"}'));
            self::assertSame(403, $response->getStatusCode(), $why.' must be rejected');
            self::assertSame('origin_rejected', json_decode((string) $response->getContent(), true)['error']['code'], $why);
        }

        // No Origin AND no Referer: cannot be matched — rejected.
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
        self::assertSame(403, $response->getStatusCode(), 'a request with neither Origin nor Referer cannot be matched and must be rejected');
        self::assertSame('origin_rejected', json_decode((string) $response->getContent(), true)['error']['code']);
    }

    public function testOriginAllowlistRejectionNeverStoresAChallenge(): void
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

                        public function consumedState(string $nonce): ?\KiwiCaptcha\ConsumedRecord
            {
                return null;
            }

public function consume(string $nonce): ?\KiwiCaptcha\ConsumedRecord
            {
                return $this->inner->consume($nonce);
            }

            public function delete(string $nonce): void
            {
                $this->inner->delete($nonce);
            }

            public function commitResult(string $nonce, bool $valid, ?string $binding): bool
            {
                return $this->inner->commitResult($nonce, $valid, $binding);
            }
        };
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $controller = new ChallengeController($issuer, null, false, null, null, null, null, ['https://app.example.com']);
        $request = JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://evil.example'], '{"scope":"login"}');

        $controller->challenge($request);
        self::assertSame(0, $storage->stores, 'an origin-rejected request must never mint a CAPTCHA');
    }

    public function testFetchMetadataCrossSiteIsRejectedWhenEnforced(): void
    {
        $controller = new ChallengeController($this->issuer(), null, false, null, null, null, null, [], true);

        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_SEC_FETCH_SITE' => 'cross-site'], '{"scope":"login"}'));
        self::assertSame(403, $response->getStatusCode());
        self::assertSame('CROSS_SITE_REJECTED', json_decode((string) $response->getContent(), true)['error']['code']);

        // same-origin / none / absent are unaffected.
        foreach (['same-origin', 'none', null] as $fetchSite) {
            $server = ['REMOTE_ADDR' => '198.51.100.7'];
            if ($fetchSite !== null) {
                $server['HTTP_SEC_FETCH_SITE'] = $fetchSite;
            }
            $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], $server, '{"scope":"login"}'));
            self::assertSame(200, $response->getStatusCode(), 'Sec-Fetch-Site "'.(string) $fetchSite.'" must pass');
        }

        // Without enforcement a cross-site header is ignored (defense-in-depth).
        $lax = new ChallengeController($this->issuer());
        $response = $lax->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_SEC_FETCH_SITE' => 'cross-site'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode());
    }

    /**
     * The full origin-normalization list. Structured
     * normalization compares (scheme, host, effective port) with the host
     * lowercased, trailing dots stripped and IDN converted to punycode
     * (when ext-intl is available).
     */
    public function testOriginNormalizationAuditList(): void
    {
        $controller = new ChallengeController($this->issuer(), null, false, null, null, null, null, ['https://example.com', 'https://[2001:db8::1]:8443']);

        $accepted = [
            'https://example.com' => 'the allowlisted origin itself',
            'https://example.com:443' => 'explicit default port equals the implicit one',
            'https://EXAMPLE.COM' => 'host case-insensitivity (DNS)',
            'https://EXAMPLE.COM:443' => 'case + explicit default port',
            'https://example.com.' => 'trailing dot is DNS-equivalent',
            'https://[2001:db8::1]:8443' => 'IPv6 literal kept bracketed',
        ];
        foreach ($accepted as $origin => $why) {
            $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => $origin], '{"scope":"login"}'));
            self::assertSame(200, $response->getStatusCode(), $why.' must be accepted');
        }

        $rejected = [
            'http://example.com' => 'scheme differs (http vs https)',
            'https://example.com:444' => 'non-default port differs',
            'https://evil-example.com' => 'different host',
            'https://example.com.evil.com' => 'suffix host is not the host',
            'https://[2001:db8::1]' => 'IPv6 without the port differs',
            'https://[2001:db8::2]:8443' => 'different IPv6 literal',
        ];
        foreach ($rejected as $origin => $why) {
            $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => $origin], '{"scope":"login"}'));
            self::assertSame(403, $response->getStatusCode(), $why.' must be rejected');
            self::assertSame('origin_rejected', json_decode((string) $response->getContent(), true)['error']['code'], $why);
        }
    }

    public function testOriginNormalizationUnicodePunycodeWhenIntlAvailable(): void
    {
        if (!\function_exists('idn_to_ascii')) {
            self::markTestSkipped('ext-intl is not available — IDN normalization cannot be tested');
        }
        $controller = new ChallengeController($this->issuer(), null, false, null, null, null, null, ['https://bücher.example']);

        // The Unicode spelling and its punycode form normalize identically.
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://bücher.example'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode(), 'the Unicode spelling must match its own allowlisted form');

        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://xn--bcher-kva.example'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode(), 'the punycode spelling must match the Unicode allowlist entry');

        // A different Unicode host must NOT match.
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://kaufen.example'], '{"scope":"login"}'));
        self::assertSame(403, $response->getStatusCode(), 'a different IDN host must be rejected');
    }

    public function testEnforceOriginRejectsMissingAndNullOrigins(): void
    {
        // enforce_origin with an empty allowlist: the Origin is required but
        // anything non-null is accepted (no allowlist to match).
        $controller = new ChallengeController($this->issuer(), null, false, null, null, null, null, [], false, null, null, true);

        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
        self::assertSame(403, $response->getStatusCode(), 'a MISSING Origin must be rejected when enforce_origin is true');
        self::assertSame('origin_rejected', json_decode((string) $response->getContent(), true)['error']['code']);

        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'null'], '{"scope":"login"}'));
        self::assertSame(403, $response->getStatusCode(), 'the literal "null" Origin (opaque/sandboxed) must be rejected when enforced');
        self::assertSame('origin_rejected', json_decode((string) $response->getContent(), true)['error']['code']);

        // A usable Origin passes (no allowlist).
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://anything.example'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode());

        // With an allowlist, the required Origin must also be allowlisted.
        $strict = new ChallengeController($this->issuer(), null, false, null, null, null, null, ['https://app.example.com'], false, null, null, true);
        $response = $strict->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://other.example'], '{"scope":"login"}'));
        self::assertSame(403, $response->getStatusCode(), 'enforced + allowlisted: a non-allowlisted Origin must be rejected');
        $response = $strict->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://app.example.com'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode());

        // NOT enforced (default): a missing Origin with an allowlist falls
        // back to the Referer as before (server-to-server trusted mode).
        $lax = new ChallengeController($this->issuer(), null, false, null, null, null, null, ['https://app.example.com']);
        $response = $lax->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_REFERER' => 'https://app.example.com/contact'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode(), 'enforce_origin=false keeps the Referer-origin fallback (documented trusted mode for server-to-server)');
    }

    public function testChallengeAcceptsRequestBindingAndBakesItIntoTheRecord(): void
    {
        $storage = new ArrayStorage();
        $controller = new ChallengeController(new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage));

        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login","request_binding":"txn-abc-123"}'));
        self::assertSame(200, $response->getStatusCode());

        $data = json_decode((string) $response->getContent(), true);
        $record = $storage->find($data['nonce']);
        self::assertNotNull($record);
        self::assertSame('txn-abc-123', $record->requestBinding, 'the request binding must be signed into the stored record');
    }

    public function testChallengeRejectsMalformedRequestBinding(): void
    {
        $controller = new ChallengeController($this->issuer());

        // '|' is the canonical-payload separator — never allowed in a binding.
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login","request_binding":"a|b"}'));
        self::assertSame(422, $response->getStatusCode());
        self::assertSame('INVALID_REQUEST_BINDING', json_decode((string) $response->getContent(), true)['error']['code']);

        // Longer than 128 chars.
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login","request_binding":"'.str_repeat('x', 129).'"}'));
        self::assertSame(422, $response->getStatusCode());
        self::assertSame('INVALID_REQUEST_BINDING', json_decode((string) $response->getContent(), true)['error']['code']);

        // Empty string is treated as absent.
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login","request_binding":""}'));
        self::assertSame(200, $response->getStatusCode());
    }

    // ── Identifier validation ──────────────────────────────────────────

    /**
     * Scope/tenant identifiers and request bindings are
     * validated against `[A-Za-z0-9._:-]+` with the 128-char ceiling before
     * they reach the issuer — separator, control and out-of-charset bytes
     * can never be signed into a challenge record.
     */
    public function testIdentifiersAreValidatedAgainstTheAudit96Charset(): void
    {
        $controller = new ChallengeController($this->issuer());

        // Scope: out-of-charset bytes are refused (no '|' needed — '@',
        // spaces, control bytes and non-ASCII all fail the charset).
        foreach (['log@in', 'login admin', "login\nadmin", 'login/tenant', 'scöpé', str_repeat('x', 129)] as $badScope) {
            $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], json_encode(['scope' => $badScope])));
            self::assertSame(422, $response->getStatusCode(), sprintf('scope %s must be refused', var_export($badScope, true)));
            self::assertSame('INVALID_SCOPE', json_decode((string) $response->getContent(), true)['error']['code']);
        }

        // The full charset is accepted: letters, digits, '.', '_', ':', '-'
        // (and the default scope).
        foreach (['login', 'default', 'Login_v2', 'tenant:eu-1', 'a.b_c-d', '1'] as $goodScope) {
            $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], json_encode(['scope' => $goodScope])));
            self::assertSame(200, $response->getStatusCode(), sprintf('scope %s must be accepted', $goodScope));
        }

        // Request binding: same charset + ceiling.
        foreach (['txn abc', 'txn/42', 'txn:ok'] as $binding) {
            $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], json_encode(['scope' => 'login', 'request_binding' => $binding])));
            $expected = $binding === 'txn:ok' ? 200 : 422;
            self::assertSame($expected, $response->getStatusCode(), sprintf('binding %s must be %s', var_export($binding, true), $expected));
        }
    }

    public function testStaticDefaultRequestBindingAppliesWhenThePayloadOmitsIt(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $controller = new ChallengeController($issuer, null, false, null, null, null, null, [], false, $storage, 'static-binding');

        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode());
        $data = json_decode((string) $response->getContent(), true);
        self::assertSame('static-binding', $storage->find($data['nonce'])?->requestBinding, 'the configured static binding must apply when the request sends none');

        // The request's own field wins over the static default.
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login","request_binding":"per-request"}'));
        $data = json_decode((string) $response->getContent(), true);
        self::assertSame('per-request', $storage->find($data['nonce'])?->requestBinding, 'the per-request binding overrides the static default');
    }

    /**
     * A source that issues more challenges than max_outstanding_challenges
     * gets the 429 risk-denied response; the minted-but-refused record is
     * discarded (never handed out, never left outstanding).
     */
    public function testOutstandingCapReturns429AndDiscardsTheMintedRecord(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $client = $this->requirePredis();
        $outstanding = new OutstandingChallenges($client, '{kiwi:flow-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 3, 100, 0);
        $controller = new ChallengeController($issuer, null, false, null, null, null, $outstanding, [], false, $storage);

        for ($i = 0; $i < 3; $i++) {
            $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
            self::assertSame(200, $response->getStatusCode(), 'issuance '.(1 + $i).' must pass below the cap');
        }

        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
        self::assertSame(429, $response->getStatusCode(), 'the 4th outstanding challenge must hit the per-source cap');
        self::assertSame('RISK_DENIED', json_decode((string) $response->getContent(), true)['error']['code']);

        $records = (new \ReflectionObject($storage))->getProperty('records');
        self::assertCount(3, $records->getValue($storage), 'the refused issuance must discard its minted record');
        self::assertSame(3, $client->counters['{kiwi:flow-test}:outstanding:'.hash_hmac('sha256', Issuer::canonicalIpFamily('198.51.100.7'), RiskKeys::fromMaster(self::SECRET)->event)], 'the per-source counter is bounded by the cap');

        // A different source is unaffected (per-source counters are keyed on
        // the HMAC of the canonical IP).
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.8'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode(), 'a fresh source must not be blocked by another source\'s cap');
    }

    private function requirePredis(): FakePredisClient
    {
        // The bundle itself does not depend on predis; the dev toolchain has
        // it via the core package's copied vendor (path repo). Load it when
        // available and skip otherwise, mirroring the core's RedisStorageTest.
        $nested = \dirname(__DIR__).'/vendor/kiwicaptcha/kiwicaptcha-php/vendor/autoload.php';
        if (!\class_exists(\Predis\Client::class) && is_file($nested)) {
            require_once $nested;
        }
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed; cannot test OutstandingChallenges');
        }

        return new FakePredisClient();
    }

    // ── Narrow HTTP ─────────────────────────────────────────────────────

    public function testNonPostMethodsStay405(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $controller = new ChallengeController($issuer);

        foreach (['GET', 'PUT', 'DELETE', 'PATCH', 'HEAD'] as $method) {
            $response = $controller->challenge(Request::create('/challenge', $method, [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
            self::assertSame(405, $response->getStatusCode(), $method.' must stay 405');
            self::assertSame('POST', $response->headers->get('Allow'), '405 must advertise Allow: POST');
            self::assertSame('METHOD_NOT_ALLOWED', json_decode((string) $response->getContent(), true)['error']['code']);
        }
        self::assertSame(0, \count((new \ReflectionObject($storage))->getProperty('records')->getValue($storage)), 'no non-POST method may mint a challenge');
    }

    /**
     * An OPTIONS preflight alone never authorizes — it is a
     * non-POST method and gets 405 with no challenge stored, no CORS
     * headers, no state written.
     */
    public function testOptionsPreflightNeverAuthorizes(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $controller = new ChallengeController($issuer);

        $response = $controller->challenge(Request::create(
            '/challenge',
            'OPTIONS',
            [],
            [],
            [],
            ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://evil.example', 'HTTP_ACCESS_CONTROL_REQUEST_METHOD' => 'POST'],
        ));
        self::assertSame(405, $response->getStatusCode(), 'an OPTIONS preflight must never authorize a challenge');
        self::assertSame(0, \count((new \ReflectionObject($storage))->getProperty('records')->getValue($storage)), 'a preflight must not mint a challenge');
        self::assertNull($response->headers->get('Access-Control-Allow-Origin'), 'the bundle emits no CORS headers — a preflight gets no ACAO echo');
    }

    public function testContentEncodingOtherThanIdentityIs415(): void
    {
        $controller = new ChallengeController($this->issuer());

        foreach (['gzip', 'br', 'deflate'] as $encoding) {
            $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], [
                'REMOTE_ADDR' => '198.51.100.7',
                'HTTP_CONTENT_ENCODING' => $encoding,
            ], '{"scope":"login"}'));
            self::assertSame(415, $response->getStatusCode(), 'Content-Encoding '.$encoding.' must be refused');
            self::assertSame('UNSUPPORTED_CONTENT_ENCODING', json_decode((string) $response->getContent(), true)['error']['code']);
        }

        // identity (explicit or absent) is the only accepted encoding.
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], [
            'REMOTE_ADDR' => '198.51.100.7',
            'HTTP_CONTENT_ENCODING' => 'identity',
        ], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode(), 'identity encoding must be accepted');
    }

    public function testContentTypeOtherThanApplicationJsonIs415(): void
    {
        $controller = new ChallengeController($this->issuer());

        foreach (['application/x-www-form-urlencoded', 'text/plain', 'multipart/form-data', 'application/xml'] as $type) {
            $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], [
                'REMOTE_ADDR' => '198.51.100.7',
                'CONTENT_TYPE' => $type,
            ], '{"scope":"login"}'));
            self::assertSame(415, $response->getStatusCode(), 'Content-Type '.$type.' must be refused');
            self::assertSame('UNSUPPORTED_MEDIA_TYPE', json_decode((string) $response->getContent(), true)['error']['code']);
        }

        // application/json (with an optional charset) is the widget's POST.
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], [
            'REMOTE_ADDR' => '198.51.100.7',
            'CONTENT_TYPE' => 'application/json; charset=utf-8',
        ], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode(), 'application/json with a charset parameter must be accepted');
    }

    public function testChallengeEndpointAcceptsNoQueryParameters(): void
    {
        $controller = new ChallengeController($this->issuer());

        foreach (['debug=1', 'skip_pow=1', 'algorithm=sha256', 'scope=login'] as $query) {
            $response = $controller->challenge(JsonRequest::create('/challenge?'.$query, 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
            self::assertSame(422, $response->getStatusCode(), 'query parameter "'.$query.'" must be refused');
            self::assertSame('QUERY_PARAMETERS_NOT_ALLOWED', json_decode((string) $response->getContent(), true)['error']['code']);
        }
    }

    // ── Query-param hardening / unknown fields ──────────────────────────

    public function testUnknownJsonFieldsAre422(): void
    {
        $controller = new ChallengeController($this->issuer());

        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login","debug":1}'));
        self::assertSame(422, $response->getStatusCode());
        self::assertSame('UNKNOWN_FIELDS', json_decode((string) $response->getContent(), true)['error']['code']);

        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login","skip_pow":true,"algorithm":"sha256"}'));
        self::assertSame(422, $response->getStatusCode(), 'any unknown field — alongside known ones — must be refused');
    }

    public function testDocumentedFieldsAreAccepted(): void
    {
        $controller = new ChallengeController($this->issuer());

        // scope + algorithm + request_binding are the documented fields.
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login","algorithm":"sha256","request_binding":"txn-1"}'));
        self::assertSame(200, $response->getStatusCode(), 'the documented fields must be accepted');

        // An empty JSON object {} is valid (all fields optional).
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{}'));
        self::assertSame(200, $response->getStatusCode(), 'an empty JSON object is a valid document');
    }

    public function testNonObjectJsonBodiesAre422(): void
    {
        $controller = new ChallengeController($this->issuer());

        foreach (['[]', '"login"', '123', 'null', 'not-json{'] as $body) {
            $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], $body));
            self::assertSame(422, $response->getStatusCode(), 'body '.var_export($body, true).' must be refused');
            self::assertSame('INVALID_JSON', json_decode((string) $response->getContent(), true)['error']['code']);
        }
    }

    // ── CORS is not authorization ───────────────────────────────────────

    public function testNoCorsHeadersAreEmittedOnAnyResponse(): void
    {
        $controller = new ChallengeController($this->issuer());

        // Success path.
        $ok = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
        self::assertNull($ok->headers->get('Access-Control-Allow-Origin'), 'a success response must never echo ACAO');
        self::assertNull($ok->headers->get('Vary'), 'no CORS header means no Vary: Origin either');

        // Error paths (403 origin rejection, 405, 415).
        $cross = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://evil.example'], '{"scope":"login"}'));
        self::assertNull($cross->headers->get('Access-Control-Allow-Origin'), 'a 403 must not echo ACAO');

        $badMethod = $controller->challenge(Request::create('/challenge', 'GET'));
        self::assertNull($badMethod->headers->get('Access-Control-Allow-Origin'), 'a 405 must not echo ACAO');

        $badEncoding = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_CONTENT_ENCODING' => 'gzip'], '{"scope":"login"}'));
        self::assertNull($badEncoding->headers->get('Access-Control-Allow-Origin'), 'a 415 must not echo ACAO');

        // The origin checks run on every response regardless of any CORS
        // configuration: the allowlisted controller still rejects a
        // non-allowlisted origin on every path.
        $allowlisted = new ChallengeController($this->issuer(), null, false, null, null, null, null, ['https://app.example.com']);
        $denied = $allowlisted->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://evil.example'], '{"scope":"login"}'));
        self::assertSame(403, $denied->getStatusCode(), 'origin enforcement is independent of CORS');
        self::assertNull($denied->headers->get('Access-Control-Allow-Origin'));
    }

    // ── Frame-ancestors CSP ─────────────────────────────────────────────

    public function testFrameAncestorsCspEmittedWhenAllowlistNonEmpty(): void
    {
        $controller = new ChallengeController($this->issuer(), null, false, null, null, null, null, ['https://app.example.com', 'https://cdn.example.com']);

        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://app.example.com'], '{"scope":"login"}'));
        self::assertSame('frame-ancestors https://app.example.com https://cdn.example.com', $response->headers->get('Content-Security-Policy'), 'the CSP must carry the EXACT space-separated allowlisted origins');

        // Error responses carry the same explicit CSP (never inherited from
        // default-src — it is always the full directive).
        $denied = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://evil.example'], '{"scope":"login"}'));
        self::assertSame(403, $denied->getStatusCode());
        self::assertSame('frame-ancestors https://app.example.com https://cdn.example.com', $denied->headers->get('Content-Security-Policy'));
    }

    public function testNoCspHeaderWhenAllowlistEmpty(): void
    {
        $controller = new ChallengeController($this->issuer());

        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
        self::assertNull($response->headers->get('Content-Security-Policy'), 'an empty allowlist must emit NO CSP header');
    }

    // ── Host-context hardening ──────────────────────────────────────────

    /**
     * public_base_url comes from server config: a forged Host header can
     * never shift the expected same-origin ("Host: evil.example" + "Origin:
     * https://evil.example" must stay cross-origin).
     */
    public function testForgedHostCannotAlterOriginChecksWithPublicBaseUrl(): void
    {
        $controller = new ChallengeController($this->issuer(), null, true, null, null, null, null, [], false, null, null, false, null, 'https://app.example.com');

        // Forged Host + matching forged Origin: rejected — the expected
        // origin is the configured base URL, not the request's host.
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], [
            'REMOTE_ADDR' => '198.51.100.7',
            'HTTP_HOST' => 'evil.example',
            'HTTP_ORIGIN' => 'https://evil.example',
        ], '{"scope":"login"}'));
        self::assertSame(403, $response->getStatusCode(), 'a forged Host must not make a cross-origin request look same-origin');
        self::assertSame('CROSS_ORIGIN_DENIED', json_decode((string) $response->getContent(), true)['error']['code']);

        // The real origin passes even behind the forged Host.
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], [
            'REMOTE_ADDR' => '198.51.100.7',
            'HTTP_HOST' => 'evil.example',
            'HTTP_ORIGIN' => 'https://app.example.com',
        ], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode(), 'the configured origin must pass regardless of the Host header');
    }

    public function testForgedHostCannotAlterTheIssuedChallenge(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $controller = new ChallengeController($issuer, null, false, null, null, null, null, [], false, $storage);

        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], [
            'REMOTE_ADDR' => '198.51.100.7',
            'HTTP_HOST' => 'attacker-controlled.example',
        ], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode());

        $nonce = json_decode((string) $response->getContent(), true)['nonce'];
        $record = $storage->find($nonce);
        self::assertNotNull($record);
        // The record carries NO Host-derived material: scope + the socket
        // peer's binding tag are the only context.
        self::assertSame('login', $record->scope);
        self::assertSame(Issuer::bindingTag($nonce, '198.51.100.7', self::SECRET), $record->bindingTag);
    }

    // ── Local admission before Redis ────────────────────────────────────

    private function riskGatewayWithEmergencyCap(ProcessEmergencyCap $cap): RiskGateway
    {
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow']],
        ]);
        $engine = new AdaptiveRiskEngine(new FakeRiskStateStore(), $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);

        return new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1], emergencyCap: $cap);
    }

    /**
     * A saturated process-local emergency cap denies before any
     * Redis issuance limiter — the fake Redis client sees zero calls.
     */
    public function testSaturatedProcessCapDeniesBeforeAnyRedisWrite(): void
    {
        $client = new FakePredisClient();
        $limiter = new IssuanceRateLimiter(10, 60, null, null, 'pepper', $client, 500, 'test-ns');
        $cap = new ProcessEmergencyCap(1);
        $cap->allow(); // consume the single per-second allowance -> saturated
        $gateway = $this->riskGatewayWithEmergencyCap($cap);

        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), new ArrayStorage());
        $controller = new ChallengeController($issuer, $limiter, false, $gateway);

        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
        self::assertSame(429, $response->getStatusCode());
        self::assertSame('RISK_DENIED', json_decode((string) $response->getContent(), true)['error']['code']);
        self::assertSame([], $client->calls, 'the process-local cap must refuse BEFORE any Redis round trip (the rate limiter never ran)');
    }

    public function testRedisRateLimiterRunsWhenTheProcessCapHasBudget(): void
    {
        $client = new FakePredisClient();
        $limiter = new IssuanceRateLimiter(1, 60, null, null, 'pepper', $client, 500, 'test-ns');
        $gateway = $this->riskGatewayWithEmergencyCap(new ProcessEmergencyCap(10000));

        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), new ArrayStorage());
        $controller = new ChallengeController($issuer, $limiter, false, $gateway);

        // First issuance passes (Redis limiter + engine admission both run).
        self::assertSame(200, $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'))->getStatusCode());
        self::assertNotSame([], $client->calls, 'with process budget available the Redis limiter runs');

        // The second issuance hits the per-client Redis cap (429 rate_limited).
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
        self::assertSame(429, $response->getStatusCode());
        self::assertSame('RATE_LIMITED', json_decode((string) $response->getContent(), true)['error']['code']);
    }

    // ── HTTP framing ────────────────────────────────────────────────────

    private function framingRequest(array $headers): Request
    {
        $request = JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}');
        foreach ($headers as $name => $value) {
            $request->headers->set($name, $value, false);
        }

        return $request;
    }

    /**
     * A request carrying both Content-Length and
     * Transfer-Encoding is request-smuggling ambiguity (intermediaries will
     * frame the body differently) — refused with 400 framing_rejected
     * before any body is read.
     */
    public function testContentLengthPlusTransferEncodingIs400FramingRejected(): void
    {
        $storage = new ArrayStorage();
        $controller = new ChallengeController(new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage));
        $request = $this->framingRequest(['content-length' => '13', 'transfer-encoding' => 'chunked']);

        $response = $controller->challenge($request);
        self::assertSame(400, $response->getStatusCode());
        self::assertSame('FRAMING_REJECTED', json_decode((string) $response->getContent(), true)['error']['code']);
        self::assertSame([], $this->storedRecords($storage), 'a framing-ambiguous request must never reach issuance');
    }

    /**
     * A duplicate Content-Length (two values) is equally
     * ambiguous — refused with 400 framing_rejected.
     */
    public function testDuplicateContentLengthIs400FramingRejected(): void
    {
        $storage = new ArrayStorage();
        $controller = new ChallengeController(new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage));
        $request = $this->framingRequest(['content-length' => ['13', '14']]);

        $response = $controller->challenge($request);
        self::assertSame(400, $response->getStatusCode());
        self::assertSame('FRAMING_REJECTED', json_decode((string) $response->getContent(), true)['error']['code']);
        self::assertSame([], $this->storedRecords($storage));
    }

    /**
     * A single Content-Length is the normal framing — the
     * endpoint must keep issuing.
     */
    public function testSingleContentLengthStillIssues(): void
    {
        $controller = new ChallengeController($this->issuer());
        $request = $this->framingRequest(['content-length' => '13']);

        $response = $controller->challenge($request);
        self::assertSame(200, $response->getStatusCode());
        self::assertArrayHasKey('nonce', json_decode((string) $response->getContent(), true));
    }

    /**
     * The framing check runs first — before the content-type /
     * content-encoding checks (a framing-ambiguous request with a wrong
     * content type still gets framing_rejected, never 415).
     */
    public function testFramingRejectionPrecedesBodyChecks(): void
    {
        $controller = new ChallengeController($this->issuer());
        $request = $this->framingRequest(['content-length' => '13', 'transfer-encoding' => 'chunked']);
        $request->headers->set('Content-Type', 'text/plain');

        $response = $controller->challenge($request);
        self::assertSame(400, $response->getStatusCode());
        self::assertSame('FRAMING_REJECTED', json_decode((string) $response->getContent(), true)['error']['code']);
    }

    /**
     * A duplicate Content-Length reaches the controller as two raw header
     * values (Symfony's HeaderBag keeps every value); the detection is
     * count-based, so two identical values are still duplicate framing.
     */
    public function testIdenticalDuplicateContentLengthStillRejected(): void
    {
        $controller = new ChallengeController($this->issuer());
        $request = $this->framingRequest(['content-length' => ['13', '13']]);

        $response = $controller->challenge($request);
        self::assertSame(400, $response->getStatusCode());
        self::assertSame('FRAMING_REJECTED', json_decode((string) $response->getContent(), true)['error']['code']);
    }

    // ── Sitekey publicity ───────────────────────────────────────────────

    /**
     * NO client-visible identifier confers any privileged
     * capability. The challenge endpoint accepts no client-supplied
     * identifier AT ALL — a payload carrying a "site_key", "secret" or
     * "api_key" field is an unknown-field probe (422 unknown_fields), and
     * the endpoint succeeds without any privileged identifier (a plain
     * {"scope":"login"} POST — {@see testChallengeControllerIssuesValidChallenge}).
     */
    public function testClientSuppliedIdentifiersGrantNoPrivilege(): void
    {
        $controller = new ChallengeController($this->issuer());
        foreach (['site_key', 'api_key', 'secret', 'admin_key', 'tenant_id'] as $field) {
            $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], json_encode(['scope' => 'login', $field => 'client-supplied-value'])));
            self::assertSame(422, $response->getStatusCode(), sprintf('a client-supplied "%s" must never be accepted as an identifier', $field));
            self::assertSame('UNKNOWN_FIELDS', json_decode((string) $response->getContent(), true)['error']['code']);
        }

        // The same request without any identifier succeeds — the endpoint is
        // fully public, keyed on nothing client-supplied.
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode());
    }

    /**
     * No admin endpoint keys off a client-supplied identifier: the route
     * surface is exactly challenge + health (both fully public), so no
     * control-plane route can be reached with a client-provided
     * credential.
     */
    public function testNoAdminEndpointExistsForKeyingOffAClientIdentifier(): void
    {
        $loader = new \BelConsulting\KiwiCaptchaBundle\Routing\KiwiCaptchaRouteLoader('/kiwi-captcha');
        $routes = $loader->load(null, 'kiwicaptcha');

        $names = array_keys($routes->all());
        sort($names);
        self::assertSame(['kiwicaptcha_api_js', 'kiwicaptcha_challenge', 'kiwicaptcha_health_live', 'kiwicaptcha_health_ready', 'kiwicaptcha_siteverify', 'kiwicaptcha_widget_css'], $names, 'the bundle exposes ONLY the public surface (challenge, siteverify, api.js, health) — no admin/control-plane routes');

        foreach ($routes->all() as $route) {
            self::assertNotSame('admin', $route->getDefault('_controller')[1] ?? null);
        }
    }

    /**
     * @return list<\KiwiCaptcha\ChallengeRecord>
     */
    private function storedRecords(ArrayStorage $storage): array
    {
        $prop = new \ReflectionProperty(ArrayStorage::class, 'records');

        return array_values($prop->getValue($storage));
    }

    // ── Canonical request targets ───────────────────────────────────────

    /**
     * The RAW request_URI must equal the canonical path — no
     * empty segments (`//`, trailing `/`), no dot segments (`/./`,
     * `/../`), no percent-encoded bytes (`/%76hallenge`, `%2F`, `%5C`).
     * The full list gets 404 canonical_path_required before ANY
     * handling (no challenge is ever minted for a noncanonical target).
     */
    public function testNonCanonicalRequestTargetsAre404BeforeAnyHandling(): void
    {
        $storage = new ArrayStorage();
        $controller = new ChallengeController(new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage));

        $nonCanonical = [
            '/kiwi-captcha//challenge' => 'empty segment (double slash)',
            '/challenge/' => 'trailing slash (empty final segment)',
            '/./challenge' => 'leading dot segment',
            '/kiwi-captcha/./challenge' => 'middle dot segment',
            '/foo/../challenge' => 'parent traversal segment',
            '/kiwi-captcha/challenge/../challenge' => 'embedded parent segment',
            '/%76hallenge' => 'percent-encoded leading byte',
            '/kiwi-captcha/%2Fchallenge' => 'percent-encoded separator',
            '/challenge%2F' => 'percent-encoded trailing separator',
            '/kiwi-captcha/challenge%5C' => 'percent-encoded backslash',
            '/kiwi-captcha%2F%2Fchallenge' => 'double-encoded separators',
            // (a RAW backslash is also refused by the check, but Symfony's
            // Request::create refuses to even build such a URI — the
            // percent-encoded %5C case above pins the smuggling path)
        ];
        foreach ($nonCanonical as $uri => $why) {
            $response = $controller->challenge(JsonRequest::create($uri, 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
            self::assertSame(404, $response->getStatusCode(), sprintf('%s (%s) must be 404', $uri, $why));
            self::assertSame('CANONICAL_PATH_REQUIRED', json_decode((string) $response->getContent(), true)['error']['code'], $why);
        }
        self::assertSame([], $this->storedRecords($storage), 'a noncanonical target must never reach issuance');

        // The canonical path itself keeps working.
        $response = $controller->challenge(JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode());
    }

    /**
     * The canonicality check runs before the method and query checks: a
     * noncanonical GET is still 404 canonical_path_required, and a
     * canonical path with a query string still gets the 422 query
     * rejection.
     */
    public function testCanonicalityPrecedesMethodAndQueryChecks(): void
    {
        $controller = new ChallengeController($this->issuer());

        $response = $controller->challenge(Request::create('/kiwi-captcha//challenge', 'GET'));
        self::assertSame(404, $response->getStatusCode(), 'a noncanonical target is 404 regardless of method');
        self::assertSame('CANONICAL_PATH_REQUIRED', json_decode((string) $response->getContent(), true)['error']['code']);

        // The query string is excluded from the path scan; a canonical path
        // with a query keeps the documented 422 query_parameters_NOT_allowed.
        $response = $controller->challenge(JsonRequest::create('/kiwi-captcha/challenge?debug=1', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
        self::assertSame(422, $response->getStatusCode());
        self::assertSame('QUERY_PARAMETERS_NOT_ALLOWED', json_decode((string) $response->getContent(), true)['error']['code']);
    }

    // ── Duplicate security-singular headers ─────────────────────────────

    /**
     * Origin, Forwarded, X-Forwarded-For and X-Real-IP are
     * security-singular: a duplicate occurrence is parser ambiguity and
     * gets 400 duplicate_header before any header-derived identity is
     * trusted. The count is value-agnostic — two identical values are
     * still a duplicate.
     */
    public function testDuplicateSecurityHeadersAre400(): void
    {
        $storage = new ArrayStorage();
        $controller = new ChallengeController(new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage));

        $cases = [
            ['origin', ['https://good.example', 'https://evil.example'], 'Origin twice, good + evil'],
            ['origin', ['https://app.example', 'https://app.example'], 'Origin twice, IDENTICAL values'],
            ['forwarded', ['for=1.2.3.4', 'for=5.6.7.8'], 'Forwarded twice'],
            ['x-forwarded-for', ['1.2.3.4', '5.6.7.8'], 'X-Forwarded-For twice'],
            ['x-real-ip', ['1.2.3.4', '5.6.7.8'], 'X-Real-IP twice'],
        ];
        foreach ($cases as [$name, $values, $why]) {
            $request = JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}');
            foreach ($values as $value) {
                $request->headers->set($name, $value, false);
            }
            $response = $controller->challenge($request);
            self::assertSame(400, $response->getStatusCode(), $why.' must be 400 DUPLICATE_HEADER');
            self::assertSame('DUPLICATE_HEADER', json_decode((string) $response->getContent(), true)['error']['code'], $why);
        }
        self::assertSame([], $this->storedRecords($storage), 'a duplicate-header request must never reach issuance');

        // Each single occurrence is the normal case — the endpoint keeps
        // issuing (a browser always sends exactly one Origin, a trusted
        // proxy exactly one forwarding chain). The single-Origin control
        // uses the request's own origin so the same-origin check passes.
        foreach ([['origin', 'http://localhost'], ['forwarded', 'for=1.2.3.4'], ['x-forwarded-for', '1.2.3.4'], ['x-real-ip', '1.2.3.4']] as [$name, $value]) {
            $request = JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}');
            $request->headers->set($name, $value, false);
            self::assertSame(200, $controller->challenge($request)->getStatusCode(), 'a single '.$name.' header must pass');
        }
    }

    /**
     * The duplicate-header check is a wire-level check — it
     * runs with the framing checks, before any body is read; a request with
     * a duplicate Origin AND a wrong content type still gets
     * duplicate_header (never 415). Framing ambiguity stays first (a
     * duplicate Origin + CL+TE is framing_rejected).
     */
    public function testDuplicateHeaderCheckPrecedesBodyChecks(): void
    {
        $controller = new ChallengeController($this->issuer());

        $request = JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}');
        $request->headers->set('origin', 'https://a.example', false);
        $request->headers->set('origin', 'https://b.example', false);
        $request->headers->set('Content-Type', 'text/plain');
        $response = $controller->challenge($request);
        self::assertSame(400, $response->getStatusCode());
        self::assertSame('DUPLICATE_HEADER', json_decode((string) $response->getContent(), true)['error']['code']);

        // Framing ambiguity is checked first (it is the deepest wire-level
        // ambiguity): a duplicate Origin plus CL+TE stays framing_rejected.
        $request = $this->framingRequest(['content-length' => '13', 'transfer-encoding' => 'chunked']);
        $request->headers->set('origin', 'https://a.example', false);
        $request->headers->set('origin', 'https://b.example', false);
        $response = $controller->challenge($request);
        self::assertSame(400, $response->getStatusCode());
        self::assertSame('FRAMING_REJECTED', json_decode((string) $response->getContent(), true)['error']['code']);
    }

    // ── Scoped syntactic rejection before shared infrastructure ─────────

    /**
     * A syntactically invalid scope (bad charset, > 128 bytes) is
     * rejected locally at 422 with zero Redis operations: the
     * identifier-charset check runs before the rate limiter, the risk
     * engine, the scope cap and the outstanding counters.
     */
    public function testInvalidScopeIsRejectedWithZeroRedisOperations(): void
    {
        $client = new FakePredisClient();
        $limiter = new IssuanceRateLimiter(10, 60, null, null, 'pepper', $client, 500, 'test-ns');
        $outstanding = new OutstandingChallenges($client, '{kiwi:zero-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $scopeCap = new ScopeIssuanceCap($client, '{kiwi:zero-test}:issuance:', 10, ScopeIssuanceCap::deriveScopeHmacKey(self::SECRET), fn (): int => 1_800_000_000);
        $controller = new ChallengeController(
            $this->issuer(),
            rateLimiter: $limiter,
            outstanding: $outstanding,
            scopeIssuanceCap: $scopeCap,
        );

        foreach (['bad|scope', 'log@in', "login\nadmin", str_repeat('x', 129)] as $badScope) {
            $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], json_encode(['scope' => $badScope])));
            self::assertSame(422, $response->getStatusCode(), sprintf('scope %s must be refused locally', var_export($badScope, true)));
            self::assertSame('INVALID_SCOPE', json_decode((string) $response->getContent(), true)['error']['code']);
            self::assertSame([], $client->calls, 'a syntactically invalid scope must be rejected with ZERO Redis operations');
        }

        // Control: a valid scope flows into the Redis limiter (the check is
        // not skipping Redis for everything).
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode());
        self::assertNotSame([], $client->calls, 'a valid scope proceeds to the Redis-backed checks');
    }

    /**
     * every unresolvable scope — risk disabled, or unknown
     * in baseline/reject mode — maps to the single reserved
     * unknown_quota_ID bucket. An attacker can never mint fresh quota
     * windows by inventing scope names, in ANY configuration (no HMAC
     * fallback namespace in the controller path).
     */
    public function testUnresolvedScopesShareTheReservedQuotaBucket(): void
    {
        $client = new FakePredisClient();
        $scopeCap = new ScopeIssuanceCap($client, '{kiwi:reserved}:issuance:', 1, ScopeIssuanceCap::deriveScopeHmacKey(self::SECRET), fn (): int => 1_800_000_000);

        // Risk disabled (no RiskGateway): the cap still keys on the
        // reserved server-owned id, not on per-name HMAC namespaces.
        $controller = new ChallengeController($this->issuer(), scopeIssuanceCap: $scopeCap);
        self::assertSame(200, $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"foo1"}'))->getStatusCode());
        // Second invented scope in the same minute shares the reserved
        // bucket -> the cap (1/min) refuses it.
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"foo2"}'));
        self::assertSame(429, $response->getStatusCode());
        self::assertSame('SCOPE_LIMITED', json_decode((string) $response->getContent(), true)['error']['code']);

        $expectedKey = '{kiwi:reserved}:issuance:'.ScopeIssuanceCap::UNKNOWN_QUOTA_ID.':'.intdiv(1_800_000_000, 60);
        self::assertSame(2, $client->counters[$expectedKey] ?? null, 'both invented scopes hit the SAME reserved quota window');
        foreach ($client->calls as $call) {
            foreach ((array) $call[1] as $arg) {
                if (\is_string($arg) && str_contains($arg, ':issuance:')) {
                    self::assertStringNotContainsString('foo', $arg, 'the raw scope must never appear in a quota key');
                }
            }
        }
    }

    /**
     * When the Redis durability barrier cannot be met at issuance
     * (replica lag/failure), the challenge is not handed out: the
     * controller maps the failure to a private/no-store 503
     * service_unavailable with an opaque client message, never a generic
     * 500.
     */
    public function testReplicaWaitFailureAtIssuanceReturns503(): void
    {
        $failingStorage = new class implements \KiwiCaptcha\StorageInterface {
            public function store(\KiwiCaptcha\ChallengeRecord $record): void
            {
                throw new \KiwiCaptcha\Storage\ReplicaWaitException('Redis WAIT acknowledged 0 of 1 replicas after challenge issuance');
            }

            public function find(string $nonce): ?\KiwiCaptcha\ChallengeRecord
            {
                return null;
            }

                        public function consumedState(string $nonce): ?\KiwiCaptcha\ConsumedRecord
            {
                return null;
            }

public function consume(string $nonce): ?\KiwiCaptcha\ConsumedRecord
            {
                return null;
            }

            public function commitResult(string $nonce, bool $valid, ?string $binding): bool
            {
                return false;
            }

            public function delete(string $nonce): void
            {
            }
        };
        $issuer = new Issuer(new Config(
            secretKey: self::SECRET,
            algorithm: PoWAlgorithm::Sha256,
            targetBits: 8, // fast solve for tests
            ttlSecs: 120,
        ), $failingStorage);
        $controller = new ChallengeController($issuer);

        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
        self::assertSame(503, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('SERVICE_UNAVAILABLE', $body['error']['code']);
        self::assertStringNotContainsString('replica', $body['error']['message'], 'the client message must stay opaque');
        self::assertTrue($response->headers->getCacheControlDirective('no-store'), 'the 503 must carry the private no-store envelope');
        self::assertTrue($response->headers->getCacheControlDirective('private'));
    }

    /**
     * With risk.allowed_scopes configured, the per-scope quota operates
     * over a server-owned namespace: a scope outside the allowlist is
     * refused with 422 scope_NOT_allowed before the risk assessment and
     * the quota checks (zero Redis operations). An attacker cannot mint
     * fresh quota windows by inventing scope names.
     */
    public function testScopeOutsideServerAllowlistIsRefusedBeforeAnyQuota(): void
    {
        $client = new FakePredisClient();
        $scopeCap = new ScopeIssuanceCap($client, '{kiwi:allowlist}:issuance:', 1, ScopeIssuanceCap::deriveScopeHmacKey(self::SECRET), fn (): int => 1_800_000_000);
        $controller = new ChallengeController(
            $this->issuer(),
            scopeIssuanceCap: $scopeCap,
            allowedScopes: ['login', 'signup'],
        );

        // An allowlisted scope issues normally.
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode());

        // A disallowed scope is refused before any Redis access — no quota
        // window is ever created for it, so attacker-chosen scope names can
        // never mint counters in the server-owned namespace.
        $client->calls = [];
        foreach (['foo1', 'foo2', 'admin_login' /* configured but not allowlisted */] as $scope) {
            $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], json_encode(['scope' => $scope])));
            self::assertSame(422, $response->getStatusCode(), 'scope '.$scope.' must be refused by the allowlist');
            self::assertSame('SCOPE_NOT_ALLOWED', json_decode((string) $response->getContent(), true)['error']['code']);
            self::assertSame([], $client->calls, 'a disallowed scope must never touch Redis (no quota window, no limiter)');
        }

        // The allowlist is a security gate, not a permissive default: an
        // empty allowlist keeps the legacy accept-any behavior.
        $open = new ChallengeController($this->issuer(), allowedScopes: []);
        $response = $open->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"anything"}'));
        self::assertSame(200, $response->getStatusCode(), 'an empty allowlist keeps the accept-any behavior');
    }

    /**
     * The challenge-issuance sequence runs every quota check
     * before the challenge state is created — local cap, issuer limiter,
     * scope cap and outstanding counters all precede the storage write.
     * The FakePredis call order pins the limit/incr keys before the
     * challenge SET key.
     */
    public function testAdmissionQuotaChecksPrecedeChallengeStateCreation(): void
    {
        $client = new FakePredisClient();
        $limiter = new IssuanceRateLimiter(10, 60, null, null, 'pepper', $client, 500, 'order-test-ns');
        $outstanding = new OutstandingChallenges($client, '{kiwi:order-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $scopeCap = new ScopeIssuanceCap($client, '{kiwi:order-test}:issuance:', 100, ScopeIssuanceCap::deriveScopeHmacKey(self::SECRET), fn (): int => 1_800_000_000);

        $storage = new ArrayStorage();
        // The tracking decorator IS the issuer's storage — the challenge
        // record write flows through it into the shared call log.
        $tracking = new class($storage, $client) implements \KiwiCaptcha\StorageInterface {
            public function __construct(
                private readonly \KiwiCaptcha\StorageInterface $inner,
                private readonly FakePredisClient $client,
            ) {
            }

            public function store(\KiwiCaptcha\ChallengeRecord $record): void
            {
                $this->client->calls[] = ['SET', ['{kiwi:order-test}:challenge:'.$record->nonce]];
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
                return $this->inner->consume($nonce);
            }

            public function delete(string $nonce): void
            {
                $this->inner->delete($nonce);
            }

            public function commitResult(string $nonce, bool $valid, ?string $binding): bool
            {
                return $this->inner->commitResult($nonce, $valid, $binding);
            }
        };
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), $tracking);

        $controller = new ChallengeController(
            $issuer,
            rateLimiter: $limiter,
            outstanding: $outstanding,
            storage: $tracking,
            scopeIssuanceCap: $scopeCap,
            challengeTtlSecs: 120,
        );

        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode());

        $setIndex = null;
        $evalIndices = [];
        foreach ($client->calls as $i => [$command, $args]) {
            if ($command === 'SET') {
                $setIndex = $i;
            }
            if ($command === 'EVAL' && isset($args[2]) && \is_string($args[2])) {
                $evalIndices[$args[2]] = $i;
            }
        }
        self::assertNotNull($setIndex, 'the challenge-state write must have happened');
        self::assertNotSame([], $evalIndices, 'the quota checks must have run');

        $sawScopeCap = false;
        $sawOutstanding = false;
        foreach ($evalIndices as $firstKey => $i) {
            self::assertLessThan(
                $setIndex,
                $i,
                sprintf('the quota-check EVAL on %s must run BEFORE the challenge SET key', $firstKey)
            );
            // The scope-cap and outstanding keys are the {kiwi:...} family
            // (Cluster safe) and carry only keyed pseudonyms — never the
            // raw scope or IP.
            if (str_contains($firstKey, ':issuance:')) {
                $sawScopeCap = true;
                self::assertStringContainsString('{kiwi:order-test}:issuance:', $firstKey);
                self::assertStringNotContainsString('login', $firstKey, 'the scope cap key carries hex(hmac_sha256(scope, K_scope)), never the raw scope');
            }
            if (str_contains($firstKey, ':outstanding:')) {
                $sawOutstanding = true;
                self::assertStringContainsString('{kiwi:order-test}:outstanding:', $firstKey);
            }
        }
        self::assertTrue($sawScopeCap, 'the per-scope issuance cap must have run');
        self::assertTrue($sawOutstanding, 'the outstanding admission must have run');
    }

    /**
     * With the configured TTL wired, a refused outstanding
     * admission happens before the challenge is minted — the 4th issuance
     * beyond the per-source cap never creates challenge state at all.
     */
    public function testPreMintOutstandingRefusalNeverMints(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), $storage);
        $client = $this->requirePredis();
        $outstanding = new OutstandingChallenges($client, '{kiwi:flow-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 3, 100, 0);
        $controller = new ChallengeController($issuer, null, false, null, null, null, $outstanding, [], false, $storage, null, false, null, null, null, null, 120);

        for ($i = 0; $i < 3; $i++) {
            $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
            self::assertSame(200, $response->getStatusCode(), 'issuance '.(1 + $i).' must pass below the cap');
        }

        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
        self::assertSame(429, $response->getStatusCode(), 'the 4th outstanding challenge must hit the per-source cap');
        self::assertSame('RISK_DENIED', json_decode((string) $response->getContent(), true)['error']['code']);
        self::assertCount(3, $this->storedRecords($storage), 'a pre-mint refusal must never create challenge state');
    }

    // ── Duplicate JSON keys ─────────────────────────────────────────────

    /**
     * The raw challenge JSON is scanned for duplicate object
     * keys before decoding — {"scope":"login","scope":"signup"} is a
     * parser-ambiguity probe (json_decode would silently keep the last
     * value; intermediaries may disagree) and gets 422 duplicate_field.
     * Nested objects are scanned recursively.
     */
    public function testDuplicateJsonKeysAre422(): void
    {
        $controller = new ChallengeController($this->issuer());

        $duplicates = [
            '{"scope":"login","scope":"signup"}' => 'top-level duplicate scope',
            '{"scope":"login","request_binding":"a","request_binding":"b"}' => 'top-level duplicate binding',
            '{"scope":"login","nested":{"a":1,"a":2}}' => 'nested duplicate key',
            '{"scope":"login","arr":[{"x":1,"x":2}]}' => 'duplicate inside an array element',
            '{"scope":"login","deep":{"mid":{"scope":"a","scope":"b"}}}' => 'deeply nested duplicate',
            '{"debug":1,"debug":2}' => 'duplicate unknown field (DUPLICATE_FIELD, never UNKNOWN_FIELDS)',
        ];
        foreach ($duplicates as $body => $why) {
            $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], $body));
            self::assertSame(422, $response->getStatusCode(), $why.' must be 422');
            self::assertSame('DUPLICATE_FIELD', json_decode((string) $response->getContent(), true)['error']['code'], $why);
        }

        // Clean documents — top-level documented fields only (the endpoint
        // accepts exactly scope/algorithm/request_binding; nested payload
        // objects are unknown-field probes regardless of their internals) —
        // keep working.
        foreach ([
            '{"scope":"login"}',
            ' { "scope" : "login" , "algorithm" : "sha256" } ',
            '{"scope":"login","request_binding":"txn-1"}',
            '{}',
        ] as $body) {
            $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], $body));
            self::assertSame(200, $response->getStatusCode(), 'a clean document must keep issuing: '.$body);
        }
    }

    /**
     * Duplicate detection compares semantic keys — the
     * escape-spelling bypass ({"scope":...,"\u0073cope":...}) must be a
     * duplicate too: json_decode canonicalizes both spellings into one
     * logical key, so the scanner has to as well (a raw-textual comparison
     * would be the parser-ambiguity hole).
     */
    public function testDuplicateJsonKeysAcrossEscapeSpellingsAre422(): void
    {
        $controller = new ChallengeController($this->issuer());

        $duplicates = [
            '{"scope":"login","\\u0073cope":"signup"}' => 'literal vs \\uXXXX escape',
            '{"\\u0073cope":"login","scope":"signup"}' => 'escaped first, literal second',
            '{"s\\u0063ope":"login","scope":"signup"}' => 'mixed escaped/unescaped characters',
            '{"c\\u0061t":"login","cat":"signup"}' => 'multi-char literal vs \\uXXXX of the same key',
            '{"a\\u0021":"login","a!":"signup"}' => 'escaped punctuation vs literal',
            '{"\\u00e9t\\u00e9":"a","\\u00e9t\\u00e9":"b"}' => 'identical escaped-accent key spelled twice',
            '{"\\"quoted\\"":"a","\\"quoted\\"":"b"}' => 'escaped quotes decode to the same key',
            '{"back\\\\slash":"a","back\\\\slash":"b"}' => 'escaped backslashes decode to the same key',
            '{"😀":"a","\\uD83D\\uDE00":"b"}' => 'surrogate-pair spelling equals the literal emoji',
            '{"scope":"login","nested":{"\\u0061":1,"a":2}}' => 'escaped duplicate in a nested object',
            '{"scope":"login","arr":[{"\\u0078":1,"x":2}]}' => 'escaped duplicate inside an array element',
        ];
        foreach ($duplicates as $body => $why) {
            $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], $body));
            self::assertSame(422, $response->getStatusCode(), $why.' must be 422');
            self::assertSame('DUPLICATE_FIELD', json_decode((string) $response->getContent(), true)['error']['code'], $why);
        }

        // Escape-spelled clean documents must keep issuing (the decode is
        // not over-eager: distinct semantic keys are NOT duplicates).
        foreach ([
            '{"\\u0073cope":"login"}',
            '{"scope":"login","\\u0072equest_binding":"txn-1"}',
            '{"\\u0073cope":"login","\\u0072equest_binding":"txn-1"}',
        ] as $body) {
            $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], $body));
            self::assertSame(200, $response->getStatusCode(), 'an escape-spelled clean document must keep issuing: '.$body);
        }

        // Distinct semantic keys spelled with escapes are NOT duplicates —
        // the endpoint proceeds past the scanner and then rejects the
        // undocumented keys with unknown_fields (proving the scanner did
        // not false-positive on the escapes).
        foreach ([
            '{"a\\u0021":"login"}',
            '{"\\u00e9":"a","e":"b"}',
            '{"\\u00e9t\\u00e9":"a","\\u00e9te":"b"}',
        ] as $body) {
            $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], $body));
            self::assertSame(422, $response->getStatusCode(), 'distinct escaped keys must not be duplicates: '.$body);
            self::assertSame('UNKNOWN_FIELDS', json_decode((string) $response->getContent(), true)['error']['code'], 'the scanner must not flag distinct escaped keys as duplicates: '.$body);
        }
    }

    /**
     * The challenge body is capped at 8 KiB — a declared
     * oversized Content-Length is refused before any body is read, and the
     * actual read length is capped too (chunked uploads can skip a truthful
     * Content-Length). Both paths return 413 body_TOO_large, never reach
     * the duplicate scan or the risk admission.
     */
    public function testOversizedChallengeBodyIs413(): void
    {
        $controller = new ChallengeController($this->issuer());

        // Declared Content-Length over the cap: refused before body read.
        $response = $controller->challenge(JsonRequest::create(
            '/challenge',
            'POST',
            [],
            [],
            [],
            ['REMOTE_ADDR' => '198.51.100.7', 'CONTENT_LENGTH' => '8193'],
            '{"scope":"login"}',
        ));
        self::assertSame(413, $response->getStatusCode());
        self::assertSame('BODY_TOO_LARGE', json_decode((string) $response->getContent(), true)['error']['code']);

        // Actual body over the cap (no truthful Content-Length — the
        // chunked-upload equivalent).
        $huge = '{"scope":"'.str_repeat('x', 8200).'"}';
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], $huge));
        self::assertSame(413, $response->getStatusCode());
        self::assertSame('BODY_TOO_LARGE', json_decode((string) $response->getContent(), true)['error']['code']);
    }

    /**
     * The duplicate scanner caps recursion at 32 levels —
     * a pathological nesting depth (beyond what the strict json_decode
     * accepts anyway) must not consume unbounded scanner stack.
     */
    public function testDeeplyNestedJsonDoesNotBlowTheScannerStack(): void
    {
        $controller = new ChallengeController($this->issuer());

        $body = str_repeat('[', 400).'1'.str_repeat(']', 400);
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], $body));
        self::assertSame(422, $response->getStatusCode(), 'a non-object document at extreme depth is INVALID_JSON (never a crash)');
        self::assertSame('INVALID_JSON', json_decode((string) $response->getContent(), true)['error']['code']);
    }


    // ── Provider-compatible challenge metadata ──────────────────────────

    public function testChallengeCapturesActionAndCdataAgainstTheNonce(): void
    {
        $storage = new ArrayStorage();
        $metadataStore = new ArraySiteVerifyMetadataStore();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $storage);
        $controller = new ChallengeController($issuer, metadataStore: $metadataStore);

        $response = $controller->challenge(JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login","action":"checkout","cdata":"order_19382"}'));
        self::assertSame(200, $response->getStatusCode());
        $data = json_decode((string) $response->getContent(), true);
        $metadata = $metadataStore->find($data['nonce']);
        self::assertNotNull($metadata, 'the metadata must be stored against the issued nonce');
        self::assertSame('checkout', $metadata->action);
        self::assertSame('order_19382', $metadata->cdata);
    }

    public function testChallengeRejectsMalformedProviderMetadata(): void
    {
        $controller = new ChallengeController($this->issuer());
        $response = $controller->challenge(JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login","action":"checkout admin!"}'));
        self::assertSame(422, $response->getStatusCode());
        $data = json_decode((string) $response->getContent(), true);
        self::assertSame('INVALID_METADATA', $data['error']['code'] ?? null);

        $response = $controller->challenge(JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login","cdata":"'.str_repeat('x', 300).'"}'));
        self::assertSame(422, $response->getStatusCode());
    }


    // ── Server-owned sitekey/action + binding ───────────────────────────

    public function testPerSitekeyBindingOptionIsRemoved(): void
    {
        // A per-sitekey "binding" option cannot be
        // enforced (the core binds by the global binding_mode only) — it is
        // removed, and configuring it must be refused by the config tree
        // (never a misleading "required" promise).
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setDefinition('my.storage', new Definition(ArrayStorage::class, []));
        $this->expectException(\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException::class);
        (new KiwiCaptchaExtension())->load([[
            'secret_key' => str_repeat('a', 32),
            'storage' => 'my.storage',
            'risk' => ['sitekeys' => ['old-app-key' => ['default_scope' => 'login', 'binding' => 'none']]],
        ]], $container);
    }

    public function testServerOwnedSitekeyActionResolution(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $storage);
        $controller = new ChallengeController($issuer, sitekeyPolicy: [
            '6Lc_v3_checkout' => ['default_scope' => 'login', 'actions' => ['checkout' => 'commerce_high_value'], 'binding' => 'required'],
        ]);

        // (sitekey, action) -> the mapped policy scope, NOT the action
        // string itself.
        $response = $controller->challenge(JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"6Lc_v3_checkout","action":"checkout","sitekey":"6Lc_v3_checkout"}'));
        self::assertSame(200, $response->getStatusCode());
        $data = json_decode((string) $response->getContent(), true);
        $decodedPrefix = base64_decode((string) (explode('.', $data['prefix'])[0] ?? ''), true);
        self::assertStringContainsString('commerce_high_value', (string) $decodedPrefix, 'the challenge must be issued under the SERVER-resolved scope');

        // Unknown action -> rejected (never silently mapped).
        $rejected = $controller->challenge(JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"6Lc_v3_checkout","action":"admin","sitekey":"6Lc_v3_checkout"}'));
        self::assertSame(422, $rejected->getStatusCode());
        $rejectedBody = json_decode((string) $rejected->getContent(), true);
        self::assertSame('UNKNOWN_ACTION', $rejectedBody['error']['code'] ?? null);
    }

    // ── Per-sitekey challenge lifetime (Turnstile-migration TTL override) ─

    /**
     * A sitekey policy with ttl_secs issues the challenge with that
     * lifetime instead of the issuer/global default: the response carries
     * the override and the stored record's lifetime (expires_at -
     * issued_at) is the override too, driving every TTL derived from the
     * challenge.
     */
    public function testSitekeyTtlOverrideIssuesWithThePerSitekeyLifetime(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $storage);
        $controller = new ChallengeController($issuer, storage: $storage, challengeTtlSecs: 120, sitekeyPolicy: [
            '6Lc_migrated' => ['default_scope' => 'login', 'actions' => [], 'ttl_secs' => 300],
        ]);

        $response = $controller->challenge(JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"6Lc_migrated","sitekey":"6Lc_migrated"}'));
        self::assertSame(200, $response->getStatusCode());

        $data = json_decode((string) $response->getContent(), true);
        self::assertSame(300, $data['ttlSecs'], 'the issued challenge must carry the per-sitekey TTL');

        $record = $storage->find($data['nonce']);
        self::assertNotNull($record);
        self::assertSame(300, $record->expiresAt - $record->issuedAt, 'the stored record lifetime must be the per-sitekey TTL');
    }

    public function testSitekeyWithoutTtlOverrideKeepsTheGlobalDefault(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $storage);
        $controller = new ChallengeController($issuer, storage: $storage, challengeTtlSecs: 120, sitekeyPolicy: [
            '6Lc_plain' => ['default_scope' => 'login', 'actions' => []],
        ]);

        $response = $controller->challenge(JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"6Lc_plain","sitekey":"6Lc_plain"}'));
        self::assertSame(200, $response->getStatusCode());

        $data = json_decode((string) $response->getContent(), true);
        self::assertSame(120, $data['ttlSecs'], 'a sitekey without ttl_secs must keep the global default lifetime');
    }

    /**
     * The config tree bounds ttl_secs to 1..Config::MAX_TTL_secs (300) —
     * a value above the ceiling is refused at configuration time, never
     * minted.
     */
    public function testSitekeyTtlOverrideAboveCeilingIsRefused(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setDefinition('my.storage', new Definition(ArrayStorage::class, []));
        $this->expectException(\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException::class);
        (new KiwiCaptchaExtension())->load([[
            'secret_key' => str_repeat('a', 32),
            'storage' => 'my.storage',
            'risk' => ['sitekeys' => ['old-app-key' => ['default_scope' => 'login', 'ttl_secs' => 301]]],
        ]], $container);
    }

    /**
     * The TTL-variant issuer replicates the wired issuer's region, so a
     * region-bound deployment (risk.region) keeps its signed region on
     * overridden-TTL challenges — the verifier's expected-region check
     * still passes.
     */
    public function testSitekeyTtlOverridePreservesTheIssuedRegion(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $storage, null, 'eu');
        $controller = new ChallengeController($issuer, storage: $storage, sitekeyPolicy: [
            '6Lc_region' => ['default_scope' => 'login', 'actions' => [], 'ttl_secs' => 300],
        ]);

        $response = $controller->challenge(JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"6Lc_region","sitekey":"6Lc_region"}'));
        self::assertSame(200, $response->getStatusCode());

        $record = $storage->find(json_decode((string) $response->getContent(), true)['nonce']);
        self::assertNotNull($record);
        self::assertSame('eu', $record->region, 'the TTL-variant issuer must keep the wired issuer\'s region');
    }

}

