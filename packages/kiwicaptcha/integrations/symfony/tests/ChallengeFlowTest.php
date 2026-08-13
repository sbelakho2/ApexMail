<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Security\OutstandingChallenges;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\RiskKeys;
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

    public function testOriginAllowlistAcceptsExactOriginAndRefererFallback(): void
    {
        $controller = new ChallengeController($this->issuer(), null, false, null, null, null, null, ['https://app.example.com']);

        // Exact Origin match (default port normalized).
        $response = $controller->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://app.example.com'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode(), 'an allowlisted Origin must pass');

        // Host is case-insensitive (DNS); explicit default port equals the
        // default.
        $response = $controller->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://APP.EXAMPLE.COM:443'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode());

        // Referer-origin fallback (no Origin header).
        $response = $controller->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_REFERER' => 'https://app.example.com/contact'], '{"scope":"login"}'));
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
            $response = $controller->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => $origin], '{"scope":"login"}'));
            self::assertSame(403, $response->getStatusCode(), $why.' must be rejected');
            self::assertSame('origin_rejected', json_decode((string) $response->getContent(), true)['error']['code'], $why);
        }

        // No Origin AND no Referer: cannot be matched — rejected.
        $response = $controller->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
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

            public function consume(string $nonce): ?\KiwiCaptcha\ChallengeRecord
            {
                return $this->inner->consume($nonce);
            }

            public function delete(string $nonce): void
            {
                $this->inner->delete($nonce);
            }
        };
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $controller = new ChallengeController($issuer, null, false, null, null, null, null, ['https://app.example.com']);
        $request = Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://evil.example'], '{"scope":"login"}');

        $controller->challenge($request);
        self::assertSame(0, $storage->stores, 'an origin-rejected request must never mint a CAPTCHA');
    }

    public function testFetchMetadataCrossSiteIsRejectedWhenEnforced(): void
    {
        $controller = new ChallengeController($this->issuer(), null, false, null, null, null, null, [], true);

        $response = $controller->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_SEC_FETCH_SITE' => 'cross-site'], '{"scope":"login"}'));
        self::assertSame(403, $response->getStatusCode());
        self::assertSame('CROSS_SITE_REJECTED', json_decode((string) $response->getContent(), true)['error']['code']);

        // same-origin / none / absent are unaffected.
        foreach (['same-origin', 'none', null] as $fetchSite) {
            $server = ['REMOTE_ADDR' => '198.51.100.7'];
            if ($fetchSite !== null) {
                $server['HTTP_SEC_FETCH_SITE'] = $fetchSite;
            }
            $response = $controller->challenge(Request::create('/challenge', 'POST', [], [], [], $server, '{"scope":"login"}'));
            self::assertSame(200, $response->getStatusCode(), 'Sec-Fetch-Site "'.(string) $fetchSite.'" must pass');
        }

        // Without enforcement a cross-site header is ignored (defense-in-depth).
        $lax = new ChallengeController($this->issuer());
        $response = $lax->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_SEC_FETCH_SITE' => 'cross-site'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode());
    }

    /**
     * Audit #43: the FULL origin-normalization audit list. Structured
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
            $response = $controller->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => $origin], '{"scope":"login"}'));
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
            $response = $controller->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => $origin], '{"scope":"login"}'));
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
        $response = $controller->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://bücher.example'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode(), 'the Unicode spelling must match its own allowlisted form');

        $response = $controller->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://xn--bcher-kva.example'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode(), 'the punycode spelling must match the Unicode allowlist entry');

        // A different Unicode host must NOT match.
        $response = $controller->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://kaufen.example'], '{"scope":"login"}'));
        self::assertSame(403, $response->getStatusCode(), 'a different IDN host must be rejected');
    }

    public function testEnforceOriginRejectsMissingAndNullOrigins(): void
    {
        // enforce_origin with an EMPTY allowlist: the Origin is required but
        // anything non-null is accepted (no allowlist to match).
        $controller = new ChallengeController($this->issuer(), null, false, null, null, null, null, [], false, null, null, true);

        $response = $controller->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
        self::assertSame(403, $response->getStatusCode(), 'a MISSING Origin must be rejected when enforce_origin is true');
        self::assertSame('origin_rejected', json_decode((string) $response->getContent(), true)['error']['code']);

        $response = $controller->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'null'], '{"scope":"login"}'));
        self::assertSame(403, $response->getStatusCode(), 'the literal "null" Origin (opaque/sandboxed) must be rejected when enforced');
        self::assertSame('origin_rejected', json_decode((string) $response->getContent(), true)['error']['code']);

        // A usable Origin passes (no allowlist).
        $response = $controller->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://anything.example'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode());

        // With an allowlist, the required Origin must ALSO be allowlisted.
        $strict = new ChallengeController($this->issuer(), null, false, null, null, null, null, ['https://app.example.com'], false, null, null, true);
        $response = $strict->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://other.example'], '{"scope":"login"}'));
        self::assertSame(403, $response->getStatusCode(), 'enforced + allowlisted: a non-allowlisted Origin must be rejected');
        $response = $strict->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://app.example.com'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode());

        // NOT enforced (default): a missing Origin with an allowlist falls
        // back to the Referer as before (server-to-server trusted mode).
        $lax = new ChallengeController($this->issuer(), null, false, null, null, null, null, ['https://app.example.com']);
        $response = $lax->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_REFERER' => 'https://app.example.com/contact'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode(), 'enforce_origin=false keeps the Referer-origin fallback (documented trusted mode for server-to-server)');
    }

    public function testChallengeAcceptsRequestBindingAndBakesItIntoTheRecord(): void
    {
        $storage = new ArrayStorage();
        $controller = new ChallengeController(new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage));

        $response = $controller->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login","request_binding":"txn-abc-123"}'));
        self::assertSame(200, $response->getStatusCode());

        $data = json_decode((string) $response->getContent(), true);
        $record = $storage->find($data['nonce']);
        self::assertNotNull($record);
        self::assertSame('txn-abc-123', $record->requestBinding, 'the request binding must be signed into the stored record (audit #41)');
    }

    public function testChallengeRejectsMalformedRequestBinding(): void
    {
        $controller = new ChallengeController($this->issuer());

        // '|' is the canonical-payload separator — never allowed in a binding.
        $response = $controller->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login","request_binding":"a|b"}'));
        self::assertSame(422, $response->getStatusCode());
        self::assertSame('INVALID_REQUEST_BINDING', json_decode((string) $response->getContent(), true)['error']['code']);

        // Longer than 128 chars.
        $response = $controller->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login","request_binding":"'.str_repeat('x', 129).'"}'));
        self::assertSame(422, $response->getStatusCode());
        self::assertSame('INVALID_REQUEST_BINDING', json_decode((string) $response->getContent(), true)['error']['code']);

        // Empty string is treated as absent.
        $response = $controller->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login","request_binding":""}'));
        self::assertSame(200, $response->getStatusCode());
    }

    public function testStaticDefaultRequestBindingAppliesWhenThePayloadOmitsIt(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $controller = new ChallengeController($issuer, null, false, null, null, null, null, [], false, $storage, 'static-binding');

        $response = $controller->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode());
        $data = json_decode((string) $response->getContent(), true);
        self::assertSame('static-binding', $storage->find($data['nonce'])?->requestBinding, 'the configured static binding must apply when the request sends none');

        // The request's own field WINS over the static default.
        $response = $controller->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login","request_binding":"per-request"}'));
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
            $response = $controller->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
            self::assertSame(200, $response->getStatusCode(), 'issuance '.(1 + $i).' must pass below the cap');
        }

        $response = $controller->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
        self::assertSame(429, $response->getStatusCode(), 'the 4th outstanding challenge must hit the per-source cap');
        self::assertSame('RISK_DENIED', json_decode((string) $response->getContent(), true)['error']['code']);

        $records = (new \ReflectionObject($storage))->getProperty('records');
        self::assertCount(3, $records->getValue($storage), 'the refused issuance must discard its minted record');
        self::assertSame(3, $client->counters['{kiwi:flow-test}:outstanding:'.hash_hmac('sha256', Issuer::canonicalIpFamily('198.51.100.7'), RiskKeys::fromMaster(self::SECRET)->event)], 'the per-source counter is bounded by the cap');

        // A DIFFERENT source is unaffected (per-source counters are keyed on
        // the HMAC of the canonical IP).
        $response = $controller->challenge(Request::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.8'], '{"scope":"login"}'));
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
}
