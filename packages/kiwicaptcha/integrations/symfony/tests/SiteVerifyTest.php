<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\SiteVerifyController;
use BelConsulting\KiwiCaptchaBundle\Risk\RequestBindingAuthorityInterface;
use BelConsulting\KiwiCaptchaBundle\Security\OutstandingChallenges;
use BelConsulting\KiwiCaptchaBundle\Security\RedisAdmissionSemaphore;
use BelConsulting\KiwiCaptchaBundle\Security\RequestScopeAdmissionGate;
use KiwiCaptcha\VerificationAdmissionGate;
use KiwiCaptcha\Risk\RiskKeys;
use BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\IdempotencyClaim;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadata;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\ArraySiteVerifyMetadataStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\ArraySiteVerifyIdempotencyStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\ArrayStorage;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Request;

/**
 * Provider-compatible Siteverify golden tests. The endpoint calls the exact
 * same atomic verifier as the native path and returns the provider-shaped
 * JSON (`success`, `challenge_ts`, `hostname`, `error-codes`).
 */
final class SiteVerifyTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';
    private const SITEVERIFY_SECRET = 'compat-secret-42';

    public function testTooFastSolutionMapsToInvalidInputResponse(): void
    {
        $controller = $this->controller();
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120, minDurationMs: 3000), $storage);
        $challenge = $issuer->issue('login', '127.0.0.1');
        $solution = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits);
        $token = SolutionToken::create($challenge->nonce, $solution, 5000, [])->encode();

        // Verified immediately after issuance: the server-side timing floor
        // (minDurationMs 3000) rejects the solve as too fast — a too-fast
        // solution is an invalid response, never a malformed request.
        $response = $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET,
            'response' => $token,
            'remoteip' => '127.0.0.1',
        ]));
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame(false, $body['success'] ?? null);
        self::assertSame(['invalid-input-response'], $body['error-codes'] ?? null, 'a too-fast solve must map to the invalid-response vocabulary');
    }

    public function testWrongProofSolutionMapsToInvalidInputResponse(): void
    {
        $controller = $this->controller();
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $storage);
        $challenge = $issuer->issue('login', '127.0.0.1');
        $valid = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits);

        // The first counter whose hash fails the target is guaranteed to
        // exist and is deterministic (all counters below the solver's
        // first success failed it).
        $saltBytes = base64_decode($challenge->salt, true);
        $wrong = 0;
        while (Verifier::leadingZeroBits(hash('sha256', $challenge->prefix.$wrong.$saltBytes, true)) >= $challenge->targetBits) {
            $wrong++;
        }
        self::assertNotSame($valid, $wrong, 'the wrong counter must differ from the valid solution');

        $token = SolutionToken::create($challenge->nonce, $wrong, 5000, [])->encode();
        $response = $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET,
            'response' => $token,
            'remoteip' => '127.0.0.1',
        ]));
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame(false, $body['success'] ?? null);
        self::assertSame(['invalid-input-response'], $body['error-codes'] ?? null, 'insufficient work must map to the invalid-response vocabulary');
    }

    private function controller(
        array $secrets = [self::SITEVERIFY_SECRET => 'login'],
        ?\BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadataStore $metadataStore = null,
        ?\BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore $idempotencyStore = null,
        ?ArrayStorage $storage = null,
        float $waitSecs = 90.0,
    ): SiteVerifyController {
        $storage ??= new ArrayStorage();
        $verifier = new Verifier($storage);

        return new SiteVerifyController($verifier, self::SECRET, $secrets, $storage, null, $metadataStore, $idempotencyStore, null, $waitSecs);
    }

    /**
     * The logical-operation identity a controller records for a claim
     * (must mirror the controller's fingerprint formula exactly).
     */
    /**
     * A form-encoded Siteverify request with the REAL body: the strict
     * form decoder requires the raw body (the framework bag alone no
     * longer carries the duplicate-name evidence), so the tests send the
     * canonical application/x-www-form-urlencoded encoding.
     */
    private function siteverifyRequest(array $fields, string $contentType = 'application/x-www-form-urlencoded'): Request
    {
        $body = $contentType === 'application/json' ? json_encode($fields, JSON_THROW_ON_ERROR) : http_build_query($fields);

        return Request::create('/kiwi-captcha/siteverify', 'POST', [], [], [], ['CONTENT_TYPE' => $contentType], (string) $body);
    }

    private function fingerprint(string $backendId, ?string $idempotencyKey, string $response, ?string $remoteIp, ?string $canonicalBinding = null): string
    {
        return hash('sha256', $backendId."\0".($idempotencyKey ?? "\0no-key")."\0".hash('sha256', $response)."\0".$this->remoteipFingerprintForTest($remoteIp)."\0".($canonicalBinding ?? "\0no-binding"));
    }

    private function remoteipFingerprintForTest(?string $remoteIp): string
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

        return 'ip:'.$canonical;
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

    public function testFreshSuccessReleasesTheOutstandingSlot(): void
    {
        // P1/P2 regression: the ordinary FRESH-success Siteverify path
        // must run the same idempotent solved(nonce) lifecycle release
        // as every other successful outcome — the release used to live
        // only in outcomeToCanonical(), which the fresh path bypasses, so
        // a provider-style client could redeem valid challenges and still
        // hit the per-source outstanding cap as though they remained
        // unsolved.
        $client = new FakePredisClient();
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $storage);
        $challenge = $issuer->issue('login', '198.51.100.7');
        $outstanding = new OutstandingChallenges($client, '{kiwi:siteverify-outstanding}:outstanding:', RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        self::assertSame(1, $outstanding->issue('198.51.100.7', $challenge->nonce, 120));
        $sourceKey = $outstanding->sourceKey('198.51.100.7');
        self::assertSame(1, $client->counters[$sourceKey], 'the issued challenge holds the source slot');

        $solution = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits);
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = SolutionToken::create($challenge->nonce, $solution, 5000, [])->encode();

        $controller = new SiteVerifyController(
            new Verifier($storage),
            self::SECRET,
            [self::SITEVERIFY_SECRET => 'login'],
            $storage,
            null,
            null,
            null,
            null,
            90.0,
            0,
            null,
            $outstanding,
        );
        $response = $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET,
            'response' => $token,
            'remoteip' => '198.51.100.7',
        ]));
        self::assertSame(200, $response->getStatusCode());
        self::assertTrue(json_decode((string) $response->getContent(), true)['success']);
        self::assertSame(0, $client->counters[$sourceKey], 'the FRESH Siteverify success releases the original source slot');
        self::assertArrayNotHasKey($challenge->nonce, $client->zsets['{kiwi:siteverify-outstanding}:outstanding:global:live'] ?? [], 'the nonce leaves the live membership');
        self::assertArrayNotHasKey('{kiwi:siteverify-outstanding}:outstanding:nonce:'.$challenge->nonce, $client->strings, 'the sidecar is dropped');
    }

    public function testCompleteSameRetryRepairsTheOutstandingRelease(): void
    {
        // P2: a same-operation retry that observes the stored success
        // (CompleteSame) re-releases through the single success-return
        // helper, repairing a transient failure of the original
        // verification's release.
        $client = new FakePredisClient();
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $storage);
        $challenge = $issuer->issue('login', '198.51.100.7');
        $outstanding = new OutstandingChallenges($client, '{kiwi:siteverify-outstanding}:outstanding:', RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        self::assertSame(1, $outstanding->issue('198.51.100.7', $challenge->nonce, 120));
        $sourceKey = $outstanding->sourceKey('198.51.100.7');
        self::assertSame(1, $client->counters[$sourceKey]);

        $solution = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits);
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = SolutionToken::create($challenge->nonce, $solution, 5000, [])->encode();

        $idem = new ArraySiteVerifyIdempotencyStore();
        $controller = new SiteVerifyController(
            new Verifier($storage),
            self::SECRET,
            [self::SITEVERIFY_SECRET => 'login'],
            $storage,
            null,
            null,
            $idem,
            null,
            90.0,
            0,
            null,
            $outstanding,
        );
        $request = fn (): Request => $this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET,
            'response' => $token,
            'remoteip' => '198.51.100.7',
            'idempotency_key' => '223e4567-e89b-42d3-a456-426614174099',
        ]);

        // First redemption: the verification succeeds but the release
        // fails transiently (a Redis outage) — the response is still the
        // success.
        $client->failCommand = 'EVAL';
        $first = $controller->siteverify($request());
        $client->failCommand = null;
        self::assertSame(200, $first->getStatusCode());
        self::assertTrue(json_decode((string) $first->getContent(), true)['success']);
        self::assertSame(1, $client->counters[$sourceKey], 'the transient failure left the slot charged');

        // The same logical operation retries: CompleteSame observes the
        // stored success and re-releases.
        $retry = $controller->siteverify($request());
        self::assertSame(200, $retry->getStatusCode());
        self::assertSame(0, $client->counters[$sourceKey], 'the CompleteSame stored-success observation repairs the release');
    }

    public function testSiteVerifyEnforcesTheAuthoritativeTransactionBinding(): void
    {
        // P1: the transaction-binding security boundary must hold on the
        // provider-compatible endpoint too — a proof cryptographically
        // anchored to transaction A must never succeed for transaction B,
        // and the mismatch must fail BEFORE the consume.
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $storage);
        $tokens = [];
        foreach (['txn-A', 'txn-A'] as $i => $binding) {
            $challenge = $issuer->issue('login', '198.51.100.7', $binding);
            $solution = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits);
            usleep(($challenge->minDurationMs + 10) * 1000);
            $tokens[$i] = SolutionToken::create($challenge->nonce, $solution, 5000, [])->encode();
        }
        $token = $tokens[0];

        // The authority resolves THIS transaction's binding (txn-B) from
        // its own trusted inputs — the siteverify request carries none.
        $authority = new class implements RequestBindingAuthorityInterface {
            public function resolve(Request $request, string $scope, ?string $presentedBinding): ?string
            {
                return 'txn-B';
            }
        };
        $controller = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, null, null, 90.0, 0, null, null, null, $authority);
        $response = $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET,
            'response' => $token,
            'remoteip' => '198.51.100.7',
        ]));
        self::assertSame(200, $response->getStatusCode());
        $json = json_decode((string) $response->getContent(), true);
        self::assertFalse($json['success'], 'a proof anchored to txn-A must never succeed for txn-B');
        self::assertSame(['invalid-input-response'], $json['error-codes']);
        self::assertNull($storage->consumedState($challenge->nonce), 'the binding mismatch fails BEFORE the consume — the challenge is never burned');
    }

    public function testIdempotencyEntryCannotBeReusedAcrossTransactionBindings(): void
    {
        // P1: the canonical binding is part of the idempotency identity —
        // the same UUID under a different authoritative transaction
        // context is a conflict, never a cached success.
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $storage);
        $challenge = $issuer->issue('login', '198.51.100.7', 'txn-A');
        $solution = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits);
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = SolutionToken::create($challenge->nonce, $solution, 5000, [])->encode();

        $binding = 'txn-A';
        $authority = new class($binding) implements RequestBindingAuthorityInterface {
            public string $binding;

            public int $calls = 0;

            public function __construct(string $binding)
            {
                $this->binding = $binding;
            }

            public function resolve(Request $request, string $scope, ?string $presentedBinding): ?string
            {
                ++$this->calls;
                return $this->binding;
            }
        };
        $idem = new ArraySiteVerifyIdempotencyStore();
        $controller = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $idem, null, 90.0, 0, null, null, null, $authority);
        $request = fn (): Request => $this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET,
            'response' => $token,
            'remoteip' => '198.51.100.7',
            'idempotency_key' => '223e4567-e89b-42d3-a456-426614174088',
        ]);

        // The matching transaction context succeeds.
        $first = $controller->siteverify($request());
        $refl = new \ReflectionObject($idem);
        $recordsProp = $refl->getProperty('records');
        self::assertSame(200, $first->getStatusCode());
        self::assertTrue(json_decode((string) $first->getContent(), true)['success']);

        // The same UUID under transaction B is a conflict (the binding is
        // part of the claim identity) — never the cached success.
        $authority->binding = 'txn-B';
        $second = $controller->siteverify($request());
        self::assertSame(400, $second->getStatusCode(), 'a changed transaction binding under the same idempotency UUID is a conflict');
        self::assertFalse(json_decode((string) $second->getContent(), true)['success']);
    }

    public function testMalformedJsonAndDeepDuplicatesNeverEscapeAsA500(): void
    {
        // R69-01/02: malformed JSON strings and depth-bomb documents are
        // the controlled 400, never an uncaught JsonException or a
        // fail-open duplicate acceptance.
        $controller = $this->controller();
        $malformed = [
            '{"secret":"0123456789abcdef0123456789abcdef","response":"\\uZZZZ"}',
            '{"secret":"0123456789abcdef0123456789abcdef","response":"\\ud800"}',
            '{"secret":"0123456789abcdef0123456789abcdef","response":"'.chr(0xFF).'"}',
            '{"secret":"0123456789abcdef0123456789abcdef","response":"\\u',
        ];
        foreach ($malformed as $body) {
            $response = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'], $body));
            self::assertLessThan(500, $response->getStatusCode(), 'malformed JSON must be the controlled 4xx: '.$body);
            self::assertSame(400, $response->getStatusCode());
        }

        // A duplicate secret whose first value is nested deeper than the
        // 32-level ceiling: refused, never accepted.
        $deep = '{"secret":'.str_repeat('[', 33).str_repeat(']', 33).',"secret":"0123456789abcdef0123456789abcdef","response":"x"}';
        $response = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'], $deep));
        self::assertSame(400, $response->getStatusCode(), 'the deep-nested duplicate is refused');
    }

    public function testCanonicalFormEncodingWithPlusAndStrictEscapes(): void
    {
        // R69-03: '+' means a space (the canonical form encoding — a
        // standards-compliant intermediary decodes '+' as a space, so the
        // strict decoder must agree), a literal '+' is the RFC3986 %2B,
        // and a malformed % escape is refused, not admitted.
        $controller = $this->controller();
        $refl = new \ReflectionMethod($controller, 'decodeStrictFormBody');

        $plus = $refl->invoke($controller, 'a=b+c&d=e');
        self::assertSame('b c', $plus['a'] ?? null, "'+' decodes to a space exactly like %20");
        $pct20 = $refl->invoke($controller, 'a=b%20c&d=e');
        self::assertSame($plus, $pct20, "'+' and %20 are the SAME canonical encoding");

        // A malformed % escape is refused by the strict decoder.
        $bad = Request::create('/kiwi-captcha/siteverify', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'], 'secret=0123456789abcdef0123456789abcdef&response=x&remoteip=127.0.0.1&request_binding=txn%ZZ');
        self::assertSame(400, $controller->siteverify($bad)->getStatusCode(), 'a malformed % escape is refused');
    }

    public function testInvalidAuthorityReturnedBindingIsRefusedAtTheBoundary(): void
    {
        // R69-05: the authority's returned binding must satisfy the
        // identifier shape — an out-of-shape value is refused at the
        // trust boundary, never allowed into the fingerprint/store.
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $storage);
        $challenge = $issuer->issue('login', '198.51.100.7', 'txn-A');
        $solution = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits);
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = SolutionToken::create($challenge->nonce, $solution, 5000, [])->encode();

        $authority = new class implements RequestBindingAuthorityInterface {
            public function resolve(Request $request, string $scope, ?string $presentedBinding): ?string
            {
                return "txn-A\x00evil";
            }
        };
        $controller = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, null, null, 90.0, 0, null, null, null, $authority);
        $response = $controller->siteverify($this->siteverifyRequest(['secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '198.51.100.7']));
        self::assertSame(400, $response->getStatusCode(), 'the authority\'s out-of-shape binding is refused at the boundary');
    }

    public function testJsonDuplicateKeysAreRefusedBeforeParsing(): void
    {
        // R68-04: the duplicate-key scanner works on the RAW document —
        // a decode-then-scan can never see a duplicate (json_decode has
        // already collapsed the members). {"secret":"A","secret":"B"} is
        // refused with the bad-request, never silently last-wins.
        $controller = $this->controller();
        $response = $controller->siteverify(Request::create(
            '/kiwi-captcha/siteverify',
            'POST',
            [],
            [],
            [],
            ['CONTENT_TYPE' => 'application/json', 'HTTP_CONTENT_TYPE' => 'application/json'],
            '{"secret":"0123456789abcdef0123456789abcdef","secret":"0123456789abcdef0123456789abcdef","response":"x"}',
        ));
        self::assertSame(400, $response->getStatusCode());
        self::assertSame(['bad-request'], json_decode((string) $response->getContent(), true)['error-codes']);
    }

    public function testFormDuplicateParametersAreRefused(): void
    {
        // R68-05: the strict form decoder rejects duplicate parameter
        // names — secret=A&secret=B is refused instead of being silently
        // collapsed by the framework's parser.
        $controller = $this->controller();
        $response = $controller->siteverify(Request::create(
            '/kiwi-captcha/siteverify',
            'POST',
            [],
            [],
            [],
            ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'],
            'secret=0123456789abcdef0123456789abcdef&secret=0123456789abcdef0123456789abcdef&response=x',
        ));
        self::assertSame(400, $response->getStatusCode());
        self::assertSame(['bad-request'], json_decode((string) $response->getContent(), true)['error-codes']);
    }

    public function testDuplicatedContentTypeAndEncodingHeadersAreRefused(): void
    {
        // R68-07: Content-Type and Content-Encoding are enforced singular.
        $controller = $this->controller();
        $request = $this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => 'x', 'remoteip' => '127.0.0.1',
        ]);
        $request->headers->set('Content-Type', ['application/json', 'application/x-www-form-urlencoded']);
        $response = $controller->siteverify($request);
        self::assertSame(400, $response->getStatusCode(), 'a duplicated Content-Type is refused');
    }

    public function testJsonAndFormRequestBindingsAreEquivalent(): void
    {
        // R68-06: the presented request_binding comes from the ONE parsed
        // body regardless of the transport — a JSON caller's
        // request_binding is honored exactly like the form caller's, so
        // the two encodings can never diverge in their binding behavior.
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $storage);
        $tokens = [];
        foreach ([0, 1] as $i) {
            $challenge = $issuer->issue('login', '198.51.100.7', 'txn-A');
            $solution = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits);
            usleep(($challenge->minDurationMs + 10) * 1000);
            $tokens[$i] = SolutionToken::create($challenge->nonce, $solution, 5000, [])->encode();
        }

        $authority = new class implements RequestBindingAuthorityInterface {
            public function resolve(Request $request, string $scope, ?string $presentedBinding): ?string
            {
                return $presentedBinding;
            }
        };
        $controller = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, null, null, 90.0, 0, null, null, null, $authority);

        $json = Request::create('/kiwi-captcha/siteverify', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'], json_encode([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $tokens[0], 'remoteip' => '198.51.100.7', 'request_binding' => 'txn-A',
        ], JSON_THROW_ON_ERROR));
        $form = Request::create('/kiwi-captcha/siteverify', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'], http_build_query([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $tokens[1], 'remoteip' => '198.51.100.7', 'request_binding' => 'txn-A',
        ]));

        $jsonBody = json_decode((string) $controller->siteverify($json)->getContent(), true);
        $formBody = json_decode((string) $controller->siteverify($form)->getContent(), true);
        self::assertSame(true, $jsonBody['success'] ?? null, 'the JSON request_binding is honored');
        self::assertSame(true, $formBody['success'] ?? null, 'the form request_binding is honored identically');
        self::assertSame($jsonBody['error-codes'] ?? null, $formBody['error-codes'] ?? null, 'JSON and form transports produce the identical logical result');
    }

    public function testSiteVerifyStampsTheScopeForTheArgonPerScopeBudget(): void
    {
        // P2: the Siteverify endpoint must attribute every redemption to
        // the expected scope for the Argon per-scope admission budget —
        // without the stamped scope attribute, all Siteverify Argon work
        // would fall into the unscoped global-only path and one busy
        // scope could starve the others.
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(
            secretKey: self::SECRET,
            algorithm: PoWAlgorithm::Argon2id,
            mKib: 64,
            t: 3,
            p: 1,
            argon2TargetBits: 4,
        ), $storage);
        $challenge = $issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $counter = 0;
        do {
            $h = sodium_crypto_pwhash(32, $challenge->prefix.$counter, base64_decode($challenge->salt, true), 3, 64 * 1024, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
            $counter++;
        } while (Verifier::leadingZeroBits($h) < $challenge->targetBits);
        --$counter;
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();

        $client = new FakePredisClient();
        $semaphore = new RedisAdmissionSemaphore($client, 4, 'siteverify-argon', 45_000, 64, 1);
        $stack = new RequestStack();
        $gate = new RequestScopeAdmissionGate($semaphore, $stack);
        $request = $this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET,
            'response' => $token,
            'remoteip' => '198.51.100.7',
        ]);
        $stack->push($request);
        $controller = new SiteVerifyController(new Verifier($storage, $gate), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, null, null, 90.0, 0, null, null, null);

        $response = $controller->siteverify($request);
        self::assertSame(200, $response->getStatusCode());
        self::assertTrue(json_decode((string) $response->getContent(), true)['success']);

        // The acquire EVAL's per-scope KEYS[3] must be the SCOPE's own
        // lease set — not the unscoped global placeholder — proving the
        // endpoint stamped the expected scope for the Argon per-scope
        // budget (one busy scope can never starve the others through the
        // provider surface).
        // The acquire EVAL is the only three-key EVAL (global lease set,
        // waiters counter, per-scope set).
        $acquires = array_values(array_filter($client->calls, static fn (array $c): bool => $c[0] === 'EVAL' && (int) ($c[1][1] ?? 0) === 3));
        self::assertNotSame([], $acquires, 'the Argon redemption must consult the admission gate');
        $last = $acquires[count($acquires) - 1];
        $args = $last[1];
        $numKeys = (int) $args[1];
        $keys = array_slice($args, 2, $numKeys);
        self::assertSame('{kiwicaptcha:argon2:leases:siteverify-argon}:'.hash('sha256', 'login'), $keys[2], 'the Siteverify endpoint stamps the expected scope for the Argon per-scope budget');
        self::assertNull($request->attributes->get(RequestScopeAdmissionGate::SCOPE_ATTRIBUTE), 'the scope attribute is restored after the verification');
    }

    public function testDisabledWithoutConfiguredSecret(): void
    {
        $storage = new ArrayStorage();
        $verifier = new Verifier($storage);
        $controller = new SiteVerifyController($verifier, self::SECRET, [], $storage);
        $response = $controller->siteverify($this->siteverifyRequest(['response' => 'x', 'secret' => 'x']));
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
        $response = $this->controller()->siteverify($this->siteverifyRequest(['response' => 'x', 'secret' => 'wrong']));
        self::assertSame(200, $response->getStatusCode());
        $json = json_decode((string) $response->getContent(), true);
        self::assertFalse($json['success']);
        self::assertSame(['invalid-input-secret'], $json['error-codes']);
    }

    public function testMissingResponseIsRejected(): void
    {
        $response = $this->controller()->siteverify($this->siteverifyRequest(['secret' => self::SITEVERIFY_SECRET]));
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
        $response = $controller->siteverify($this->siteverifyRequest([
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

        // JSON-encoded body works identically — with a fresh token (the
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

        $first = $controller->siteverify($this->siteverifyRequest(['response' => $solution, 'secret' => self::SITEVERIFY_SECRET, 'remoteip' => '203.0.113.7']));
        self::assertTrue(json_decode((string) $first->getContent(), true)['success']);

        // The compatibility boundary distinguishes the first
        // redemption from replays. A repeated Siteverify redemption of the
        // same nonce MUST NOT report success again — it returns the
        // provider vocabulary for a consumed token. (The native verifier's
        // deterministic-result retry semantics stay internal.)
        $replay = $controller->siteverify($this->siteverifyRequest(['response' => $solution, 'secret' => self::SITEVERIFY_SECRET, 'remoteip' => '203.0.113.7']));
        $json = json_decode((string) $replay->getContent(), true);
        self::assertFalse($json['success'], 'a replayed response must not succeed again');
        self::assertSame(['timeout-or-duplicate'], $json['error-codes']);
    }

    public function testCrossSecretScopeEscalationIsRejected(): void
    {
        // The secret resolves the expected scope — a login
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

        $ok = $controller->siteverify($this->siteverifyRequest(['response' => $solution, 'secret' => 'secret-login', 'remoteip' => '203.0.113.7']));
        self::assertTrue(json_decode((string) $ok->getContent(), true)['success']);

        // The same login token against the admin secret: the wrong
        // scope is a security verdict about this request, so it stands
        // even though the record is already consumed — the identity-gated
        // replay exemption never overrides it, and the consumed evidence
        // is preserved (never deleted by the hard failure). The provider
        // vocabulary surfaces the scope refusal as invalid-input-response
        // — the escalation is refused, never success.
        $rejected = $controller->siteverify($this->siteverifyRequest(['response' => $solution, 'secret' => 'secret-admin', 'remoteip' => '203.0.113.7']));
        $json = json_decode((string) $rejected->getContent(), true);
        self::assertFalse($json['success']);
        self::assertSame(['invalid-input-response'], $json['error-codes']);
        self::assertNotNull($storage->find($challenge->nonce), 'the consumed recovery evidence survives the cross-secret replay');

        // The admin secret itself is sound: a challenge minted for the
        // admin scope verifies with it.
        $adminChallenge = $issuer->issue('admin_login', '203.0.113.7');
        $adminSolution = $this->solveSolution($storage->find($adminChallenge->nonce));
        usleep(((int) $adminChallenge->minDurationMs + 10) * 1000);
        $adminOk = $controller->siteverify($this->siteverifyRequest(['response' => $adminSolution, 'secret' => 'secret-admin', 'remoteip' => '203.0.113.7']));
        self::assertTrue(json_decode((string) $adminOk->getContent(), true)['success'], 'the admin secret accepts its own scope');
    }

    public function testHostnameSurvivesARedisSerializeDeserializeRoundTrip(): void
    {
        // Hostname must survive a real serialize -> Redis ->
        // deserialize cycle (ArrayStorage would mask a fromArray drop).
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        try {
            $redis = new \Predis\Client(self::redisTestUrl(), ['timeout' => 1.0, 'read_write_timeout' => 1.0]);
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
            $response = $controller->siteverify($this->siteverifyRequest([
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
        $response = $controller->siteverify($this->siteverifyRequest(['response' => $solution, 'secret' => self::SITEVERIFY_SECRET, 'remoteip' => '203.0.113.7']));
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
        $response = $controller->siteverify($this->siteverifyRequest(['response' => $token]));
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('missing-input-secret', $body['error-codes'][0] ?? null);
    }

    public function testWrongSecretMapsToInvalidInputSecret(): void
    {
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage);
        $controller = $this->controller();
        $response = $controller->siteverify($this->siteverifyRequest(['secret' => str_repeat('x', 24), 'response' => $token]));
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('invalid-input-secret', $body['error-codes'][0] ?? null);
    }

    public function testMalformedIdempotencyKeyIsRejectedBeforeTheVerifier(): void
    {
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage);
        $controller = $this->controller(secrets: [self::SITEVERIFY_SECRET => 'login'], idempotencyStore: new ArraySiteVerifyIdempotencyStore());
        $response = $controller->siteverify($this->siteverifyRequest([
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
        $response = $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET,
            'response' => str_repeat('A', 9000),
        ]));
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('invalid-input-response', $body['error-codes'][0] ?? null);
    }

    public function testRequestSuppliedActionIsIgnoredAndServerBoundMetadataIsReturned(): void
    {
        // The full trust chain: metadata bound at issuance (sidecar) is
        // returned on verification; a forged request action/cdata is
        // ignored (it is not even parsed anymore).
        $storage = new ArrayStorage();
        [$token, $nonce] = $this->issuedToken($storage);
        $metadataStore = new ArraySiteVerifyMetadataStore();
        $metadataStore->store($nonce, new SiteVerifyMetadata('checkout', 'order_19382', 'login'), 300);
        $controller = $this->controller(metadataStore: $metadataStore, storage: $storage);

        $response = $controller->siteverify($this->siteverifyRequest([
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

        $first = json_decode((string) $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]))->getContent(), true);
        self::assertSame(true, $first['success'] ?? null);

        $second = json_decode((string) $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]))->getContent(), true);
        self::assertSame($first, $second, 'a same-key retry must return the IDENTICAL canonical response');

        // Same token + a different key -> timeout-or-duplicate (no idempotency).
        $third = json_decode((string) $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => '223e4567-e89b-42d3-a456-426614174000',
        ]))->getContent(), true);
        self::assertSame(false, $third['success'] ?? null);
        self::assertSame('timeout-or-duplicate', $third['error-codes'][0] ?? null);
    }

    public function testSameFingerprintRetryReturnsTheIdenticalCanonicalResponse(): void
    {
        // The idempotency fingerprint covers backend identity + response
        // hash + canonicalized remoteip; the same key + token + remoteip
        // stays the normal retry path (complete -> identical bytes).
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage);
        $store = new ArraySiteVerifyIdempotencyStore();
        $controller = $this->controller(idempotencyStore: $store, storage: $storage);
        $uuid = 'b23e4567-e89b-42d3-a456-426614174000';

        $first = (string) $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]))->getContent();
        self::assertSame(true, json_decode($first, true)['success'] ?? null);
        $second = (string) $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]))->getContent();
        self::assertSame($first, $second, 'same key + token + remoteip is the normal retry path: identical canonical bytes');
    }

    public function testChangedRemoteipConflictsWhileTheEntryIsPending(): void
    {
        // remoteip materially changes verification under IP binding, so the
        // claim fingerprint binds it: while the entry is pending, a request
        // with the same key + token but a different remoteip must conflict
        // — it can neither join the pending entry nor overtake it.
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage);
        $store = new ArraySiteVerifyIdempotencyStore();
        $controller = $this->controller(idempotencyStore: $store, storage: $storage);
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $uuid = '923e4567-e89b-42d3-a456-426614174000';

        // The owner claims with remoteip 127.0.0.1 and stalls: the entry
        // stays pending under fingerprint 'ip:127.0.0.1'.
        [$claim] = $store->claim($backendId, $uuid, hash('sha256', $token), 300, 'ip:127.0.0.1');
        self::assertSame(IdempotencyClaim::Claimed, $claim);

        $response = $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '203.0.113.9', 'idempotency_key' => $uuid,
        ]));
        self::assertSame(400, $response->getStatusCode());
        self::assertSame(['bad-request'], json_decode((string) $response->getContent(), true)['error-codes']);
    }

    public function testChangedRemoteipConflictsAfterTheEntryIsComplete(): void
    {
        // Same conflict after completion: the stored fingerprint is
        // authoritative, so a changed remoteip can never receive the stored
        // outcome of a verification bound to another IP.
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage);
        $store = new ArraySiteVerifyIdempotencyStore();
        $controller = $this->controller(idempotencyStore: $store, storage: $storage);
        $uuid = 'a23e4567-e89b-42d3-a456-426614174000';

        $first = $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        self::assertSame(200, $first->getStatusCode());

        $second = $controller->siteverify($this->siteverifyRequest([
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

        $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $tokenA, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        $second = json_decode((string) $controller->siteverify($this->siteverifyRequest([
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
        // A wrong remoteip makes the bound verification fail.
        $first = json_decode((string) $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '203.0.113.9', 'idempotency_key' => $uuid,
        ]))->getContent(), true);
        self::assertSame(false, $first['success'] ?? null);
        // Retry with the same remoteip and the same key -> the same
        // canonical failure (idempotency freezes the outcome; the
        // fingerprint binds the remoteip, so the retry must repeat it).
        $second = json_decode((string) $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '203.0.113.9', 'idempotency_key' => $uuid,
        ]))->getContent(), true);
        self::assertSame($first, $second);
    }

    public function testIdempotencyNamespacesDoNotCollideAcrossSecrets(): void
    {
        // Different configured secrets (backends) share the same UUID
        // without colliding: each backend's namespace is separate, so each
        // claims and succeeds with its own token.
        $storage = new ArrayStorage();
        [$tokenA] = $this->issuedToken($storage);
        [$tokenB] = $this->issuedToken($storage);
        $store = new ArraySiteVerifyIdempotencyStore();
        $uuid = '523e4567-e89b-42d3-a456-426614174000';
        $controllerA = $this->controller(secrets: ['secret-A-'.str_repeat('a', 16) => 'login'], idempotencyStore: $store, storage: $storage);
        $controllerB = $this->controller(secrets: ['secret-B-'.str_repeat('b', 16) => 'login'], idempotencyStore: $store, storage: $storage);
        $first = json_decode((string) $controllerA->siteverify($this->siteverifyRequest([
            'secret' => 'secret-A-'.str_repeat('a', 16), 'response' => $tokenA, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]))->getContent(), true);
        self::assertSame(true, $first['success'] ?? null);
        $second = json_decode((string) $controllerB->siteverify($this->siteverifyRequest([
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
        // A short configurable lease makes the expiry instant in the test.
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

        $first = (string) $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $malformed, 'idempotency_key' => $uuid,
        ]))->getContent();
        $body = json_decode($first, true);
        self::assertFalse($body['success'] ?? true);
        self::assertSame(['invalid-input-response'], $body['error-codes'] ?? null);

        // A same-key retry reproduces the identical canonical failure.
        $second = (string) $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $malformed, 'idempotency_key' => $uuid,
        ]))->getContent();
        self::assertSame($first, $second, 'a same-key malformed retry must return the identical canonical failure');
        self::assertSame(['invalid-input-response'], json_decode($second, true)['error-codes'] ?? null);

        // The claim was finalized: the store exposes the failure.
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
        $won = $winner->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        $wonBody = json_decode((string) $won->getContent(), true);
        self::assertSame(true, $wonBody['success'] ?? null, 'waiter body: '.(string) $won->getContent());
        self::assertSame(1, $counting->consumes, 'the token was consumed exactly once, by the takeover winner');
        self::assertSame($wonBody, $store->stored($backendId, $uuid), 'the takeover winner finalizes its canonical response');
    }

    // ── the `PENDING_SAME` exponential backoff + lease-aware takeover ────

    /**
     * A store decorator that records the wall-clock time of every
     * stored() poll and takeover() attempt, so the wait-loop cadence is
     * observable. The poll intervals must grow (the exponential backoff),
     * and the takeover attempts must happen only once the owner's lease
     * is at/expired from the waiter's perspective.
     *
     * @return array{0: \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore, 1: object} the
     *         decorated store and the recorder (polls/takeovers arrays)
     */
    private function recordingStore(\BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore $inner): array
    {
        $recorder = new class($inner) implements \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore {
            /** @var list<float> wall seconds of each stored() poll */
            public array $polls = [];

            /** @var list<float> wall seconds of each takeover() attempt */
            public array $takeovers = [];

            public function __construct(private readonly \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore $inner)
            {
            }

            public int $finalizeCount = 0;
            public bool $alwaysRefuse = false;

            public function leaseSeconds(): int
            {
                return $this->inner->leaseSeconds();
            }

            public function claim(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null, ?string $binding = null): array
            {
                return $this->inner->claim($backendId, $idempotencyKey, $responseHash, $ttlSeconds, $remoteipFingerprint, $leaseSeconds);
            }

            public function takeover(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null, ?string $binding = null): array
            {
                $this->takeovers[] = microtime(true);

                return $this->inner->takeover($backendId, $idempotencyKey, $responseHash, $ttlSeconds, $remoteipFingerprint, $leaseSeconds);
            }

            public function renew(string $backendId, string $idempotencyKey, string $owner): bool
            {
                return $this->inner->renew($backendId, $idempotencyKey, $owner);
            }

            public function finalize(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonicalResponse): bool
            {
                return $this->inner->finalize($backendId, $idempotencyKey, $responseHash, $owner, $canonicalResponse);
            }

            public function stored(string $backendId, string $idempotencyKey): ?array
            {
                $this->polls[] = microtime(true);

                return $this->inner->stored($backendId, $idempotencyKey);
            }
        };

        return [$recorder, $recorder];
    }

    /**
     * The lease-aware backoff: a `PENDING_SAME` waiter polls the stored
     * result with growing intervals (100 ms -> 200 ms -> 400 ms -> ...)
     * and probes the owner's lease once up front (a single atomic
     * takeover attempt). A held lease is then left alone until the
     * expiry boundary, a full fixed lease window after the pending entry
     * was first observed. There the takeover is re-armed and the crashed
     * owner is taken over, verified and finalized with the takeover
     * owner token.
     */
    public function testPendingSameBacksOffAndTakesOverOnlyNearTheLeaseExpiry(): void
    {
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage);
        $now = 1_700_000_000;
        // The store clock ticks one second per takeover call (the crashed
        // owner's lease expires while the waiter polls).
        $clock = static function () use (&$now): int {
            return ++$now;
        };
        // A short fixed lease (1s) keeps the boundary quick; the waiter
        // bound (5s) exceeds it (the construction invariant).
        $store = new ArraySiteVerifyIdempotencyStore($clock, 1);
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $uuid = 'b3e4567e-e89b-42d3-a456-4266141740ff';
        $hash = hash('sha256', $token);

        // The stalled owner claims and never finalizes.
        [$claim] = $store->claim($backendId, $uuid, $hash, 300, 'ip:127.0.0.1');
        self::assertSame(IdempotencyClaim::Claimed, $claim);

        [$recording] = $this->recordingStore($store);
        $controller = $this->controller(idempotencyStore: $recording, storage: $storage, waitSecs: 5.0);
        $start = microtime(true);
        $won = $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        $wonBody = json_decode((string) $won->getContent(), true);
        self::assertSame(true, $wonBody['success'] ?? null, 'the waiter must take over near the lease expiry and verify: '.(string) $won->getContent());

        // The lease-aware takeover: at most the one-time lease probe may
        // happen while the lease still has room — every takeover attempt
        // after the probe lands only once the fixed lease window has
        // elapsed since the waiter started.
        $takeovers = $recording->takeovers;
        self::assertGreaterThanOrEqual(2, \count($takeovers), 'the lease probe plus the expiry-boundary takeover must run');
        self::assertLessThan(0.5, $takeovers[0] - $start, 'the one-time lease probe runs up front');
        foreach (\array_slice($takeovers, 1) as $takeoverAt) {
            self::assertGreaterThanOrEqual(0.9, $takeoverAt - $start, 'takeover attempts beyond the initial probe happen only near/after the lease expiry — never while the lease has room');
        }

        // Exponential backoff: the stored-result polls before the winning
        // takeover grow (100ms, 200ms, 400ms, ...) — never a fixed
        // 100ms hammer.
        $phase1Polls = array_values(array_filter($recording->polls, static fn (float $t): bool => $t < $takeovers[\count($takeovers) - 1]));
        $deltas = [];
        for ($i = 1; $i < \count($phase1Polls); $i++) {
            $deltas[] = ($phase1Polls[$i] - $phase1Polls[$i - 1]) * 1000;
        }
        self::assertGreaterThanOrEqual(3, \count($deltas), 'the wait must poll the stored result several times before the takeover');
        foreach ($deltas as $i => $delta) {
            if ($i > 0) {
                self::assertGreaterThanOrEqual($deltas[$i - 1] - 50, $delta, 'the poll intervals must grow (the exponential backoff), not stay flat');
            }
        }
        self::assertLessThan(10, \count($phase1Polls), 'the growing backoff bounds the pre-takeover polls — a fixed 100ms cadence would need ~10 polls per second');
    }

    /**
     * The hard bound: a waiter whose takeover can never win is answered
     * with the retryable 503 internal-error at the bound, because the
     * owner's lease never expires with a frozen store clock. Every
     * takeover attempt beyond the one-time lease probe is gated on the
     * lease window, never wasted while the lease has room. The entry is
     * left pending for a later retry.
     */
    public function testPendingSameHardBoundReturnsTheRetryable503WithoutWastefulTakeovers(): void
    {
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage);
        // The store clock is frozen: the owner's lease never expires in
        // store time, so the armed takeover always loses.
        $now = 1_700_000_000;
        $store = new ArraySiteVerifyIdempotencyStore(static fn (): int => $now, 1);
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $uuid = 'c3e4567e-e89b-42d3-a456-4266141740aa';
        $hash = hash('sha256', $token);

        [$claim] = $store->claim($backendId, $uuid, $hash, 300, 'ip:127.0.0.1');
        self::assertSame(IdempotencyClaim::Claimed, $claim);

        [$recording] = $this->recordingStore($store);
        $controller = $this->controller(idempotencyStore: $recording, storage: $storage, waitSecs: 2.5);
        $start = microtime(true);
        $response = $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        self::assertSame(503, $response->getStatusCode(), 'the hard bound must answer the retryable 503 internal-error');
        self::assertSame(['internal-error'], json_decode((string) $response->getContent(), true)['error-codes']);
        self::assertNull($store->stored($backendId, $uuid), 'the entry stays pending — a later retry can still take over or read the stored result');
        // Beyond the one-time lease probe, no takeover is wasted while
        // the lease has room: every later attempt lands only after the
        // lease window.
        $takeovers = $recording->takeovers;
        foreach (\array_slice($takeovers, \min(1, \count($takeovers))) as $takeoverAt) {
            self::assertGreaterThanOrEqual(0.9, $takeoverAt - $start, 'a takeover beyond the initial probe must never be attempted while the lease still has room');
        }
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

        // Once the renewed lease expires, the takeover succeeds.
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
        // "203.0.113.4, 10.0.0.4") must be rejected as a normal provider
        // bad-request — the core's IP canonicalization must never throw
        // past the boundary as a 500.
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage);
        $controller = $this->controller(storage: $storage);

        $response = $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET,
            'response' => $token,
            'remoteip' => '203.0.113.4, 10.0.0.4',
        ]));
        self::assertSame(400, $response->getStatusCode());
        self::assertSame(['bad-request'], json_decode((string) $response->getContent(), true)['error-codes']);
    }

    public function testMalformedRemoteipIsRejectedBeforeIdempotencyClaim(): void
    {
        // Same rejection on the idempotent path: the malformed IP is
        // refused before any claim is made, so no entry may be created
        // (or joined) under a malformed remoteip.
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage);
        $store = new ArraySiteVerifyIdempotencyStore();
        $controller = $this->controller(idempotencyStore: $store, storage: $storage);
        $uuid = 'c23e4567-e89b-42d3-a456-426614174000';

        $response = $controller->siteverify($this->siteverifyRequest([
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
        // (::ffff:192.0.2.1) to the same identity as the plain IPv4
        // spelling (the core's Issuer::canonicalIpFamily); the
        // idempotency fingerprint must mirror that exactly, so the two
        // spellings of one address are the same claim — a same-key retry
        // under the mapped spelling returns the identical canonical bytes
        // instead of conflicting.
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage, 'login', '192.0.2.1');
        $store = new ArraySiteVerifyIdempotencyStore();
        $controller = $this->controller(idempotencyStore: $store, storage: $storage);
        $uuid = 'd23e4567-e89b-42d3-a456-426614174000';

        $first = (string) $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '192.0.2.1', 'idempotency_key' => $uuid,
        ]))->getContent();
        self::assertSame(true, json_decode($first, true)['success'] ?? null);

        $second = (string) $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '::ffff:192.0.2.1', 'idempotency_key' => $uuid,
        ]))->getContent();
        self::assertSame($first, $second, 'the mapped-v6 spelling is the SAME identity: identical canonical bytes, not a conflict');
    }

    // ── The complete finalize / takeover identity ──────────────────────

    public function testFinalizeWithWrongResponseHashIsANoOp(): void
    {
        // finalize must authorize both the owner token AND the response
        // hash bound in the record: a finalize with the correct owner but
        // a wrong hash is a no-op and the entry stays pending.
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
        // takeover must enforce the complete claim identity itself: the
        // remoteip fingerprint is bound in the record, so a takeover with
        // the correct response hash but a different fingerprint is
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
     * Crash recovery for a token submitted late in its lifetime: the
     * owner consumes + commits the token but dies before finalizing; the
     * signed challenge expires. The retry (same key) takes over after the
     * owner's lease and must reconstruct the original committed success —
     * a fresh verification would now answer Expired
     * (timeout-or-duplicate), violating the identical-canonical-response
     * promise. The owner lease is the store's fixed configured lease
     * (the per-token derivation is gone): the test configures a short
     * store lease (3s) plus a waiter bound above it (5s), so the
     * takeover happens quickly. The retained-state recovery covers the
     * reconstruction after the signed expiry.
     */
    public function testLateTokenCrashRecoveryReconstructsTheOriginalSuccessAfterExpiry(): void
    {
        $storage = new ArrayStorage();
        // A token with a short lifetime: the owner verifies it ~1s after
        // issuance (remaining ~4s); the fixed 3s store lease expires
        // before the signed expiry, so the takeover happens quickly and
        // the reconstruction then works after the signed expiry (the
        // retained-state margin covers it).
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 5), $storage);
        $challenge = $issuer->issue('login', '127.0.0.1');
        $solution = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits);
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = SolutionToken::create($challenge->nonce, $solution, 5000, [])->encode();
        // A short fixed store lease (3s) with a waiter bound above it
        // (5s — the construction invariant) makes the takeover quick.
        $store = new ArraySiteVerifyIdempotencyStore(static fn (): int => time(), 3);
        // The "crash" seam: finalize() is a no-op for the owner, exactly
        // like a process dying between the core commit and the Siteverify
        // finalize. Everything else delegates.
        $crashingStore = new class($store) implements \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore {
            public function __construct(private readonly \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore $inner)
            {
            }

            public int $finalizeCount = 0;
            public bool $alwaysRefuse = false;



            public function leaseSeconds(): int
            {
                return $this->inner->leaseSeconds();
            }

            public function claim(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null, ?string $binding = null): array
            {
                return $this->inner->claim($backendId, $idempotencyKey, $responseHash, $ttlSeconds, $remoteipFingerprint, $leaseSeconds);
            }

            public function takeover(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null, ?string $binding = null): array
            {
                return $this->inner->takeover($backendId, $idempotencyKey, $responseHash, $ttlSeconds, $remoteipFingerprint, $leaseSeconds);
            }

            public function renew(string $backendId, string $idempotencyKey, string $owner): bool
            {
                return $this->inner->renew($backendId, $idempotencyKey, $owner);
            }



            public function finalize(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonicalResponse): bool
            {
                // The OWNER's finalize never lands (process death): the
                // first finalize is refused; a later takeover's finalize
                // (a different owner token) delegates normally — unless
                // alwaysRefuse is set (the crash persists).
                if ($this->alwaysRefuse || $this->finalizeCount === 0) {
                    ++$this->finalizeCount;

                    return false;
                }

                return $this->inner->finalize($backendId, $idempotencyKey, $responseHash, $owner, $canonicalResponse);
            }

            public function stored(string $backendId, string $idempotencyKey): ?array
            {
                return $this->inner->stored($backendId, $idempotencyKey);
            }
        };
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $uuid = 'e4f5a6b7-8c9d-4eaf-b012-3c4d5e6f7081';

        // The owner claims, verifies (committed success) and "dies"
        // without finalizing. The identity-bearing consume (Claimed path)
        // recorded the owner's fingerprint in the consumed record.
        $owner = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $crashingStore, null, 5.0);
        $ownerResponse = $owner->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        // The owner's finalize is REFUSED (the simulated crash): under the
        // durable state-machine contract a locally computed result is
        // NEVER returned as authoritative after a refused finalize — the
        // retryable 503, with the claim still pending for the takeover.
        self::assertSame(503, $ownerResponse->getStatusCode(), 'a refused finalize is an ownership loss — never a local success');
        self::assertSame(['internal-error'], json_decode((string) $ownerResponse->getContent(), true)['error-codes']);
        // The owner consumed + committed but never finalized: the entry is
        // still pending with a committed core result.
        self::assertNull($store->stored($backendId, $uuid), 'the owner crashed before the Siteverify finalize');
        $consumed = $storage->consumedState($challenge->nonce);
        self::assertNotNull($consumed);
        self::assertSame(
            $this->fingerprint($backendId, $uuid, $token, '127.0.0.1'),
            $consumed->operationIdentity,
            'the consumed record carries the ACTUAL atomic consume winner\'s operation identity',
        );

        // Wait past the signed expiry (ttl 5s) and the fixed 3s lease.
        sleep(7);
        $waiter = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $crashingStore, null, 5.0);
        $retry = $waiter->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        $retryBody = json_decode((string) $retry->getContent(), true);
        self::assertSame(true, $retryBody['success'] ?? null, 'the retry must reconstruct the ORIGINAL committed success after the signed expiry: '.(string) $retry->getContent());
        self::assertSame([], $retryBody['error-codes'] ?? null, 'the reconstructed response is the canonical success');
        self::assertTrue(isset($retryBody['challenge_ts']), 'the canonical success carries the challenge timestamp');
    }

    // ── The consumed-record operation-identity gate ────────────────────

    /**
     * The decisive regression: a used token must never become successful
     * again through a different idempotency UUID. The first logical
     * operation (UUID A) redeems the token and its fingerprint is
     * recorded in the consumed record atomically with the
     * pending→consumed transition. A replay under a new UUID B is a
     * different logical operation and is answered with
     * timeout-or-duplicate, and its claim is finalized as CompleteSame
     * (the canonical duplicate). After B's owner lease expires, a retry
     * with B must still be timeout-or-duplicate — the entry returns the
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
        // A short configured store lease (3s) keeps the lease-expiry step
        // instant; the waiter bound (5s) exceeds it (the construction
        // invariant).
        $store = new ArraySiteVerifyIdempotencyStore($clock, 3);
        $controller = $this->controller(idempotencyStore: $store, storage: $storage, waitSecs: 5.0);
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $uuidA = '123e4567-e89b-42d3-a456-42661417401a';
        $uuidB = '123e4567-e89b-42d3-a456-42661417401b';

        // 1. The original logical operation: UUID A redeems the token once.
        $first = json_decode((string) $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidA,
        ]))->getContent(), true);
        self::assertSame(true, $first['success'] ?? null);

        // The consumed record carries A's fingerprint — the identity was
        // written atomically with the pending→consumed transition, so it
        // is provably the actual atomic consume winner's.
        $consumed = $storage->consumedState($nonce);
        self::assertNotNull($consumed);
        self::assertSame(
            $this->fingerprint($backendId, $uuidA, $token, '127.0.0.1'),
            $consumed->operationIdentity,
            'the consumed record must carry the winner\'s operation identity',
        );

        // 2. A different UUID for the same (already-redeemed) token is a
        // different logical operation: timeout-or-duplicate — and its
        // claim is finalized as CompleteSame with the canonical duplicate
        // (never left pending for a later takeover).
        $second = json_decode((string) $controller->siteverify($this->siteverifyRequest([
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

        // 4. The retry with UUID B must still be timeout-or-duplicate —
        // a consumed token can never become successful again through a
        // different idempotency UUID.
        $retry = json_decode((string) $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidB,
        ]))->getContent(), true);
        self::assertSame(false, $retry['success'] ?? null, 'a consumed token must NEVER become successful again through a different idempotency UUID');
        self::assertSame(['timeout-or-duplicate'], $retry['error-codes'] ?? null);
    }

    /**
     * The crash-window variant of the decisive regression: the first
     * B-replay detects the duplicate but the finalize does not land (a
     * process dies between detect and finalize — the claim stays
     * pending). After B's lease expires, the retry with B takes over its
     * own pending claim — but the consumed record's own operation
     * identity is A's fingerprint, not B's. B's fingerprint cannot match
     * the actual atomic consume winner, so the takeover is not
     * recovery-eligible: the ordinary verify returns timeout-or-duplicate
     * for the consumed token, never a reconstructed success. The record's
     * own identity is the structural backstop of the
     * crash-between-detect-and-finalize window.
     */
    public function testCrashWindowDuplicateFinalizeIsBackstoppedByTheConsumedRecordIdentityGate(): void
    {
        $storage = new ArrayStorage();
        [$token, $nonce] = $this->issuedToken($storage);
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

            public int $finalizeCount = 0;
            public bool $alwaysRefuse = true;



            public function leaseSeconds(): int
            {
                return $this->inner->leaseSeconds();
            }

            public function claim(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null, ?string $binding = null): array
            {
                return $this->inner->claim($backendId, $idempotencyKey, $responseHash, $ttlSeconds, $remoteipFingerprint, $leaseSeconds);
            }

            public function takeover(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null, ?string $binding = null): array
            {
                return $this->inner->takeover($backendId, $idempotencyKey, $responseHash, $ttlSeconds, $remoteipFingerprint, $leaseSeconds);
            }

            public function renew(string $backendId, string $idempotencyKey, string $owner): bool
            {
                return $this->inner->renew($backendId, $idempotencyKey, $owner);
            }



            public function finalize(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonicalResponse): bool
            {
                // The OWNER's finalize never lands (process death): the
                // first finalize is refused; a later takeover's finalize
                // (a different owner token) delegates normally — unless
                // alwaysRefuse is set (the crash persists).
                if ($this->alwaysRefuse || $this->finalizeCount === 0) {
                    ++$this->finalizeCount;

                    return false;
                }

                return $this->inner->finalize($backendId, $idempotencyKey, $responseHash, $owner, $canonicalResponse);
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

        // 1. UUID A redeems the token (the original logical operation),
        // but its finalize is refused (the simulated crash): the
        // authoritative completed state was not established, so the 503 —
        // never the locally computed success.
        $firstResponse = $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidA,
        ]));
        self::assertSame(503, $firstResponse->getStatusCode(), 'a refused finalize never returns the local result as authoritative');
        $first = json_decode((string) $firstResponse->getContent(), true);
        $consumed = $storage->consumedState($nonce);
        self::assertNotNull($consumed);
        self::assertSame(
            $this->fingerprint($backendId, $uuidA, $token, '127.0.0.1'),
            $consumed->operationIdentity,
            'the consumed record carries the original winner\'s identity',
        );

        // 2. UUID B detects the duplicate (timeout-or-duplicate) but the
        // finalize never lands: claim B is still pending.
        $secondResponse = $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidB,
        ]));
        // B's finalize is refused too (the crash persists): the 503, never
        // the locally computed duplicate as authoritative.
        self::assertSame(503, $secondResponse->getStatusCode(), 'a refused finalize never returns the local duplicate as authoritative');
        $second = json_decode((string) $secondResponse->getContent(), true);
        self::assertSame(['internal-error'], $second['error-codes'] ?? null);
        self::assertNull($store->stored($backendId, $uuidB), 'the finalize crashed between detect and landing — claim B stays pending');

        // 3. B's lease expires while the entry is still pending — the
        // exact window where a takeover would reconstruct the success.
        $now += 4;

        // 4. The retry with B takes over its own pending claim — but the
        // consumed record's OWN operation identity is A's fingerprint (the
        // actual atomic consume winner's), and B's fingerprint differs:
        // the identity gate blocks the recovery — the ordinary verify
        // returns timeout-or-duplicate for the consumed token.
        $retryController = $this->controller(idempotencyStore: $crashingStore, storage: $storage, waitSecs: 5.0);
        $retryResponse = $retryController->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidB,
        ]));
        // The identity gate blocks the recovery (the consumed record's own
        // identity is A's fingerprint, never B's) and the refused finalize
        // then answers the 503 — the local duplicate is never returned as
        // authoritative.
        self::assertSame(503, $retryResponse->getStatusCode(), 'the identity gate + the refused finalize answer the 503, never the local result');
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
            public function claim(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null, ?string $binding = null): array
            {
                throw new \RuntimeException('idempotency store outage');
            }

            public function leaseSeconds(): int
            {
                return 60;
            }

            public function finalize(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonicalResponse): bool
            {
            }

            public function stored(string $backendId, string $idempotencyKey): ?array
            {
                return null;
            }

            public function takeover(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null, ?string $binding = null): array
            {
                return [IdempotencyClaim::StillPending, null];
            }

            public function renew(string $backendId, string $idempotencyKey, string $owner): bool
            {
                return false;
            }
        };
        $controller = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $throwing);

        $response = $controller->siteverify($this->siteverifyRequest([
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
        // The finalize runs after the core consumed+committed the token:
        // a throwing finalize must NOT become a 500 — the response is the
        // retryable 503 internal-error, the entry stays pending, and a
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

            public int $finalizeCount = 0;
            public bool $alwaysRefuse = false;

            public function leaseSeconds(): int
            {
                return $this->inner->leaseSeconds();
            }

            public function claim(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null, ?string $binding = null): array
            {
                return $this->inner->claim($backendId, $idempotencyKey, $responseHash, $ttlSeconds, $remoteipFingerprint, $leaseSeconds);
            }

            public function takeover(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null, ?string $binding = null): array
            {
                return $this->inner->takeover($backendId, $idempotencyKey, $responseHash, $ttlSeconds, $remoteipFingerprint, $leaseSeconds);
            }

            public function renew(string $backendId, string $idempotencyKey, string $owner): bool
            {
                return $this->inner->renew($backendId, $idempotencyKey, $owner);
            }

            public function finalize(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonicalResponse): bool
            {
                throw new \RuntimeException('finalize outage');
            }

            public function stored(string $backendId, string $idempotencyKey): ?array
            {
                return $this->inner->stored($backendId, $idempotencyKey);
            }
        };
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $uuid = '123e4567-e89b-42d3-a456-42661417401f';

        // The verification succeeds (the token is consumed+committed by
        // the core — the Claimed path records the owner's fingerprint as
        // the consumed record's operation identity), but the finalize
        // throws: 503 internal-error, never a 500, and the entry stays
        // pending.
        $owner = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $finalizeThrowing, null, 5.0);
        $ownerResponse = $owner->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        self::assertSame(503, $ownerResponse->getStatusCode(), 'a throwing finalize after consumption must map to 503 internal-error, never a 500');
        self::assertSame(['internal-error'], json_decode((string) $ownerResponse->getContent(), true)['error-codes']);
        self::assertNull($inner->stored($backendId, $uuid), 'the finalize failed — the entry stays pending');

        // Expire the owner's lease: a same-key retry takes over and
        // reconstructs the committed outcome via the retained state — the
        // retry's fingerprint equals the consumed record's identity (the
        // same logical operation: same backend + UUID + response + IP).
        $now += 4;
        $retry = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $inner, null, 5.0);
        $retryResponse = $retry->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        $retryBody = json_decode((string) $retryResponse->getContent(), true);
        self::assertSame(true, $retryBody['success'] ?? null, 'the same-key retry must reconstruct the committed outcome: '.(string) $retryResponse->getContent());
        self::assertSame([], $retryBody['error-codes'] ?? null);
    }

    public function testNonIdempotentRequestNeverTouchesTheIdempotencyStore(): void
    {
        // The idempotency machinery is strictly key-gated: a request
        // without an idempotency_key never claims, never waits and never
        // finalizes — even a store whose claim() throws cannot affect it.
        // The challenge storage's own failure is handled inside the
        // verifier (StorageUnavailable), and the compatibility boundary
        // maps that retryable server-side failure to the 503
        // internal-error response — never a 500, never a 200
        // bad-request.
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
            public function claim(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null, ?string $binding = null): array
            {
                throw new \RuntimeException('idempotency store outage');
            }

            public function leaseSeconds(): int
            {
                return 60;
            }

            public function finalize(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonicalResponse): bool
            {
            }

            public function stored(string $backendId, string $idempotencyKey): ?array
            {
                return null;
            }

            public function takeover(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null, ?string $binding = null): array
            {
                return [IdempotencyClaim::StillPending, null];
            }

            public function renew(string $backendId, string $idempotencyKey, string $owner): bool
            {
                return false;
            }
        };
        $controller = new SiteVerifyController(new Verifier($throwing), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $throwing, null, null, $throwingIdem);

        $response = $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET,
            'response' => $token,
            'remoteip' => '127.0.0.1',
        ]));
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame(503, $response->getStatusCode(), 'the non-idempotent path never touches the idempotency store; a verifier storage outage maps to the retryable 503 internal-error');
        self::assertFalse($body['success'] ?? true);
        self::assertSame(['internal-error'], $body['error-codes'] ?? null, 'a verifier storage outage must map to internal-error, never bad-request');
    }

    // ── The consumed-record identity gate: decisive tails ──────────────

    /**
     * First redemption without a key: the token is validated with no
     * idempotency key, so the non-idempotent verify records no operation
     * identity (the consumed record's identity stays null). A later
     * keyed replay under UUID B claims a fresh entry (the no-key
     * redemption never touched the idempotency store) — and cannot
     * register itself as the original: the record is already consumed,
     * so B's identity-bearing consume is a no-op. After B's lease
     * expires and B takes over, the consumed record's identity (null)
     * can never equal B's fingerprint — the takeover refuses
     * reconstruction and the retry is timeout-or-duplicate.
     */
    public function testFirstRedemptionWithoutAKeyThenKeyedReplayCanNeverReconstruct(): void
    {
        $storage = new ArrayStorage();
        [$token, $nonce] = $this->issuedToken($storage);
        $now = 1_700_000_000;
        $clock = static function () use (&$now): int {
            return $now;
        };
        $store = new ArraySiteVerifyIdempotencyStore($clock, 3);
        // The "crash" seam: finalize() never lands, so the keyed
        // replay's claim stays pending (the takeover window stays open).
        $crashingStore = new class($store) implements \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore {
            public function __construct(private readonly \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore $inner)
            {
            }

            public int $finalizeCount = 0;
            public bool $alwaysRefuse = false;



            public function leaseSeconds(): int
            {
                return $this->inner->leaseSeconds();
            }

            public function claim(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null, ?string $binding = null): array
            {
                return $this->inner->claim($backendId, $idempotencyKey, $responseHash, $ttlSeconds, $remoteipFingerprint, $leaseSeconds);
            }

            public function takeover(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null, ?string $binding = null): array
            {
                return $this->inner->takeover($backendId, $idempotencyKey, $responseHash, $ttlSeconds, $remoteipFingerprint, $leaseSeconds);
            }

            public function renew(string $backendId, string $idempotencyKey, string $owner): bool
            {
                return $this->inner->renew($backendId, $idempotencyKey, $owner);
            }



            public function finalize(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonicalResponse): bool
            {
                // The OWNER's finalize never lands (process death): the
                // first finalize is refused; a later takeover's finalize
                // (a different owner token) delegates normally — unless
                // alwaysRefuse is set (the crash persists).
                if ($this->alwaysRefuse || $this->finalizeCount === 0) {
                    ++$this->finalizeCount;

                    return false;
                }

                return $this->inner->finalize($backendId, $idempotencyKey, $responseHash, $owner, $canonicalResponse);
            }

            public function stored(string $backendId, string $idempotencyKey): ?array
            {
                return $this->inner->stored($backendId, $idempotencyKey);
            }
        };
        $controller = $this->controller(idempotencyStore: $crashingStore, storage: $storage, waitSecs: 5.0);
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $uuidB = '123e4567-e89b-42d3-a456-4266141740b2';

        // 1. The first redemption has NO idempotency key: success, and NO
        //    identity is recorded (the non-idempotent verify passes null).
        $first = json_decode((string) $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1',
        ]))->getContent(), true);
        self::assertSame(true, $first['success'] ?? null);
        $consumed = $storage->consumedState($nonce);
        self::assertNotNull($consumed);
        self::assertNull($consumed->operationIdentity, 'a no-key first redemption records NO operation identity');

        // 2. A keyed replay under UUID B: fresh claim, the verify finds
        //    the consumed record -> timeout-or-duplicate, and the
        //    finalize crashes: B's entry stays pending.
        $secondResponse = $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidB,
        ]));
        // The replay's own finalize is refused (the simulated crash): the
        // 503, never the locally computed duplicate as authoritative.
        self::assertSame(503, $secondResponse->getStatusCode(), 'the refused replay finalize answers the 503');
        $second = json_decode((string) $secondResponse->getContent(), true);
        self::assertSame(['internal-error'], $second['error-codes'] ?? null);
        self::assertNull($store->stored($backendId, $uuidB), 'the replay finalize crashed — claim B stays pending');

        // 3. B's lease expires while the entry is still pending.
        $now += 4;

        // 4. The retry with B takes over its own pending claim — but the
        //    consumed record's identity is null (the no-key redemption
        //    recorded nothing), which can never equal B's fingerprint:
        //    the takeover refuses reconstruction and the ordinary verify
        //    returns timeout-or-duplicate. The keyed replay can never
        //    register itself as the original.
        $retry = json_decode((string) $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidB,
        ]))->getContent(), true);
        self::assertSame(false, $retry['success'] ?? null, 'a keyed replay of a no-key redemption must NEVER reconstruct a success');
        self::assertSame(['timeout-or-duplicate'], $retry['error-codes'] ?? null);
    }

    /**
     * Two same-scope backend secrets: the original redemption runs via
     * secret 1. A retry with the same token + same UUID via secret 2
     * (different backendId, same scope) claims a fresh entry (the
     * idempotency store is namespaced by backendId), detects the
     * duplicate, and its finalize crashes. After the lease expires the
     * retry takes over — but the fingerprint binds the backendId, so
     * secret-2's fingerprint differs from the consumed record's identity
     * (secret 1's): the takeover must not reconstruct. Two secrets
     * mapped to the same scope can never each claim to be the original.
     */
    public function testTwoSameScopeBackendSecretsRetryCanNeverReconstruct(): void
    {
        $storage = new ArrayStorage();
        [$token, $nonce] = $this->issuedToken($storage);
        $now = 1_700_000_000;
        $clock = static function () use (&$now): int {
            return $now;
        };
        $store = new ArraySiteVerifyIdempotencyStore($clock, 3);
        $crashingStore = new class($store) implements \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore {
            public function __construct(private readonly \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore $inner)
            {
            }

            public int $finalizeCount = 0;
            public bool $alwaysRefuse = false;



            public function leaseSeconds(): int
            {
                return $this->inner->leaseSeconds();
            }

            public function claim(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null, ?string $binding = null): array
            {
                return $this->inner->claim($backendId, $idempotencyKey, $responseHash, $ttlSeconds, $remoteipFingerprint, $leaseSeconds);
            }

            public function takeover(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null, ?string $binding = null): array
            {
                return $this->inner->takeover($backendId, $idempotencyKey, $responseHash, $ttlSeconds, $remoteipFingerprint, $leaseSeconds);
            }

            public function renew(string $backendId, string $idempotencyKey, string $owner): bool
            {
                return $this->inner->renew($backendId, $idempotencyKey, $owner);
            }



            public function finalize(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonicalResponse): bool
            {
                // The OWNER's finalize never lands (process death): the
                // first finalize is refused; a later takeover's finalize
                // (a different owner token) delegates normally — unless
                // alwaysRefuse is set (the crash persists).
                if ($this->alwaysRefuse || $this->finalizeCount === 0) {
                    ++$this->finalizeCount;

                    return false;
                }

                return $this->inner->finalize($backendId, $idempotencyKey, $responseHash, $owner, $canonicalResponse);
            }

            public function stored(string $backendId, string $idempotencyKey): ?array
            {
                return $this->inner->stored($backendId, $idempotencyKey);
            }
        };
        $secret1 = 'secret-one-'.str_repeat('a', 16);
        $secret2 = 'secret-two-'.str_repeat('b', 16);
        $controller1 = $this->controller(secrets: [$secret1 => 'login'], idempotencyStore: $crashingStore, storage: $storage, waitSecs: 5.0);
        $controller2 = $this->controller(secrets: [$secret2 => 'login'], idempotencyStore: $crashingStore, storage: $storage, waitSecs: 5.0);
        $backendId1 = hash('sha256', $secret1.'|login|0');
        $backendId2 = hash('sha256', $secret2.'|login|0');
        $uuid = '123e4567-e89b-42d3-a456-4266141740b4';

        // 1. The original redemption via secret 1 (scope 'login'): the
        //    identity-bearing consume records secret-1's fingerprint, but
        //    the finalize is refused (the simulated crash): the 503, never
        //    the local result as authoritative.
        $firstResponse = $controller1->siteverify($this->siteverifyRequest([
            'secret' => $secret1, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        self::assertSame(503, $firstResponse->getStatusCode(), 'the refused finalize answers the 503');
        $first = json_decode((string) $firstResponse->getContent(), true);
        $consumed = $storage->consumedState($nonce);
        self::assertNotNull($consumed);
        self::assertSame(
            $this->fingerprint($backendId1, $uuid, $token, '127.0.0.1'),
            $consumed->operationIdentity,
            'the consumed record carries secret-1\'s fingerprint (the backendId is inside it)',
        );

        // 2. The same token + same UUID via secret 2: fresh entry in
        //    secret-2's backend namespace, the verify finds the consumed
        //    record -> timeout-or-duplicate, and the finalize crashes.
        $secondResponse = $controller2->siteverify($this->siteverifyRequest([
            'secret' => $secret2, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        // Secret-2's finalize is the SECOND finalize: it delegates and
        // lands the timeout-or-duplicate.
        self::assertSame(200, $secondResponse->getStatusCode());
        $second = json_decode((string) $secondResponse->getContent(), true);
        self::assertSame(false, $second['success'] ?? null);
        self::assertSame(['timeout-or-duplicate'], $second['error-codes'] ?? null);
        self::assertNotNull($store->stored($backendId2, $uuid), 'the secret-2 duplicate finalize lands');

        // 3. The lease expires while secret-2's entry is still pending.
        $now += 4;

        // 4. The retry via secret 2 takes over its own pending claim —
        //    but the backendId is inside the fingerprint, so secret-2's
        //    fingerprint differs from the consumed record's identity
        //    (secret 1's): the takeover MUST NOT reconstruct — the
        //    ordinary verify returns timeout-or-duplicate.
        $retry = json_decode((string) $controller2->siteverify($this->siteverifyRequest([
            'secret' => $secret2, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]))->getContent(), true);
        self::assertSame(false, $retry['success'] ?? null, 'a same-scope backend secret can never reconstruct another backend\'s redemption');
        self::assertSame(['timeout-or-duplicate'], $retry['error-codes'] ?? null);
    }

    /**
     * The deterministic Array-store + clock variant of the three-owner
     * same-key recovery chain across two crash boundaries. A claims UUID
     * K and crashes before verification (claim only). B retries K, takes
     * over (no consumed state exists yet), performs the first
     * verification — the TookOver owner's fingerprint is recorded
     * atomically with the consume. The finalize then crashes: B's
     * response is the retryable internal-error and the entry stays
     * pending. C retries K, takes over, the recovery gate compares the
     * record identity to C's fingerprint (same UUID K + same token +
     * same remoteip → identical) and reconstruction succeeds with the
     * identical canonical success bytes. D with a different UUID K2 on
     * the same token must still be refused after its own takeover; the
     * identity gate is not weakened.
     */
    public function testThreeOwnerSameKeyRecoveryChainAcrossTwoCrashBoundaries(): void
    {
        $storage = new ArrayStorage();
        [$token, $nonce] = $this->issuedToken($storage);
        $now = 1_700_000_000;
        $clock = static function () use (&$now): int {
            return $now;
        };
        // A short configured store lease (3s) keeps the lease-expiry steps
        // instant; the waiter bound (5s) exceeds it (the construction
        // invariant).
        $store = new ArraySiteVerifyIdempotencyStore($clock, 3);
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $uuidK = '123e4567-e89b-42d3-a456-4266141740c1';
        $uuidK2 = '123e4567-e89b-42d3-a456-4266141740c2';

        // A claims UUID K and crashes before verification (claim only):
        // the entry is pending with no consumed state.
        [$claimA] = $store->claim($backendId, $uuidK, hash('sha256', $token), 300, 'ip:127.0.0.1');
        self::assertSame(IdempotencyClaim::Claimed, $claimA);
        // A's lease expires (no verification ever ran).
        $now += 4;

        // B retries K: takes over (no consumed state exists yet), performs
        // the first verification — its fingerprint is recorded atomically
        // with the consume — and the finalize crashes: B's response is the
        // retryable internal-error and the entry stays pending.
        $finalizeThrowing = new class($store) implements SiteVerifyIdempotencyStore {
            public function __construct(private readonly SiteVerifyIdempotencyStore $inner)
            {
            }

            public function leaseSeconds(): int
            {
                return $this->inner->leaseSeconds();
            }

            public function claim(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null, ?string $binding = null): array
            {
                return $this->inner->claim($backendId, $idempotencyKey, $responseHash, $ttlSeconds, $remoteipFingerprint, $leaseSeconds);
            }

            public function takeover(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null, ?string $binding = null): array
            {
                return $this->inner->takeover($backendId, $idempotencyKey, $responseHash, $ttlSeconds, $remoteipFingerprint, $leaseSeconds);
            }

            public function renew(string $backendId, string $idempotencyKey, string $owner): bool
            {
                return $this->inner->renew($backendId, $idempotencyKey, $owner);
            }

            public function finalize(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonicalResponse): bool
            {
                // The finalize crashes (process death between the core
                // commit and the Siteverify finalize).
                throw new \RuntimeException('finalize outage');
            }

            public function stored(string $backendId, string $idempotencyKey): ?array
            {
                return $this->inner->stored($backendId, $idempotencyKey);
            }
        };
        $bController = $this->controller(idempotencyStore: $finalizeThrowing, storage: $storage, waitSecs: 5.0);
        $bResponse = $bController->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidK,
        ]));
        self::assertSame(503, $bResponse->getStatusCode(), 'the takeover owner\'s crashed finalize must map to the retryable internal-error');
        self::assertSame(['internal-error'], json_decode((string) $bResponse->getContent(), true)['error-codes']);
        self::assertNull($store->stored($backendId, $uuidK), 'B crashed before the Siteverify finalize — the entry stays pending');
        $consumed = $storage->consumedState($nonce);
        self::assertNotNull($consumed, 'B consumed and committed the token');
        self::assertNotNull($consumed->consumedResult, 'B committed its success');
        self::assertSame(true, $consumed->consumedResult->valid);
        self::assertSame(
            $this->fingerprint($backendId, $uuidK, $token, '127.0.0.1'),
            $consumed->operationIdentity,
            'the TookOver owner that performs the FIRST verification records the identity atomically with the consume',
        );

        // B's lease expires while the entry is still pending.
        $now += 4;

        // C retries K: takes over, the consumed result exists and the
        // recovery gate compares the record identity to C's fingerprint
        // (same UUID K + same token + same remoteip → identical):
        // reconstruction succeeds with the identical canonical success
        // bytes.
        $cController = $this->controller(idempotencyStore: $store, storage: $storage, waitSecs: 5.0);
        $cResponse = $cController->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidK,
        ]));
        $cBody = json_decode((string) $cResponse->getContent(), true);
        self::assertSame(true, $cBody['success'] ?? null, 'C must reconstruct the ORIGINAL success after two crash boundaries: '.(string) $cResponse->getContent());
        $record = $storage->find($nonce);
        self::assertNotNull($record);
        $expectedCanonical = json_encode([
            'action' => null,
            'cdata' => null,
            'challenge_ts' => gmdate('Y-m-d\TH:i:s\Z', $record->issuedAt),
            'error-codes' => [],
            'hostname' => $record->hostname,
            'success' => true,
        ], JsonResponse::DEFAULT_ENCODING_OPTIONS);
        self::assertSame($expectedCanonical, (string) $cResponse->getContent(), 'C receives the IDENTICAL canonical success bytes');

        // D claims a different UUID K2 on the same token (claim only,
        // crashes before verification); after the lease expiry D's retry
        // takes over K2's pending claim — but the consumed record's
        // identity is K's fingerprint, never D's: the identity gate
        // refuses the reconstruction — timeout-or-duplicate. The gate is
        // not weakened.
        [$claimD] = $store->claim($backendId, $uuidK2, hash('sha256', $token), 300, 'ip:127.0.0.1');
        self::assertSame(IdempotencyClaim::Claimed, $claimD);
        $now += 4;
        $dController = $this->controller(idempotencyStore: $store, storage: $storage, waitSecs: 5.0);
        $dResponse = $dController->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidK2,
        ]));
        $dBody = json_decode((string) $dResponse->getContent(), true);
        self::assertSame(false, $dBody['success'] ?? null, 'a DIFFERENT UUID must never reconstruct the same-key success');
        self::assertSame(['timeout-or-duplicate'], $dBody['error-codes'] ?? null);
    }

    public function testCanonicalSuccessStorageOutageReturns503InternalError(): void
    {
        // A storage outage in canonicalSuccess()'s fresh find() — after
        // the token was consumed and verified — must map to the
        // retryable 503 internal-error response, never a raw 500 (worst
        // for non-idempotent requests, which have no same-key recovery).
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
                throw new \RuntimeException('storage outage after consumption');
            }

            public function consumedState(string $nonce): ?\KiwiCaptcha\ConsumedRecord
            {
                return null;
            }

            public function consume(string $nonce): ?\KiwiCaptcha\ConsumedRecord
            {
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
        // The verifier runs against the healthy storage (the verification
        // succeeds and consumes the token); the controller's storage is
        // the throwing decorator, so canonicalSuccess()'s fresh find()
        // hits the outage after consumption.
        $controller = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $throwing);

        $response = $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET,
            'response' => $token,
            'remoteip' => '127.0.0.1',
        ]));
        self::assertSame(503, $response->getStatusCode(), 'a canonicalSuccess storage outage must map to 503 internal-error, never a raw 500');
        self::assertSame(['internal-error'], json_decode((string) $response->getContent(), true)['error-codes']);
    }

    // ── The uncommitted-result resume (lost reply after the consume) ───

    /**
     * The defect-shaped crash: the atomic consume executes (the
     * pending→consumed transition lands and the operation identity is
     * recorded atomically with the state flip) but the reply is lost
     * before the derivation/commit — consumed_result stays null forever
     * for the ordinary verifier (ConsumeIndeterminate). The original
     * attempt answers the retryable 503 internal-error with the claim
     * staying pending. The same-key retry (a fresh controller with the
     * working storage) takes over the expired short lease and the
     * recovery gate proves the identity (same key + token + remoteip →
     * the consumed record's own identity equals the retry's fingerprint).
     * The derivation is resumed and committed — the original canonical
     * success bytes.
     */
    public function testLostConsumeReplyThenSameKeyRetryResumesTheOriginalSuccess(): void
    {
        $storage = new ArrayStorage();
        [$token, $nonce] = $this->issuedToken($storage);
        $now = 1_700_000_000;
        $clock = static function () use (&$now): int {
            return $now;
        };
        // A short configured store lease (3s) keeps the lease-expiry step
        // instant; the waiter bound (5s) exceeds it (the construction
        // invariant).
        $store = new ArraySiteVerifyIdempotencyStore($clock, 3);
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $uuid = '123e4567-e89b-42d3-a456-4266141740e1';

        // The "lost reply" seam: consumeWithOperationIdentity() delegates
        // — the transition executes and the identity lands atomically with
        // the state flip — and the response is then lost. Everything else
        // delegates.
        $lostReply = new class($storage) implements \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyRecoveryCapableStorageInterface {
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
                // The transition executes (the identity lands atomically
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

            public function deleteIfPending(string $nonce): \KiwiCaptcha\DeleteIfPendingResult
            {
                return $this->inner->deleteIfPending($nonce);
            }
        };
        $owner = new SiteVerifyController(new Verifier($lostReply), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $lostReply, null, null, $store, null, 5.0);
        $ownerResponse = $owner->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        self::assertSame(503, $ownerResponse->getStatusCode(), 'the lost consume reply must map to the retryable 503 internal-error');
        self::assertSame(['internal-error'], json_decode((string) $ownerResponse->getContent(), true)['error-codes']);
        self::assertNull($store->stored($backendId, $uuid), 'the lost reply must NOT finalize the claim — the entry stays pending');
        $consumed = $storage->consumedState($nonce);
        self::assertNotNull($consumed, 'the transition executed — the token IS consumed');
        self::assertSame(
            $this->fingerprint($backendId, $uuid, $token, '127.0.0.1'),
            $consumed->operationIdentity,
            'the consumed record carries the operation identity of the ACTUAL atomic consume winner',
        );
        self::assertNull($consumed->consumedResult, 'the derivation never ran — consumed_result stays null forever for the ordinary verifier');

        // The same-key retry with the working storage: pending -> wait ->
        // takeover (the 3s lease expired) -> the recovery gate matches the
        // consumed record's OWN identity against the retry's fingerprint ->
        // the uncommitted derivation is resumed and committed.
        $now += 4;
        $retry = $this->controller(idempotencyStore: $store, storage: $storage, waitSecs: 5.0);
        $retryResponse = $retry->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        $retryBody = json_decode((string) $retryResponse->getContent(), true);
        self::assertSame(true, $retryBody['success'] ?? null, 'the identity-proven retry must RESUME the derivation and succeed: '.(string) $retryResponse->getContent());
        self::assertSame([], $retryBody['error-codes'] ?? null);
        $record = $storage->find($nonce);
        self::assertNotNull($record);
        $expectedCanonical = json_encode([
            'action' => null,
            'cdata' => null,
            'challenge_ts' => gmdate('Y-m-d\TH:i:s\Z', $record->issuedAt),
            'error-codes' => [],
            'hostname' => $record->hostname,
            'success' => true,
        ], JsonResponse::DEFAULT_ENCODING_OPTIONS);
        self::assertSame($expectedCanonical, (string) $retryResponse->getContent(), 'the retry receives the ORIGINAL canonical success bytes');
        self::assertNotNull($storage->consumedState($nonce)?->consumedResult, 'the resumed derivation must be committed');
        self::assertSame(['success' => true], array_intersect_key($store->stored($backendId, $uuid) ?? [], ['success' => true]), 'the resumed outcome is finalized as COMPLETE_SAME');
    }

    /**
     * The lost-reply flow with a wrong counter: the resumed derivation
     * deterministically fails (InsufficientWork), the canonical
     * invalid-input-response failure is finalized, and a same-UUID retry
     * returns the identical stored failure — the same canonical-failure
     * promise as an ordinary failed verification.
     */
    public function testLostConsumeReplyInvalidSolutionResumesDeterministicInsufficientWork(): void
    {
        $storage = new ArrayStorage();
        [$token, $nonce] = $this->issuedToken($storage);
        // The first counter whose hash fails the target is deterministic
        // and differs from the valid solution.
        $record = $storage->find($nonce);
        self::assertNotNull($record);
        $saltBytes = base64_decode($record->salt, true);
        $wrong = 0;
        while (Verifier::leadingZeroBits(hash('sha256', $record->prefix.$wrong.$saltBytes, true)) >= $record->targetBits) {
            $wrong++;
        }
        $wrongToken = SolutionToken::create($nonce, $wrong, 5000, [])->encode();
        self::assertNotSame($token, $wrongToken);

        $now = 1_700_000_000;
        $clock = static function () use (&$now): int {
            return $now;
        };
        $store = new ArraySiteVerifyIdempotencyStore($clock, 3);
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $uuid = '123e4567-e89b-42d3-a456-4266141740e2';

        $lostReply = new class($storage) implements \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyRecoveryCapableStorageInterface {
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
        $owner = new SiteVerifyController(new Verifier($lostReply), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $lostReply, null, null, $store, null, 5.0);
        $ownerResponse = $owner->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $wrongToken, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        self::assertSame(503, $ownerResponse->getStatusCode(), 'the lost consume reply must map to the retryable 503 internal-error');
        self::assertNull($store->stored($backendId, $uuid), 'the claim stays pending');

        // The same-key retry takes over and resumes: the derivation fails
        // deterministically (wrong counter) — InsufficientWork maps to the
        // provider invalid-input-response and the claim is finalized with
        // the canonical failure.
        $now += 4;
        $retry = $this->controller(idempotencyStore: $store, storage: $storage, waitSecs: 5.0);
        $retryResponse = $retry->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $wrongToken, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        $retryBody = json_decode((string) $retryResponse->getContent(), true);
        self::assertSame(false, $retryBody['success'] ?? null, 'the resumed derivation must deterministically fail the wrong counter');
        self::assertSame(['invalid-input-response'], $retryBody['error-codes'] ?? null, 'insufficient work maps to the invalid-response vocabulary');
        self::assertNotNull($storage->consumedState($nonce)?->consumedResult, 'the resumed invalid outcome must be committed');
        self::assertSame(false, $storage->consumedState($nonce)->consumedResult->valid);
        $stored = $store->stored($backendId, $uuid);
        self::assertIsArray($stored, 'a failed resumed verification is ALSO finalized');
        self::assertSame(['invalid-input-response'], $stored['error-codes'] ?? null);

        // A same-UUID retry now returns the identical stored canonical
        // failure (CompleteSame) — never a re-derivation.
        $again = $this->controller(idempotencyStore: $store, storage: $storage, waitSecs: 5.0);
        $againResponse = $again->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $wrongToken, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        self::assertSame($retryBody, json_decode((string) $againResponse->getContent(), true), 'a same-UUID retry reproduces the identical canonical failure');
    }

    /**
     * A different UUID can never resume the winner's uncommitted
     * derivation: the consumed record's own identity is A's fingerprint,
     * never B's — the takeover gate refuses. The ordinary verify reports
     * ConsumeIndeterminate, and B's retry answers the retryable 503
     * internal-error without finalizing (A's recovery evidence survives).
     */
    public function testLostConsumeReplyDifferentUuidCannotResume(): void
    {
        $storage = new ArrayStorage();
        [$token, $nonce] = $this->issuedToken($storage);
        $now = 1_700_000_000;
        $clock = static function () use (&$now): int {
            return $now;
        };
        $store = new ArraySiteVerifyIdempotencyStore($clock, 3);
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $uuidA = '123e4567-e89b-42d3-a456-4266141740e3';
        $uuidB = '123e4567-e89b-42d3-a456-4266141740e4';

        $lostReply = new class($storage) implements \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyRecoveryCapableStorageInterface {
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
        $owner = new SiteVerifyController(new Verifier($lostReply), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $lostReply, null, null, $store, null, 5.0);
        $ownerResponse = $owner->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidA,
        ]));
        self::assertSame(503, $ownerResponse->getStatusCode());
        $consumed = $storage->consumedState($nonce);
        self::assertNotNull($consumed);
        self::assertSame($this->fingerprint($backendId, $uuidA, $token, '127.0.0.1'), $consumed->operationIdentity);
        self::assertNull($consumed->consumedResult);

        // B claims a fresh entry and attempts a fresh verification: the
        // consumed-without-result record is ConsumeIndeterminate -> the
        // retryable 503 (never a finalized duplicate). B's entry stays
        // pending; its lease expires.
        $bFirst = $this->controller(idempotencyStore: $store, storage: $storage, waitSecs: 5.0);
        $bFirstResponse = $bFirst->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidB,
        ]));
        self::assertSame(503, $bFirstResponse->getStatusCode(), 'B cannot derive a consumed-without-result record — the retryable 503');
        self::assertNull($store->stored($backendId, $uuidB), 'B\'s claim stays pending — nothing was finalized');
        $now += 4;

        // B's retry takes over B's own pending claim: the identity gate
        // compares the record's identity (A's fingerprint) against B's —
        // refused, so the resume never runs; the ordinary verify remains
        // ConsumeIndeterminate -> 503.
        $bRetry = $this->controller(idempotencyStore: $store, storage: $storage, waitSecs: 5.0);
        $bRetryResponse = $bRetry->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidB,
        ]));
        $bRetryBody = json_decode((string) $bRetryResponse->getContent(), true);
        self::assertSame(503, $bRetryResponse->getStatusCode(), 'a different UUID must NEVER resume the winner\'s derivation');
        self::assertSame(['internal-error'], $bRetryBody['error-codes'] ?? null);
        self::assertNull($storage->consumedState($nonce)?->consumedResult, 'B\'s refused takeover must not commit anything — A\'s recovery evidence survives');

        // A's own retry can still resume the original success.
        $now += 4;
        $aRetry = $this->controller(idempotencyStore: $store, storage: $storage, waitSecs: 5.0);
        $aRetryResponse = $aRetry->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidA,
        ]));
        self::assertSame(true, json_decode((string) $aRetryResponse->getContent(), true)['success'] ?? null, 'the winner\'s same-key retry still resumes after B\'s refused attempts');
    }

    /**
     * A no-key first redemption whose consume reply is lost records NO
     * operation identity; a later keyed replay can never resume — the
     * identity gate sees null, the ordinary verify stays
     * ConsumeIndeterminate (503, no finalize).
     */
    public function testLostConsumeReplyNoKeyFirstRedemptionCannotResume(): void
    {
        $storage = new ArrayStorage();
        [$token, $nonce] = $this->issuedToken($storage);
        $now = 1_700_000_000;
        $clock = static function () use (&$now): int {
            return $now;
        };
        $store = new ArraySiteVerifyIdempotencyStore($clock, 3);
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $uuidB = '123e4567-e89b-42d3-a456-4266141740e5';

        $lostReply = new class($storage) implements \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyRecoveryCapableStorageInterface {
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
                // The no-key path uses the plain consume: the transition
                // executes without any identity — and the reply is lost.
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

            public function deleteIfPending(string $nonce): \KiwiCaptcha\DeleteIfPendingResult
            {
                return $this->inner->deleteIfPending($nonce);
            }
        };
        $owner = new SiteVerifyController(new Verifier($lostReply), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $lostReply, null, null, $store, null, 5.0);
        $ownerResponse = $owner->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1',
        ]));
        self::assertSame(503, $ownerResponse->getStatusCode(), 'the no-key lost consume reply maps to the retryable 503');
        $consumed = $storage->consumedState($nonce);
        self::assertNotNull($consumed);
        self::assertNull($consumed->operationIdentity, 'the no-key redemption records NO operation identity');

        // The keyed replay claims a fresh entry, cannot resume (null
        // identity), and the ordinary verify stays ConsumeIndeterminate.
        $keyed = $this->controller(idempotencyStore: $store, storage: $storage, waitSecs: 5.0);
        $keyedResponse = $keyed->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidB,
        ]));
        self::assertSame(503, $keyedResponse->getStatusCode(), 'a keyed replay of a no-key redemption must NEVER resume');
        self::assertNull($store->stored($backendId, $uuidB), 'the keyed replay must not finalize anything');
    }

    /**
     * The resume's commit reply is lost after the commit lands: the
     * read-after-failed-commit resolves the stored result and the retry
     * still receives the original canonical success bytes.
     */
    public function testLostConsumeReplyCommitReplyLostResolvesTheStoredResult(): void
    {
        $storage = new ArrayStorage();
        [$token, $nonce] = $this->issuedToken($storage);
        $now = 1_700_000_000;
        $clock = static function () use (&$now): int {
            return $now;
        };
        $store = new ArraySiteVerifyIdempotencyStore($clock, 3);
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $uuid = '123e4567-e89b-42d3-a456-4266141740e6';

        // Seam A: the consume reply is lost after the transition lands.
        $lostConsume = new class($storage) implements \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyRecoveryCapableStorageInterface {
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
        $owner = new SiteVerifyController(new Verifier($lostConsume), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $lostConsume, null, null, $store, null, 5.0);
        $ownerResponse = $owner->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        self::assertSame(503, $ownerResponse->getStatusCode());
        self::assertNull($storage->consumedState($nonce)?->consumedResult, 'precondition: nothing committed yet');

        // Seam B (used by the retry): the resume's commit reply is lost
        // after the commit lands — the read-after-failed-commit path.
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
                // The commit executes (the result lands) — and the reply
                // is then lost.
                $result = $this->inner->commitResult($nonce, $valid, $binding);

                throw new \RuntimeException('commit reply lost after the commit');
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
        $now += 4;
        $retry = new SiteVerifyController(new Verifier($lostCommit), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $lostCommit, null, null, $store, null, 5.0);
        $retryResponse = $retry->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        $retryBody = json_decode((string) $retryResponse->getContent(), true);
        self::assertSame(true, $retryBody['success'] ?? null, 'the read-after-failed-commit must resolve the winner\'s stored result: '.(string) $retryResponse->getContent());
        self::assertNotNull($storage->consumedState($nonce)?->consumedResult, 'the commit really landed');
        $record = $storage->find($nonce);
        self::assertNotNull($record);
        $expectedCanonical = json_encode([
            'action' => null,
            'cdata' => null,
            'challenge_ts' => gmdate('Y-m-d\TH:i:s\Z', $record->issuedAt),
            'error-codes' => [],
            'hostname' => $record->hostname,
            'success' => true,
        ], JsonResponse::DEFAULT_ENCODING_OPTIONS);
        self::assertSame($expectedCanonical, (string) $retryResponse->getContent(), 'the retry receives the ORIGINAL canonical success bytes');
    }

    /**
     * The lost-reply flow with a changed remoteip: the idempotency claim
     * itself binds the remoteip fingerprint, so the same UUID under a
     * different IP conflicts at the claim layer (400 bad-request) before
     * any recovery — the fingerprint includes the IP.
     */
    public function testLostConsumeReplyChangedRemoteipConflicts(): void
    {
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage);
        $now = 1_700_000_000;
        $clock = static function () use (&$now): int {
            return $now;
        };
        $store = new ArraySiteVerifyIdempotencyStore($clock, 3);
        $uuid = '123e4567-e89b-42d3-a456-4266141740e7';

        $lostReply = new class($storage) implements \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyRecoveryCapableStorageInterface {
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
        $owner = new SiteVerifyController(new Verifier($lostReply), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $lostReply, null, null, $store, null, 5.0);
        $ownerResponse = $owner->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        self::assertSame(503, $ownerResponse->getStatusCode());

        // Same UUID + changed remoteip: conflict at the claim layer — the
        // entry is bound to the original remoteip fingerprint.
        $conflict = $this->controller(idempotencyStore: $store, storage: $storage, waitSecs: 5.0);
        $conflictResponse = $conflict->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '203.0.113.9', 'idempotency_key' => $uuid,
        ]));
        self::assertSame(400, $conflictResponse->getStatusCode(), 'a changed remoteip under the same UUID must CONFLICT');
        self::assertSame(['bad-request'], json_decode((string) $conflictResponse->getContent(), true)['error-codes']);
    }

    /**
     * The lost-reply Argon flow: the resumed derivation is Argon2id, so
     * the Argon admission gate applies to the resume too — a saturated
     * gate answers the retryable 503 internal-error without committing.
     * The next same-key retry (capacity freed) takes over and resumes to
     * the original success.
     */
    public function testLostConsumeReplyArgonResumeAdmissionUnavailableThenSucceeds(): void
    {
        \BelConsulting\KiwiCaptchaBundle\Security\InProcessArgonGate::resetForTests();
        try {
            $storage = new ArrayStorage();
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
            $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
            $nonce = $challenge->nonce;

            $now = 1_700_000_000;
            $clock = static function () use (&$now): int {
                return $now;
            };
            $store = new ArraySiteVerifyIdempotencyStore($clock, 3);
            $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
            $uuid = '123e4567-e89b-42d3-a456-4266141740e8';

            $lostReply = new class($storage) implements \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyRecoveryCapableStorageInterface {
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
            $owner = new SiteVerifyController(new Verifier($lostReply), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $lostReply, null, null, $store, null, 5.0);
            $ownerResponse = $owner->siteverify($this->siteverifyRequest([
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame(503, $ownerResponse->getStatusCode(), 'the lost Argon consume reply maps to the retryable 503');
            self::assertNull($storage->consumedState($nonce)?->consumedResult, 'precondition: nothing committed yet');

            // The retry resumes with a saturated admission gate: the
            // resumed Argon derivation is refused (CapacityExceeded ->
            // 503 internal-error) without committing — the entry stays
            // pending and the record stays resumable.
            $now += 4;
            $gate = new \BelConsulting\KiwiCaptchaBundle\Security\InProcessArgonGate(1);
            $outsideLease = $gate->acquire(); // saturate the single slot from the outside
            self::assertIsString($outsideLease);
            $gated = new SiteVerifyController(new Verifier($storage, $gate), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 5.0);
            $gatedResponse = $gated->siteverify($this->siteverifyRequest([
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame(503, $gatedResponse->getStatusCode(), 'admission exhaustion during the resume must map to the retryable 503');
            self::assertSame(['internal-error'], json_decode((string) $gatedResponse->getContent(), true)['error-codes']);
            self::assertNull($storage->consumedState($nonce)?->consumedResult, 'admission rejection must NOT commit anything');
            self::assertNull($store->stored($backendId, $uuid), 'the admission rejection must NOT finalize — the entry stays pending');

            // Capacity freed: the next same-key retry resumes to the
            // original success.
            $now += 4;
            $gate->release($outsideLease);
            $retry = new SiteVerifyController(new Verifier($storage, $gate), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 5.0);
            $retryResponse = $retry->siteverify($this->siteverifyRequest([
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            $retryBody = json_decode((string) $retryResponse->getContent(), true);
            self::assertSame(true, $retryBody['success'] ?? null, 'with admission capacity available the resume must succeed: '.(string) $retryResponse->getContent());
            self::assertNotNull($storage->consumedState($nonce)?->consumedResult, 'the resumed Argon outcome must be committed');
        } finally {
            \BelConsulting\KiwiCaptchaBundle\Security\InProcessArgonGate::resetForTests();
        }
    }

    // ── The indeterminate-consume retry contract ───────────────────────

    /**
     * Case B of the indeterminate consume: the atomic consume's response
     * is lost before the transition executes (the storage decorator
     * throws without delegating) — the challenge remains perfectly
     * redeemable, but the verifier reports ConsumeIndeterminate. The
     * mapping must answer with the retryable 503 internal-error and must
     * not finalize the claim (the internal-error arm returns before any
     * finalize, so the entry stays pending — the idempotency_key retry
     * contract survives). The same-key retry (a fresh controller with
     * the working storage) claims the pending entry, waits, takes over
     * the expired short lease, finds no consumed record (nothing to
     * reconstruct) and verifies the still-pending challenge to success
     * with the canonical success shape. A never-executed consume must be
     * retryable to success.
     */
    public function testIndeterminateConsumeBeforeTheTransitionIsRetryableToSuccess(): void
    {
        $storage = new ArrayStorage();
        [$token, $nonce] = $this->issuedToken($storage);
        $now = 1_700_000_000;
        $clock = static function () use (&$now): int {
            return $now;
        };
        // A short configured store lease (3s) keeps the lease-expiry step
        // instant; the waiter bound (5s) exceeds it (the construction
        // invariant).
        $store = new ArraySiteVerifyIdempotencyStore($clock, 3);
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $uuid = '123e4567-e89b-42d3-a456-4266141740d1';

        // The "lost response" seam: consumeWithOperationIdentity() throws
        // before delegating — the pending→consumed transition never
        // executes, the challenge stays perfectly redeemable. Everything
        // else delegates.
        $lostBeforeTransition = new class($storage) implements \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyRecoveryCapableStorageInterface {
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
                // The response is lost before the transition executes:
                // throw without delegating — nothing was consumed.
                throw new \RuntimeException('consume response lost before the transition');
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
        $owner = new SiteVerifyController(new Verifier($lostBeforeTransition), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $lostBeforeTransition, null, null, $store, null, 5.0);
        $ownerResponse = $owner->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        self::assertSame(503, $ownerResponse->getStatusCode(), 'an indeterminate consume must map to the retryable 503 internal-error, never a permanent duplicate');
        self::assertSame(['internal-error'], json_decode((string) $ownerResponse->getContent(), true)['error-codes']);
        self::assertNull($store->stored($backendId, $uuid), 'the indeterminate consume must NOT finalize the claim — the entry stays pending for a same-key retry');
        self::assertNull($storage->consumedState($nonce), 'the transition never executed — the challenge stays perfectly redeemable');

        // The same-key retry with the working storage: pending -> wait ->
        // takeover (the 3s lease expired); the recovery gate finds no
        // consumed record (nothing to reconstruct), and the ordinary
        // verify redeems the still-pending challenge to success.
        $now += 4;
        $retry = $this->controller(idempotencyStore: $store, storage: $storage, waitSecs: 5.0);
        $retryResponse = $retry->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        $retryBody = json_decode((string) $retryResponse->getContent(), true);
        self::assertSame(true, $retryBody['success'] ?? null, 'a never-executed consume must be retryable to success: '.(string) $retryResponse->getContent());
        self::assertSame([], $retryBody['error-codes'] ?? null);
        $record = $storage->find($nonce);
        self::assertNotNull($record);
        $expectedCanonical = json_encode([
            'action' => null,
            'cdata' => null,
            'challenge_ts' => gmdate('Y-m-d\TH:i:s\Z', $record->issuedAt),
            'error-codes' => [],
            'hostname' => $record->hostname,
            'success' => true,
        ], JsonResponse::DEFAULT_ENCODING_OPTIONS);
        self::assertSame($expectedCanonical, (string) $retryResponse->getContent(), 'the retry receives the canonical success shape');
    }

    /**
     * Case A of the indeterminate consume: the atomic consume executes
     * (the pending→consumed transition lands and the operation identity
     * is recorded atomically with the state flip). The original
     * attempt's deterministic outcome is committed — but the response to
     * the client is lost. The request answers the retryable 503
     * internal-error and the claim stays pending. The same-key retry (a
     * fresh controller with the working storage) takes over the expired
     * short lease. The recovery gate compares the consumed record's own
     * operation identity against the retry's fingerprint (same key +
     * same token + same remoteip → identical). The reconstruction
     * returns the original canonical result bytes — Case A recovery
     * through the retained consumed state.
     */
    public function testIndeterminateConsumeAfterTheTransitionReconstructsTheOriginalSuccess(): void
    {
        $storage = new ArrayStorage();
        [$token, $nonce] = $this->issuedToken($storage);
        $now = 1_700_000_000;
        $clock = static function () use (&$now): int {
            return $now;
        };
        // A short configured store lease (3s) keeps the lease-expiry step
        // instant; the waiter bound (5s) exceeds it (the construction
        // invariant).
        $store = new ArraySiteVerifyIdempotencyStore($clock, 3);
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $uuid = '123e4567-e89b-42d3-a456-4266141740d2';

        // The "lost response" seam: consumeWithOperationIdentity() delegates
        // — the transition executes and the identity lands atomically with
        // the state flip — and the response is then lost: the decorator's
        // next read (the controller's post-verify canonicalSuccess peek)
        // throws, so the request answers the retryable 503 even though the
        // transition + deterministic commit landed. Everything else
        // delegates.
        $lostAfterTransition = new class($storage) implements \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyRecoveryCapableStorageInterface {
            public function __construct(private readonly \KiwiCaptcha\AtomicStorageInterface $inner)
            {
            }

            private bool $responseLost = false;

            public function store(\KiwiCaptcha\ChallengeRecord $record): void
            {
                $this->inner->store($record);
            }

            public function find(string $nonce): ?\KiwiCaptcha\ChallengeRecord
            {
                if ($this->responseLost) {
                    throw new \RuntimeException('response lost after the consume transition');
                }

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
                // The transition executes (the identity lands atomically
                // with the state flip) — and the response is then lost.
                $this->responseLost = true;

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

            public function deleteIfPending(string $nonce): \KiwiCaptcha\DeleteIfPendingResult
            {
                return $this->inner->deleteIfPending($nonce);
            }
        };
        $owner = new SiteVerifyController(new Verifier($lostAfterTransition), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $lostAfterTransition, null, null, $store, null, 5.0);
        $ownerResponse = $owner->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        self::assertSame(503, $ownerResponse->getStatusCode(), 'a lost response after the consume transition must map to the retryable 503 internal-error');
        self::assertSame(['internal-error'], json_decode((string) $ownerResponse->getContent(), true)['error-codes']);
        self::assertNull($store->stored($backendId, $uuid), 'the lost response must NOT finalize the claim — the entry stays pending');
        $consumed = $storage->consumedState($nonce);
        self::assertNotNull($consumed, 'the transition executed — the token IS consumed');
        self::assertSame(
            $this->fingerprint($backendId, $uuid, $token, '127.0.0.1'),
            $consumed->operationIdentity,
            'the consumed record carries the operation identity of the ACTUAL atomic consume winner',
        );
        self::assertNotNull($consumed->consumedResult, 'the original attempt committed its deterministic outcome');
        self::assertSame(true, $consumed->consumedResult->valid);

        // The same-key retry with the working storage: pending -> wait ->
        // takeover (the 3s lease expired); the recovery gate matches the
        // consumed record's own identity against the retry's fingerprint
        // (same key + same token + same remoteip -> identical), and the
        // reconstruction returns the original canonical result bytes.
        $now += 4;
        $retry = $this->controller(idempotencyStore: $store, storage: $storage, waitSecs: 5.0);
        $retryResponse = $retry->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        $retryBody = json_decode((string) $retryResponse->getContent(), true);
        self::assertSame(true, $retryBody['success'] ?? null, 'the retry must reconstruct the ORIGINAL success via the retained consumed state: '.(string) $retryResponse->getContent());
        self::assertSame([], $retryBody['error-codes'] ?? null);
        $record = $storage->find($nonce);
        self::assertNotNull($record);
        $expectedCanonical = json_encode([
            'action' => null,
            'cdata' => null,
            'challenge_ts' => gmdate('Y-m-d\TH:i:s\Z', $record->issuedAt),
            'error-codes' => [],
            'hostname' => $record->hostname,
            'success' => true,
        ], JsonResponse::DEFAULT_ENCODING_OPTIONS);
        self::assertSame($expectedCanonical, (string) $retryResponse->getContent(), 'the retry receives the ORIGINAL canonical success bytes');
    }

    // ── Security-epoch monitor wiring ──────────────────────────────────

    /**
     * A real SecurityEpochMonitor over the FakePredisClient, sharing the
     * controller's verifier (the monitor rotates the verifier's expected
     * epoch exactly like the container wiring).
     *
     * @return array{0: FakePredisClient, 1: SecurityEpochMonitor}
     */
    private function monitorFixture(Verifier $verifier, int $configuredEpoch, int $centralEpoch, \Closure $clockMs): array
    {
        $redis = new FakePredisClient();
        $redis->hset('{kiwi:test-ns}:security-policy', SecurityEpochMonitor::MIN_POLICY_EPOCH_FIELD, (string) $centralEpoch);

        return [$redis, new SecurityEpochMonitor($verifier, $redis, 'test-ns', $configuredEpoch, 1, $clockMs, null, null, 60)];
    }

    public function testMonitorRefreshMovesTheClaimToTheEffectiveEpochKey(): void
    {
        // A worker that only serves Siteverify traffic never refreshes
        // the monitor through native paths — the controller must refresh
        // it per authenticated request, so a central policy bump moves
        // the backend identity (and with it the idempotency claim) to
        // the effective epoch, never the static configured one.
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120, policyVersion: 3), $storage);
        $challenge = $issuer->issue('login', '203.0.113.7');
        $token = $this->solveSolution($storage->find($challenge->nonce));
        usleep(((int) $challenge->minDurationMs + 10) * 1000);

        $verifier = new Verifier($storage);
        [, $monitor] = $this->monitorFixture($verifier, 2, 3, static fn (): float => 0.0);
        $store = new ArraySiteVerifyIdempotencyStore();
        $controller = new SiteVerifyController($verifier, self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 90.0, 2, null, null, $monitor);
        $uuid = 'f47ac10b-58cc-4372-a567-0e02b2c3d479';

        $response = $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET,
            'response' => $token,
            'remoteip' => '203.0.113.7',
            'idempotency_key' => $uuid,
        ]));
        self::assertSame(200, $response->getStatusCode());
        self::assertTrue(json_decode((string) $response->getContent(), true)['success']);

        $staticEpochBackendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|2');
        $effectiveEpochBackendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|3');
        self::assertNotSame($staticEpochBackendId, $effectiveEpochBackendId, 'precondition: the effective epoch must differ from the static one');
        $stored = $store->stored($effectiveEpochBackendId, $uuid);
        self::assertIsArray($stored, 'the claim must be finalized under the EFFECTIVE-epoch backend identity');
        self::assertTrue($stored['success'] ?? false);
        self::assertNull($store->stored($staticEpochBackendId, $uuid), 'the static-epoch key must never be touched');
    }

    public function testStaleMonitorRefusesVerificationWithRetryableInternalError(): void
    {
        // The max-stale fail-closed check applies to Siteverify too: once
        // the central policy state has not been confirmed within the
        // window, the endpoint answers the retryable provider
        // internal-error — NO claim and NO verification (the token stays
        // pending for a later retry).
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $storage);
        $challenge = $issuer->issue('login', '203.0.113.7');
        $token = $this->solveSolution($storage->find($challenge->nonce));
        usleep(((int) $challenge->minDurationMs + 10) * 1000);
        $nonce = $challenge->nonce;

        $clockMs = 0.0;
        $verifier = new Verifier($storage);
        [$redis, $monitor] = $this->monitorFixture($verifier, 1, 1, static function () use (&$clockMs): float {
            return $clockMs;
        });
        self::assertSame(1, $monitor->refresh(), 'precondition: the monitor observes the central state');
        // Past the max-stale window (60 s) with the central read failing:
        // the cached epoch can no longer be confirmed.
        $redis->failCommand = '*';
        $clockMs = 90_000.0;
        self::assertTrue($monitor->isStale(), 'precondition: the monitor is stale');

        $store = new ArraySiteVerifyIdempotencyStore();
        $controller = new SiteVerifyController($verifier, self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 90.0, 1, null, null, $monitor);
        $uuid = 'f47ac10b-58cc-4372-a567-0e02b2c3d479';
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|1');

        // Ordinary (non-idempotent) path.
        $response = $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET,
            'response' => $token,
            'remoteip' => '203.0.113.7',
        ]));
        self::assertSame(503, $response->getStatusCode(), 'a stale security state must answer the retryable 503 internal-error');
        self::assertSame(['internal-error'], json_decode((string) $response->getContent(), true)['error-codes']);
        self::assertNull($storage->consumedState($nonce), 'no verification may run — the token stays pending');

        // Idempotent path: the claim must never be created.
        $idemResponse = $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET,
            'response' => $token,
            'remoteip' => '203.0.113.7',
            'idempotency_key' => $uuid,
        ]));
        self::assertSame(503, $idemResponse->getStatusCode(), 'the idempotent path must fail closed identically');
        self::assertSame(['internal-error'], json_decode((string) $idemResponse->getContent(), true)['error-codes']);
        self::assertNull($store->stored($backendId, $uuid), 'a stale request must not claim');
        self::assertNull($storage->consumedState($nonce), 'the idempotent stale path must not verify either');

        // The token is still redeemable once the central state is
        // confirmable again — the fail-closed 503s never burned it.
        $redis->failCommand = null;
        $clockMs = 0.0;
        $recovered = $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET,
            'response' => $token,
            'remoteip' => '203.0.113.7',
        ]));
        self::assertSame(200, $recovered->getStatusCode(), 'once the central state is confirmable the token verifies: '.(string) $recovered->getContent());
        self::assertTrue(json_decode((string) $recovered->getContent(), true)['success']);
    }

    public function testStaleMonitorOnTheRetryLeavesThePendingClaimUntouched(): void
    {
        // The owner's request claims and consumes, but the reply is lost
        // (retryable 503 — the claim stays pending). A retry that arrives
        // when the monitor has gone stale must fail closed before any
        // idempotency work: the pending claim is untouched, and a later
        // fresh retry still takes over and resumes the original outcome.
        $storage = new ArrayStorage();
        [$token, $nonce] = $this->issuedToken($storage);
        $secs = 0;
        $storeClock = static function () use (&$secs): int {
            return $secs;
        };
        $monitorClock = static function () use (&$secs): float {
            return $secs * 1000.0;
        };
        // A short configured store lease (3s) keeps the lease-expiry step
        // instant; the waiter bound (5s) exceeds it (the construction
        // invariant).
        $store = new ArraySiteVerifyIdempotencyStore($storeClock, 3);
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|1');
        $uuid = '123e4567-e89b-42d3-a456-4266141740e1';

        // The "lost reply" seam: consumeWithOperationIdentity() delegates
        // — the transition executes and the identity lands atomically with
        // the state flip — and the response is then lost. Everything else
        // delegates.
        $lostReply = new class($storage) implements \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyRecoveryCapableStorageInterface {
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
                // The transition executes (the identity lands atomically
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

            public function deleteIfPending(string $nonce): \KiwiCaptcha\DeleteIfPendingResult
            {
                return $this->inner->deleteIfPending($nonce);
            }
        };
        $ownerVerifier = new Verifier($lostReply);
        [$redis, $monitor] = $this->monitorFixture($ownerVerifier, 1, 1, $monitorClock);
        $owner = new SiteVerifyController($ownerVerifier, self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $lostReply, null, null, $store, null, 5.0, 1, null, null, $monitor);
        $ownerResponse = $owner->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        self::assertSame(503, $ownerResponse->getStatusCode(), 'the lost consume reply must map to the retryable 503 internal-error');
        self::assertNull($store->stored($backendId, $uuid), 'the lost reply must NOT finalize the claim — the entry stays pending');
        $consumed = $storage->consumedState($nonce);
        self::assertNotNull($consumed, 'the transition executed — the token IS consumed');
        self::assertSame(
            $this->fingerprint($backendId, $uuid, $token, '127.0.0.1'),
            $consumed->operationIdentity,
            'the consumed record carries the operation identity of the ACTUAL atomic consume winner',
        );
        self::assertNull($consumed->consumedResult, 'the derivation never ran — consumed_result stays null');

        // The monitor goes stale (past max-stale with the central read
        // failing): the same-key retry fails closed before any idempotency
        // work — the pending claim is untouched and the interrupted
        // derivation is NOT resumed.
        $redis->failCommand = '*';
        $secs = 90;
        $staleRetry = $owner->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        self::assertSame(503, $staleRetry->getStatusCode(), 'a stale monitor must fail the retry closed');
        self::assertSame(['internal-error'], json_decode((string) $staleRetry->getContent(), true)['error-codes']);
        self::assertNull($store->stored($backendId, $uuid), 'the stale retry must not touch the pending claim');
        self::assertNull($storage->consumedState($nonce)?->consumedResult, 'the stale retry must not resume the derivation');

        // The monitor recovers (the central read answers again): the same
        // fresh retry takes over the untouched entry and resumes the
        // original outcome.
        $redis->failCommand = null;
        $secs = 91;
        $recoveredRetry = $owner->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        $recoveredBody = json_decode((string) $recoveredRetry->getContent(), true);
        self::assertSame(true, $recoveredBody['success'] ?? null, 'the fresh retry must take over the untouched entry and resume the original success: '.(string) $recoveredRetry->getContent());
        self::assertSame([], $recoveredBody['error-codes'] ?? null);
        self::assertNotNull($storage->consumedState($nonce)?->consumedResult, 'the resumed derivation must be committed');
    }
    private static function redisTestUrl(): string
    {
        $url = \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl::resolve();
        if ($url === null) {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis suites run in the CI Redis-service job');
        }

        return $url;
    }
}

