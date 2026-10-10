<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Security\Agents\AgentDefinition;
use BelConsulting\KiwiCaptchaBundle\Security\Agents\AgentNonceStore;
use BelConsulting\KiwiCaptchaBundle\Security\Agents\AgentQuota;
use BelConsulting\KiwiCaptchaBundle\Security\Agents\AgentRegistry;
use BelConsulting\KiwiCaptchaBundle\Security\Agents\AgentSignatureVerifier;
use BelConsulting\KiwiCaptchaBundle\Security\Agents\AgentsVerifier;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\AgentSigner;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\LoggerSpy;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter;
use KiwiCaptcha\Risk\Outcomes\OutcomeHandleDimension;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\ArrayStorage;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The adversarial matrix of the verified-agents plane, through the
 * challenge controller. Every attack shape must answer a typed 401,
 * 403 or 429 (never a 500). The happy path issues without widget
 * eligibility at the agent's tier with the attribution handle
 * present, and a quota overrun escalates an agent-dimension mark
 * through the outcomes surface.
 */
final class AgentsAdversarialMatrixTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';
    private const KEY_ID = 'acme-bot-2026q4';
    private const URI = 'http://localhost/kiwi/challenge';

    private FakePredisClient $redis;
    private SpyOutcomeReporter $outcomes;
    private LoggerSpy $logger;
    private AgentSigner $signer;

    protected function setUp(): void
    {
        if (!\function_exists('sodium_crypto_sign_verify_detached')) {
            self::markTestSkipped('ext-sodium is required');
        }
        $this->redis = new FakePredisClient();
        $this->outcomes = new SpyOutcomeReporter();
        $this->logger = new LoggerSpy();
        $this->signer = new AgentSigner(AgentSigner::seed('matrix-acme'));
    }

    /**
     * The happy path: a correctly signed agent request issues a
     * challenge directly — 200 with the machine-client markers (the
     * widget-eligibility flag off, the agent identity, the tier) and
     * the request attribute carrying the agent id. The verified
     * result exposes the agent-dimension attribution handle.
     */
    public function testHappyPathIssuesWithoutWidgetEligibilityWithAttribution(): void
    {
        $controller = $this->controller();
        $request = $this->signedRequest($this->agentRequestServer(), '{"scope":"login"}');
        $response = $controller->challenge($request);

        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('acme-bot', $body['agent']);
        self::assertSame('standard', $body['price_tier']);
        self::assertFalse($body['widget_eligible']);
        self::assertArrayHasKey('nonce', $body);
        self::assertSame('acme-bot', $request->attributes->get('kiwi_agent'));

        // The attribution handle of the verified request: the agent
        // dimension, addressed by the configured agent name (verified
        // through a fresh nonce and ledger, since the request's own
        // nonce was consumed by the issuance above).
        $fresh = $this->verifier(new FakePredisClient());
        $freshRequest = $this->signedRequest($this->agentRequestServer(), '{"scope":"login"}');
        $verified = $fresh->verifySignature($freshRequest, '{"scope":"login"}');
        self::assertTrue($verified->isVerified());
        $handle = $verified->agent()->outcomeHandle();
        self::assertSame(OutcomeHandleDimension::Agent, $handle->dimension);
        self::assertSame('acme-bot', $handle->id);
    }

    /** Replay: the same signed request twice, the nonce burns on the first. */
    public function testReplayOfTheSameSignedRequestIsRefused(): void
    {
        $controller = $this->controller();
        $first = $this->signedRequest($this->agentRequestServer(), '{"scope":"login"}', overrides: ['nonce' => 'fixed-replay-nonce']);
        self::assertSame(Response::HTTP_OK, $controller->challenge($first)->getStatusCode());

        $replay = $this->signedRequest($this->agentRequestServer(), '{"scope":"login"}', overrides: ['nonce' => 'fixed-replay-nonce']);
        $response = $controller->challenge($replay);

        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        self::assertSame('AGENT_SIGNATURE_REPLAYED', json_decode((string) $response->getContent(), true)['error']['code']);
        self::assertSame([], $this->outcomes->reports);
    }

    /** Skew: a created parameter outside the ±300 s window fails. */
    public function testCreatedOutsideTheSkewWindowIsRefused(): void
    {
        foreach ([-301, 301] as $offset) {
            $controller = $this->controller();
            $request = $this->signedRequest($this->agentRequestServer(), '{"scope":"login"}', overrides: ['createdOffset' => $offset]);
            $response = $controller->challenge($request);

            self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode(), sprintf('offset %d', $offset));
            self::assertSame('AGENT_SIGNATURE_SKEW', json_decode((string) $response->getContent(), true)['error']['code']);
        }
        // Exactly at the window edge (300) still verifies.
        $edge = $this->controller()->challenge($this->signedRequest($this->agentRequestServer(), '{"scope":"login"}', overrides: ['createdOffset' => -300]));
        self::assertSame(Response::HTTP_OK, $edge->getStatusCode());
    }

    /** Header-strip: the covered content-digest header removed from the wire. */
    public function testStrippedContentDigestWithBodyPresentIsRefused(): void
    {
        $controller = $this->controller();
        $server = $this->agentRequestServer();
        $body = '{"scope":"login"}';
        $request = $this->signedRequest($server, $body);
        $request->headers->remove('Content-Digest');
        $response = $controller->challenge($request);

        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        self::assertSame('AGENT_SIGNATURE_INVALID', json_decode((string) $response->getContent(), true)['error']['code']);
    }

    /** Alg confusion: any alg other than ed25519 fails closed. */
    public function testAlgConfusionIsRefused(): void
    {
        foreach (['ed25519-phoenix', 'hmac-sha256', 'ED25519', 'rsa-pss'] as $alg) {
            $controller = $this->controller();
            $request = $this->signedRequest($this->agentRequestServer(), '{"scope":"login"}', overrides: ['algOverride' => $alg]);
            $response = $controller->challenge($request);

            self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode(), sprintf('alg %s', $alg));
            self::assertSame('AGENT_ALG_REJECTED', json_decode((string) $response->getContent(), true)['error']['code']);
        }
    }

    /** Tampered body: signed digest of body A, wire carries body B. */
    public function testTamperedBodyFailsTheDigest(): void
    {
        $controller = $this->controller();
        $tampered = Request::create(self::URI, 'POST', [], [], [], $this->withSignedHeaders($this->agentRequestServer(), '{"scope":"login"}'), '{"scope":"admin"}');
        $response = $controller->challenge($tampered);

        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        self::assertSame('AGENT_SIGNATURE_INVALID', json_decode((string) $response->getContent(), true)['error']['code']);
    }

    /** Tampered @target-uri: signed for one target, sent to another. */
    public function testTamperedTargetUriIsRefused(): void
    {
        $controller = $this->controller();
        $tampered = $this->signedRequestForUri('http://localhost/kiwi/challenge2', '{"scope":"login"}');
        $response = $controller->challenge($tampered);

        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        self::assertSame('AGENT_SIGNATURE_INVALID', json_decode((string) $response->getContent(), true)['error']['code']);
    }

    /** Expired: an expires parameter in the past fails. */
    public function testExpiredSignatureIsRefused(): void
    {
        $controller = $this->controller();
        $request = $this->signedRequest($this->agentRequestServer(), '{"scope":"login"}', overrides: ['expiresOffset' => -400]);
        $response = $controller->challenge($request);

        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        self::assertSame('AGENT_SIGNATURE_EXPIRED', json_decode((string) $response->getContent(), true)['error']['code']);
    }

    /** Unknown key id: a stranger kid never resolves to an agent. */
    public function testUnknownKeyIdIsRefused(): void
    {
        $controller = $this->controller();
        $request = $this->signedRequest($this->agentRequestServer(), '{"scope":"login"}', overrides: ['kidOverride' => 'stranger-kid']);
        $response = $controller->challenge($request);

        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        self::assertSame('AGENT_UNKNOWN_KEY', json_decode((string) $response->getContent(), true)['error']['code']);
    }

    /**
     * Revoked key: the key material that verified inside the
     * rotation window fails once the key is gone from the
     * configuration. This is the container-rebuild revocation
     * latency at unit scale: the kid still resolves, so the refusal
     * is the typed signature-invalid, never a verification.
     */
    public function testRevokedKeyFailsAfterTheRegistryLosesIt(): void
    {
        $revoked = new AgentSigner(AgentSigner::seed('matrix-revoked'));
        $controller = $this->controller(publicKeys: [
            $this->signer->publicKeyBase64(),
            $revoked->publicKeyBase64(),
        ]);
        $server = $this->withSignedHeaders($this->agentRequestServer(), '{"scope":"login"}', signer: $revoked);
        $request = Request::create(self::URI, 'POST', [], [], [], $server, '{"scope":"login"}');
        self::assertSame(Response::HTTP_OK, $controller->challenge($request)->getStatusCode());

        // One config reload: the registry rebuilt without the revoked
        // key (the primary key stays).
        $rebuilt = $this->controller(new FakePredisClient(), [$this->signer->publicKeyBase64()]);
        $again = Request::create(self::URI, 'POST', [], [], [], $server, '{"scope":"login"}');
        $response = $rebuilt->challenge($again);
        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        self::assertSame('AGENT_SIGNATURE_INVALID', json_decode((string) $response->getContent(), true)['error']['code']);
    }

    /**
     * Quota overrun: the third request of a per-minute cap of two
     * answers 429 with Retry-After, the typed code, an escalation
     * log line and an agent-dimension abuse mark through the
     * outcomes surface.
     */
    public function testQuotaOverrunAnswers429WithRetryAfterAndEscalatesAMark(): void
    {
        $controller = $this->controller(perMinute: 2);
        for ($i = 0; $i < 2; ++$i) {
            self::assertSame(Response::HTTP_OK, $controller->challenge($this->signedRequest($this->agentRequestServer(), '{"scope":"login"}'))->getStatusCode());
        }
        $refused = $controller->challenge($this->signedRequest($this->agentRequestServer(), '{"scope":"login"}'));

        self::assertSame(Response::HTTP_TOO_MANY_REQUESTS, $refused->getStatusCode());
        $body = json_decode((string) $refused->getContent(), true);
        self::assertSame('AGENT_QUOTA_EXCEEDED', $body['error']['code']);
        self::assertMatchesRegularExpression('/per-minute/', $body['error']['message']);
        self::assertSame('60', $refused->headers->get('Retry-After'));

        // The escalation: one agent-dimension abuse mark.
        self::assertCount(1, $this->outcomes->reports);
        $report = $this->outcomes->reports[0];
        self::assertSame('spamReported', $report['outcome']->value);
        self::assertSame(OutcomeHandleDimension::Agent, $report['handle']->dimension);
        self::assertSame('acme-bot', $report['handle']->id);
        self::assertNotEmpty(array_filter($this->logger->warnings, static fn (string $m): bool => str_contains($m, 'exceeded its per-')));
    }

    /** Scope refusal: an allowed-scope violation answers 403 with the typed code. */
    public function testScopeOutsideTheAllowedSetIsRefusedWith403(): void
    {
        $controller = $this->controller();
        $request = $this->signedRequest($this->agentRequestServer(), '{"scope":"financial_action"}');
        $response = $controller->challenge($request);

        self::assertSame(Response::HTTP_FORBIDDEN, $response->getStatusCode());
        self::assertSame('AGENT_SCOPE_NOT_ALLOWED', json_decode((string) $response->getContent(), true)['error']['code']);
        self::assertSame([], $this->outcomes->reports);
    }

    /** Nonce ledger unavailable: fail closed 401, never a verification. */
    public function testNonceLedgerUnavailableFailsClosedWith401(): void
    {
        $this->redis->failCommand = 'set';
        $controller = $this->controller();
        $request = $this->signedRequest($this->agentRequestServer(), '{"scope":"login"}');
        $response = $controller->challenge($request);

        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        self::assertSame('AGENT_NONCE_UNAVAILABLE', json_decode((string) $response->getContent(), true)['error']['code']);
    }

    /**
     * A covered set missing content-digest (with a body), or naming
     * an outside component, is refused before any crypto runs.
     */
    public function testCoverageViolationsAreRefused(): void
    {
        foreach ([
            ['@method', '@target-uri'],
            ['@method', '@target-uri', 'content-digest', 'x-custom'],
        ] as $covered) {
            $controller = $this->controller();
            $request = $this->signedRequest($this->agentRequestServer(), '{"scope":"login"}', overrides: ['coveredOverride' => $covered]);
            $response = $controller->challenge($request);

            self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
            self::assertSame('AGENT_COVERAGE_INVALID', json_decode((string) $response->getContent(), true)['error']['code']);
        }
    }

    /**
     * The browser baseline: with agents configured, a request
     * without signature headers rides the ordinary widget flow
     * (200, no agent markers); a Signature-Input header with a
     * broken body is a typed 401, never a widget issuance.
     */
    public function testUnsignedRequestRidesTheWidgetFlowAndGarbageSignatureIsTyped401(): void
    {
        $controller = $this->controller();
        $browser = Request::create(self::URI, 'POST', [], [], [], [
            'CONTENT_TYPE' => 'application/json',
            'CONTENT_LENGTH' => '17',
            'REMOTE_ADDR' => '127.0.0.1',
        ], '{"scope":"login"}');
        $widgetResponse = $controller->challenge($browser);
        self::assertSame(Response::HTTP_OK, $widgetResponse->getStatusCode());
        $widgetBody = json_decode((string) $widgetResponse->getContent(), true);
        self::assertArrayNotHasKey('agent', $widgetBody);
        self::assertArrayNotHasKey('widget_eligible', $widgetBody);

        $garbage = Request::create(self::URI, 'POST', [], [], [], [
            'CONTENT_TYPE' => 'application/json',
            'CONTENT_LENGTH' => '17',
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_SIGNATURE_INPUT' => 'not a structured field',
        ], '{"scope":"login"}');
        $refused = $controller->challenge($garbage);
        self::assertSame(Response::HTTP_UNAUTHORIZED, $refused->getStatusCode());
        self::assertSame('AGENT_SIGNATURE_MALFORMED', json_decode((string) $refused->getContent(), true)['error']['code']);
    }

    /**
     * The tier prices the issuance: a critical-tier agent receives
     * the Argon2id fixed-envelope rung, a low-tier agent the SHA-256
     * 16-bit rung (the interim tier pricing of the bundle).
     */
    public function testTierPricesTheIssuance(): void
    {
        $critical = $this->controller(priceTier: 'critical');
        $response = $critical->challenge($this->signedRequest($this->agentRequestServer(), '{"scope":"login"}'));
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('argon2id', $body['algorithm']);
        self::assertSame(16384, $body['mKib']);
        self::assertSame('critical', $body['price_tier']);

        $low = $this->controller(priceTier: 'low');
        $lowBody = json_decode((string) $low->challenge($this->signedRequest($this->agentRequestServer(), '{"scope":"login"}'))->getContent(), true);
        self::assertSame('sha256', $lowBody['algorithm']);
        self::assertSame(16, $lowBody['targetBits']);
        self::assertSame('low', $lowBody['price_tier']);
    }

    /**
     * @return array<string,string> the $server bag of one agent request
     */
    private function agentRequestServer(): array
    {
        return [
            'CONTENT_TYPE' => 'application/json',
            'REMOTE_ADDR' => '203.0.113.10',
        ];
    }

    /**
     * @param array<string,string> $server
     * @param array<string,string> $overrides
     */
    private function withSignedHeaders(array $server, string $body, array $overrides = [], ?AgentSigner $signer = null): array
    {
        $signer ??= $this->signer;
        $created = \time() + (int) ($overrides['createdOffset'] ?? 0);
        $expires = \time() + 300 + (int) ($overrides['expiresOffset'] ?? 0);
        $nonce = $overrides['nonce'] ?? bin2hex(random_bytes(8));
        $keyId = $overrides['kidOverride'] ?? self::KEY_ID;
        $alg = $overrides['algOverride'] ?? 'ed25519';
        $tag = $overrides['tagOverride'] ?? 'kiwi-agents-v1';
        $covered = $overrides['coveredOverride'] ?? ['@method', '@target-uri', 'content-digest', 'content-length'];
        $digest = $overrides['digestOverride'] ?? AgentSigner::contentDigest($body);
        $parameters = ['created' => $created, 'expires' => $expires, 'nonce' => $nonce, 'keyid' => $keyId, 'alg' => $alg, 'tag' => $tag];
        $base = AgentSigner::signatureBase($covered, $parameters, [
            '@method' => 'POST',
            '@target-uri' => self::URI,
            'content-digest' => $digest,
            'content-length' => (string) \strlen($body),
            'x-custom' => 'x',
        ]);
        $headers = $signer->signedHeaders($covered, $parameters, $base);

        return $server + [
            'CONTENT_LENGTH' => (string) \strlen($body),
            'HTTP_CONTENT_DIGEST' => $digest,
            'HTTP_SIGNATURE_INPUT' => $headers['Signature-Input'],
            'HTTP_SIGNATURE' => $headers['Signature'],
        ];
    }

    /**
     * @param array<string,string> $server
     * @param array<string,string> $overrides
     */
    private function signedRequest(array $server, string $body, array $overrides = []): Request
    {
        $server = $this->withSignedHeaders($server, $body, $overrides);

        return Request::create(self::URI, 'POST', [], [], [], $server, $body);
    }

    private function signedRequestForUri(string $uri, string $body): Request
    {
        // Sign for the configured challenge target, then send to a
        // different one: the @target-uri of the base no longer
        // matches the wire request.
        $server = $this->withSignedHeaders($this->agentRequestServer(), $body);

        return Request::create($uri, 'POST', [], [], [], $server, $body);
    }

    private function verifier(?FakePredisClient $redis = null, ?array $publicKeys = null, string $priceTier = 'standard', int $perMinute = 1000): AgentsVerifier
    {
        $redis ??= $this->redis;
        $registry = AgentRegistry::fromConfig(['acme-bot' => [
            'key_id' => self::KEY_ID,
            'public_keys' => $publicKeys ?? [$this->signer->publicKeyBase64()],
            'allowed_scopes' => ['login'],
            'per_minute' => $perMinute,
            'per_day' => 100000,
            'price_tier' => $priceTier,
            'contact' => 'ops@acme.example',
        ]]);

        return new AgentsVerifier(
            new AgentSignatureVerifier($registry, new AgentNonceStore($redis, '{kiwi:test}:'), 300, null, 'http://localhost'),
            new AgentQuota($redis, '{kiwi:test}:'),
            $this->outcomes,
            $this->logger,
        );
    }

    private function controller(?FakePredisClient $redis = null, ?array $publicKeys = null, string $priceTier = 'standard', int $perMinute = 1000): ChallengeController
    {
        $issuer = new Issuer(new Config(
            secretKey: self::SECRET,
            algorithm: PoWAlgorithm::Sha256,
            targetBits: 8,
            ttlSecs: 120,
        ), new ArrayStorage());

        return new ChallengeController($issuer, agentsVerifier: $this->verifier($redis, $publicKeys, $priceTier, $perMinute));
    }
}
