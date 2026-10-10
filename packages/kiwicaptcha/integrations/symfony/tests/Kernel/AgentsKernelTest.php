<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Security\Agents\AgentsVerifier;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\AgentSigner;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The container wiring of the verified-agents plane and the
 * one-rebuild revocation. A real compiled kernel serves a signed
 * agent request through the wired controller (the machine-client
 * markers in the response prove the injected gate ran). The
 * outcomes reporter is armed by the agents configuration alone.
 * Rebuilding the kernel without the agent fails the same
 * credentials within exactly that one config reload.
 */
final class AgentsKernelTest extends TestCase
{
    private const URI = 'http://localhost/kiwi/challenge';

    /** @var array<string, AgentsTestKernel> the shared kernel per key-set variant (one compile each) */
    private static array $kernels = [];

    private function boot(string $keySet): ContainerInterface
    {
        self::$kernels[$keySet] ??= new AgentsTestKernel('test', false, $keySet);
        self::$kernels[$keySet]->boot();

        return self::$kernels[$keySet]->getContainer()->get('test.service_container');
    }

    public function testWiringServesASignedAgentRequest(): void
    {
        $container = $this->boot(AgentsTestKernel::KEY_BOTH);

        // The outcomes reporter is armed by the agents configuration
        // alone (no bridge, no step-up): the quota escalation has its
        // marks surface.
        self::assertTrue($container->has(AgentsVerifier::class));
        self::assertTrue($container->has(\BelConsulting\KiwiCaptchaBundle\Risk\OutcomeReporterInterface::class));

        $controller = $container->get(ChallengeController::class);
        self::assertInstanceOf(ChallengeController::class, $controller);

        $response = $controller->challenge(self::signedRequest('{"scope":"login"}'));
        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame(AgentsTestKernel::AGENT_NAME, $body['agent']);
        self::assertSame('standard', $body['price_tier']);
        self::assertFalse($body['widget_eligible']);
    }

    /**
     * Revocation within one config reload. The retired key's
     * credentials verify on the kernel whose rotation window still
     * lists the key. They fail on the rebuilt kernel whose
     * configuration dropped it — the typed 401, never a
     * verification, within exactly one container rebuild.
     */
    public function testRevokedKeyFailsWithinOneConfigReload(): void
    {
        $controllerA = $this->boot(AgentsTestKernel::KEY_BOTH)->get(ChallengeController::class);
        $issued = $controllerA->challenge(self::signedRequest('{"scope":"login"}', signerSeed: 'kernel-retired'));
        self::assertSame(Response::HTTP_OK, $issued->getStatusCode());

        // One container rebuild with the retired key removed from the
        // rotation window (the current key stays).
        $controllerB = $this->boot(AgentsTestKernel::KEY_CURRENT)->get(ChallengeController::class);
        self::assertInstanceOf(ChallengeController::class, $controllerB);

        $refused = $controllerB->challenge(self::signedRequest('{"scope":"login"}', signerSeed: 'kernel-retired'));
        self::assertSame(Response::HTTP_UNAUTHORIZED, $refused->getStatusCode());
        $body = json_decode((string) $refused->getContent(), true);
        self::assertSame('AGENT_SIGNATURE_INVALID', $body['error']['code']);

        // A plain widget request still issues on the rebuilt kernel:
        // the key removal changes nothing for the browser flow.
        $widget = $controllerB->challenge(Request::create(self::URI, 'POST', [], [], [], [
            'CONTENT_TYPE' => 'application/json',
            'CONTENT_LENGTH' => '17',
            'REMOTE_ADDR' => '127.0.0.1',
        ], '{"scope":"login"}'));
        self::assertSame(Response::HTTP_OK, $widget->getStatusCode());
        self::assertArrayNotHasKey('agent', json_decode((string) $widget->getContent(), true));
    }

    /**
     * An unconfigured agents plane ignores the signature headers: a
     * deployment with no risk.agents entries keeps the widget flow
     * byte-identical for a request carrying stray signature headers.
     */
    public function testUnconfiguredPlaneLeavesTheWidgetFlowUnchanged(): void
    {
        $container = $this->boot(AgentsTestKernel::KEY_NONE);
        self::assertFalse($container->has(AgentsVerifier::class));
        $controller = $container->get(ChallengeController::class);

        $stray = $controller->challenge(self::signedRequest('{"scope":"login"}'));
        self::assertSame(Response::HTTP_OK, $stray->getStatusCode());
        self::assertArrayNotHasKey('agent', json_decode((string) $stray->getContent(), true));
    }

    /**
     * The replay ledger is shared across the container: the same
     * nonce never verifies twice on one deployment (the fake Redis
     * of the kernel is the single shared backend of both calls).
     */
    public function testNonceLedgerIsSharedAcrossRequestsOfTheKernel(): void
    {
        $controller = $this->boot(AgentsTestKernel::KEY_BOTH)->get(ChallengeController::class);

        $first = $controller->challenge(self::signedRequest('{"scope":"login"}', 'shared-kernel-nonce'));
        self::assertSame(Response::HTTP_OK, $first->getStatusCode());
        $replay = $controller->challenge(self::signedRequest('{"scope":"login"}', 'shared-kernel-nonce'));
        self::assertSame(Response::HTTP_UNAUTHORIZED, $replay->getStatusCode());
        self::assertSame('AGENT_SIGNATURE_REPLAYED', json_decode((string) $replay->getContent(), true)['error']['code']);
    }

    private static function signedRequest(string $body, ?string $nonce = null, string $signerSeed = 'kernel-agent'): Request
    {
        $signer = new AgentSigner(AgentSigner::seed($signerSeed));
        $created = \time();
        $nonce ??= bin2hex(random_bytes(8));
        $digest = AgentSigner::contentDigest($body);
        $covered = ['@method', '@target-uri', 'content-digest', 'content-length'];
        $parameters = [
            'created' => $created,
            'expires' => $created + 300,
            'nonce' => $nonce,
            'keyid' => AgentsTestKernel::AGENT_KEY_ID,
            'alg' => 'ed25519',
            'tag' => 'kiwi-agents-v1',
        ];
        // @target-uri derives from the configured public_base_url
        // (https://captcha.example.com), never the request Host: the
        // request below is created against localhost on purpose, and
        // only a signature over the configured origin verifies.
        $base = AgentSigner::signatureBase($covered, $parameters, [
            '@method' => 'POST',
            '@target-uri' => 'https://captcha.example.com/kiwi/challenge',
            'content-digest' => $digest,
            'content-length' => (string) \strlen($body),
        ]);
        $headers = $signer->signedHeaders($covered, $parameters, $base);

        return Request::create(self::URI, 'POST', [], [], [], [
            'CONTENT_TYPE' => 'application/json',
            'CONTENT_LENGTH' => (string) \strlen($body),
            'REMOTE_ADDR' => '203.0.113.10',
            'HTTP_CONTENT_DIGEST' => $digest,
            'HTTP_SIGNATURE_INPUT' => $headers['Signature-Input'],
            'HTTP_SIGNATURE' => $headers['Signature'],
        ], $body);
    }
}
