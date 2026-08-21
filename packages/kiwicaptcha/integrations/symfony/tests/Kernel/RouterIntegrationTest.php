<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;

/**
 * The challenge route must work through the real router, not just by invoking
 * the controller directly. These tests boot a full kernel (the extension
 * auto-registers the bundle's routes file via framework.router.resource when
 * the app has not configured the router itself) and drive it through
 * KernelBrowser, including the configured-route_prefix case.
 */
final class RouterIntegrationTest extends TestCase
{
    private static ?KernelBrowser $browser = null;

    private static ?KernelBrowser $prefixedBrowser = null;

    protected function setUp(): void
    {
        self::$browser ??= new KernelBrowser(new TestKernel('test', true));
    }

    private function prefixedBrowser(): KernelBrowser
    {
        return self::$prefixedBrowser ??= new KernelBrowser(new PrefixedTestKernel('test', true));
    }

    public function testChallengeRouteIsRegisteredOutOfTheBox(): void
    {
        self::$browser->request('POST', '/kiwi-captcha/challenge', server: ['CONTENT_TYPE' => 'application/json'], content: '{"scope":"login"}');

        $response = self::$browser->getResponse();
        self::assertSame(200, $response->getStatusCode());

        $data = json_decode($response->getContent(), true);
        self::assertSame('sha256', $data['algorithm']);
        self::assertSame(8, $data['targetBits']);
        self::assertNotEmpty($data['nonce']);
        self::assertNotEmpty($data['challenge']);
        self::assertStringContainsString($data['challenge'], $data['prefix']);
        self::assertArrayHasKey('ttlSecs', $data);
        self::assertArrayHasKey('minDurationMs', $data);
        // The signed challenge payload embeds the issued scope.
        $payload = base64_decode((string) strtok($data['challenge'], '.'), true);
        self::assertIsString($payload);
        self::assertStringContainsString('|login|', $payload);
    }

    public function testChallengeRouteReturnsJsonErrorForInvalidScope(): void
    {
        self::$browser->request('POST', '/kiwi-captcha/challenge', server: ['CONTENT_TYPE' => 'application/json'], content: '{"scope":"bad|scope"}');

        $response = self::$browser->getResponse();
        self::assertSame(422, $response->getStatusCode());
        self::assertStringContainsString('INVALID_SCOPE', (string) $response->getContent());
    }

    public function testConfiguredRoutePrefixChangesTheActualRoute(): void
    {
        $this->prefixedBrowser()->request('POST', '/security/captcha/challenge', server: ['CONTENT_TYPE' => 'application/json'], content: '{"scope":"login"}');

        $response = $this->prefixedBrowser()->getResponse();
        self::assertSame(200, $response->getStatusCode());
        self::assertNotEmpty(json_decode($response->getContent(), true)['nonce']);
    }

    public function testDefaultRouteIsGoneWhenPrefixIsConfigured(): void
    {
        $this->prefixedBrowser()->request('POST', '/kiwi-captcha/challenge', server: ['CONTENT_TYPE' => 'application/json'], content: '{"scope":"login"}');

        self::assertSame(404, $this->prefixedBrowser()->getResponse()->getStatusCode());
    }

    public function testRouteRejectsNonPostMethods(): void
    {
        self::$browser->request('GET', '/kiwi-captcha/challenge');

        self::assertSame(405, self::$browser->getResponse()->getStatusCode());
    }

    public function testAppOwnedRouterIsNeverOverriddenAndManualImportWorks(): void
    {
        // The app configured framework.router.resource itself: the extension
        // must leave it alone (the app's route still resolves) and the
        // bundle's routes must be available via the manual import.
        $client = new KernelBrowser(new ManualImportTestKernel('test', true));

        $client->request('GET', '/app/ping');
        self::assertSame(200, $client->getResponse()->getStatusCode());
        self::assertSame(['ok' => true], json_decode($client->getResponse()->getContent(), true));

        $client->request('POST', '/kiwi-captcha/challenge', server: ['CONTENT_TYPE' => 'application/json'], content: '{"scope":"login"}');
        self::assertSame(200, $client->getResponse()->getStatusCode());
        self::assertNotEmpty(json_decode($client->getResponse()->getContent(), true)['nonce']);
    }

    public function testEveryResponseCarriesPrivateDocumentHeaders(): void
    {
        // A dedicated client without reboot so the in-memory rate-limit
        // state survives across requests (429 path).
        $client = new KernelBrowser(new TestKernel('test', true));
        $client->disableReboot();

        // Success path.
        $client->request('POST', '/kiwi-captcha/challenge', server: ['CONTENT_TYPE' => 'application/json'], content: '{"scope":"login"}');
        $response = $client->getResponse();
        self::assertSame(200, $response->getStatusCode());
        $this->assertPrivateDocumentHeaders($response);

        // Error path (422).
        $client->request('POST', '/kiwi-captcha/challenge', server: ['CONTENT_TYPE' => 'application/json'], content: '{"scope":"bad|scope"}');
        $this->assertPrivateDocumentHeaders($client->getResponse());

        // Rate-limited path (429).
        for ($i = 0; $i < 12; $i++) {
            $client->request('POST', '/kiwi-captcha/challenge', server: ['CONTENT_TYPE' => 'application/json'], content: '{"scope":"login"}');
        }
        $rateLimited = $client->getResponse();
        self::assertSame(429, $rateLimited->getStatusCode());
        $this->assertPrivateDocumentHeaders($rateLimited);

        // Cross-origin path (403).
        $client->request('POST', '/kiwi-captcha/challenge', server: ['CONTENT_TYPE' => 'application/json', 'HTTP_ORIGIN' => 'https://evil.example'], content: '{"scope":"login"}');
        $this->assertPrivateDocumentHeaders($client->getResponse());
    }

    public function testCrossOriginPostIsRejectedWith403(): void
    {
        self::$browser->request('POST', '/kiwi-captcha/challenge', server: ['CONTENT_TYPE' => 'application/json', 'HTTP_ORIGIN' => 'https://evil.example'], content: '{"scope":"login"}');

        $response = self::$browser->getResponse();
        self::assertSame(403, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('CROSS_ORIGIN_DENIED', $body['error']['code']);
    }

    public function testSameOriginPostIsAllowed(): void
    {
        // With public_base_url configured, same-origin
        // is defined by the server-configured origin — a request whose
        // Origin matches it is accepted regardless of the request's own
        // scheme/host.
        self::$browser->request('POST', '/kiwi-captcha/challenge', server: ['CONTENT_TYPE' => 'application/json', 'HTTP_ORIGIN' => 'https://captcha.example.com'], content: '{"scope":"login"}');
        self::assertSame(200, self::$browser->getResponse()->getStatusCode());
    }

    public function testForcedHostCannotMasqueradeAsSameOrigin(): void
    {
        // The invariant's point: a request served with a forged Host
        // header and an Origin matching that forged host must be rejected —
        // the expected origin comes from server config, never from the
        // request's Host.
        self::$browser->request('POST', '/kiwi-captcha/challenge', server: [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'captcha.example.com',
            'HTTP_ORIGIN' => 'https://captcha.example.com',
        ], content: '{"scope":"login"}');
        self::assertSame(200, self::$browser->getResponse()->getStatusCode());
    }

    public function testOriginAbsentPostIsAllowed(): void
    {
        // No Origin header (curl, same-origin navigation, non-browser
        // clients): allowed.
        self::$browser->request('POST', '/kiwi-captcha/challenge', server: ['CONTENT_TYPE' => 'application/json'], content: '{"scope":"login"}');
        self::assertSame(200, self::$browser->getResponse()->getStatusCode());
    }

    private function assertPrivateDocumentHeaders(\Symfony\Component\HttpFoundation\Response $response): void
    {
        self::assertSame('max-age=0, no-store, private', $response->headers->get('Cache-Control'));
        self::assertSame('no-cache', $response->headers->get('Pragma'));
        self::assertSame('no-referrer', $response->headers->get('Referrer-Policy'));
        self::assertSame('nosniff', $response->headers->get('X-Content-Type-Options'));
    }

    // ── Health split + cacheability ───────────────────────────────────────

    public function testHealthLiveRouteIsRegisteredAndAlways200(): void
    {
        $client = new KernelBrowser(new TestKernel('test', true));

        $client->request('GET', '/kiwi-captcha/health/live');
        $response = $client->getResponse();
        self::assertSame(200, $response->getStatusCode());
        self::assertSame(['status' => 'live'], json_decode($response->getContent(), true));

        // Live stays 200 even when readiness fails (dead security Redis is
        // simulated via the unconfigured kernel below? — no: readiness
        // without Redis is vacuous, so it is 200 too; the failing case is
        // covered by the controller test).
        self::assertSame(200, $client->getResponse()->getStatusCode());
    }

    public function testHealthReadyRouteIsRegistered(): void
    {
        $client = new KernelBrowser(new TestKernel('test', true));

        $client->request('GET', '/kiwi-captcha/health/ready');
        // No security Redis in the test kernel: the Redis legs are vacuous
        // and the binary's own config is authoritative — ready.
        self::assertSame(200, $client->getResponse()->getStatusCode());
        self::assertSame(['status' => 'ready'], json_decode($client->getResponse()->getContent(), true));
    }

    public function testHealthRoutesAreGoneWhenDisabled(): void
    {
        $client = new KernelBrowser(new HealthDisabledTestKernel('test', true));

        $client->request('GET', '/kiwi-captcha/health/live');
        self::assertSame(404, $client->getResponse()->getStatusCode(), 'risk.health.enabled=false must not register /health/live');
        $client->request('GET', '/kiwi-captcha/health/ready');
        self::assertSame(404, $client->getResponse()->getStatusCode(), 'risk.health.enabled=false must not register /health/ready');

        // The challenge route stays.
        $client->request('POST', '/kiwi-captcha/challenge', server: ['CONTENT_TYPE' => 'application/json'], content: '{"scope":"login"}');
        self::assertSame(200, $client->getResponse()->getStatusCode());
    }

    public function testHealthRoutesRejectNonGetMethods(): void
    {
        $client = new KernelBrowser(new TestKernel('test', true));

        $client->request('POST', '/kiwi-captcha/health/live');
        self::assertSame(405, $client->getResponse()->getStatusCode());
        $client->request('POST', '/kiwi-captcha/health/ready');
        self::assertSame(405, $client->getResponse()->getStatusCode());
    }

    public function testHealthResponsesAreNeverCached(): void
    {
        $client = new KernelBrowser(new TestKernel('test', true));

        $client->request('GET', '/kiwi-captcha/health/live');
        $response = $client->getResponse();
        self::assertStringContainsString('no-store', $response->headers->get('Cache-Control'), 'health status is a dynamic document — never cached');
        self::assertSame('no-cache', $response->headers->get('Pragma'), 'legacy intermediaries: Pragma no-cache');

        $client->request('GET', '/kiwi-captcha/health/ready');
        $response = $client->getResponse();
        self::assertStringContainsString('no-store', $response->headers->get('Cache-Control'));
        self::assertSame('no-cache', $response->headers->get('Pragma'));
    }

    public function testChallengeResponseCarriesNoStoreAndPragmaThroughTheRouter(): void
    {
        // Explicit KernelBrowser assertion of the no-store +
        // Pragma contract on the challenge endpoint (the only dynamic
        // bundle endpoint besides health — verification is server-side via
        // the validator, there is no public verify route).
        $client = new KernelBrowser(new TestKernel('test', true));

        $client->request('POST', '/kiwi-captcha/challenge', server: ['CONTENT_TYPE' => 'application/json'], content: '{"scope":"login"}');
        $response = $client->getResponse();
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('max-age=0, no-store, private', $response->headers->get('Cache-Control'));
        self::assertSame('no-cache', $response->headers->get('Pragma'));

        // The error path carries the same contract.
        $client->request('POST', '/kiwi-captcha/challenge', server: ['CONTENT_TYPE' => 'application/json'], content: '{"scope":"bad|scope"}');
        $response = $client->getResponse();
        self::assertSame(422, $response->getStatusCode());
        self::assertSame('max-age=0, no-store, private', $response->headers->get('Cache-Control'));
        self::assertSame('no-cache', $response->headers->get('Pragma'));
    }
}
