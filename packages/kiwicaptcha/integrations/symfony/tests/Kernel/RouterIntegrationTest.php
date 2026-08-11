<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;

/**
 * The challenge route must work through the REAL router, not just by invoking
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
        self::$browser->request('POST', '/kiwi-captcha/challenge', content: '{"scope":"login"}');

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
        self::$browser->request('POST', '/kiwi-captcha/challenge', content: '{"scope":"bad|scope"}');

        $response = self::$browser->getResponse();
        self::assertSame(422, $response->getStatusCode());
        self::assertStringContainsString('INVALID_SCOPE', (string) $response->getContent());
    }

    public function testConfiguredRoutePrefixChangesTheActualRoute(): void
    {
        $this->prefixedBrowser()->request('POST', '/security/captcha/challenge', content: '{"scope":"login"}');

        $response = $this->prefixedBrowser()->getResponse();
        self::assertSame(200, $response->getStatusCode());
        self::assertNotEmpty(json_decode($response->getContent(), true)['nonce']);
    }

    public function testDefaultRouteIsGoneWhenPrefixIsConfigured(): void
    {
        $this->prefixedBrowser()->request('POST', '/kiwi-captcha/challenge', content: '{"scope":"login"}');

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

        $client->request('POST', '/kiwi-captcha/challenge', content: '{"scope":"login"}');
        self::assertSame(200, $client->getResponse()->getStatusCode());
        self::assertNotEmpty(json_decode($client->getResponse()->getContent(), true)['nonce']);
    }

    public function testEveryResponseCarriesPrivateDocumentHeaders(): void
    {
        // A dedicated client WITHOUT reboot so the in-memory rate-limit
        // state survives across requests (429 path).
        $client = new KernelBrowser(new TestKernel('test', true));
        $client->disableReboot();

        // Success path.
        $client->request('POST', '/kiwi-captcha/challenge', content: '{"scope":"login"}');
        $response = $client->getResponse();
        self::assertSame(200, $response->getStatusCode());
        $this->assertPrivateDocumentHeaders($response);

        // Error path (422).
        $client->request('POST', '/kiwi-captcha/challenge', content: '{"scope":"bad|scope"}');
        $this->assertPrivateDocumentHeaders($client->getResponse());

        // Rate-limited path (429).
        for ($i = 0; $i < 12; $i++) {
            $client->request('POST', '/kiwi-captcha/challenge', content: '{"scope":"login"}');
        }
        $rateLimited = $client->getResponse();
        self::assertSame(429, $rateLimited->getStatusCode());
        $this->assertPrivateDocumentHeaders($rateLimited);

        // Cross-origin path (403).
        $client->request('POST', '/kiwi-captcha/challenge', server: ['HTTP_ORIGIN' => 'https://evil.example'], content: '{"scope":"login"}');
        $this->assertPrivateDocumentHeaders($client->getResponse());
    }

    public function testCrossOriginPostIsRejectedWith403(): void
    {
        self::$browser->request('POST', '/kiwi-captcha/challenge', server: ['HTTP_ORIGIN' => 'https://evil.example'], content: '{"scope":"login"}');

        $response = self::$browser->getResponse();
        self::assertSame(403, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('CROSS_ORIGIN_DENIED', $body['error']['code']);
    }

    public function testSameOriginPostIsAllowed(): void
    {
        // The request itself is served at http://localhost (KernelBrowser
        // default): a matching Origin must be accepted.
        self::$browser->request('POST', '/kiwi-captcha/challenge', server: ['HTTP_ORIGIN' => 'http://localhost'], content: '{"scope":"login"}');
        self::assertSame(200, self::$browser->getResponse()->getStatusCode());
    }

    public function testOriginAbsentPostIsAllowed(): void
    {
        // No Origin header (curl, same-origin navigation, non-browser
        // clients): allowed.
        self::$browser->request('POST', '/kiwi-captcha/challenge', content: '{"scope":"login"}');
        self::assertSame(200, self::$browser->getResponse()->getStatusCode());
    }

    private function assertPrivateDocumentHeaders(\Symfony\Component\HttpFoundation\Response $response): void
    {
        self::assertSame('max-age=0, no-store, private', $response->headers->get('Cache-Control'));
        self::assertSame('no-cache', $response->headers->get('Pragma'));
        self::assertSame('no-referrer', $response->headers->get('Referrer-Policy'));
        self::assertSame('nosniff', $response->headers->get('X-Content-Type-Options'));
    }
}
