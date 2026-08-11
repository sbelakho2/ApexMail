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
}
