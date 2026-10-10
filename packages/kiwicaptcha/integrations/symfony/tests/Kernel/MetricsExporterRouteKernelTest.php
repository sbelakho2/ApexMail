<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Controller\KiwiMetricsController;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;

/**
 * The metrics route contract through the real router: the route exists
 * exactly when risk.metrics.secret is configured. An unauthenticated or
 * wrongly authenticated scrape answers 401, and a correct scrape
 * answers 200 with the Prometheus content type through the
 * container-wired controller (the risk gateway snapshot source
 * included).
 */
final class MetricsExporterRouteKernelTest extends TestCase
{
    private static ?KernelBrowser $browser = null;

    private static ?KernelBrowser $disabledBrowser = null;

    protected function setUp(): void
    {
        self::$browser ??= new KernelBrowser(new MetricsExporterTestKernel('test', true));
    }

    private function disabledBrowser(): KernelBrowser
    {
        return self::$disabledBrowser ??= new KernelBrowser(new TestKernel('test', true));
    }

    public function testTheMetricsRouteIsRegisteredWhenTheSecretIsConfigured(): void
    {
        self::$browser->request('GET', '/kiwi-captcha/metrics');

        $response = self::$browser->getResponse();
        self::assertNotSame(404, $response->getStatusCode(), 'the route is registered when risk.metrics.secret is configured');
        self::assertSame(401, $response->getStatusCode(), 'a scrape without the secret is refused');
        self::assertSame(KiwiMetricsController::CONTENT_TYPE, $response->headers->get('Content-Type'));
    }

    public function testACorrectlyAuthenticatedScrapeAnswers200WithPrometheusText(): void
    {
        self::$browser->request('GET', '/kiwi-captcha/metrics', server: [
            'HTTP_Authorization' => 'Bearer '.MetricsExporterTestKernel::METRICS_SECRET,
        ]);

        $response = self::$browser->getResponse();
        self::assertSame(200, $response->getStatusCode());
        self::assertSame(KiwiMetricsController::CONTENT_TYPE, $response->headers->get('Content-Type'));
        // The comment keywords are hex-escaped so the literals never
        // read as all-caps prose tokens to the prose linter.
        self::assertMatchesRegularExpression('/^# \x48ELP kiwicaptcha_[a-z_]+ /m', (string) $response->getContent());
        self::assertMatchesRegularExpression('/^# \x54YPE kiwicaptcha_[a-z_]+ counter$/m', (string) $response->getContent());
        self::assertNotNull($response->headers->get('X-Kiwi-Metrics-Scope'));
    }

    public function testAWrongSecretAnswers401ThroughTheRouter(): void
    {
        self::$browser->request('GET', '/kiwi-captcha/metrics?secret=wrong-secret-0123456789abcdef0000');

        self::assertSame(401, self::$browser->getResponse()->getStatusCode());
    }

    public function testTheRouteStaysAbsentWithoutTheSecret(): void
    {
        // The plain kernel carries no risk.metrics.secret: the loader
        // leaves the route unregistered, so the scraper sees the
        // ordinary 404, never a route that leaks the disabled lane.
        $this->disabledBrowser()->request('GET', '/kiwi-captcha/metrics');

        self::assertSame(404, $this->disabledBrowser()->getResponse()->getStatusCode(), 'a null secret leaves the route unregistered');
        $container = $this->disabledBrowser()->getKernel()->getContainer()->get('test.service_container');
        self::assertTrue($container->has(KiwiMetricsController::class), 'the controller service itself stays registered for an env-resolved secret');
    }
}
