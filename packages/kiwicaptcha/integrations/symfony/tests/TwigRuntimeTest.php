<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Twig\KiwiCaptchaRuntime;
use PHPUnit\Framework\TestCase;
use Twig\Environment;
use Twig\Loader\ArrayLoader;

final class TwigRuntimeTest extends TestCase
{
    private function runtime(): array
    {
        $loader = new ArrayLoader([
            '@KiwiCaptcha/form_div_layout.html.twig' => file_get_contents(__DIR__.'/../src/Resources/views/form_div_layout.html.twig'),
        ]);
        $env = new Environment($loader);

        return [$env, new KiwiCaptchaRuntime('/kiwi-captcha', template: '@KiwiCaptcha/form_div_layout.html.twig')];
    }

    public function testRenderEmbedsAllAssetsAndEndpoint(): void
    {
        [$env, $runtime] = $this->runtime();
        $html = $runtime->renderWidget($env, ['endpoint' => '/kiwi-captcha/challenge', 'scope' => 'login']);

        self::assertStringContainsString('data-kiwi-endpoint="/kiwi-captcha/challenge"', $html);
        self::assertStringContainsString('data-kiwi-scope="login"', $html);
        self::assertStringContainsString('data-kiwi-token', $html);
        self::assertStringContainsString('data-kiwi-widget', $html);
        // CSS inlined
        self::assertStringContainsString('.kiwi-container', $html);
        // WASM solver embed inlined
        self::assertStringContainsString('KIWI_WASM_B64', $html);
        // Driver inlined
        self::assertStringContainsString('window.KiwiCaptcha = { init:', $html);
        // Audit #41: the driver sends the container's request binding with
        // the challenge POST and writes the hidden kiwi_request_binding form
        // field next to the token.
        self::assertStringContainsString('request_binding', $html, 'the driver must include the request_binding challenge field');
        self::assertStringContainsString("input[name='kiwi_request_binding']", $html, 'the driver must create the hidden kiwi_request_binding form input');
        // No external requests: no <link>, no <script src>, no fetchable URLs
        // (the SVG xmlns is an XML namespace, not a network fetch).
        self::assertStringNotContainsString('<link ', $html);
        self::assertStringNotContainsString('<script src=', $html);
        self::assertStringNotContainsString('https://', $html);
        self::assertStringNotContainsString('http://api.', $html);
    }

    public function testDefaultEndpointUsesRoutePrefix(): void
    {
        [$env, $runtime] = $this->runtime();
        $html = $runtime->renderWidget($env, []);

        self::assertStringContainsString('data-kiwi-endpoint="/kiwi-captcha/challenge"', $html);
        self::assertStringContainsString('data-kiwi-scope="login"', $html);
    }

    public function testTelemetryRenderedFromRuntimeDefaultAndContext(): void
    {
        [$env, $runtime] = $this->runtime();
        $html = $runtime->renderWidget($env, []);
        self::assertStringContainsString('data-kiwi-telemetry="off"', $html, 'the runtime default telemetry must be off');

        $html = $runtime->renderWidget($env, ['telemetry' => 'full']);
        self::assertStringContainsString('data-kiwi-telemetry="full"', $html);

        [$env, $runtime] = $this->runtimeWithTelemetry('minimal');
        $html = $runtime->renderWidget($env, []);
        self::assertStringContainsString('data-kiwi-telemetry="minimal"', $html, 'the configured telemetry mode must be the render default');
    }

    private function runtimeWithTelemetry(string $telemetry): array
    {
        $loader = new ArrayLoader([
            '@KiwiCaptcha/form_div_layout.html.twig' => file_get_contents(__DIR__.'/../src/Resources/views/form_div_layout.html.twig'),
        ]);

        return [$env = new Environment($loader), new KiwiCaptchaRuntime('/kiwi-captcha', template: '@KiwiCaptcha/form_div_layout.html.twig', telemetry: $telemetry)];
    }

    public function testRequestBindingRenderedFromRuntimeDefaultAndContext(): void
    {
        [$env, $runtime] = $this->runtime();
        $html = $runtime->renderWidget($env, []);
        // The driver script always mentions the attribute; the CONTAINER
        // must not carry it when no binding is configured.
        self::assertStringContainsString('data-kiwi-telemetry="off">', $html, 'no binding configured: the container must not render data-kiwi-request-binding');

        // The static risk.request_binding config default renders into the
        // widget container.
        $loader = new ArrayLoader([
            '@KiwiCaptcha/form_div_layout.html.twig' => file_get_contents(__DIR__.'/../src/Resources/views/form_div_layout.html.twig'),
        ]);
        $env = new Environment($loader);
        $runtime = new KiwiCaptchaRuntime('/kiwi-captcha', template: '@KiwiCaptcha/form_div_layout.html.twig', requestBinding: 'static-txn');
        $html = $runtime->renderWidget($env, []);
        self::assertStringContainsString('data-kiwi-request-binding="static-txn"', $html, 'the static binding must render as data-kiwi-request-binding (audit #41)');

        // A dynamic per-render binding overrides the runtime default.
        $html = $runtime->renderWidget($env, ['request_binding' => 'per-transaction']);
        self::assertStringContainsString('data-kiwi-request-binding="per-transaction"', $html);
        self::assertStringNotContainsString('data-kiwi-request-binding="static-txn"', $html);
    }

    public function testMissingAssetThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('sync-assets.sh');
        new KiwiCaptchaRuntime('/kiwi-captcha', '/nonexistent/assets/dir');
    }
}
