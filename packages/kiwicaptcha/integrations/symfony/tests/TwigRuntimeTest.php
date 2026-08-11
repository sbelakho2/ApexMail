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

    public function testMissingAssetThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('sync-assets.sh');
        new KiwiCaptchaRuntime('/kiwi-captcha', '/nonexistent/assets/dir');
    }
}
