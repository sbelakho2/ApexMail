<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Symfony;

use KiwiCaptcha\Issuer;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use KiwiCaptcha\Symfony\Twig\KiwiCaptchaRuntime;
use PHPUnit\Framework\TestCase;
use Twig\Environment;
use Twig\Loader\ArrayLoader;

final class TwigRuntimeTest extends TestCase
{
    public function testRenderWidgetEmbedsAssetsAndEndpoint(): void
    {
        $loader = new ArrayLoader([
            'widget.html.twig' => file_get_contents(__DIR__.'/../../templates/widget.html.twig'),
        ]);
        $env = new Environment($loader);

        $runtime = new KiwiCaptchaRuntime('/kiwi-captcha', template: 'widget.html.twig');
        $html = $runtime->renderWidget($env, 'login', '/kiwi-captcha/challenge');

        self::assertStringContainsString('data-kiwi-endpoint="/kiwi-captcha/challenge"', $html);
        self::assertStringContainsString('data-kiwi-scope="login"', $html);
        self::assertStringContainsString('kiwi__token', $html);
        self::assertStringContainsString('data-kiwi-widget', $html);
        // The wasm embed must be present (65KB base64 blob).
        self::assertStringContainsString('KIWI_WASM_B64', $html);
        // The driver must be present.
        self::assertStringContainsString('__kiwiCaptchaWasm', $html);
        self::assertStringContainsString('window.KiwiCaptcha = { init:', $html);
        // CSS must be inlined.
        self::assertStringContainsString('.kiwi-container', $html);
        // The SVG mark.
        self::assertStringContainsString('viewBox="0 0 32 32"', $html);
    }

    public function testRenderWidgetUsesDefaultRouteWhenEndpointOmitted(): void
    {
        $loader = new ArrayLoader([
            'widget.html.twig' => file_get_contents(__DIR__.'/../../templates/widget.html.twig'),
        ]);
        $env = new Environment($loader);

        $runtime = new KiwiCaptchaRuntime('/kiwi-captcha', template: 'widget.html.twig');
        $html = $runtime->renderWidget($env, 'default');

        self::assertStringContainsString('data-kiwi-endpoint="/kiwi-captcha/challenge"', $html);
    }

    public function testMissingAssetThrowsWithActionableMessage(): void
    {
        $loader = new ArrayLoader([
            'widget.html.twig' => file_get_contents(__DIR__.'/../../templates/widget.html.twig'),
        ]);
        $env = new Environment($loader);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('sync-assets.sh');

        $runtime = new KiwiCaptchaRuntime('/kiwi-captcha', '/nonexistent/assets/dir');
        // Unused-but-referenced so the constructor failure is the test subject.
        $runtime->renderWidget($env, 'default');
    }
}
