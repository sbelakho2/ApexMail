<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ApiJsController;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * The compat loader ({prefix}/api.js): the lazy locales module's
 * content-addressed descriptor is derived from the real asset bytes.
 * A missing locales asset fails loudly at loader construction with the
 * actionable remedy. It never silently hashes the empty string (which
 * would pin an SRI digest of bytes that exist nowhere, so every lazy
 * locale fetch would fail the browser's integrity check with no
 * server-side signal).
 */
final class ApiJsControllerTest extends TestCase
{
    private const ASSETS_DIR = __DIR__.'/../Resources/public';

    protected function tearDown(): void
    {
        // The loader body is a per-process static cache: reset it so a
        // test that swapped the asset dir never leaks into the next one.
        (new \ReflectionClass(ApiJsController::class))->setStaticPropertyValue('cachedBody', null);
    }

    public function testTheLocalesMarkerPinsTheRealAssetBytes(): void
    {
        (new \ReflectionClass(ApiJsController::class))->setStaticPropertyValue('cachedBody', null);
        $controller = new ApiJsController(self::ASSETS_DIR);
        $response = $controller->apiJs(new Request());
        $body = (string) $response->getContent();

        $asset = (string) file_get_contents(self::ASSETS_DIR.'/widget-locales.js');
        self::assertStringContainsString(
            'window.__kiwiCaptchaCompatLocales={name:"locales",hash:"'.hash('sha256', $asset).'",sri:"sha256-'.base64_encode(hash('sha256', $asset, true)).'"}',
            $body,
            'the compat loader pins the locales module\'s exact content hash and SRI digest',
        );
        self::assertSame(200, $response->getStatusCode());
    }

    public function testAMissingLocalesAssetFailsLoudlyWithTheActionableRemedy(): void
    {
        // A temporarily missing widget-locales.js (an incomplete asset
        // sync) must refuse to build the loader: hashing the empty
        // string would publish an SRI digest that matches no served
        // bytes. The failure names the asset path and the remedy, the
        // same contract as KiwiCaptchaRuntime::readAsset().
        $dir = sys_get_temp_dir().'/kiwi-apijs-'.bin2hex(random_bytes(4));
        mkdir($dir, 0777, true);
        try {
            foreach (['kiwicaptcha-wasm.js', 'widget-driver.js', 'widget-risk.js', 'widget-compat.js'] as $chunk) {
                copy(self::ASSETS_DIR.'/'.$chunk, $dir.'/'.$chunk);
            }
            // widget-locales.js is deliberately NOT copied.

            (new \ReflectionClass(ApiJsController::class))->setStaticPropertyValue('cachedBody', null);
            $controller = new ApiJsController($dir);

            try {
                $controller->apiJs(new Request());
                self::fail('a missing widget-locales.js asset must refuse to build the compat loader');
            } catch (\RuntimeException $e) {
                self::assertStringContainsString('KiwiCaptcha asset not found', $e->getMessage());
                self::assertStringContainsString('widget-locales.js', $e->getMessage(), 'the failure names the missing asset');
                self::assertStringContainsString('sync-assets', $e->getMessage(), 'the failure names the actionable remedy');
                self::assertStringContainsString($dir, $e->getMessage(), 'the failure names the searched path');
            }
        } finally {
            foreach (scandir($dir) ?: [] as $file) {
                if ($file !== '.' && $file !== '..') {
                    @unlink($dir.'/'.$file);
                }
            }
            @rmdir($dir);
        }
    }
}
