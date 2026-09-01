<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\AssetController;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * The versioned immutable asset route of asset_mode "files": the exact
 * bytes the inline mode embeds, the content hash in the URL, a long
 * immutable cache lifetime, the Content-Length and the content-hash
 * ETag. Also covered: a 304 revalidation and a 404 for unknown
 * hashes.
 */
final class AssetControllerTest extends TestCase
{
    private const ASSETS_DIR = __DIR__.'/../Resources/public';

    private function controller(): AssetController
    {
        return new AssetController(self::ASSETS_DIR);
    }

    /** @return array{0: string, 1: string, 2: string} [name, url hash (the full 256-bit sha256 hex), full sha256] */
    private function assetFixture(string $name, string $file, string $ext): array
    {
        $body = (string) file_get_contents(self::ASSETS_DIR.'/'.$file);
        $full = hash('sha256', $body);

        return [$name, $full, $full];
    }

    private function assertImmutableCache(Response $response): void
    {
        $cacheControl = (string) $response->headers->get('Cache-Control');
        self::assertStringContainsString('immutable', $cacheControl, 'the versioned asset is immutable');
        self::assertStringContainsString('max-age=31536000', $cacheControl, 'the versioned asset carries the long max-age');
        self::assertStringContainsString('public', $cacheControl, 'the versioned asset is publicly cacheable');
    }

    #[DataProvider('assetProvider')]
    public function testServesTheExactInlineBytesWithImmutableHeaders(string $name, string $file, string $ext, string $contentType): void
    {
        [, $hash] = $this->assetFixture($name, $file, $ext);
        $response = $this->controller()->asset(new Request(), $name, $hash, $ext);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame((string) file_get_contents(self::ASSETS_DIR.'/'.$file), $response->getContent(), 'the asset route must serve the exact bytes the inline mode embeds');
        $this->assertImmutableCache($response);
        self::assertSame($contentType, $response->headers->get('Content-Type'));
        self::assertSame((string) \strlen($response->getContent()), $response->headers->get('Content-Length'));
        self::assertSame('"'.hash('sha256', (string) $response->getContent()).'"', $response->headers->get('ETag'), 'the ETag is the exact content hash');
        self::assertSame('nosniff', $response->headers->get('X-Content-Type-Options'));
    }

    public static function assetProvider(): iterable
    {
        yield 'widget css' => ['widget', 'widget.css', 'css', 'text/css; charset=UTF-8'];
        yield 'runtime js' => ['runtime', 'kiwicaptcha-wasm.js', 'js', 'application/javascript; charset=UTF-8'];
        yield 'driver js' => ['driver', 'widget-driver.js', 'js', 'application/javascript; charset=UTF-8'];
        yield 'worker js' => ['worker', 'kiwi-worker.js', 'js', 'application/javascript; charset=UTF-8'];
        yield 'execution js' => ['execution', 'execution-interpreter.js', 'js', 'application/javascript; charset=UTF-8'];
    }

    public function testUnknownHashIs404(): void
    {
        [$name, , ] = $this->assetFixture('driver', 'widget-driver.js', 'js');

        $this->expectException(NotFoundHttpException::class);
        $this->controller()->asset(new Request(), $name, str_repeat('0', 64), 'js');
    }

    public function testWrongNameExtensionPairIs404(): void
    {
        [$name, $hash] = $this->assetFixture('widget', 'widget.css', 'css');

        $this->expectException(NotFoundHttpException::class);
        $this->controller()->asset(new Request(), $name, $hash, 'js');
    }

    public function testUnknownAssetNameIs404(): void
    {
        $this->expectException(NotFoundHttpException::class);
        $this->controller()->asset(new Request(), 'logo', str_repeat('0', 64), 'js');
    }

    public function testIfNoneMatchReturns304(): void
    {
        [$name, $hash, $full] = $this->assetFixture('runtime', 'kiwicaptcha-wasm.js', 'js');
        $request = new Request();
        $request->headers->set('If-None-Match', '"'.$full.'"');

        $response = $this->controller()->asset($request, $name, $hash, 'js');

        self::assertSame(304, $response->getStatusCode());
        self::assertSame('"'.$full.'"', $response->headers->get('ETag'));
        $this->assertImmutableCache($response);
        self::assertSame('', $response->getContent());
    }
}
