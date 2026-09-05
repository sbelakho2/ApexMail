<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Form\Type\KiwiCaptchaType;
use BelConsulting\KiwiCaptchaBundle\Twig\KiwiCaptchaRuntime;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Response;

/**
 * The rendered-URL-is-routable invariant of asset_mode "files"
 * (docs/configuration.md): every asset URL the default widget render
 * emits must route through the real Symfony router and serve the exact
 * bytes the inline mode embeds.
 *
 * This is the permanent integration guard the plain controller test
 * cannot provide. The controller unit tests invoke
 * {@see \BelConsulting\KiwiCaptchaBundle\Controller\AssetController}
 * directly, so a route constraint that omits an asset name (the
 * `worker` gap this test locks in) passes unit tests and the Twig
 * markup tests, while the production URL 404s at the router. The
 * rendered markup is the source of truth here: every extracted URL
 * (the stylesheet link, the driver script, the lazy runtime and the
 * same-origin worker data attributes) is GET-ed through the booted
 * kernel's real router. Each must answer 200 with the hash in the URL
 * matching the served bytes, the exact content type, the SRI digest
 * of the served bytes and the long immutable cache contract.
 */
final class AssetRouteKernelIntegrationTest extends TestCase
{
    private const ASSETS_DIR = __DIR__.'/../../Resources/public';

    private const ASSET_SPECS = [
        'widget' => ['file' => 'widget.css', 'content_type' => 'text/css; charset=UTF-8', 'ext' => 'css'],
        'driver' => ['file' => 'widget-driver.js', 'content_type' => 'application/javascript; charset=UTF-8', 'ext' => 'js'],
        'runtime' => ['file' => 'kiwicaptcha-wasm.js', 'content_type' => 'application/javascript; charset=UTF-8', 'ext' => 'js'],
        'worker' => ['file' => 'kiwi-worker.js', 'content_type' => 'application/javascript; charset=UTF-8', 'ext' => 'js'],
        'execution' => ['file' => 'execution-interpreter.js', 'content_type' => 'application/javascript; charset=UTF-8', 'ext' => 'js'],
        'risk' => ['file' => 'widget-risk.js', 'content_type' => 'application/javascript; charset=UTF-8', 'ext' => 'js'],
        'telemetry' => ['file' => 'widget-telemetry.js', 'content_type' => 'application/javascript; charset=UTF-8', 'ext' => 'js'],
        'locales' => ['file' => 'widget-locales.js', 'content_type' => 'application/javascript; charset=UTF-8', 'ext' => 'js'],
    ];

    private static ?KernelBrowser $browser = null;

    protected function setUp(): void
    {
        self::$browser ??= new KernelBrowser(new TestKernel('test', true));
    }

    private function container(): ContainerInterface
    {
        $kernel = self::$browser->getKernel();
        $kernel->boot();

        return $kernel->getContainer()->get('test.service_container');
    }

    /**
     * Render the default (files-mode) widget markup and extract every
     * Twig-generated asset URL it carries: `{name}.{sha256-64}.{ext}`
     * (the full 256-bit content hash) under the configured asset prefix.
     *
     * @return list<array{name: string, hash: string, ext: string, url: string}>
     */
    private function renderedAssetUrls(): array
    {
        // The files-mode emission registry is request-scoped; direct
        // twig renders never cross a kernel.request, so the registry must
        // be reset before the render (the same discipline as
        // KernelIntegrationTest).
        $this->container()->get(KiwiCaptchaRuntime::class)->reset();
        $factory = $this->container()->get('form.factory');
        $form = $factory->createNamed('captcha', KiwiCaptchaType::class, null, ['scope' => 'login']);
        $html = (string) $this->container()->get('twig')->render('@Test/form.html.twig', ['form' => $form->createView()]);

        self::assertStringContainsString('/kiwi-captcha/assets/widget.', $html, 'the default files-mode render emits the stylesheet link');
        self::assertStringContainsString('/kiwi-captcha/assets/driver.', $html, 'the default files-mode render emits the driver script');
        self::assertStringContainsString('data-kiwi-runtime-src="/kiwi-captcha/assets/runtime.', $html, 'the lazy runtime URL rides the container attribute');
        self::assertStringContainsString('data-kiwi-worker-src="/kiwi-captcha/assets/worker.', $html, 'the same-origin worker URL rides the container attribute');
        self::assertStringContainsString('data-kiwi-execution-src="/kiwi-captcha/assets/execution.', $html, 'the lazy execution interpreter URL rides the container attribute');
        self::assertStringContainsString('data-kiwi-risk-src="/kiwi-captcha/assets/risk.', $html, 'the lazy widget-risk module URL rides the container attribute');
        self::assertStringContainsString('data-kiwi-telemetry-src="/kiwi-captcha/assets/telemetry.', $html, 'the lazy widget-telemetry module URL rides the container attribute');

        preg_match_all('~/(kiwi-captcha/assets/(execution|widget|driver|runtime|worker|risk|telemetry)\.([0-9a-f]{64})\.(css|js))~', $html, $matches, PREG_SET_ORDER);
        self::assertCount(7, $matches, 'the files-mode widget render emits exactly the seven asset URLs (widget, driver, runtime, worker, execution, risk, telemetry)');

        $urls = [];
        foreach ($matches as $match) {
            $urls[] = [
                'name' => $match[2],
                'hash' => $match[3],
                'ext' => $match[4],
                'url' => '/'.$match[1],
            ];
        }

        return $urls;
    }

    /**
     * The SRI integrity attribute the markup declares for an asset URL,
     * or null when the URL carries no integrity attribute. The scan is
     * lazy after the URL so the first integrity in the tag wins (the
     * widget/driver tags carry `integrity=`, the runtime/worker data
     * attributes carry `data-kiwi-*-integrity=`).
     */
    private function integrityFor(string $html, string $url): ?string
    {
        if (preg_match('~<[^>]+(?:href|src)="'.preg_quote($url, '~').'"[^>]*?\bintegrity="(sha256-[A-Za-z0-9+/=]+)"~', $html, $m) === 1) {
            return $m[1];
        }

        return null;
    }

    private function assertImmutableCacheContract(Response $response): void
    {
        $cacheControl = (string) $response->headers->get('Cache-Control');
        self::assertStringContainsString('public', $cacheControl);
        self::assertStringContainsString('max-age=31536000', $cacheControl);
        self::assertStringContainsString('immutable', $cacheControl);
        self::assertSame('nosniff', $response->headers->get('X-Content-Type-Options'));
    }

    public function testEveryTwigAssetUrlRoutesAndServesTheExactInlineBytes(): void
    {
        $urls = $this->renderedAssetUrls();

        // The seven rendered names are exactly the routable asset set:
        // css, driver js, runtime js, worker js, execution js, and the
        // two lazy widget-module js assets (widget-risk.js /
        // widget-telemetry.js).
        self::assertEqualsCanonicalizing(['widget', 'driver', 'runtime', 'worker', 'execution', 'risk', 'telemetry'], array_column($urls, 'name'));

        foreach ($urls as $asset) {
            $name = $asset['name'];
            $spec = self::ASSET_SPECS[$name];
            $embedded = (string) file_get_contents(self::ASSETS_DIR.'/'.$spec['file']);
            self::assertNotSame('', $embedded, $name.' must ship non-empty bytes in Resources/public');
            $fullHash = hash('sha256', $embedded);

            self::$browser->request('GET', $asset['url']);
            $response = self::$browser->getResponse();

            self::assertSame(200, $response->getStatusCode(), sprintf('%s (%s) must route through the real router', $name, $asset['url']));
            self::assertSame($spec['content_type'], $response->headers->get('Content-Type'), $name.' serves its exact MIME type');
            self::assertSame($embedded, (string) $response->getContent(), $name.' serves the exact bytes the inline mode embeds');
            self::assertSame($fullHash, $asset['hash'], $name.' hash in the URL is the full 256-bit sha256 of the served bytes');
            self::assertSame('"'.$fullHash.'"', $response->headers->get('ETag'), $name.' ETag is the full content hash');
            self::assertSame((string) \strlen($embedded), $response->headers->get('Content-Length'));
            $this->assertImmutableCacheContract($response);
        }
    }

    public function testTheSriDigestOfTheServedBytesMatchesTheMarkupIntegrity(): void
    {
        // The SRI contract: the bytes the router serves for a rendered
        // URL hash to the exact integrity attribute the markup declared,
        // so a browser fetching the asset verifies the served bytes
        // against the render-time digest (a content change anywhere
        // breaks the pair: the URL hash, the SRI and the served bytes).
        $this->container()->get(KiwiCaptchaRuntime::class)->reset();
        $factory = $this->container()->get('form.factory');
        $form = $factory->createNamed('captcha', KiwiCaptchaType::class, null, ['scope' => 'login']);
        $html = (string) $this->container()->get('twig')->render('@Test/form.html.twig', ['form' => $form->createView()]);

        foreach ($this->renderedAssetUrls() as $asset) {
            $integrity = $this->integrityFor($html, $asset['url']);
            self::$browser->request('GET', $asset['url']);
            $served = (string) self::$browser->getResponse()->getContent();
            self::assertSame(
                'sha256-'.base64_encode(hash('sha256', $served, true)),
                $integrity,
                $asset['name'].' SRI digest must equal the digest of the bytes the router serves',
            );
        }
    }

    public function testAnUnknownHashStays404ThroughTheRouter(): void
    {
        $urls = $this->renderedAssetUrls();
        self::$browser->request('GET', str_replace('.'.($urls[0]['hash']).'.', '.'.str_repeat('0', 64).'.', $urls[0]['url']));
        self::assertSame(404, self::$browser->getResponse()->getStatusCode(), 'an unknown content hash is a 404 through the router, never a cache-bypass serve');
    }

    public function testTheAssetUrlHashDeterministicallyMatchesTheResourceBytes(): void
    {
        // The router serves the shipped resource byte-for-byte: the URL
        // hash must equal the full 256-bit sha256 of the committed
        // resource file, which is what the Twig runtime hashed at render
        // time.
        foreach (self::ASSET_SPECS as $name => $spec) {
            $embedded = (string) file_get_contents(self::ASSETS_DIR.'/'.$spec['file']);
            $expectedHash = hash('sha256', $embedded);
            self::$browser->request('GET', '/kiwi-captcha/assets/'.$name.'.'.$expectedHash.'.'.$spec['ext']);
            self::assertSame(200, self::$browser->getResponse()->getStatusCode(), $name.' routes under its deterministic content hash');
            self::assertSame($embedded, (string) self::$browser->getResponse()->getContent());
        }
    }
}
