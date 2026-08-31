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

        // The inline tier is the compatibility / zero-request mode; these
        // tests pin its rendering explicitly (the bundle default is "files",
        // asserted in testRuntimeDefaultAssetModeIsFiles).
        return [$env, new KiwiCaptchaRuntime('/kiwi-captcha', template: '@KiwiCaptcha/form_div_layout.html.twig', assetMode: 'inline')];
    }

    public function testRuntimeDefaultAssetModeIsFiles(): void
    {
        $loader = new ArrayLoader([
            '@KiwiCaptcha/form_div_layout.html.twig' => file_get_contents(__DIR__.'/../src/Resources/views/form_div_layout.html.twig'),
        ]);
        $env = new Environment($loader);
        // No assetMode argument: the runtime default is the recommended
        // files tier (a fresh integrator gets the versioned asset tags).
        $runtime = new KiwiCaptchaRuntime('/kiwi-captcha', template: '@KiwiCaptcha/form_div_layout.html.twig');

        self::assertSame('files', $runtime->assetMode(), 'the runtime default asset mode must be files');
        $html = $runtime->renderWidget($env, []);
        self::assertStringContainsString('<link rel="stylesheet" href="/kiwi-captcha/assets/widget.', $html, 'the default render emits the versioned stylesheet link');
        self::assertStringContainsString('<script src="/kiwi-captcha/assets/driver.', $html, 'the default render emits the versioned driver script');
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
        self::assertStringContainsString('window.KiwiCaptcha = {', $html);
        self::assertStringContainsString('render: kiwiRender', $html);
        // The driver sends the container's request binding with
        // the challenge POST and writes the hidden kiwi_request_binding form
        // field next to the token.
        self::assertStringContainsString('request_binding', $html, 'the driver must include the request_binding challenge field');
        self::assertStringContainsString('input[name="kiwi_request_binding"]', $html, 'the driver must create the hidden kiwi_request_binding form input');
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

    // ── Files-mode asset delivery (asset_mode "files") ───────────────────

    private function filesRuntime(): array
    {
        $loader = new ArrayLoader([
            '@KiwiCaptcha/form_div_layout.html.twig' => file_get_contents(__DIR__.'/../src/Resources/views/form_div_layout.html.twig'),
        ]);
        $env = new Environment($loader);

        return [$env, new KiwiCaptchaRuntime('/kiwi-captcha', template: '@KiwiCaptcha/form_div_layout.html.twig', assetMode: 'files')];
    }

    public function testFilesModeEmitsVersionedAssetTagsWithSri(): void
    {
        [$env, $runtime] = $this->filesRuntime();
        $html = $runtime->renderWidget($env, ['endpoint' => '/kiwi-captcha/challenge', 'scope' => 'login']);

        // No inline style/script blocks in files mode.
        self::assertStringNotContainsString('<style', $html);
        self::assertStringNotContainsString('KIWI_WASM_B64', $html, 'the runtime embed must stay lazy in files mode');
        self::assertStringNotContainsString('window.KiwiCaptcha = {', $html, 'the driver must not be inlined in files mode');

        // The stylesheet link and the driver script carry the versioned
        // URLs and the SRI integrity of the exact bytes they reference.
        preg_match_all('~<link rel="stylesheet" href="(/kiwi-captcha/assets/widget\.[0-9a-f]{12}\.css)" integrity="(sha256-[A-Za-z0-9+/=]+)">~', $html, $cssMatches);
        self::assertCount(1, $cssMatches[0], 'the widget stylesheet must be emitted exactly once');
        self::assertSame('/kiwi-captcha/assets/widget.'.substr(hash('sha256', (string) file_get_contents(__DIR__.'/../Resources/public/widget.css')), 0, 12).'.css', $cssMatches[1][0]);
        self::assertSame('sha256-'.base64_encode(hash('sha256', (string) file_get_contents(__DIR__.'/../Resources/public/widget.css'), true)), $cssMatches[2][0]);

        preg_match_all('~<script src="(/kiwi-captcha/assets/driver\.[0-9a-f]{12}\.js)" integrity="(sha256-[A-Za-z0-9+/=]+)"></script>~', $html, $driverMatches);
        self::assertCount(1, $driverMatches[0], 'the driver script must be emitted exactly once');
        self::assertSame('/kiwi-captcha/assets/driver.'.substr(hash('sha256', (string) file_get_contents(__DIR__.'/../Resources/public/widget-driver.js')), 0, 12).'.js', $driverMatches[1][0]);
        self::assertSame('sha256-'.base64_encode(hash('sha256', (string) file_get_contents(__DIR__.'/../Resources/public/widget-driver.js'), true)), $driverMatches[2][0]);

        // The runtime stays lazy: no runtime script tag (only the driver
        // script is emitted); its URL and SRI digest ride the container
        // attributes for the driver's argon-time fetch.
        self::assertStringNotContainsString('<script src="/kiwi-captcha/assets/runtime.', $html, 'the runtime must never be emitted as a script tag');
        self::assertStringContainsString('data-kiwi-runtime-src="/kiwi-captcha/assets/runtime.'.substr(hash('sha256', (string) file_get_contents(__DIR__.'/../Resources/public/kiwicaptcha-wasm.js')), 0, 12).'.js"', $html);
        self::assertStringContainsString('data-kiwi-runtime-integrity="sha256-'.base64_encode(hash('sha256', (string) file_get_contents(__DIR__.'/../Resources/public/kiwicaptcha-wasm.js'), true)).'"', $html);
    }

    public function testFilesModeEmitsEachAssetExactlyOnceAcrossWidgets(): void
    {
        [$env, $runtime] = $this->filesRuntime();
        $first = $runtime->renderWidget($env, ['endpoint' => '/kiwi-captcha/challenge', 'scope' => 'login']);
        $second = $runtime->renderWidget($env, ['endpoint' => '/kiwi-captcha/challenge', 'scope' => 'login']);

        // The request-scoped registry: the first widget emits the assets,
        // the second widget renders the container only.
        self::assertSame(1, substr_count($first, '<link rel="stylesheet"'), 'the first widget emits the stylesheet');
        self::assertSame(1, substr_count($first, '<script src='), 'the first widget emits the driver');
        self::assertStringNotContainsString('<link ', $second, 'the second widget must not re-emit the stylesheet');
        self::assertStringNotContainsString('<script src=', $second, 'the second widget must not re-emit the driver');
        self::assertStringContainsString('data-kiwi-runtime-src=', $second, 'the second widget still carries the runtime URL');
        self::assertStringContainsString('data-kiwi-token', $second, 'the second widget still renders its container');
    }

    public function testFilesModeNonceRidesTheDriverScriptTag(): void
    {
        [$env, $runtime] = $this->filesRuntime();
        $html = $runtime->renderWidget($env, ['nonce' => 'abc123']);

        self::assertStringContainsString(' integrity="sha256-', $html);
        self::assertSame(1, substr_count($html, ' nonce="abc123"'), 'the driver script tag carries the CSP nonce exactly once');
    }

    public function testFilesModeSkippedOutsideFilesMode(): void
    {
        [$env, $runtime] = $this->runtime();
        $html = $runtime->renderWidget($env, ['endpoint' => '/kiwi-captcha/challenge']);

        self::assertStringNotContainsString('<link ', $html);
        self::assertStringNotContainsString('<script src=', $html);
        self::assertStringNotContainsString('data-kiwi-runtime-src=', $html, 'inline mode renders no runtime URL attribute');
    }

    public function testResetClearsTheEmissionRegistry(): void
    {
        [$env, $runtime] = $this->filesRuntime();
        $runtime->renderWidget($env, ['endpoint' => '/kiwi-captcha/challenge']);
        $runtime->reset();
        $html = $runtime->renderWidget($env, ['endpoint' => '/kiwi-captcha/challenge']);

        self::assertSame(1, substr_count($html, '<link rel="stylesheet"'), 'after reset the next render emits the assets again (kernel.reset contract)');
    }

    // ── Widget-page frame-ancestors CSP helper ────────────────────────────

    public function testCspFrameAncestorsIsNullForAnEmptyAllowlist(): void
    {
        [$env, $runtime] = $this->runtime();
        self::assertNull($runtime->cspFrameAncestors(), 'an empty allowlist must produce no CSP directive');
    }

    public function testCspFrameAncestorsCarriesTheAllowlistedOrigins(): void
    {
        $runtime = new KiwiCaptchaRuntime('/kiwi-captcha', template: '@KiwiCaptcha/form_div_layout.html.twig', challengeOriginAllowlist: ['https://app.example.com', 'https://cdn.example.com']);

        self::assertSame(
            'frame-ancestors https://app.example.com https://cdn.example.com',
            $runtime->cspFrameAncestors(),
            'the directive must be EXPLICIT and space-separated (never default-src inheritance)',
        );
    }

    public function testTwigFunctionExposesTheFrameAncestorsDirective(): void
    {
        $env = new Environment(new ArrayLoader([]));
        $extension = new \BelConsulting\KiwiCaptchaBundle\Twig\KiwiCaptchaExtension();
        $env->addExtension($extension);
        $env->addRuntimeLoader(new \Twig\RuntimeLoader\FactoryRuntimeLoader([
            \BelConsulting\KiwiCaptchaBundle\Twig\KiwiCaptchaRuntime::class => static fn () => new KiwiCaptchaRuntime('/kiwi-captcha', template: '@KiwiCaptcha/form_div_layout.html.twig', challengeOriginAllowlist: ['https://app.example.com']),
        ]));

        $html = $env->createTemplate('{{ kiwi_captcha_csp_frame_ancestors() }}')->render([]);
        self::assertSame('frame-ancestors https://app.example.com', $html);
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
        // The driver script always mentions the attribute; the container
        // must not carry it when no binding is configured.
        self::assertStringContainsString('data-kiwi-telemetry="off">', $html, 'no binding configured: the container must not render data-kiwi-request-binding');

        // The static risk.request_binding config default renders into the
        // widget container.
        $loader = new ArrayLoader([
            '@KiwiCaptcha/form_div_layout.html.twig' => file_get_contents(__DIR__.'/../src/Resources/views/form_div_layout.html.twig'),
        ]);
        $env = new Environment($loader);
        $runtime = new KiwiCaptchaRuntime('/kiwi-captcha', template: '@KiwiCaptcha/form_div_layout.html.twig', assetMode: 'inline', requestBinding: 'static-txn');
        $html = $runtime->renderWidget($env, []);
        self::assertStringContainsString('data-kiwi-request-binding="static-txn"', $html, 'the static binding must render as data-kiwi-request-binding');

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

    // ── Backend-originated binding ────────────────────────────────────────

    /**
     * The widget's rendered container carries only the
     * SERVER-provided binding — the value comes from the form option /
     * runtime configuration (a flow_id stored server-side), never from the
     * client. With a binding configured, the container carries exactly one
     * data-kiwi-request-binding equal to the server value; without one, the
     * container carries NO binding attribute at all.
     */
    public function testWidgetContainerCarriesOnlyTheServerProvidedBinding(): void
    {
        $loader = new ArrayLoader([
            '@KiwiCaptcha/form_div_layout.html.twig' => file_get_contents(__DIR__.'/../src/Resources/views/form_div_layout.html.twig'),
        ]);
        $env = new Environment($loader);

        // Backend-originated: the form/backend renders the binding into the
        // container; the widget only ever forwards it.
        $runtime = new KiwiCaptchaRuntime('/kiwi-captcha', template: '@KiwiCaptcha/form_div_layout.html.twig', requestBinding: 'server-flow-id-42');
        $html = $runtime->renderWidget($env, []);
        self::assertSame(1, substr_count($html, 'data-kiwi-request-binding="server-flow-id-42"'), 'the container carries the server-provided binding exactly once');
        self::assertStringNotContainsString('data-kiwi-request-binding="server-flow-id-42" data-kiwi-request-binding', $html, 'no second binding attribute may exist');
        self::assertStringNotContainsString('randomUUID', $html, 'the rendered widget never synthesizes a binding client-side');

        // No binding configured: the container renders NO binding attribute
        // (the driver mentions the attribute in its source, but the
        // container itself carries nothing for the client to fill in).
        $runtime = new KiwiCaptchaRuntime('/kiwi-captcha', template: '@KiwiCaptcha/form_div_layout.html.twig');
        $html = $runtime->renderWidget($env, []);
        self::assertStringNotContainsString('data-kiwi-request-binding=', $html, 'without a server-provided binding the container carries no binding attribute');
    }

    /**
     * The widget driver never generates a transaction binding
     * itself — no crypto.randomUUID / getRandomValues / Math.random binding
     * synthesis. The only source of the binding is the container attribute
     * the server rendered (backend-originated mode), so a client can never
     * mint a binding the backend did not issue.
     */
    public function testDriverNeverGeneratesATransactionBinding(): void
    {
        $driver = (string) file_get_contents(__DIR__.'/../Resources/public/widget-driver.js');

        self::assertStringContainsString('data-kiwi-request-binding', $driver, 'the driver reads the server-rendered binding attribute');
        self::assertStringContainsString('var requestBinding = W.getAttribute("data-kiwi-request-binding")', $driver, 'the binding variable is assigned ONLY from the container attribute');
        self::assertStringNotContainsString('randomUUID', $driver, 'the driver must never generate bindings with crypto.randomUUID');
        // crypto.getRandomValues is allowed exactly once (the call): the
        // client-side `CSPRNG` draw of the decoy (honeypot) rendering
        // strategy — a presentation dimension, never a security boundary
        // and never a binding. The binding path stays attribute-only
        // (asserted above).
        self::assertSame(1, substr_count($driver, 'crypto.getRandomValues(buf)'), 'crypto.getRandomValues must be limited to the decoy-strategy draw — bindings are never synthesized client-side');
        // Math.random exists exactly three times — the per-widget
        // data-kiwi-instance debugging marker, the per-widget hCaptcha
        // response-key marker, and the presentation-only fallback of the
        // decoy-strategy draw on engines without crypto.getRandomValues.
        // It must never appear in the binding path: the binding is
        // assigned from the container attribute only (asserted above).
        self::assertSame(3, substr_count($driver, 'Math.random'), 'Math.random must be limited to the instance-id, response-key and decoy-strategy fallback markers — bindings are never synthesized client-side');
    }
}
