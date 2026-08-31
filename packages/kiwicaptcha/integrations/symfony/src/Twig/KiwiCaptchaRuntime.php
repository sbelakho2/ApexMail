<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Twig;

use Twig\Environment;

/**
 * Renders the KiwiCaptcha widget.
 *
 * The widget markup, CSS, WASM solver embed, and driver script are the
 * shared assets under Resources/public (synced from the Rust packages with
 * packages/kiwicaptcha-wasm/build.sh + bin/sync-assets.sh), so the PHP and
 * Rust implementations stay byte-identical.
 *
 * Two asset delivery tiers (kiwi_captcha.asset_mode):
 *  - "files" (default): the theme emits versioned immutable first-party
 *    asset URLs ({prefix}/assets/widget.<hash>.css, runtime.<hash>.js,
 *    driver.<hash>.js, worker.<hash>.js) with SRI integrity attributes,
 *    deduplicated once per page across widgets. The dedup registry is
 *    request-scoped, and the runtime resets it between requests via the
 *    kernel.reset tag, so long-lived runtimes never leak the registry
 *    into the next request. The stylesheet link and the driver script
 *    are emitted as tags. The runtime and the worker are the lazy heavy
 *    modules. Their URLs and SRI digests ride the widget container as
 *    data-kiwi-runtime-src / data-kiwi-runtime-integrity and
 *    data-kiwi-worker-src / data-kiwi-worker-integrity, and the driver
 *    fetches them only when a memory-hard challenge arrives, so a plain
 *    SHA-256 page pays nothing for the Argon machinery. The worker runs
 *    as a same-origin Worker (no Blob), so files mode needs
 *    worker-src 'self'.
 *  - "inline" (compatibility / zero-request tier): all assets are
 *    inlined at render time — the widget makes no external requests (the
 *    historical behavior). The Blob worker it builds needs
 *    worker-src blob:.
 *
 * The telemetry mode (off/minimal/full) follows the bundle config (forced
 * 'off' under strict privacy mode) and is rendered as data-kiwi-telemetry on
 * the widget container; it stays overridable per render call. The coarse
 * risk-v2 client-context opt-in (risk.client_context) is rendered as
 * data-kiwi-risk-context="coarse" on the widget container when enabled,
 * since the driver sends the coarse capability tag only under that
 * attribute, and stays overridable per render call (default false).
 */
final class KiwiCaptchaRuntime
{
    public const DEFAULT_TEMPLATE = '@KiwiCaptcha/form_div_layout.html.twig';

    /** The asset URL key => (twig file var, URL name, extension). */
    private const ASSET_KEYS = [
        'widget' => ['css', 'css'],
        'runtime' => ['wasm', 'js'],
        'driver' => ['driver', 'js'],
        'worker' => ['worker', 'js'],
    ];

    private readonly string $css;
    private readonly string $wasm;
    private readonly string $driver;
    private readonly string $worker;

    /** @var array<string, array{url: string, sri: string}>|null */
    private ?array $assetInfo = null;

    /** @var array<string, true> the assets already emitted this request */
    private array $emittedAssetKeys = [];

    public function __construct(
        private readonly string $routePrefix,
        private readonly ?string $assetDir = null,
        private readonly string $template = self::DEFAULT_TEMPLATE,
        private readonly string $telemetry = 'off',
        private readonly ?string $requestBinding = null,
        private readonly array $challengeOriginAllowlist = [],
        private readonly bool $riskClientContext = false,
        private readonly bool $privacyStrict = false,
        private readonly string $assetMode = 'files',
    ) {
        $assetDir ??= \dirname(__DIR__, 2).'/Resources/public';
        $this->css = $this->readAsset($assetDir, 'widget.css');
        $this->wasm = $this->readAsset($assetDir, 'kiwicaptcha-wasm.js');
        $this->driver = $this->readAsset($assetDir, 'widget-driver.js');
        $this->worker = $this->readAsset($assetDir, 'kiwi-worker.js');
    }

    private function readAsset(string $dir, string $name): string
    {
        $path = rtrim($dir, '/').'/'.$name;
        $contents = @file_get_contents($path);
        if ($contents === false) {
            throw new \RuntimeException(sprintf('KiwiCaptcha asset not found: %s (run bin/sync-assets.sh)', $path));
        }

        return $contents;
    }

    public function css(): string
    {
        return $this->css;
    }

    public function wasm(): string
    {
        return $this->wasm;
    }

    public function driver(): string
    {
        return $this->driver;
    }

    public function worker(): string
    {
        return $this->worker;
    }

    public function assetMode(): string
    {
        return $this->assetMode;
    }

    /**
     * Request-scoped registry reset (kernel.reset tag): the emitted-asset
     * set must never leak across requests in a long-lived runtime
     * (RoadRunner/Swoole/amphp), where the shared runtime service would
     * otherwise suppress the asset tags of the next request.
     */
    public function reset(): void
    {
        $this->emittedAssetKeys = [];
        $this->assetInfo = null;
    }

    /**
     * The versioned asset descriptors of files mode: the content-addressed
     * URL ({prefix}/assets/{name}.{sha256-12}.{ext}) and the SRI
     * integrity value (sha256-<base64 of the full content hash>), both
     * derived from the exact bytes the inline mode embeds and the asset
     * route serves.
     *
     * @return array<string, array{url: string, sri: string}>
     */
    private function assets(): array
    {
        if ($this->assetInfo !== null) {
            return $this->assetInfo;
        }
        $prefix = rtrim($this->routePrefix, '/');
        $contents = ['widget' => $this->css, 'runtime' => $this->wasm, 'driver' => $this->driver, 'worker' => $this->worker];
        $info = [];
        foreach (self::ASSET_KEYS as $key => [$var, $ext]) {
            $content = $contents[$key];
            $info[$key] = [
                'url' => $prefix.'/assets/'.$key.'.'.substr(hash('sha256', $content), 0, 12).'.'.$ext,
                'sri' => 'sha256-'.base64_encode(hash('sha256', $content, true)),
            ];
        }
        $this->assetInfo = $info;

        return $info;
    }

    /**
     * The files-mode asset tags not yet emitted on this request: the
     * stylesheet link and the driver script. The runtime stays lazy:
     * its URL rides data-kiwi-runtime-src and the driver fetches it
     * only when a memory-hard challenge arrives, so a plain SHA-256
     * page pays nothing for the Argon machinery. Each asset is emitted
     * at most once per page, so a page with several widgets carries
     * each asset exactly once. Returns an empty string in inline mode
     * or when every asset is already emitted.
     */
    public function assetTags(?string $nonce = null): string
    {
        if ($this->assetMode !== 'files') {
            return '';
        }
        $assets = $this->assets();
        $nonceAttr = $nonce !== null && $nonce !== '' ? ' nonce="'.$nonce.'"' : '';
        $out = '';
        foreach (['widget', 'driver'] as $key) {
            if (isset($this->emittedAssetKeys[$key])) {
                continue;
            }
            $this->emittedAssetKeys[$key] = true;
            $url = $assets[$key]['url'];
            $sri = $assets[$key]['sri'];
            $out .= $key === 'widget'
                ? '<link rel="stylesheet" href="'.$url.'" integrity="'.$sri.'">'."\n"
                : '<script src="'.$url.'" integrity="'.$sri.'"'.$nonceAttr.'></script>'."\n";
        }

        return $out;
    }

    /**
     * The driver's data-kiwi-runtime-src value (files mode): the versioned
     * runtime URL the driver fetches lazily when a memory-hard challenge
     * arrives. Empty in inline mode.
     */
    public function runtimeSrc(): string
    {
        if ($this->assetMode !== 'files') {
            return '';
        }

        return $this->assets()['runtime']['url'];
    }

    /**
     * The driver's data-kiwi-runtime-integrity value (files mode): the SRI
     * digest of the runtime asset (sha256-<base64>), verified by the
     * driver against the fetched bytes before they run in the worker.
     * Empty in inline mode.
     */
    public function runtimeIntegrity(): string
    {
        if ($this->assetMode !== 'files') {
            return '';
        }

        return $this->assets()['runtime']['sri'];
    }

    /**
     * The driver's data-kiwi-worker-src value (files mode): the versioned
     * worker asset URL the driver fetches lazily when a memory-hard
     * challenge arrives and runs as a same-origin Worker (no Blob URL).
     * Empty in inline mode.
     */
    public function workerSrc(): string
    {
        if ($this->assetMode !== 'files') {
            return '';
        }

        return $this->assets()['worker']['url'];
    }

    /**
     * The driver's data-kiwi-worker-integrity value (files mode): the SRI
     * digest of the worker asset (sha256-<base64>), verified by the driver
     * against the fetched bytes before the same-origin Worker is
     * constructed. Empty in inline mode.
     */
    public function workerIntegrity(): string
    {
        if ($this->assetMode !== 'files') {
            return '';
        }

        return $this->assets()['worker']['sri'];
    }

    /**
     * The explicit `frame-ancestors` CSP directive for the widget page:
     * the space-separated allowlisted origins
     * (risk.challenge_origin_allowlist), always explicit, never
     * default-src inheritance. Returns null when the allowlist is empty
     * (no CSP promise to make).
     *
     * The application should append this directive to the Content-Security-
     * Policy header of every page that embeds the widget. Frame-ancestors
     * is ignored inside <meta> tags, so the header is the only delivery
     * that works, and the challenge endpoint itself emits the header
     * automatically. The value already includes the directive name:
     *
     *     Content-Security-Policy: default-src 'self'; <?= $runtime->cspFrameAncestors() ?>
     */
    public function cspFrameAncestors(): ?string
    {
        if ($this->challengeOriginAllowlist === []) {
            return null;
        }

        return 'frame-ancestors '.implode(' ', $this->challengeOriginAllowlist);
    }

    /**
     * @param array<string, mixed> $context
     *
     * @throws \RuntimeException when an asset file is missing
     */
    public function renderWidget(Environment $env, array $context = []): string
    {
        $algorithm = isset($context['algorithm']) ? (string) $context['algorithm'] : null;

        return $env->render($this->template, [
            'endpoint' => $context['endpoint'] ?? rtrim($this->routePrefix, '/').'/challenge',
            'scope' => $context['scope'] ?? 'login',
            'nonce' => $context['nonce'] ?? null,
            'telemetry' => $context['telemetry'] ?? $this->telemetry,
            // The coarse client-context opt-in rendered into
            // data-kiwi-risk-context="coarse" (defaults to the configured
            // risk.client_context; the app may pass a dynamic per-render
            // override). Without the attribute the driver sends no
            // client_context. Under privacy_mode "strict" the attribute
            // is never rendered, not even via the per-render override
            // (the compile-time refusal covers the configured value; this
            // closes the render-time bypass).
            'risk_client_context' => $this->privacyStrict ? false : ($context['risk_client_context'] ?? $this->riskClientContext),
            // The transaction binding rendered into
            // data-kiwi-request-binding (defaults to the configured static
            // risk.request_binding; the app may pass a dynamic per-render
            // binding).
            'request_binding' => $context['request_binding'] ?? $this->requestBinding,
            // The requested algorithm rendered into data-kiwi-algorithm
            // when explicitly provided (the driver reads it; the server
            // response stays authoritative).
            'algorithm' => $algorithm,
            // Standalone renders have no form view vars; provide working defaults.
            'id' => $context['id'] ?? '',
            'full_name' => $context['full_name'] ?? 'kiwi__token',
            'kiwi_css' => $this->css,
            'kiwi_wasm' => $this->wasm,
            'kiwi_driver' => $this->driver,
            // Files-mode delivery state (asset_mode + the request-scoped
            // emission registry + the driver's lazy runtime and worker
            // URLs and SRI digests).
            'asset_mode' => $this->assetMode,
            'asset_tags' => $this->assetTags($context['nonce'] ?? null),
            'runtime_src' => $this->runtimeSrc(),
            'runtime_integrity' => $this->runtimeIntegrity(),
            'worker_src' => $this->workerSrc(),
            'worker_integrity' => $this->workerIntegrity(),
        ]);
    }
}
