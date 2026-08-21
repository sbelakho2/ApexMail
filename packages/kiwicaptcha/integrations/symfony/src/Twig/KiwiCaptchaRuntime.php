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
 * Rust implementations stay byte-identical. All assets are inlined at
 * render time — the widget makes no external requests.
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

    private readonly string $css;
    private readonly string $wasm;
    private readonly string $driver;

    public function __construct(
        private readonly string $routePrefix,
        private readonly ?string $assetDir = null,
        private readonly string $template = self::DEFAULT_TEMPLATE,
        private readonly string $telemetry = 'off',
        private readonly ?string $requestBinding = null,
        private readonly array $challengeOriginAllowlist = [],
        private readonly bool $riskClientContext = false,
        private readonly bool $privacyStrict = false,
    ) {
        $assetDir ??= \dirname(__DIR__, 2).'/Resources/public';
        $this->css = $this->readAsset($assetDir, 'widget.css');
        $this->wasm = $this->readAsset($assetDir, 'kiwicaptcha-wasm.js');
        $this->driver = $this->readAsset($assetDir, 'widget-driver.js');
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
            // Standalone renders have no form view vars; provide working defaults.
            'id' => $context['id'] ?? '',
            'full_name' => $context['full_name'] ?? 'kiwi__token',
            'kiwi_css' => $this->css,
            'kiwi_wasm' => $this->wasm,
            'kiwi_driver' => $this->driver,
        ]);
    }
}
