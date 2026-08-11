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
            // Standalone renders have no form view vars; provide working defaults.
            'id' => $context['id'] ?? '',
            'full_name' => $context['full_name'] ?? 'kiwi__token',
            'kiwi_css' => $this->css,
            'kiwi_wasm' => $this->wasm,
            'kiwi_driver' => $this->driver,
        ]);
    }
}
