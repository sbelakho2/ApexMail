<?php

declare(strict_types=1);

namespace KiwiCaptcha\Symfony\Twig;

use Twig\Environment;

/**
 * Renders the KiwiCaptcha widget.
 *
 * The markup, CSS, WASM solver embed, and driver script all come from the
 * shared asset files under Resources/public (synced from the Rust packages
 * with bin/sync-assets.sh) so the PHP and Rust implementations stay
 * byte-identical.
 */
final class KiwiCaptchaRuntime
{
    public const DEFAULT_TEMPLATE = '@KiwiCaptcha/widget.html.twig';

    /** The kiwi bird mark (must match packages/kiwicaptcha/src/logo.rs). */
    public const KIWI_SVG = <<<'SVG'
<svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M28 20C28 25.5228 23.5228 30 18 30C12.4772 30 8 25.5228 8 20C8 16 10.5 11.5 14.5 10.5C15.5 10.25 17 10 19 10C24.5228 10 28 14.4772 28 20Z" fill="currentColor"/>
  <path d="M14.5 10.5C12.5 9 11.5 6.5 12 4.5C12.5 2.5 14.5 1.5 16.5 2C18.5 2.5 19.5 4.5 19 6.5C18.8 7.5 18.5 8.5 19 10" fill="currentColor"/>
  <path d="M12.5 5L3 9.5C2.5 9.7 2.5 10.3 3 10.5L13.5 12" fill="currentColor"/>
  <circle cx="15.5" cy="5.5" r="1.2" fill="white"/>
  <circle cx="16" cy="5" r="0.6" fill="currentColor">
    <animate attributeName="opacity" values="1;1;0;1;1" keyTimes="0;0.95;0.97;0.99;1" dur="4s" repeatCount="indefinite" />
  </circle>
  <path d="M14 30V32M22 30V32" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
</svg>
SVG;

    private readonly string $css;
    private readonly string $wasm;
    private readonly string $driver;

    public function __construct(
        private readonly string $routePrefix,
        private readonly ?string $assetDir = null,
        private readonly string $template = self::DEFAULT_TEMPLATE,
    ) {
        $assetDir ??= \dirname(__DIR__, 3).'/Resources/public';
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

    /**
     * @param string      $scope    Challenge scope.
     * @param string|null $endpoint Challenge endpoint URL (default: bundle route).
     *
     * @throws \RuntimeException when an asset file is missing
     */
    public function renderWidget(Environment $env, string $scope = 'default', ?string $endpoint = null): string
    {
        $endpoint ??= rtrim($this->routePrefix, '/').'/challenge';

        return $env->render($this->template, [
            'endpoint' => $endpoint,
            'scope' => $scope,
            'kiwi_css' => $this->css,
            'kiwi_wasm' => $this->wasm,
            'kiwi_driver' => $this->driver,
            'kiwi_svg' => self::KIWI_SVG,
        ]);
    }
}
