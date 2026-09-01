<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Routing;

use BelConsulting\KiwiCaptchaBundle\Controller\ApiJsController;
use BelConsulting\KiwiCaptchaBundle\Controller\AssetController;
use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Controller\KiwiHealthController;
use BelConsulting\KiwiCaptchaBundle\Controller\SiteVerifyController;
use Symfony\Component\Config\Loader\Loader;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;

/**
 * Registers the bundle's routes with the configured prefix.
 *
 * A #[Route] attribute on the controller is NOT sufficient for a bundle:
 * attribute routes are only discovered for the application's own
 * src/Controller directory, never for vendor bundle directories. This loader
 * is the bundle-owned source of truth for the routes, and the paths are built
 * from the `kiwi_captcha.route_prefix` config option so the configured prefix
 * affects the actual routes, not just the widget's requested endpoint.
 *
 * Routes:
 *  - POST  {prefix}/challenge          (the widget's challenge endpoint).
 *  - POST  {prefix}/challenge/cancel   (the widget's bounded cancellation
 *                                       endpoint — retire an abandoned
 *                                       challenge and release its
 *                                       live-outstanding slot).
 *  -  GET   {prefix}/assets/{name}.{hash}.{js|css}
 *                                      (the versioned immutable widget
 *                                       assets of asset_mode "files":
 *                                       runtime/widget/driver/worker/
 *                                       execution, served with a long
 *                                       immutable cache lifetime).
 *  - GET   {prefix}/health/live        (liveness, always 200).
 *  - GET   {prefix}/health/ready       (readiness, 200 only when signing
 *                                       keys + security Redis + the central
 *                                       security-policy state are all
 *                                       compatible; risk.health.enabled
 *                                       defaults true).
 *
 * Loaded either automatically (the extension prepends
 * src/Resources/config/routes.php as the app's framework.router.resource when
 * the app has not configured the router itself) or manually by the
 * application importing '@KiwiCaptchaBundle/Resources/config/routes.php'.
 */
final class KiwiCaptchaRouteLoader extends Loader
{
    private const ROUTE_TYPE = 'kiwicaptcha';

    private bool $isLoaded = false;

    public function __construct(
        private readonly string $routePrefix,
        private readonly bool $healthEnabled = true,
    ) {
    }

    public function load(mixed $resource, ?string $type = null): RouteCollection
    {
        if ($this->isLoaded) {
            throw new \RuntimeException('Do not add the "kiwicaptcha" route loader twice.');
        }
        $this->isLoaded = true;

        $prefix = rtrim($this->routePrefix, '/');
        $routes = new RouteCollection();
        // Provider-compatible Siteverify + migration loader.
        $routes->add('kiwicaptcha_siteverify', new Route(
            $prefix.'/siteverify',
            ['_controller' => [SiteVerifyController::class, 'siteverify']],
            [],
            [],
            '',
            [],
            ['POST'],
        ));
        $routes->add('kiwicaptcha_api_js', new Route(
            $prefix.'/api.js',
            ['_controller' => [ApiJsController::class, 'apiJs']],
            [],
            [],
            '',
            [],
            ['GET'],
        ));
        // The compatibility loader links the stylesheet at
        // {prefix}/widget.css — the production route must exist (the
        // Playwright fixture hid its absence).
        $routes->add('kiwicaptcha_widget_css', new Route(
            $prefix.'/widget.css',
            ['_controller' => [ApiJsController::class, 'widgetCss']],
            [],
            [],
            '',
            [],
            ['GET'],
        ));

        // The versioned immutable asset route (asset_mode "files"): the
        // theme emits {prefix}/assets/{name}.{sha256-64}.{js|css} URLs and
        // the controller serves the exact inline-mode bytes with a long
        // immutable cache lifetime, the full 256-bit content hash in the
        // URL, the content-hash ETag and the Content-Length. The hash is
        // validated before any bytes are served; an unknown hash is a 404.
        // The `name` constraint is the complete asset set: the widget css,
        // the driver js, the lazy WASM runtime js, the same-origin worker
        // js and the lazy execution interpreter js. A Twig-emitted URL
        // must always match this route (the KernelBrowser invariant test
        // asserts every rendered URL is routable), so the constraint is
        // the five names, never a subset.
        $routes->add('kiwicaptcha_asset', new Route(
            $prefix.'/assets/{name}.{hash}.{extension}',
            ['_controller' => [AssetController::class, 'asset']],
            ['name' => 'execution|runtime|widget|driver|worker', 'hash' => '[0-9a-f]{64}', 'extension' => 'js|css'],
            [],
            '',
            [],
            ['GET'],
        ));

        $routes->add('kiwicaptcha_challenge', new Route(
            $prefix.'/challenge',
            ['_controller' => [ChallengeController::class, 'challenge']],
            [],
            [],
            '',
            [],
            ['POST'],
        ));

        // The cancellation endpoint (the exhaustion->debt feedback break):
        // POST-only, bounded body, the same origin checks and a bounded
        // per-source limiter as the challenge endpoint.
        $routes->add('kiwicaptcha_challenge_cancel', new Route(
            $prefix.'/challenge/cancel',
            ['_controller' => [ChallengeController::class, 'cancel']],
            [],
            [],
            '',
            [],
            ['POST'],
        ));

        // Rollback-resistant health split: liveness is never
        // tied to saturation; readiness gate-keeps the security Redis and
        // the central security-policy state. Both are GET-only.
        if ($this->healthEnabled) {
            $routes->add('kiwicaptcha_health_live', new Route(
                $prefix.'/health/live',
                ['_controller' => [KiwiHealthController::class, 'live']],
                [],
                [],
                '',
                [],
                ['GET'],
            ));
            $routes->add('kiwicaptcha_health_ready', new Route(
                $prefix.'/health/ready',
                ['_controller' => [KiwiHealthController::class, 'ready']],
                [],
                [],
                '',
                [],
                ['GET'],
            ));
        }

        return $routes;
    }

    public function supports(mixed $resource, ?string $type = null): bool
    {
        return self::ROUTE_TYPE === $type;
    }
}
