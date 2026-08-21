<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Routing;

use BelConsulting\KiwiCaptchaBundle\Controller\ApiJsController;
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

        $routes->add('kiwicaptcha_challenge', new Route(
            $prefix.'/challenge',
            ['_controller' => [ChallengeController::class, 'challenge']],
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
