<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Routing;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Controller\KiwiHealthController;
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
 * affects the ACTUAL routes (not just the widget's requested endpoint).
 *
 * Routes:
 *  - POST  {prefix}/challenge          (the widget's challenge endpoint)
 *  - GET   {prefix}/health/live        (audit #51: liveness — always 200)
 *  - GET   {prefix}/health/ready       (audit #58: readiness — 200 only when
 *                                       signing keys + security Redis + the
 *                                       CENTRAL security-policy state are all
 *                                       compatible; risk.health.enabled
 *                                       defaults true)
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
        $routes->add('kiwicaptcha_challenge', new Route(
            $prefix.'/challenge',
            ['_controller' => [ChallengeController::class, 'challenge']],
            [],
            [],
            '',
            [],
            ['POST'],
        ));

        // Rollback-resistant health split (audit #51/#58): liveness is never
        // tied to saturation; readiness gate-keeps the security Redis + the
        // CENTRAL security-policy state. Both are GET-only.
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
