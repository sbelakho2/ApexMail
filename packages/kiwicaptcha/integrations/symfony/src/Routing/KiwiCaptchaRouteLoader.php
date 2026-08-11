<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Routing;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use Symfony\Component\Config\Loader\Loader;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;

/**
 * Registers the challenge endpoint route with the bundle's configured prefix.
 *
 * A #[Route] attribute on the controller is NOT sufficient for a bundle:
 * attribute routes are only discovered for the application's own
 * src/Controller directory, never for vendor bundle directories. This loader
 * is the bundle-owned source of truth for the route, and the path is built
 * from the `kiwi_captcha.route_prefix` config option so the configured prefix
 * affects the ACTUAL route (not just the widget's requested endpoint).
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

    public function __construct(private readonly string $routePrefix)
    {
    }

    public function load(mixed $resource, ?string $type = null): RouteCollection
    {
        if ($this->isLoaded) {
            throw new \RuntimeException('Do not add the "kiwicaptcha" route loader twice.');
        }
        $this->isLoaded = true;

        $routes = new RouteCollection();
        $routes->add('kiwicaptcha_challenge', new Route(
            rtrim($this->routePrefix, '/').'/challenge',
            ['_controller' => [ChallengeController::class, 'challenge']],
            [],
            [],
            '',
            [],
            ['POST'],
        ));

        return $routes;
    }

    public function supports(mixed $resource, ?string $type = null): bool
    {
        return self::ROUTE_TYPE === $type;
    }
}
