<?php

declare(strict_types=1);

use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/*
 * The carrier kernels' routing resource: the bundle's own endpoints
 * plus the shipped step-up resource (the documented one-line import),
 * so the advertised step-up email begin and complete paths are
 * registered the way a real deployment registers them.
 */
return static function (RoutingConfigurator $routes): void {
    $routes->import('@KiwiCaptchaBundle/Resources/config/routes.php');
    $routes->import('@KiwiCaptchaBundle/Resources/config/routes/step_up.php');
};
