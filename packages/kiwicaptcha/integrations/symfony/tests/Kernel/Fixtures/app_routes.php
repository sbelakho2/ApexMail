<?php

declare(strict_types=1);

use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\Fixtures\PingController;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/*
 * Stand-in for an APPLICATION's own routing resource (config/routes.yaml in a
 * real app): it defines an app route and imports the KiwiCaptcha bundle's
 * routes manually — the documented fallback for apps that configure
 * framework.router themselves (the extension never overrides an app-owned
 * router resource).
 */
return static function (RoutingConfigurator $routes): void {
    $routes->add('app_ping', '/app/ping')
        ->controller(PingController::class)
        ->methods(['GET']);

    $routes->import('@KiwiCaptchaBundle/Resources/config/routes.php');
};
