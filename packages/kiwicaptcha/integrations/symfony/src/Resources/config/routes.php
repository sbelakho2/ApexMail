<?php

declare(strict_types=1);

use BelConsulting\KiwiCaptchaBundle\Routing\KiwiCaptchaRouteLoader;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/*
 * Importable routing resource of the KiwiCaptcha bundle.
 *
 * The extension registers this file automatically when the application has
 * not configured framework.router itself (see KiwiCaptchaExtension::prepend).
 * Applications that configure their own router must import it manually:
 *
 *     # config/routes.yaml
 *     kiwi_captcha:
 *         resource: '@KiwiCaptchaBundle/Resources/config/routes.php'
 *
 * The challenge path is taken from the kiwi_captcha.route_prefix option
 * (default /kiwi-captcha), so POST /kiwi-captcha/challenge works out of the
 * box and follows a configured prefix.
 */
return static function (RoutingConfigurator $routes): void {
    $routes->import('@KiwiCaptchaBundle/Routing/KiwiCaptchaRouteLoader.php', 'kiwicaptcha');
};
