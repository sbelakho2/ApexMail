<?php

declare(strict_types=1);

use BelConsulting\KiwiCaptchaBundle\Controller\StepUpController;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/*
 * The application-side route registration of the journey kernel: the
 * anonymous email pair plus the bundle's own endpoints.
 */
return static function (RoutingConfigurator $routes): void {
    $controller = StepUpController::class;

    $routes->add('kiwi_step_up_email_begin', '/kiwi/step-up/email/begin')
        ->controller($controller.'::emailBegin')
        ->methods(['POST']);

    $routes->add('kiwi_step_up_email_complete', '/kiwi/step-up/email/complete')
        ->controller($controller.'::emailComplete')
        ->methods(['POST']);

    $routes->import('@KiwiCaptchaBundle/Resources/config/routes.php');
};
