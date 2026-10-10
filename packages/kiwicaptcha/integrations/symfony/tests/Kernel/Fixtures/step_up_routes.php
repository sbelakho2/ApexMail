<?php

declare(strict_types=1);

use BelConsulting\KiwiCaptchaBundle\Controller\StepUpController;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/*
 * The application-side route registration of the step-up endpoints:
 * the documented integration (the bundle exposes the controller as a
 * service; the application wires its own routes at the configured
 * begin_path / complete_path and imports the bundle's routes file).
 */
return static function (RoutingConfigurator $routes): void {
    $routes->add('kiwi_step_up_begin', '/kiwi/step-up/begin')
        ->controller([StepUpController::class, 'begin'])
        ->methods(['GET', 'POST']);

    $routes->add('kiwi_step_up_complete', '/kiwi/step-up/complete')
        ->controller([StepUpController::class, 'complete'])
        ->methods(['GET', 'POST']);

    $routes->import('@KiwiCaptchaBundle/Resources/config/routes.php');
};
