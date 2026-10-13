<?php

use BelConsulting\KiwiCaptchaBundle\Controller\StepUpController;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

return static function (RoutingConfigurator $routes): void {
    $routes->add('kiwi_step_up_begin', '/kiwi/step-up/begin')
        ->controller([StepUpController::class, 'begin'])
        ->methods(['POST']);
    $routes->add('kiwi_step_up_complete', '/kiwi/step-up/complete')
        ->controller([StepUpController::class, 'complete'])
        ->methods(['POST']);
    $routes->add('kiwi_step_up_email_begin', '/kiwi/step-up/email/begin')
        ->controller([StepUpController::class, 'emailBegin'])
        ->methods(['POST']);
    $routes->add('kiwi_step_up_email_complete', '/kiwi/step-up/email/complete')
        ->controller([StepUpController::class, 'emailComplete'])
        ->methods(['POST']);
};
