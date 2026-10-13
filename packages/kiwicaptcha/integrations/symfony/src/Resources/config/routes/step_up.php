<?php

declare(strict_types=1);

use BelConsulting\KiwiCaptchaBundle\Controller\StepUpController;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOwnershipStepUp;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/*
 * Importable step-up routing resource of the KiwiCaptcha bundle.
 *
 * The step-up endpoints are application-facing: their chrome, paths
 * and access control belong to the application's own auth flow. They
 * are therefore NOT part of the bundle's default route loader. This
 * file ships the documented default paths. A deployment registers
 * them with one import instead of hand-writing four routes.
 *
 *     # config/routes.yaml
 *     kiwi_captcha_step_up:
 *         resource: '@KiwiCaptchaBundle/Resources/config/routes/step_up.php'
 *
 * Routes:
 *  - GET/POST {app}/kiwi/step-up/begin          kiwi_step_up_begin.
 *  - GET/POST {app}/kiwi/step-up/complete       kiwi_step_up_complete.
 *  - POST    {app}/kiwi/step-up/email/begin     kiwi_step_up_email_begin.
 *  - POST    {app}/kiwi/step-up/email/complete  kiwi_step_up_email_complete.
 *
 * The email begin path is the one the step-up 403 body advertises
 * (EmailOwnershipStepUp::BEGIN_PATH). The anonymous visitor the body
 * addresses can always reach the factor. The principal begin and
 * complete belong behind the application's authentication firewall:
 * the principal is resolved server-side through the wired resolver,
 * never from a client-supplied field. The paths must equal the
 * risk.step_up begin_path / complete_path knobs, or those knobs must
 * point at the application's own paths.
 */
return static function (RoutingConfigurator $routes): void {
    $controller = StepUpController::class;

    $routes->add('kiwi_step_up_begin', '/kiwi/step-up/begin')
        ->controller($controller.'::begin')
        ->methods(['GET', 'POST']);

    $routes->add('kiwi_step_up_complete', '/kiwi/step-up/complete')
        ->controller($controller.'::complete')
        ->methods(['GET', 'POST']);

    $routes->add('kiwi_step_up_email_begin', EmailOwnershipStepUp::BEGIN_PATH)
        ->controller($controller.'::emailBegin')
        ->methods(['POST']);

    $routes->add('kiwi_step_up_email_complete', EmailOwnershipStepUp::COMPLETE_PATH)
        ->controller($controller.'::emailComplete')
        ->methods(['POST']);
};
