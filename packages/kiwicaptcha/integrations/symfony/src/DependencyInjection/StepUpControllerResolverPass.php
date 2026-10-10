<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\DependencyInjection;

use BelConsulting\KiwiCaptchaBundle\Controller\StepUpController;
use BelConsulting\KiwiCaptchaBundle\Risk\PrincipalResolverInterface;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Binds the application's principal resolver into the step-up
 * controller. The extension's load-time container view cannot see
 * app-registered services in every kernel timing, so the binding
 * happens here, on the final container. When a
 * PrincipalResolverInterface service exists, the controller resolves
 * its principal through it. Without one the controller keeps the null
 * resolver and refuses begin(), fail-closed: the principal is never
 * client-supplied.
 */
final class StepUpControllerResolverPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        if (!$container->hasDefinition(StepUpController::class)) {
            return;
        }
        if (!$container->has(PrincipalResolverInterface::class)) {
            return;
        }
        $container->getDefinition(StepUpController::class)
            ->setArgument('$principalResolver', new Reference(PrincipalResolverInterface::class));
    }
}
