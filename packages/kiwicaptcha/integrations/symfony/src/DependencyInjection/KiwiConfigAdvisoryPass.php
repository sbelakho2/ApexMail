<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\DependencyInjection;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * No-op compiler pass used only as the log channel for the extension's
 * advisory build notes (ContainerBuilder::log prefixes every message with
 * the pass class name). It is intentionally never registered with the
 * Compiler: it exists so KiwiCaptchaExtension::load() can emit advisory
 * notes about the deployment's secret-derivation defaults without
 * throwing or running any pass logic.
 */
final class KiwiConfigAdvisoryPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        // No-op: the pass is a logging token, not a registered pass.
    }
}
