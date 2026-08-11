<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel\Fixtures;

use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * Stand-in for an application's own controller, referenced by the
 * application's routing resource (app_routes.php). No constructor args, so
 * the framework can instantiate it without a service definition.
 */
final class PingController
{
    public function __invoke(): JsonResponse
    {
        return new JsonResponse(['ok' => true]);
    }
}
