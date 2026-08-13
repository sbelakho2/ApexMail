<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

use BelConsulting\KiwiCaptchaBundle\Risk\PrincipalResolverInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Test double: resolves a fixed raw principal for every request, so tests
 * can assert that the gateway's contexts carry the principal pseudonym.
 */
final class FakePrincipalResolver implements PrincipalResolverInterface
{
    public function __construct(private readonly string $principal = 'user-42')
    {
    }

    public function resolve(Request $request, string $scope): ?string
    {
        return $this->principal;
    }
}
