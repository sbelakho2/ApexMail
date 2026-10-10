<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

use BelConsulting\KiwiCaptchaBundle\Risk\PrincipalResolverInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * The typical application principal resolver: the authenticated user of
 * the current token, exactly like $security->getUser(). A pending token
 * deliberately answers no user (it must never pass IS_AUTHENTICATED_*
 * checks), so this resolver returns null until the step-up controller
 * unwraps the pending token for the duration of the resolution.
 */
final class TokenStoragePrincipalResolver implements PrincipalResolverInterface
{
    public function __construct(
        private readonly TokenStorageInterface $tokenStorage,
    ) {
    }

    public function resolve(Request $request, string $scope): ?string
    {
        $user = $this->tokenStorage->getToken()?->getUser();
        if ($user instanceof UserInterface) {
            $id = $user->getUserIdentifier();

            return $id !== '' ? $id : null;
        }

        return null;
    }
}
