<?php

declare(strict_types=1);

/**
 * Test shims of the security bundle's event classes.
 *
 * The bundle does not depend on symfony/security-http, so the outcome
 * bridge duck-types the events and the extension gates the bridge on
 * the classes existing. This file provides the three event classes plus
 * the passport and user badge with the accessor surface of the real
 * classes, loaded explicitly by the bridge tests through require_once
 * so the class_exists wiring gates resolve to true. Nothing outside the
 * bridge tests dispatches these events; when a project installs the
 * real security bundle its autoloaded classes never collide with these
 * (the file is required only by tests that also assert the classes were
 * absent first).
 */

namespace Symfony\Component\Security\Http\Authenticator\Passport\Badge {

    final class UserBadge
    {
        private ?object $user = null;

        public function __construct(
            private readonly string $identifier,
            private readonly ?\Closure $userLoader = null,
        ) {
        }

        public function getUserIdentifier(): string
        {
            return $this->identifier;
        }

        /**
         * The lazy user resolution of the real badge: the loader runs
         * once, a resolution error throws (the bridge observes it and
         * swallows its own probe).
         */
        public function getUser(): object
        {
            if ($this->user !== null) {
                return $this->user;
            }
            if ($this->userLoader === null) {
                throw new \LogicException('no user loader');
            }
            $user = ($this->userLoader)($this->identifier);
            if (!\is_object($user)) {
                throw new \Symfony\Component\Security\Core\Exception\UsernameNotFoundException();
            }
            $this->user = $user;

            return $this->user;
        }
    }
}

namespace Symfony\Component\Security\Core\Exception {

    class AuthenticationException extends \RuntimeException
    {
    }

    class UsernameNotFoundException extends AuthenticationException
    {
    }
}

namespace Symfony\Component\Security\Http\Authenticator\Passport {

    use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

    final class Passport
    {
        /** @param array<string, object> $badges */
        public function __construct(
            private readonly array $badges = [],
        ) {
        }

        public function getBadge(string $badgeClass): ?object
        {
            return $this->badges[$badgeClass] ?? null;
        }
    }
}

namespace Symfony\Component\Security\Http\Event {

    use Symfony\Component\HttpFoundation\Request;
    use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

    final class LoginSuccessEvent
    {
        public function __construct(
            private readonly Request $request,
            private readonly object $user,
        ) {
        }

        public function getRequest(): Request
        {
            return $this->request;
        }

        public function getUser(): object
        {
            return $this->user;
        }
    }

    final class LoginFailureEvent
    {
        public function __construct(
            private readonly \Throwable $exception,
            private readonly Request $request,
            private readonly string $firewallName = 'main',
        ) {
        }

        public function getException(): \Throwable
        {
            return $this->exception;
        }

        public function getRequest(): Request
        {
            return $this->request;
        }

        public function getFirewallName(): string
        {
            return $this->firewallName;
        }
    }

    final class CheckPassportEvent
    {
        public function __construct(
            private readonly Passport $passport,
            private readonly Request $request,
        ) {
        }

        public function getPassport(): Passport
        {
            return $this->passport;
        }

        public function getRequest(): Request
        {
            return $this->request;
        }
    }
}
