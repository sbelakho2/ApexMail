<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpPendingToken;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpPendingTokenVoter;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * The pending token must never pass an IS_AUTHENTICATED_* check: a
 * credential stuffer holding a pending token is not a session.
 */
final class StepUpPendingTokenVoterTest extends TestCase
{
    public function testAPendingTokenIsNeverAuthenticated(): void
    {
        $inner = new class implements TokenInterface {
            private array $attributes = [];

            public function __toString(): string
            {
                return 't';
            }

            public function getUserIdentifier(): string
            {
                return 'user-42';
            }

            public function getRoleNames(): array
            {
                return ['ROLE_USER'];
            }

            public function getUser(): ?UserInterface
            {
                return null;
            }

            public function setUser(UserInterface $user): void
            {
            }

            public function getAttributes(): array
            {
                return $this->attributes;
            }

            public function setAttributes(array $attributes): void
            {
                $this->attributes = $attributes;
            }

            public function hasAttribute(string $name): bool
            {
                return isset($this->attributes[$name]);
            }

            public function getAttribute(string $name): mixed
            {
                return $this->attributes[$name] ?? null;
            }

            public function setAttribute(string $name, mixed $value): void
            {
                $this->attributes[$name] = $value;
            }

            public function __serialize(): array
            {
                return ['attributes' => $this->attributes];
            }

            public function __unserialize(array $data): void
            {
                $this->attributes = $data['attributes'] ?? [];
            }
        };
        $token = new StepUpPendingToken($inner);
        $voter = new StepUpPendingTokenVoter();

        self::assertSame(VoterInterface::ACCESS_DENIED, $voter->vote($token, null, ['IS_AUTHENTICATED_FULLY']));
        self::assertSame(VoterInterface::ACCESS_DENIED, $voter->vote($token, null, ['IS_AUTHENTICATED']));
        self::assertSame(VoterInterface::ACCESS_DENIED, $voter->vote($token, null, ['IS_AUTHENTICATED_REMEMBERED']));
        self::assertSame(VoterInterface::ACCESS_ABSTAIN, $voter->vote($token, null, ['ROLE_USER']));
    }

    public function testAPendingTokenExposesNoUser(): void
    {
        $inner = new class implements TokenInterface {
            private array $attributes = [];
            public function __toString(): string { return 't'; }
            public function getUserIdentifier(): string { return 'user-42'; }
            public function getRoleNames(): array { return ['ROLE_USER']; }
            public function getUser(): ?UserInterface { return null; }
            public function setUser(UserInterface $user): void {}
            public function getAttributes(): array { return $this->attributes; }
            public function setAttributes(array $attributes): void { $this->attributes = $attributes; }
            public function hasAttribute(string $name): bool { return isset($this->attributes[$name]); }
            public function getAttribute(string $name): mixed { return $this->attributes[$name] ?? null; }
            public function setAttribute(string $name, mixed $value): void { $this->attributes[$name] = $value; }
            public function __serialize(): array { return ['attributes' => $this->attributes]; }
            public function __unserialize(array $data): void { $this->attributes = $data['attributes'] ?? []; }
        };
        $token = new StepUpPendingToken($inner);
        self::assertNull($token->getUser(), 'a pending token must expose no user so AuthenticatedVoter never grants IS_AUTHENTICATED_*');
        self::assertSame('user-42', $token->getUserIdentifier(), 'the identifier survives for the restore');
    }
}
