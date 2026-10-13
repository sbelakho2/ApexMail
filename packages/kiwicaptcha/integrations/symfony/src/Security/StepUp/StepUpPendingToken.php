<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * The pending step-up token: the two-factor pattern applied to the
 * first-attempt gate. When the engine demands a step-up before the
 * session is granted, the just-created authenticated token is wrapped
 * in this one. The wrapper grants only {@see self::ROLE} — the step-up
 * routes accept that role, every other firewall path does not — and it
 * carries the wrapped token so the real one can be restored after the
 * factor completes.
 */
final class StepUpPendingToken implements TokenInterface
{
    /** The only role the pending token grants. */
    public const ROLE = 'IS_KIWI_STEP_UP_PENDING';

    /**
     * The attribute carrying the risk scope the demand was raised
     * under. The first-attempt gate stamps the scope it resolved for
     * the login (the risk.login_scopes target of the event's firewall)
     * onto the pending token. The step-up flow books its challenge
     * under that scope per event. The attribute is serialized with the
     * token, so the scope survives the session round-trip.
     */
    public const SCOPE_ATTRIBUTE = '_kiwi_step_up_scope';

    /**
     * The attribute carrying the exact demand identity of this pending
     * login. The mint happens at wrap time, so two pending logins of
     * one session always hold two identities. The begin of the factor
     * names this identity as its demand id. The finalization unwraps a
     * pending token only when the demand it finalized is exactly the
     * one the token was wrapped under: completing login A's factor can
     * never restore login B's pending session, even with the same
     * principal, scope and session.
     */
    public const DEMAND_ID_ATTRIBUTE = '_kiwi_step_up_demand_id';

    /** @var array<string, mixed> */
    private array $attributes = [];

    public function __construct(
        private readonly TokenInterface $inner,
        ?string $demandId = null,
    ) {
        // Every pending token carries its demand identity from birth:
        // the caller's exact mint when given, an unguessable fresh one
        // otherwise. The attribute rides the serialized token, so the
        // identity survives the session round-trip.
        $this->attributes[self::DEMAND_ID_ATTRIBUTE] = $demandId !== null && preg_match('/^[A-Za-z0-9_-]{16,43}$/D', $demandId) === 1
            ? $demandId
            : self::mintDemandId();
    }

    /** Mint an unguessable demand id: the base64url of 16 random bytes. */
    public static function mintDemandId(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '=');
    }

    public function getWrapped(): TokenInterface
    {
        return $this->inner;
    }

    /**
     * The risk scope the demand was raised under, null when the token
     * carries none (a token built outside the guard).
     */
    public function scope(): ?string
    {
        $scope = $this->attributes[self::SCOPE_ATTRIBUTE] ?? null;
        if (!\is_string($scope) || $scope === '') {
            return null;
        }
        if (preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $scope) !== 1) {
            return null;
        }

        return $scope;
    }

    /**
     * The exact demand identity of this pending login, null when the
     * attribute is absent or malformed (a token built outside the
     * guard, or a mangled session payload). The finalization compares
     * it with the demand the completed factor names.
     */
    public function demandId(): ?string
    {
        $demand = $this->attributes[self::DEMAND_ID_ATTRIBUTE] ?? null;
        if (!\is_string($demand) || preg_match('/^[A-Za-z0-9_-]{16,43}$/D', $demand) !== 1) {
            return null;
        }

        return $demand;
    }

    public function __toString(): string
    {
        return 'kiwi-step-up-pending('.$this->getUserIdentifier().')';
    }

    public function getUserIdentifier(): string
    {
        return $this->inner->getUserIdentifier();
    }

    /** @return list<string> */
    public function getRoleNames(): array
    {
        return [self::ROLE];
    }

    /**
     * Always null: a pending token is never an authenticated session.
     * Symfony's AuthenticatedVoter treats a token with a user as fully
     * authenticated, so returning the real user here would open every
     * IS_AUTHENTICATED_* route to a credential stuffer holding a
     * pending token. The wrapped token keeps the user for the restore.
     */
    public function getUser(): ?UserInterface
    {
        return null;
    }

    public function setUser(UserInterface $user): void
    {
        $this->inner->setUser($user);
    }

    /**
     * The wrapper holds no credentials of its own, so erasure forwards
     * to the wrapped token (the only place sensitive data can live).
     * Symfony 8 removed eraseCredentials() from TokenInterface, so the
     * forward is guarded: an inner token of a line without the method
     * carries nothing to erase through it.
     */
    public function eraseCredentials(): void
    {
        if (method_exists($this->inner, 'eraseCredentials')) {
            $this->inner->eraseCredentials();
        }
    }

    /** @return array<string, mixed> */
    public function getAttributes(): array
    {
        return $this->attributes;
    }

    /** @param array<string, mixed> $attributes */
    public function setAttributes(array $attributes): void
    {
        $this->attributes = $attributes;
    }

    public function hasAttribute(string $name): bool
    {
        return \array_key_exists($name, $this->attributes);
    }

    public function getAttribute(string $name): mixed
    {
        return $this->attributes[$name] ?? null;
    }

    public function setAttribute(string $name, mixed $value): void
    {
        $this->attributes[$name] = $value;
    }

    /** @return array{inner: TokenInterface, attributes: array<string, mixed>} */
    public function __serialize(): array
    {
        return ['inner' => $this->inner, 'attributes' => $this->attributes];
    }

    /** @param array{inner: TokenInterface, attributes?: array<string, mixed>} $data */
    public function __unserialize(array $data): void
    {
        $this->inner = $data['inner'];
        $this->attributes = $data['attributes'] ?? [];
    }
}
