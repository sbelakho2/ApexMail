<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\Authority;

/**
 * The typed refusal of the authority-transition guard: the authority
 * the deployment is pinned to and the authority that is serving now
 * differ, or the pinned authority can no longer be verified.
 *
 * The message always names the pinned vs observed identity and the
 * remediation (re-pin explicitly after a deliberate authority change).
 * The bundle's guard wiring treats the exception as a hard stop: a
 * durability-critical transition must never execute on a changed
 * authority.
 */
final class PinnedAuthorityRefusalException extends \LogicException
{
    public function __construct(
        string $message,
        private readonly ?string $pinnedIdentity = null,
        private readonly ?string $observedIdentity = null,
    ) {
        parent::__construct($message);
    }

    /**
     * The pinned identity ("role|run_id") the deployment was pinned to,
     * or null when no pin was ever established.
     */
    public function pinnedIdentity(): ?string
    {
        return $this->pinnedIdentity;
    }

    /**
     * The identity observed at refusal time, or null when the identity
     * could not be read at all.
     */
    public function observedIdentity(): ?string
    {
        return $this->observedIdentity;
    }
}
