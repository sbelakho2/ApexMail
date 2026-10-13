<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The delivery identity one code send rides on: the demand that funds
 * it and the escalation generation the demand belongs to.
 *
 * The mailer-backed sender derives the Message-ID from this identity:
 * `<kiwi.<base64urlDemandId>.<generation>@message-id-domain>`. Every
 * delivered code therefore carries a stable, server-minted id, and every
 * value in the id is transport-safe by construction: the demand id is
 * base64url (no colons), the generation is an integer, and the domain
 * is the configured From identity's domain. A raw `demand:generation`
 * spelling would be invalid: a colon is not allowed in the dot-atom
 * local part of a Message-ID.
 *
 * The generation-bound reservation id of the mail quota
 * (`<demandId>.<generation>.<send>`) rides the same identity, so a
 * quota reservation and the message that spends it are auditable as
 * one unit.
 */
final class EmailOwnershipDeliveryMetadata
{
    public function __construct(
        public readonly string $demandId,
        public readonly int $generation,
        /** The delivery index inside the demand: 1 for the initial code, 2 for the bounded resend. */
        public readonly int $sendIndex,
    ) {
        if (preg_match('/^[A-Za-z0-9_-]{16,43}$/D', $this->demandId) !== 1) {
            throw new \InvalidArgumentException('The delivery metadata demand id must be the base64url id shape');
        }
        if ($this->generation < 0 || $this->generation > StepUpDemand::MAX_GENERATION) {
            throw new \InvalidArgumentException('The delivery metadata generation must be within the escalation depth');
        }
        if ($this->sendIndex < 1 || $this->sendIndex > StepUpDemand::MAX_SENDS) {
            throw new \InvalidArgumentException('The delivery metadata send index must be one funded delivery');
        }
    }

    /**
     * The generation-bound quota reservation id of this delivery:
     * `<base64urlDemandId>.<generation>.<sendIndex>`, dot-atom safe.
     */
    public function reservationId(): string
    {
        return $this->demandId.'.'.$this->generation.'.'.$this->sendIndex;
    }

    /**
     * The Message-ID local part of the delivery:
     * `kiwi.<base64urlDemandId>.<generation>`. Colons never appear: the
     * demand id is base64url and the rest is a dot-separated integer.
     */
    public function messageIdLocalPart(): string
    {
        return 'kiwi.'.$this->demandId.'.'.$this->generation;
    }
}
