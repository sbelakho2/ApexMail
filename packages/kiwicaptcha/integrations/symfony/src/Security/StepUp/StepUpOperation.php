<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The protected operation a step-up demand binds to, resolved at the
 * boundary the application owns. Three values:
 *
 *  - logicalOperationId: the server-owned unique idempotency key the
 *    application minted for this logical operation, carried by a
 *    request attribute the application sets, never a raw client field.
 *  - canonicalProtectedContents: the canonical string over the
 *    business contents the scope's recipe names (amount, currency,
 *    beneficiary, ...), built by the shared canonicalizer of
 *    StepUpOperationDigest.
 *  - principal: the authenticated principal pseudonym the operation
 *    belongs to, null when nothing resolves.
 *
 * The mint hashes the identity and content digests over the first two
 * values; the finalization rerun hashes the same bytes again, so a
 * changed amount, currency or beneficiary can never ride an
 * authorization minted for the original contents.
 */
final class StepUpOperation
{
    public function __construct(
        public readonly string $logicalOperationId,
        public readonly string $canonicalProtectedContents,
        public readonly ?string $principal = null,
    ) {
    }
}
