<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * The durable post-solve disposition record behind one nonce: the store's
 * claim state (pending = a computation is in flight / complete = the final
 * disposition is persisted), the claim owner and lease deadline while
 * pending, the final disposition once complete, and the ORIGINAL pre-issue
 * decision handle the first owner consumed (the handle survives in the
 * pending claim so a crash-taken-over computation keeps it; the complete
 * record keeps it too).
 */
final readonly class PostSolveDispositionRecord
{
    public function __construct(
        public string $state,
        public ?string $owner = null,
        public ?int $leaseUntil = null,
        public ?PostSolveDisposition $disposition = null,
        public ?string $decisionId = null,
    ) {
    }
}
