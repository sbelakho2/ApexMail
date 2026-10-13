<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The typed answer of {@see SessionRestorer::restore()}: whether the
 * pending login unwrapped, and under which status otherwise. The
 * caller, the demand finalizer, journals the session_restored entry
 * only on a landed restore. A refused or failed restore answers no
 * user-visible success: the authorization may be terminal, the session
 * it opens is not. The demand-bound retry exists exactly for that gap.
 */
final class StepUpSessionRestore
{
    /** The pending token unwrapped; the session carries the authenticated identity. */
    public const RESTORED = 'restored';

    /** No pending token stood: a plain step-up inside an already authenticated session. */
    public const NOTHING_PENDING = 'nothing_pending';

    /** Either side named no usable pseudonym, so the equality is unprovable. */
    public const REFUSED_EMPTY_PSEUDONYM = 'refused_empty_pseudonym';

    /** The completed proof belongs to another account: nothing upgrades. */
    public const REFUSED_PRINCIPAL_MISMATCH = 'refused_principal_mismatch';

    /** The proof names a demand other than the one the session pends under. */
    public const REFUSED_DEMAND_MISMATCH = 'refused_demand_mismatch';

    /** The restore itself threw; nothing can be claimed about the session. */
    public const FAILED = 'failed';

    private function __construct(
        public readonly string $status,
    ) {
    }

    public static function restored(): self
    {
        return new self(self::RESTORED);
    }

    public static function nothingPending(): self
    {
        return new self(self::NOTHING_PENDING);
    }

    public static function refusedEmptyPseudonym(): self
    {
        return new self(self::REFUSED_EMPTY_PSEUDONYM);
    }

    public static function refusedPrincipalMismatch(): self
    {
        return new self(self::REFUSED_PRINCIPAL_MISMATCH);
    }

    public static function refusedDemandMismatch(): self
    {
        return new self(self::REFUSED_DEMAND_MISMATCH);
    }

    public static function failed(): self
    {
        return new self(self::FAILED);
    }

    /**
     * Whether the restore landed (or trivially had nothing to restore).
     * A refusal and a failure answer false: the caller must never turn
     * them into user-visible success.
     */
    public function landed(): bool
    {
        return $this->status === self::RESTORED || $this->status === self::NOTHING_PENDING;
    }
}
