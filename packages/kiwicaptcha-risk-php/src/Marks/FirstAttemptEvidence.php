<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Marks;

/**
 * The first-attempt prevention evidence (D3.5 P0-1): the signals that
 * must stop a valid stolen credential on its very first attempt, before
 * any failure has accumulated anywhere. Each flag is independent
 * evidence for the interactive step-up. It is never a deny: the
 * legitimate owner must always be able to finish the login.
 *
 * - novelNetwork: the principal has never been seen from this network
 *   bucket (/64 or IPv4) OR the account has no prior trusted network,
 *   so the login cannot be vouched for by any network history.
 * - breachedCredential: the presented credential is known-breached
 *   (caller-supplied corpus verdict, same step-up-worthy shape as
 *   honeypot evidence).
 * - scopePressure: the scope failure-ratio pressure is running at/above
 *   MarksEscalation::`SCOPE_PRESSURE`_FLOOR / `SCOPE_PRESSURE`_LEVEL, so
 *   every first-attempt login escalates, not only the attacked
 *   target's.
 * - evidenceUnavailable: a trusted-history probe failed with a store
 *   error, so no read can vouch for the login. Fail closed: the
 *   request counts as novel under enforcement, while learn mode stays
 *   on Allow; the decision carries the evidence-unavailable reason in
 *   both modes.
 * - wouldStepUpUnderEnforce: the unmasked novelty verdict, recorded
 *   before the enforcement mode is applied. The post-Allow binding
 *   reads it to decide whether the login may mint session and device
 *   trust. An Allow that enforce mode would have stepped up records
 *   its bindings without trust, so a novel (deferred) login mints no
 *   trust even in learn mode. The repeat visit from granted history
 *   is the trust-earning event; a credential change revokes the
 *   trust mirrors so the gate re-arms.
 *
 * Rust mirror: marks::FirstAttemptEvidence.
 */
final class FirstAttemptEvidence
{
    public function __construct(
        public readonly bool $novelNetwork = false,
        public readonly bool $breachedCredential = false,
        public readonly bool $scopePressure = false,
        public readonly bool $evidenceUnavailable = false,
        public readonly bool $wouldStepUpUnderEnforce = false,
    ) {
    }

    /** Neutral: no first-attempt evidence at all. */
    public static function zero(): self
    {
        return new self();
    }

    /** True when any first-attempt prevention signal fired. */
    public function requiresStepUp(): bool
    {
        return $this->novelNetwork || $this->breachedCredential || $this->scopePressure;
    }
}
