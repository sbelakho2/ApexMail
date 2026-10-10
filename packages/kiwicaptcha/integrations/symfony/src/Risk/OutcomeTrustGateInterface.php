<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * The success-trust rule of the outcomes plane: an authenticationSuccess
 * always credits the principal. It credits the session and the source
 * only when the identity's windowed failure ratio is below the
 * deployment threshold and the target was not under attack.
 *
 * The authoritative home of the rule is the core's apply-feedback path
 * (the Rust and PHP engines); this interface is the bridge-level gate
 * that decides which identity material a bridge report carries at all.
 * The data-backed binding is {@see StoreBackedOutcomeTrustGate}, over
 * the bridge-observed {@see AuthOutcomeWindowInterface} and the risk
 * store's marks surface; {@see FailClosedOutcomeTrustGate} remains the
 * no-evidence fallback and refuses credit unconditionally. The
 * principal credit is unconditional in every binding.
 */
interface OutcomeTrustGateInterface
{
    /**
     * True when this authentication success may also credit the session
     * and the source dimension of the identity.
     *
     * @param string $principalPseudonym the principal pseudonym the
     *                                   report addresses.
     * @param string|null $sessionPseudonym the session pseudonym whose
     *                                      windowed history decides the
     *                                      credit, null when the request
     *                                      carries no continuity cookie.
     * @param string|null $targetPseudonym the target pseudonym of the
     *                                     same flow when one was
     *                                     derived, null otherwise.
     */
    public function allowsSessionSourceCredit(string $principalPseudonym, ?string $sessionPseudonym, ?string $targetPseudonym): bool;
}
