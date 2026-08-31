<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\Authority;

/**
 * The authority-transition guard seam (docs/ha-authority.md): the
 * runtime enforcement point for the authority-change replay posture.
 *
 * Every durability-critical Redis-backed service in the bundle
 * (storage, rate limit, Argon admission, risk state) is constructed
 * through a checked-client wrapper that calls this guard with the
 * actual client instance. Every wiring path therefore passes through
 * it: DSN-built clients, explicit service ids, aliases, decorators,
 * custom factories and env-resolved constructions. The compile-time
 * classifier sees only definition shapes and skips env-resolved
 * postures, so it is early UX only; this interface is the boundary.
 *
 * Implementations:
 *  - {@see RuntimeAuthorityClassifier} is the default: it classifies
 *    the live connection and refuses under replay_durability
 *    "fail_closed" when the client is an automatic-failover aggregate
 *    or uninspectable, with the typed LogicException naming the
 *    posture, the classification and the remediation. Under
 *    operator_managed and best_effort every classification serves and
 *    the doctor carries the deployment contract.
 *  - {@see PinnedPrimaryAuthorityGuard} is the pinned-primary
 *    variant: it pins the serving authority on first use and refuses
 *    on any change, making the operator contract mechanical.
 *
 * The refusal contract is deliberately strict: the guard can only
 * fail closed, and an unverifiable authority is treated as unsafe.
 */
interface AuthorityTransitionGuard
{
    /**
     * Refuse to serve when the client's authority-transition semantics
     * are unsafe under the deployment posture.
     *
     * @param mixed $client        the actual constructed client that is
     *        about to serve durability-critical transitions
     * @param bool  $securityFinal true when the operation about to
     *        execute is a mutating security-final transition (a
     *        consume, a committed result, a chain or idempotency
     *        finalize). Implementations bypass their verification cache
     *        for this lane, so a security-final transition can never
     *        execute on a changed authority within a stale window.
     *
     * @throws \LogicException with the posture, the classification and
     *                         the remediation when the client must not
     *                         serve
     */
    public function assertServeEligible(mixed $client, bool $securityFinal = false): void;
}
