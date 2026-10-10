<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The application-level step-up contract of the step-up plane.
 *
 * The adaptive engine names StepUp as a terminal disposition: proof of
 * work alone is judged insufficient for the request and the application
 * must verify the actor through a second factor. The typed entry point
 * is the validator violation `kiwi.post_solve_step_up_required`
 * ({@see \BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED});
 * the application answers it by beginning one of these handlers, then
 * completing it with the proof the user presented.
 *
 * begin() presents the challenge to the user: the returned Response is
 * a rendered form for the html presentation mode of the context, a
 * machine-readable challenge document for the json mode. The begun
 * challenge carries a server-side state record with a bounded TTL and
 * single-use consumption, so a completion can be answered exactly once.
 * complete() verifies the presented proof and, on success, credits the
 * stepUpCompleted outcome for the principal and the target pseudonyms
 * through the outcomes plane, so a legitimate user is not demanded a
 * second step-up while the credited trust holds.
 *
 * Reference handlers: the email one-time-passcode handler and the
 * time-based one-time passcode handler of RFC 6238. The WebAuthn
 * handler is the phishing-resistant target of the plane; see
 * {@see WebAuthnStepUpHandler} for its deliberately bounded state.
 */
interface StepUpHandlerInterface
{
    /**
     * Begin one challenge for the context's principal and present it to
     * the user. The Response may be an interaction surface (a rendered
     * form, a json challenge document) or a refusal: a rate-bound
     * refusal answers the 429 status with a retry window, fail-closed.
     *
     * The begun challenge is single-use and replay safe: the server-side
     * state record is consumed by exactly one completion, and the
     * client-carrying half is a signed, expiry-bounded ticket it cannot
     * alter or extend.
     */
    public function begin(Request $request, StepUpContext $context): Response;

    /**
     * Complete the challenge of the request and answer its verdict.
     *
     * A succeeded verdict credits the principal (and the target when
     * the context carried one) with the stepUpCompleted outcome, with an
     * idempotency key derived from the challenge record id, so a
     * replayed or double completion can never double-credit. A failed
     * verdict is terminal for that challenge; a pending verdict leaves
     * the challenge live within its attempt cap.
     */
    public function complete(Request $request): StepUpResult;
}
