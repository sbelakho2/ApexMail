<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The application-level step-up contract of the step-up plane, under
 * the demand architecture: a handler is a factor. begin() presents the
 * factor challenge, complete() verifies the presented proof and
 * answers the verified factor proof. A completion is never an
 * authorization: the factor books no outcome and restores no session.
 * The authorization lives in the demand plane: the proof names the
 * demand it answers, the demand is completed atomically with the
 * proof, and the shared {@see StepUpDemandFinalizer} reassesses and,
 * only when authorized, books the completion effects. The typed entry
 * point of the flow is the validator violation
 * `kiwi.post_solve_step_up_required`
 * ({@see \BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED}).
 * The application answers it by beginning one of these handlers, then
 * completing it with the proof the user presented.
 *
 * begin() presents the challenge to the user: the returned Response is
 * a rendered form for the html presentation mode of the context, a
 * machine-readable challenge document for the json mode. The begun
 * challenge carries a server-side state record with a bounded TTL and
 * single-use consumption, so a completion can be answered exactly
 * once. The challenge also carries the demandId of the context: it is
 * bound to the demand it answers, and a proof of an unbound challenge
 * finalizes nothing.
 *
 * Reference handlers: the email one-time-passcode handler and the
 * time-based one-time passcode handler of RFC 6238. The WebAuthn
 * handler is the phishing-resistant target of the plane; see
 * {@see WebAuthnStepUpHandler} for its deliberately bounded state.
 * Custom handlers implement the same contract through the same
 * mechanism: the demandId rides the context and the challenge record,
 * so a custom handler cannot bypass the demand plane.
 */
interface StepUpHandlerInterface
{
    /**
     * The server-owned identity of the factor: the name the rest of
     * the plane spells it with (the registry key, the session success
     * markers, the enrollment factor floors). Never client-chosen.
     */
    public function assurance(): StepUpFactorAssurance;

    /**
     * Begin one challenge for the context's principal and present it to
     * the user. The Response may be an interaction surface (a rendered
     * form, a json challenge document) or a refusal: a rate-bound
     * refusal answers the 429 status with a retry window, fail-closed.
     *
     * The begun challenge is single-use and replay safe: the server-side
     * state record is consumed by exactly one completion, and the
     * client-carrying half is a signed, expiry-bounded ticket it cannot
     * alter or extend. The challenge binds the demandId of the context,
     * so its proof can only ever answer that demand.
     */
    public function begin(Request $request, StepUpContext $context): Response;

    /**
     * Complete the challenge of the request and answer the verified
     * factor proof.
     *
     * A succeeded verdict is the factor's proof only: it names the
     * demand the challenge was bound to and carries the assurance of
     * the factor, and it books nothing. The demand finalization
     * (reassessment, the terminal settlement and the completion
     * effects) is the finalizer's work, never the handler's. A failed
     * verdict is terminal for that challenge; a pending verdict leaves
     * the challenge live within its attempt cap.
     */
    public function complete(Request $request): StepUpResult;
}
