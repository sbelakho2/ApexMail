<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The RFC 6238 time-based one-time passcode reference handler. A 30 s
 * step, a plus-or-minus one step acceptance window, and a replay guard
 * that refuses the same time-step twice per principal. The algorithm
 * is in-bundle ({@see TotpCode}, hash_hmac based, SHA-1 or SHA-256,
 * with the base32 codec of RFC 4648), so this handler adds no composer
 * dependency.
 *
 * Enrollment surface: enroll() generates a fresh 160-bit secret,
 * persists it server-side keyed by the principal pseudonym and answers
 * its base32 form for the application to render. A QR label is the
 * application's own surface. The secret is sealed at rest with
 * XSalsa20-Poly1305 (sodium_crypto_secretbox) under a seal key derived
 * from the step-up master and bound to the owning principal's
 * pseudonym, so a ciphertext copied across principal slots never
 * decrypts; only the sealed blob is ever persisted. Unsealing a value
 * this key cannot open (data predating the seal, a tampered store, a
 * cross-principal transplant) fails closed with the typed
 * {@see TotpSecretUnsealException}, which complete() maps to a typed
 * failure verdict, never an uncaught error.
 *
 * The completion credit runs through {@see StepUpCompletionCredit} on
 * the one consumed record, exactly once per challenge.
 */
final class TotpStepUpHandler implements StepUpHandlerInterface
{
    public const TICKET_FIELD = 'kiwi_step_up_ticket';
    public const CODE_FIELD = 'kiwi_step_up_code';

    private const SECRET_BYTES = 20;

    /** How far back a completed session step-up may authorize enrollment. */
    private const ENROLLMENT_LOOKBACK_SECS = 900;

    public function __construct(
        private readonly StepUpChallengeStore $store,
        private readonly StepUpTicket $ticket,
        private readonly StepUpCompletionCredit $credit,
        private readonly string $algo = 'sha1',
        private readonly int $digits = 6,
        private readonly int $window = 1,
        private readonly int $challengeTtlSecs = 300,
        private readonly int $maxAttempts = 5,
        private readonly int $maxBegins = 3,
        private readonly int $beginWindowSecs = 900,
        private readonly string $completePath = '/kiwi/step-up/complete',
        private readonly ?\Closure $now = null,
        private readonly string $master = '',
        private readonly ?StepUpLockoutGuard $lockout = null,
        private readonly ?StepUpOwnerNotifier $ownerNotifier = null,
        private readonly ?StepUpBootstrapGate $bootstrapGate = null,
    ) {
        if ($master === '') {
            throw new \InvalidArgumentException('The time-based handler needs the step-up master so enrollment secrets are sealed at rest; pass the same master the ticket service uses');
        }
        if (!\in_array($this->algo, ['sha1', 'sha256'], true)) {
            throw new \InvalidArgumentException('The RFC 6238 algorithm must be sha1 or sha256');
        }
        if ($digits !== 6 && $digits !== 8) {
            throw new \InvalidArgumentException('The code length must be 6 or 8 digits');
        }
        if ($window < 0 || $window > 2) {
            throw new \InvalidArgumentException('The acceptance window must be 0..2 steps');
        }
    }

    /**
     * The at-rest seal key: HKDF over the step-up master, purpose-
     * separated AND bound to the owning principal's pseudonym (the
     * pseudonym rides the HKDF info), so a sealed secret transplanted
     * into another principal's record slot never decrypts.
     */
    private function sealKey(string $principalPseudonym): string
    {
        return hash_hkdf('sha256', $this->master, 32, 'kiwi/v2/totp-seal|'.$principalPseudonym, 'kiwicaptcha/deploy-salt/v1');
    }

    /**
     * Seal a fresh secret for its owning principal: base64(nonce ||
     * ciphertext), never plaintext at rest.
     */
    private function seal(string $secret, string $principalPseudonym): string
    {
        $nonce = random_bytes(\SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        return base64_encode($nonce.sodium_crypto_secretbox($secret, $nonce, $this->sealKey($principalPseudonym)));
    }

    /**
     * Unseal a stored secret under the owning principal's key. A value
     * this key cannot open (data written before sealing existed, a
     * tampered store, or a ciphertext copied across principal slots)
     * fails closed with the typed {@see TotpSecretUnsealException}: the
     * operator re-enrolls the account rather than the deployment
     * silently downgrading to plaintext or erroring as a 500.
     *
     * @throws TotpSecretUnsealException when the stored value cannot be decrypted for this principal
     */
    private function unseal(string $sealed, string $principalPseudonym): string
    {
        $blob = base64_decode($sealed, true);
        if (\is_string($blob) && \strlen($blob) > \SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            $nonce = substr($blob, 0, \SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $plain = sodium_crypto_secretbox_open(substr($blob, \SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), $nonce, $this->sealKey($principalPseudonym));
            if ($plain !== false) {
                return $plain;
            }
        }

        throw new TotpSecretUnsealException('The stored time-based secret could not be decrypted for this principal; the account must re-enroll its passcode (legacy plaintext data, tampered record, or a cross-principal transplant)');
    }

    /**
     * Enroll (or re-enroll) the principal: a fresh 160-bit secret is
     * generated, stored keyed by the principal pseudonym and answered
     * in base32 for the application's provisioning surface (a QR code,
     * a manual-entry block). Re-enrollment overwrites the stored
     * secret, sealed at rest; the replay guard is left untouched.
     *
     * Every enrollment (first OR re-enroll) demands a step-up completed
     * in this session within the lookback window, the same rule as the
     * WebAuthn enrollment surface. A first enrollment with no step-up is
     * exactly the credential-stuffing takeover path (a stolen password
     * plants the attacker's own authenticator), so it is refused like a
     * cross-session re-enroll. The factor floor is strongest-factor:
     * re-enrollment must prove with the current totp factor, a first
     * enrollment with any already-established factor (email_otp is the
     * weakest, so `minFactor = 'email_otp'` accepts any enrolled
     * factor). A principal-level success marker never authorizes
     * enrollment, only the session-scoped one does.
     *
     * @param string|null $sessionId the PHP session requesting enrollment;
     *                               required for any enrollment (first or
     *                               re-enroll) so only that session's own
     *                               completed step-up can authorize it.
     */
    public function enroll(string $principalPseudonym, ?string $sessionId = null): string
    {
        self::assertPseudonym($principalPseudonym);
        $sessionId = (string) $sessionId;
        $now = $this->now();
        $hasSecret = $this->store->findTotpSecret($principalPseudonym) !== null;
        $minFactor = $hasSecret ? 'totp' : 'email_otp';
        // First enrollment only: a re-enroll always needs a completed
        // step-up with the current factor. The bootstrap grant is
        // single-use, session-scoped and expires after 15 minutes.
        $bootstrapOk = !$hasSecret
            && $this->bootstrapGate?->allowsFirstEnrollment(null, $principalPseudonym) === true;
        if ($sessionId === ''
            || (!$bootstrapOk && !$this->store->recentSessionStepUpSuccess($sessionId, $principalPseudonym, $minFactor, self::ENROLLMENT_LOOKBACK_SECS, $now))) {
            throw new \RuntimeException(
                $hasSecret
                    ? 'Re-enrolling the time-based passcode needs a step-up completed in this session with the current factor first.'
                    : 'Enrolling the time-based passcode needs a step-up completed in this session with an already-established factor first.',
            );
        }
        $secret = random_bytes(self::SECRET_BYTES);
        $this->store->saveTotpSecret($principalPseudonym, $this->seal($secret, $principalPseudonym));
        try {
            $this->ownerNotifier?->notifyFactorEnrolled($principalPseudonym, 'totp');
        } catch (\Throwable) {
        }

        return TotpCode::base32Encode($secret);
    }

    /** Whether the principal carries an enrollment secret. */
    public function isEnrolled(string $principalPseudonym): bool
    {
        self::assertPseudonym($principalPseudonym);

        return $this->store->findTotpSecret($principalPseudonym) !== null;
    }

    public function begin(Request $request, StepUpContext $context): Response
    {
        $now = $this->now();
        if (!$this->isEnrolled($context->principalPseudonym)) {
            return $this->refusal(
                $context,
                Response::HTTP_CONFLICT,
                'step_up_not_enrolled',
                'This account has no enrolled authenticator; enroll one before step-up.',
            );
        }
        $contextKey = StepUpLockoutGuard::contextKeyOf($request);
        $trusted = $this->lockout?->isTrustedContext($request, $context->principalPseudonym, $now) ?? false;
        $retryAfter = $this->lockout?->retryAfterSecs($context->principalPseudonym, $context->targetPseudonym, $now, $contextKey, $trusted) ?? 0;
        if ($retryAfter > 0) {
            return $this->refusal(
                $context,
                Response::HTTP_TOO_MANY_REQUESTS,
                'step_up_locked_out',
                'Too many failed verification attempts; retry after the lockout window.',
                ['Retry-After' => (string) $retryAfter],
            );
        }
        $admissions = $this->store->countBegin($context->principalPseudonym, $this->beginWindowSecs);
        if ($admissions > $this->maxBegins) {
            return $this->refusal(
                $context,
                Response::HTTP_TOO_MANY_REQUESTS,
                'step_up_rate_limited',
                'Too many step-up challenges were begun for this account; retry after the window.',
                ['Retry-After' => (string) $this->beginWindowSecs],
            );
        }

        $challenge = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::Totp,
            $context->principalPseudonym,
            $context->targetPseudonym,
            $context->scope,
            $context->returnPath,
            $context->reason,
            $now,
            $this->challengeTtlSecs,
            $this->maxAttempts,
            null,
            null,
            StepUpSessionBinding::sessionId($request),
            $context->targetOwned,
        );
        $this->store->create($challenge, $this->challengeTtlSecs);

        return $this->presentation($context, $challenge, $now);
    }

    public function complete(Request $request): StepUpResult
    {
        $boundSessionId = StepUpSessionBinding::sessionId($request);
        $boundContextKey = StepUpLockoutGuard::contextKeyOf($request);
        $now = $this->now();
        $resolved = $this->challengeOfRequest($request, $now);
        if ($resolved instanceof StepUpChallengeExpired) {
            return StepUpResult::failed(StepUpResult::FAIL_EXPIRED);
        }
        if ($resolved === null) {
            return StepUpResult::failed(StepUpResult::FAIL_UNKNOWN_CHALLENGE);
        }
        $challenge = $resolved;
        if ($challenge->kind !== StepUpChallengeKind::Totp) {
            return StepUpResult::failed(StepUpResult::FAIL_UNKNOWN_CHALLENGE, $challenge->id);
        }
        // The completion is bound to the session that began the
        // challenge: a ticket presented under another principal is
        // refused before any code is compared.
        if (!StepUpSessionBinding::matches($request, $challenge)) {
            return StepUpResult::failed(StepUpResult::FAIL_SESSION_MISMATCH, $challenge->id);
        }
        $trusted = $this->lockout?->isTrustedContext($request, $challenge->principalPseudonym, $now) ?? false;
        $retryAfter = $this->lockout?->retryAfterSecs($challenge->principalPseudonym, $challenge->targetPseudonym, $now, $boundContextKey, $trusted) ?? 0;
        if ($retryAfter > 0) {
            return StepUpResult::failed(StepUpResult::FAIL_LOCKED_OUT, $challenge->id);
        }
        if ($challenge->expired($now)) {
            $this->store->consume($challenge->id);

            return StepUpResult::failed(StepUpResult::FAIL_EXPIRED, $challenge->id);
        }
        $stored = $this->store->findTotpSecret($challenge->principalPseudonym);
        if ($stored === null) {
            $this->store->consume($challenge->id);

            return StepUpResult::failed(StepUpResult::FAIL_NOT_ENROLLED, $challenge->id);
        }
        try {
            $secret = $this->unseal($stored, $challenge->principalPseudonym);
        } catch (TotpSecretUnsealException) {
            // Fail closed as a typed verdict: an unopenable stored
            // secret is an unusable factor (re-enroll required), never
            // an uncaught error bubbling out as a 500.
            $this->store->consume($challenge->id);

            return StepUpResult::failed(StepUpResult::FAIL_SECRET_UNUSABLE, $challenge->id);
        }
        $code = (string) $request->request->get(self::CODE_FIELD, '');
        $step = $this->matchingStep($secret, $code, TotpCode::stepOf($now));
        if ($step === null) {
            return $this->failedAttempt($challenge, $boundContextKey);
        }
        // The replay guard: the first presentation of a time-step wins;
        // the same step can never verify twice.
        if (!$this->store->markTotpStep($challenge->principalPseudonym, $step, ($this->window + 2) * TotpCode::STEP_SECS)) {
            return StepUpResult::failed(StepUpResult::FAIL_REPLAYED_STEP, $challenge->id);
        }

        // The single-use boundary: exactly one completer consumes the
        // record; a replayed completion answers unknown_challenge and
        // never reaches the credit.
        $consumed = $this->store->consume($challenge->id);
        if ($consumed === null) {
            return StepUpResult::failed(StepUpResult::FAIL_UNKNOWN_CHALLENGE, $challenge->id);
        }
        $this->lockout?->registerSuccess($challenge->principalPseudonym, $challenge->targetOwned ? $challenge->targetPseudonym : null, $boundContextKey);

        return $this->credit($challenge, $boundSessionId);
    }

    /**
     * The accepted step of a presented code: the RFC 6238 value at the
     * current step, then each step of the acceptance window (past
     * before future, so the earliest valid spelling wins), or null when
     * no step of the window matches.
     */
    private function matchingStep(string $secret, string $code, int $currentStep): ?int
    {
        if (!preg_match('/^[0-9]{6,8}$/D', $code) || \strlen($code) !== $this->digits) {
            return null;
        }
        if (hash_equals(TotpCode::at($secret, $currentStep, $this->algo, $this->digits), $code)) {
            return $currentStep;
        }
        for ($i = 1; $i <= $this->window; $i++) {
            foreach ([$currentStep - $i, $currentStep + $i] as $candidate) {
                if ($candidate < 0) {
                    continue;
                }
                if (hash_equals(TotpCode::at($secret, $candidate, $this->algo, $this->digits), $code)) {
                    return $candidate;
                }
            }
        }

        return null;
    }

    private function failedAttempt(StepUpChallenge $challenge, string $contextKey = ''): StepUpResult
    {
        // Every rejected code feeds the cross-challenge brute-force
        // budget before the per-challenge attempt cap.
        $this->lockout?->registerFailure($challenge->principalPseudonym, $challenge->targetPseudonym, $contextKey);
        $answer = $this->store->recordFailure($challenge->id, $challenge->maxAttempts);
        if ($answer === 0) {
            return StepUpResult::failed(StepUpResult::FAIL_TOO_MANY_ATTEMPTS, $challenge->id);
        }
        if ($answer < 0) {
            return StepUpResult::failed(StepUpResult::FAIL_UNKNOWN_CHALLENGE, $challenge->id);
        }

        return StepUpResult::pending($challenge->id);
    }

    /**
     * The challenge of the request, the StepUpChallengeExpired marker
     * when the presented ticket is well-signed but past its own expiry,
     * or null when no live one resolves.
     */
    private function challengeOfRequest(Request $request, int $now): StepUpChallenge|StepUpChallengeExpired|null
    {
        $ticket = (string) $request->request->get(self::TICKET_FIELD, '');
        if ($ticket === '') {
            return null;
        }
        $payload = $this->ticket->verify($ticket, $now);
        if ($payload === null) {
            $looked = $this->ticket->look($ticket);
            if ($looked !== null && $looked['expiresAt'] <= $now) {
                return StepUpChallengeExpired::marker();
            }

            return null;
        }

        return $this->store->read($payload['challengeId']);
    }

    private function credit(StepUpChallenge $challenge, string $boundSessionId = ''): StepUpResult
    {
        $result = $this->creditOnce($challenge);
        if ($result->status === StepUpResultStatus::Succeeded) {
            $this->store->markStepUpSuccess($challenge->principalPseudonym, 900, $this->now());
            $this->store->markSessionStepUpSuccess(
                $boundSessionId,
                $challenge->principalPseudonym,
                'totp',
                900,
                $this->now(),
            );
        }

        return $result;
    }

    private function creditOnce(StepUpChallenge $challenge): StepUpResult
    {
        try {
            return $this->credit->credit($challenge->id, $challenge);
        } catch (\Throwable) {
            return StepUpResult::failed(StepUpResult::FAIL_OUTCOME_UNAVAILABLE, $challenge->id);
        }
    }

    /**
     * The begin presentation: the code-entry form for the html mode,
     * the challenge document for the json mode. A stateless begin (no
     * session) also returns its one-time client secret here, the only
     * channel that ever carries the plaintext.
     */
    private function presentation(StepUpContext $context, StepUpChallenge $challenge, int $now): Response
    {
        $ticket = $this->ticket->issue($challenge->id, $challenge->expiresAt);
        $expiresIn = max(0, $challenge->expiresAt - $now);
        $clientSecret = $challenge->issuedClientSecret();
        if ($context->mode === StepUpContext::MODE_JSON) {
            $body = (string) json_encode(array_filter([
                'handler' => 'totp',
                'challenge' => $ticket,
                'expires_in' => $expiresIn,
                'digits' => $this->digits,
                'complete_path' => $this->completePath,
                'client_secret' => $clientSecret,
            ], static fn ($v): bool => $v !== null), JSON_UNESCAPED_SLASHES);

            return new Response($body, Response::HTTP_OK, ['Content-Type' => 'application/json', 'Cache-Control' => 'no-store']);
        }
        $action = htmlspecialchars($this->completePath, ENT_QUOTES);
        $ticketField = htmlspecialchars(self::TICKET_FIELD, ENT_QUOTES);
        $codeField = htmlspecialchars(self::CODE_FIELD, ENT_QUOTES);
        $ticketValue = htmlspecialchars($ticket, ENT_QUOTES);
        $secretInput = $clientSecret !== null && $clientSecret !== ''
            ? '<input type="hidden" name="'.htmlspecialchars(StepUpSessionBinding::CLIENT_SECRET_FIELD, ENT_QUOTES).'" value="'.htmlspecialchars($clientSecret, ENT_QUOTES).'">'
            : '';
        $html = <<<HTML
            <!DOCTYPE html>
            <html lang="en">
            <head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Authenticator code</title></head>
            <body>
            <main style="max-width:28rem;margin:4rem auto;font-family:system-ui,sans-serif">
            <h1>Authenticator code</h1>
            <p>Enter the current {$this->digits}-digit code from your authenticator app.</p>
            <form method="post" action="{$action}">
            <input type="hidden" name="{$ticketField}" value="{$ticketValue}">
            {$secretInput}
            <label for="kiwi-step-up-code">Code</label>
            <input id="kiwi-step-up-code" name="{$codeField}" inputmode="numeric" autocomplete="one-time-code" required minlength="6" maxlength="8">
            <button type="submit">Verify</button>
            </form>
            </main>
            </body>
            </html>
            HTML;

        return new Response($html, Response::HTTP_OK, ['Content-Type' => 'text/html; charset=utf-8', 'Cache-Control' => 'no-store']);
    }

    /**
     * @param array<string, string> $headers
     */
    private function refusal(StepUpContext $context, int $status, string $code, string $message, array $headers = []): Response
    {
        if ($context->mode === StepUpContext::MODE_JSON) {
            $body = (string) json_encode(['error' => $code, 'message' => $message], JSON_UNESCAPED_SLASHES);

            return new Response($body, $status, $headers + ['Content-Type' => 'application/json', 'Cache-Control' => 'no-store']);
        }

        return new Response($message, $status, $headers + ['Content-Type' => 'text/plain; charset=utf-8', 'Cache-Control' => 'no-store']);
    }

    private static function assertPseudonym(string $pseudonym): void
    {
        if (preg_match('/^[0-9a-f]{32}$/D', $pseudonym) !== 1) {
            throw new \InvalidArgumentException('The enrollment principal must be the 32 lowercase hex pseudonym, never a raw identifier');
        }
    }

    private function now(): int
    {
        return ($this->now) ? ($this->now)() : time();
    }
}
