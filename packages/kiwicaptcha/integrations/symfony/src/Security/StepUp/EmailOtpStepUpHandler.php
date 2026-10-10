<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The email one-time-passcode reference handler: a 6 or 8 digit code
 * from random_int, delivered through the application-bound
 * {@see StepUpCodeSenderInterface}.
 *
 * Only a keyed hash of the code is stored, under a purpose-separated
 * key from the bundle's shared HKDF derivation. A store snapshot leaks
 * no second factor; the code itself lives solely in the delivery
 * channel. The challenge carries a 300 s configurable TTL, a 5-attempt
 * cap and single-use consumption. Begin is rate-bounded per principal
 * through a store-backed window counter, 3 admissions per 15 minutes
 * by default; beyond the bound begin answers a 429 refusal with the
 * window as the retry hint, fail-closed.
 *
 * The completion credit runs through {@see StepUpCompletionCredit} on
 * the one consumed record, so a legitimate user books stepUpCompleted
 * exactly once and is not stepped up twice.
 */
final class EmailOtpStepUpHandler implements StepUpHandlerInterface
{
    public const TICKET_FIELD = 'kiwi_step_up_ticket';
    public const CODE_FIELD = 'kiwi_step_up_code';

    private const HKDF_INFO = 'kiwi/v1/stepup-otp';

    private const HKDF_SALT = 'kiwicaptcha/deploy-salt/v1';

    private readonly string $otpKey;

    private readonly StepUpTicket $ticket;

    public function __construct(
        private readonly StepUpChallengeStore $store,
        StepUpTicket $ticket,
        private readonly StepUpCompletionCredit $credit,
        private readonly StepUpCodeSenderInterface $sender,
        string $secretMaster,
        private readonly int $ttlSecs = 300,
        private readonly int $maxAttempts = 5,
        private readonly int $digits = 6,
        private readonly int $maxBegins = 3,
        private readonly int $beginWindowSecs = 900,
        private readonly string $completePath = '/kiwi/step-up/complete',
        private readonly ?\Closure $now = null,
        private readonly ?StepUpLockoutGuard $lockout = null,
    ) {
        if ($digits !== 6 && $digits !== 8) {
            throw new \InvalidArgumentException('The one-time passcode length must be 6 or 8 digits');
        }
        if (\strlen($secretMaster) < 32) {
            throw new \InvalidArgumentException('The step-up secret master must be at least 32 bytes (the same floor as secret_key)');
        }
        $this->otpKey = hash_hkdf('sha256', $secretMaster, 32, self::HKDF_INFO, self::HKDF_SALT);
        $this->ticket = $ticket;
    }

    public function begin(Request $request, StepUpContext $context): Response
    {
        $now = $this->now();
        // The cross-challenge brute-force budget: while the requesting
        // context (or the shared account/target backstops) is locked
        // out, no fresh challenge is minted — unless the request rides
        // the owner's trusted context, which may always begin.
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

        $code = str_pad((string) random_int(0, (10 ** $this->digits) - 1), $this->digits, '0', STR_PAD_LEFT);
        $challenge = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::EmailOtp,
            $context->principalPseudonym,
            $context->targetPseudonym,
            $context->scope,
            $context->returnPath,
            $context->reason,
            $now,
            $this->ttlSecs,
            $this->maxAttempts,
            $this->codeHash($code),
            null,
            StepUpSessionBinding::sessionId($request),
            $context->targetOwned,
        );
        try {
            $this->store->create($challenge, $this->ttlSecs);
            $this->sender->send($code, $context, $this->ttlSecs);
        } catch (\Throwable $e) {
            // Delivery refused: no challenge record may outlive an
            // undelivered code (a later completion could not be
            // attributed to a user who never saw it). Fail-closed.
            try {
                $this->store->consume($challenge->id);
            } catch (\Throwable) {
                // The record expires with its TTL regardless.
            }

            return $this->refusal(
                $context,
                Response::HTTP_SERVICE_UNAVAILABLE,
                'step_up_delivery_failed',
                'The verification code could not be delivered; try again.',
                [],
                $e,
            );
        }

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
        if ($challenge->kind !== StepUpChallengeKind::EmailOtp) {
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
        $code = (string) $request->request->get(self::CODE_FIELD, '');
        if (!preg_match('/^[0-9]{6,8}$/D', $code) || !hash_equals((string) $challenge->codeHash, $this->codeHash($code))) {
            return $this->failedAttempt($challenge, $boundContextKey);
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
     * The failure accounting of one rejected code: pending while
     * attempts remain, terminal when the cap is reached or the record
     * is gone.
     */
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
     * or null when no live one resolves. The marker lets the completion
     * answer the expired failure code instead of a bare unknown.
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
                'email_otp',
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
     * The keyed hash of one code: the only stored form of the secret.
     */
    private function codeHash(string $code): string
    {
        return hash_hmac('sha256', $code, $this->otpKey);
    }

    /**
     * The begin presentation: a self-contained html form for the html
     * mode, the challenge document for the json mode. A stateless
     * begin (no session) also returns its one-time client secret here —
     * the only channel that ever carries the plaintext.
     */
    private function presentation(StepUpContext $context, StepUpChallenge $challenge, int $now): Response
    {
        $ticket = $this->ticket->issue($challenge->id, $challenge->expiresAt);
        $expiresIn = max(0, $challenge->expiresAt - $now);
        $clientSecret = $challenge->issuedClientSecret();
        if ($context->mode === StepUpContext::MODE_JSON) {
            $body = (string) json_encode(array_filter([
                'handler' => 'email_otp',
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
        $reason = htmlspecialchars($context->reason, ENT_QUOTES);
        $secretInput = $clientSecret !== null && $clientSecret !== ''
            ? '<input type="hidden" name="'.htmlspecialchars(StepUpSessionBinding::CLIENT_SECRET_FIELD, ENT_QUOTES).'" value="'.htmlspecialchars($clientSecret, ENT_QUOTES).'">'
            : '';
        $html = <<<HTML
            <!DOCTYPE html>
            <html lang="en">
            <head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Verification required</title></head>
            <body>
            <main style="max-width:28rem;margin:4rem auto;font-family:system-ui,sans-serif">
            <h1>Verification required</h1>
            <p>A {$this->digits}-digit code was sent to your address. It expires in {$expiresIn} seconds.</p>
            <p hidden>{$reason}</p>
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
    private function refusal(
        StepUpContext $context,
        int $status,
        string $code,
        string $message,
        array $headers,
        ?\Throwable $cause = null,
    ): Response {
        if ($context->mode === StepUpContext::MODE_JSON) {
            $body = (string) json_encode(['error' => $code, 'message' => $message], JSON_UNESCAPED_SLASHES);

            return new Response($body, $status, $headers + ['Content-Type' => 'application/json', 'Cache-Control' => 'no-store']);
        }

        return new Response($message, $status, $headers + ['Content-Type' => 'text/plain; charset=utf-8', 'Cache-Control' => 'no-store']);
    }

    private function now(): int
    {
        return ($this->now) ? ($this->now)() : time();
    }
}
