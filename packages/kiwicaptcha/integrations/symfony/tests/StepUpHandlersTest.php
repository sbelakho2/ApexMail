<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOtpStepUpHandler;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpCompletionCredit;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpContext;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpResult;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpResultStatus;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpTicket;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\TotpCode;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\TotpStepUpHandler;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\CapturingStepUpCodeSender;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter;
use KiwiCaptcha\Risk\Outcomes\Outcome;
use KiwiCaptcha\Risk\Outcomes\OutcomeHandleDimension;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * The bounded reference handlers against the in-memory store. Covered:
 * the one-time-passcode lifecycle of single use, TTL, attempt cap,
 * begin rate bound, hash-only storage and delivery failure. Also the
 * time-based lifecycle of enrollment, window and replay guard, and the
 * completion credit contract of exactly-once crediting, coherent with
 * the typed violation the flow answers.
 */
final class StepUpHandlersTest extends TestCase
{
    private const MASTER = '0123456789abcdef0123456789abcdef';

    private const PRINCIPAL = '00112233445566778899aabbccddeeff';

    /** The canonical target spelling: the full 32-byte digest, 64 hex chars. */
    private const TARGET = 'ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100';

    /** The outcomes handle / mark key of the target: its leading 128 bits. */
    private const TARGET_MARK_KEY = 'ffeeddccbbaa99887766554433221100';

    private ArrayStepUpChallengeStore $store;

    private SpyOutcomeReporter $reporter;

    private CapturingStepUpCodeSender $sender;

    private int $now = 1700000000;

    private StepUpTicket $ticket;

    protected function setUp(): void
    {
        $this->store = new ArrayStepUpChallengeStore($this->clock());
        $this->reporter = new SpyOutcomeReporter();
        $this->sender = new CapturingStepUpCodeSender();
        $this->ticket = new StepUpTicket(self::MASTER);
    }

    public function testTheContextRefusesRawIdentifiers(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new StepUpContext('user-42@example.com', null, 'login', '/back', 'post_solve_step_up_required');
    }

    public function testTheContextRefusesOpenRedirects(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new StepUpContext(self::PRINCIPAL, null, 'login', 'https://evil.example.com/back', 'post_solve_step_up_required');
    }

    public function testTheOtpFlowCompletesAndCreditsOnce(): void
    {
        $handler = $this->otpHandler();
        $response = $handler->begin($this->beginRequest(), $this->context());
        self::assertSame(200, $response->getStatusCode());
        self::assertMatchesRegularExpression('/name="kiwi_step_up_ticket" value="[^"]+"/', $response->getContent());
        $code = $this->sender->lastCode();
        self::assertNotNull($code);
        self::assertMatchesRegularExpression('/^[0-9]{6}$/D', $code);

        $result = $handler->complete($this->completeRequest($this->ticketOf($response), $code));
        self::assertSame(StepUpResultStatus::Succeeded, $result->status);
        self::assertTrue($result->creditedPrincipal);
        self::assertTrue($result->creditedTarget);

        // The credit: stepUpCompleted on the principal and the target,
        // each with an idempotency key derived from the challenge id.
        self::assertCount(2, $this->reporter->reports);
        self::assertSame(Outcome::StepUpCompleted, $this->reporter->reports[0]['outcome']);
        self::assertSame(OutcomeHandleDimension::Principal, $this->reporter->reports[0]['handle']->dimension);
        self::assertSame(self::PRINCIPAL, $this->reporter->reports[0]['handle']->id);
        self::assertSame(OutcomeHandleDimension::Target, $this->reporter->reports[1]['handle']->dimension);
        // The target handle carries the one derived mark key (the
        // leading 128 bits of the canonical 64-hex pseudonym).
        self::assertSame(self::TARGET_MARK_KEY, $this->reporter->reports[1]['handle']->id);
        self::assertNotSame($this->reporter->reports[0]['idempotencyKey'], $this->reporter->reports[1]['idempotencyKey']);

        // The replayed completion is rejected and credits nothing.
        $replay = $handler->complete($this->completeRequest($this->ticketOf($response), $code));
        self::assertSame(StepUpResultStatus::Failed, $replay->status);
        self::assertSame(StepUpResult::FAIL_UNKNOWN_CHALLENGE, $replay->failureCode);
        self::assertCount(2, $this->reporter->reports);
    }

    public function testTheStoredRecordCarriesOnlyTheCodeHash(): void
    {
        $records = [];
        $inner = $this->store;
        $store = new class ($inner, $records) implements \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeStore {
            /** @param list<string> $records */
            public function __construct(
                private readonly ArrayStepUpChallengeStore $inner,
                private array $records,
            ) {
            }

            public function create(\BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge $challenge, int $ttlSecs): string
            {
                $this->records[] = (string) json_encode($challenge->toArray(), JSON_UNESCAPED_SLASHES);

                return $this->inner->create($challenge, $ttlSecs);
            }

            public function read(string $challengeId): ?\BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge
            {
                return $this->inner->read($challengeId);
            }

            public function consume(string $challengeId): ?\BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge
            {
                return $this->inner->consume($challengeId);
            }

            public function recordFailure(string $challengeId, int $maxAttempts): int
            {
                return $this->inner->recordFailure($challengeId, $maxAttempts);
            }

            public function countBegin(string $principalPseudonym, int $windowSecs): int
            {
                return $this->inner->countBegin($principalPseudonym, $windowSecs);
            }

            public function saveTotpSecret(string $principalPseudonym, string $secretRaw): void
            {
                $this->inner->saveTotpSecret($principalPseudonym, $secretRaw);
            }

            public function findTotpSecret(string $principalPseudonym): ?string
            {
                return $this->inner->findTotpSecret($principalPseudonym);
            }

            public function markTotpStep(string $principalPseudonym, int $step, int $ttlSecs): bool
            {
                return $this->inner->markTotpStep($principalPseudonym, $step, $ttlSecs);
            }

            public function markStepUpSuccess(string $principalPseudonym, int $ttlSecs, int $now): void
            {
                $this->inner->markStepUpSuccess($principalPseudonym, $ttlSecs, $now);
            }

            public function markSessionStepUpSuccess(string $sessionId, string $principalPseudonym, string $factor, int $ttlSecs, int $now): void
            {
                $this->inner->markSessionStepUpSuccess($sessionId, $principalPseudonym, $factor, $ttlSecs, $now);
            }

            public function recentSessionStepUpSuccess(string $sessionId, string $principalPseudonym, ?string $minFactor, int $withinSecs, int $now): bool
            {
                return $this->inner->recentSessionStepUpSuccess($sessionId, $principalPseudonym, $minFactor, $withinSecs, $now);
            }

            public function recentStepUpSuccess(string $principalPseudonym, int $withinSecs, int $now): bool
            {
                return $this->inner->recentStepUpSuccess($principalPseudonym, $withinSecs, $now);
            }

            public function countLockoutFailure(string $dimension, string $pseudonym, int $windowSecs): int
            {
                return $this->inner->countLockoutFailure($dimension, $pseudonym, $windowSecs);
            }

            public function lockoutUntil(string $dimension, string $pseudonym, int $now): int
            {
                return $this->inner->lockoutUntil($dimension, $pseudonym, $now);
            }

            public function armLockout(string $dimension, string $pseudonym, int $now, int $ttlSecs): void
            {
                $this->inner->armLockout($dimension, $pseudonym, $now, $ttlSecs);
            }

            public function clearLockout(string $dimension, string $pseudonym): void
            {
                $this->inner->clearLockout($dimension, $pseudonym);
            }

            /** @return list<string> */
            public function recorded(): array
            {
                return $this->records;
            }
        };
        $handler = new EmailOtpStepUpHandler($store, $this->ticket, $this->credit(), $this->sender, self::MASTER);
        $handler->begin($this->beginRequest(), $this->context());
        $code = (string) $this->sender->lastCode();
        $stored = $store->recorded();
        self::assertCount(1, $stored);
        self::assertStringNotContainsString($code, $stored[0], 'the raw code is never stored');
        self::assertStringContainsString('"code_hash"', $stored[0]);
    }

    public function testTheWrongCodeStaysPendingUntilTheAttemptCap(): void
    {
        $handler = $this->otpHandler(maxAttempts: 3);
        $response = $handler->begin($this->beginRequest(), $this->context());
        $ticket = $this->ticketOf($response);
        $result = $handler->complete($this->completeRequest($ticket, '000000'));
        self::assertSame(StepUpResultStatus::Pending, $result->status);
        $result = $handler->complete($this->completeRequest($ticket, '000000'));
        self::assertSame(StepUpResultStatus::Pending, $result->status);
        // The third wrong code exhausts the cap: terminal.
        $result = $handler->complete($this->completeRequest($ticket, '000000'));
        self::assertSame(StepUpResultStatus::Failed, $result->status);
        self::assertSame(StepUpResult::FAIL_TOO_MANY_ATTEMPTS, $result->failureCode);
        // Even the right code is refused afterwards.
        $result = $handler->complete($this->completeRequest($ticket, (string) $this->sender->lastCode()));
        self::assertSame(StepUpResult::FAIL_UNKNOWN_CHALLENGE, $result->failureCode);
    }

    public function testTheChallengeExpiresWithItsTtl(): void
    {
        $handler = $this->otpHandler(ttl: 120);
        $response = $handler->begin($this->beginRequest(), $this->context());
        $this->now += 121;
        $result = $handler->complete($this->completeRequest($this->ticketOf($response), (string) $this->sender->lastCode()));
        self::assertSame(StepUpResultStatus::Failed, $result->status);
        self::assertSame(StepUpResult::FAIL_EXPIRED, $result->failureCode);
        // The expired ticket keeps answering expired, and the record is
        // gone: no completion can ever succeed on it.
        self::assertSame(StepUpResult::FAIL_EXPIRED, $handler->complete($this->completeRequest($this->ticketOf($response), '000000'))->failureCode);
    }

    public function testBeginIsRateBoundedPerPrincipal(): void
    {
        $handler = $this->otpHandler(maxBegins: 3, window: 900);
        for ($i = 0; $i < 3; $i++) {
            self::assertSame(200, $handler->begin($this->beginRequest(), $this->context())->getStatusCode());
        }
        $refusal = $handler->begin($this->beginRequest(), $this->context());
        self::assertSame(429, $refusal->getStatusCode());
        self::assertSame('900', $refusal->headers->get('Retry-After'));
        // A distinct principal is unaffected: the bound is per identity.
        self::assertSame(200, $handler->begin($this->beginRequest(), $this->context('aabbccdd00112233445566778899eeff'))->getStatusCode());
    }

    public function testADeliveryFailureRemovesTheChallengeAndRefuses(): void
    {
        $this->sender->throwOnSend = new \RuntimeException('mailbox unavailable');
        $handler = $this->otpHandler();
        $response = $handler->begin($this->beginRequest(), $this->context());
        self::assertSame(503, $response->getStatusCode());
        // The store holds no challenge record after the refusal.
        $result = $handler->complete($this->completeRequest('anything', '000000'));
        self::assertSame(StepUpResult::FAIL_UNKNOWN_CHALLENGE, $result->failureCode);
    }

    public function testAForgedOrExpiredTicketNeverResolvesAChallenge(): void
    {
        $handler = $this->otpHandler();
        $handler->begin($this->beginRequest(), $this->context());
        $result = $handler->complete($this->completeRequest('forged.ticket', (string) $this->sender->lastCode()));
        self::assertSame(StepUpResult::FAIL_UNKNOWN_CHALLENGE, $result->failureCode);
        // A ticket signed under a different master is refused the same.
        $other = new StepUpTicket(str_repeat('z', 32));
        $ticket = $other->issue('AAAAAAAAAAAAAAAAAAAAAAAA', $this->now + 300);
        self::assertSame(StepUpResult::FAIL_UNKNOWN_CHALLENGE, $handler->complete($this->completeRequest($ticket, '000000'))->failureCode);
    }

    public function testAnOtpTicketOrCodeInTheQueryStringIsIgnored(): void
    {
        // Secrets ride the POST body only: a query-string ticket/code
        // never resolves a challenge (the handler reads $request->request).
        $handler = $this->otpHandler();
        $response = $handler->begin($this->beginRequest(), $this->context());
        $ticket = $this->ticketOf($response);

        $queryOnly = Request::create(
            'https://example.com/kiwi/step-up/complete?'.http_build_query([
                EmailOtpStepUpHandler::TICKET_FIELD => $ticket,
                EmailOtpStepUpHandler::CODE_FIELD => (string) $this->sender->lastCode(),
            ]),
        );
        \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpSessionBinding::bind($queryOnly, self::PRINCIPAL);
        $result = $handler->complete($queryOnly);
        self::assertSame(StepUpResult::FAIL_UNKNOWN_CHALLENGE, $result->failureCode, 'OTP secrets ride the POST body only');
    }

    public function testATotpTicketOrCodeInTheQueryStringIsIgnored(): void
    {
        // Secrets ride the POST body only: a query-string ticket/code
        // never resolves a challenge (the handler reads $request->request).
        $handler = $this->totpHandler();
        $this->store->markSessionStepUpSuccess('sess-totp', self::PRINCIPAL, 'email_otp', 900, $this->now);
        $secret = TotpCode::base32Decode($handler->enroll(self::PRINCIPAL, 'sess-totp'));
        $response = $handler->begin($this->beginRequest(), $this->contextNoTarget());
        $ticket = $this->ticketOf($response);

        $queryOnly = Request::create(
            'https://example.com/kiwi/step-up/complete?'.http_build_query([
                TotpStepUpHandler::TICKET_FIELD => $ticket,
                TotpStepUpHandler::CODE_FIELD => TotpCode::at((string) $secret, TotpCode::stepOf($this->now)),
            ]),
        );
        \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpSessionBinding::bind($queryOnly, self::PRINCIPAL);
        $result = $handler->complete($queryOnly);
        self::assertSame(StepUpResult::FAIL_UNKNOWN_CHALLENGE, $result->failureCode, 'TOTP secrets ride the POST body only');
    }

    public function testTheTotpFlowEnrollsVerifiesAndGuardsReplay(): void
    {
        $handler = $this->totpHandler();
        $this->store->markSessionStepUpSuccess('sess-totp', self::PRINCIPAL, 'totp', 900, $this->now);
        $secret32 = $handler->enroll(self::PRINCIPAL, 'sess-totp');
        self::assertMatchesRegularExpression('/^[A-Z2-7]{32}$/D', $secret32);
        $secret = TotpCode::base32Decode($secret32);
        self::assertNotNull($secret);

        $response = $handler->begin($this->beginRequest(), $this->contextNoTarget());
        self::assertSame(200, $response->getStatusCode());
        $step = TotpCode::stepOf($this->now);
        $result = $handler->complete($this->completeRequest($this->ticketOf($response), TotpCode::at((string) $secret, $step)));
        self::assertSame(StepUpResultStatus::Succeeded, $result->status, 'the current step verifies');
        self::assertTrue($result->creditedPrincipal);
        self::assertFalse($result->creditedTarget);
        self::assertCount(1, $this->reporter->reports, 'the principal-only context credits once');

        // The replay guard: the same step can never verify twice.
        $response2 = $handler->begin($this->beginRequest(), $this->contextNoTarget());
        $replay = $handler->complete($this->completeRequest($this->ticketOf($response2), TotpCode::at((string) $secret, $step)));
        self::assertSame(StepUpResult::FAIL_REPLAYED_STEP, $replay->failureCode);

        // The next time-step verifies on a fresh begin, and the window
        // accepts a code of the step before the current one when that
        // step was never used.
        $this->now += 60;
        $response3 = $handler->begin($this->beginRequest(), $this->contextNoTarget());
        $current = TotpCode::stepOf($this->now);
        self::assertSame(StepUpResultStatus::Succeeded, $handler->complete($this->completeRequest($this->ticketOf($response3), TotpCode::at((string) $secret, $current - 1)))->status);
        // The used step is refused on the next challenge of the window.
        $response4 = $handler->begin($this->beginRequest(), $this->contextNoTarget());
        $result4 = $handler->complete($this->completeRequest($this->ticketOf($response4), TotpCode::at((string) $secret, $current - 1)));
        self::assertSame(StepUpResult::FAIL_REPLAYED_STEP, $result4->failureCode);
    }

    /**
     * First-time totp enrollment is gated exactly like a re-enroll:
     * without a step-up completed in this session (with an established
     * factor) the handler refuses — the credential-stuffing takeover
     * path (planting the attacker's own authenticator on a secret-less
     * account) must never run. A principal-level marker never suffices.
     */
    public function testFirstTotpEnrollmentRequiresASessionStepUp(): void
    {
        $handler = $this->totpHandler();
        // No step-up at all: refused.
        try {
            $handler->enroll(self::PRINCIPAL, 'sess-totp');
            self::fail('HOLE: first TOTP enrollment ran with no session step-up');
        } catch (\RuntimeException $e) {
            self::assertStringContainsString('step-up completed in this session', $e->getMessage());
        }
        // No session id at all: refused.
        try {
            $handler->enroll(self::PRINCIPAL);
            self::fail('HOLE: first TOTP enrollment ran with no session id');
        } catch (\RuntimeException) {
        }
        // A principal-level marker is not session-scoped: refused.
        $this->store->markStepUpSuccess(self::PRINCIPAL, 900, $this->now);
        try {
            $handler->enroll(self::PRINCIPAL, 'sess-totp');
            self::fail('HOLE: a principal-level marker authorized first enrollment');
        } catch (\RuntimeException) {
        }
        // The session-scoped step-up with any established factor (the
        // email_otp floor) authorizes the first enrollment.
        $this->store->markSessionStepUpSuccess('sess-totp', self::PRINCIPAL, 'email_otp', 900, $this->now);
        $secret32 = $handler->enroll(self::PRINCIPAL, 'sess-totp');
        self::assertMatchesRegularExpression('/^[A-Z2-7]{32}$/D', $secret32);
        // Re-enroll then demands the strongest-factor floor (totp), so
        // the stale email_otp marker no longer opens the swap.
        try {
            $handler->enroll(self::PRINCIPAL, 'sess-totp');
            self::fail('HOLE: an email_otp marker authorized a TOTP re-enroll');
        } catch (\RuntimeException $e) {
            self::assertStringContainsString('current factor', $e->getMessage());
        }
    }

    /**
     * The at-rest seal is bound to the owning principal: a sealed
     * secret transplanted into another principal's record slot never
     * decrypts, and the failure is the typed unseal error mapped to a
     * failed verdict — never an uncaught exception / 500.
     */
    public function testTotpSecretsAreBoundToTheirPrincipal(): void
    {
        $handler = $this->totpHandler();
        $this->store->markSessionStepUpSuccess('sess-totp', self::PRINCIPAL, 'email_otp', 900, $this->now);
        $secret32 = $handler->enroll(self::PRINCIPAL, 'sess-totp');
        $sealed = $this->store->findTotpSecret(self::PRINCIPAL);
        self::assertIsString($sealed);
        self::assertNotSame($secret32, $sealed, 'the stored value is the sealed blob, never the raw key material');
        self::assertNotSame((string) TotpCode::base32Decode($secret32), $sealed);

        // Cross-slot copy: the victim's sealed secret planted on another
        // principal must fail closed as a typed failure, not 500.
        $other = 'ffeeddccbbaa99887766554433221100';
        $this->store->saveTotpSecret($other, $sealed);
        $begin = $handler->begin($this->beginRequest(), $this->contextNoTargetFor($other));
        $ticket = $this->ticketOf($begin);
        $result = $handler->complete($this->completeRequestFor($other, $ticket, '000000'));
        self::assertSame(StepUpResultStatus::Failed, $result->status);
        self::assertSame(StepUpResult::FAIL_SECRET_UNUSABLE, $result->failureCode, 'a cross-principal transplant is an unusable secret, typed');

        // A legacy plaintext record (predates the seal) is the same
        // typed failure.
        $this->store->saveTotpSecret(self::PRINCIPAL, 'plaintext-legacy-secret');
        $begin2 = $handler->begin($this->beginRequest(), $this->contextNoTarget());
        $result2 = $handler->complete($this->completeRequest($this->ticketOf($begin2), '000000'));
        self::assertSame(StepUpResultStatus::Failed, $result2->status);
        self::assertSame(StepUpResult::FAIL_SECRET_UNUSABLE, $result2->failureCode);
        // The typed error itself is the documented unseal failure.
        self::assertTrue(is_a(\BelConsulting\KiwiCaptchaBundle\Security\StepUp\TotpSecretUnsealException::class, \RuntimeException::class, true));
    }

    public function testTheTotpHandlerRefusesUnenrolledPrincipalsAndFarCodes(): void
    {
        $handler = $this->totpHandler();
        $response = $handler->begin($this->beginRequest(), $this->context());
        self::assertSame(409, $response->getStatusCode(), 'an unenrolled principal cannot begin');

        $this->store->markSessionStepUpSuccess('sess-totp', self::PRINCIPAL, 'email_otp', 900, $this->now);
        $handler->enroll(self::PRINCIPAL, 'sess-totp');
        $response = $handler->begin($this->beginRequest(), $this->context());
        $farStep = TotpCode::stepOf($this->now) + 5;
        $result = $handler->complete($this->completeRequest($this->ticketOf($response), TotpCode::at('12345678901234567890', $farStep)));
        self::assertSame(StepUpResultStatus::Pending, $result->status, 'a code outside the window is a retryable rejection');
    }

    public function testACreditFailureFailsTheCompletionClosed(): void
    {
        $this->reporter->throwOnReport = new \RuntimeException('outcome backend down');
        $handler = $this->otpHandler();
        $response = $handler->begin($this->beginRequest(), $this->context());
        $result = $handler->complete($this->completeRequest($this->ticketOf($response), (string) $this->sender->lastCode()));
        self::assertSame(StepUpResultStatus::Failed, $result->status);
        self::assertSame(StepUpResult::FAIL_OUTCOME_UNAVAILABLE, $result->failureCode);
        // The challenge was consumed: a retry must begin fresh, never
        // re-complete.
        $again = $handler->complete($this->completeRequest($this->ticketOf($response), (string) $this->sender->lastCode()));
        self::assertSame(StepUpResult::FAIL_UNKNOWN_CHALLENGE, $again->failureCode);
    }

    public function testTheJsonModeAnswersAChallengeDocument(): void
    {
        $handler = $this->otpHandler();
        $response = $handler->begin($this->beginRequest(), $this->context(mode: StepUpContext::MODE_JSON));
        self::assertSame('application/json', $response->headers->get('Content-Type'));
        $document = json_decode((string) $response->getContent(), true);
        self::assertIsArray($document);
        self::assertSame('email_otp', $document['handler']);
        self::assertSame(300, $document['expires_in']);
        self::assertArrayHasKey('challenge', $document);
    }

    public function testTheChallengeRecordDecodesStrictly(): void
    {
        $record = \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::begin(
            'AAAAAAAAAAAAAAAAAAAAAAAA',
            StepUpChallengeKind::EmailOtp,
            self::PRINCIPAL,
            self::TARGET,
            'login',
            '/back',
            'post_solve_step_up_required',
            $this->now,
            300,
            5,
            str_repeat('a', 64),
        );
        $round = \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::fromJson((string) json_encode($record->toArray(), JSON_UNESCAPED_SLASHES));
        self::assertSame($record->toArray(), $round->toArray());

        $corrupt = $record->toArray();
        unset($corrupt['code_hash']);
        $this->expectException(\BelConsulting\KiwiCaptchaBundle\Security\StepUp\MalformedStepUpChallengeException::class);
        \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::fromArray($corrupt);
    }

    private function otpHandler(int $ttl = 300, int $maxAttempts = 5, int $maxBegins = 3, int $window = 900): EmailOtpStepUpHandler
    {
        return new EmailOtpStepUpHandler(
            $this->store,
            $this->ticket,
            $this->credit(),
            $this->sender,
            self::MASTER,
            $ttl,
            $maxAttempts,
            6,
            $maxBegins,
            $window,
            '/kiwi/step-up/complete',
            $this->clock(),
        );
    }

    private function totpHandler(): TotpStepUpHandler
    {
        return new TotpStepUpHandler(
            $this->store,
            $this->ticket,
            $this->credit(),
            'sha1',
            6,
            1,
            300,
            5,
            100,
            900,
            '/kiwi/step-up/complete',
            $this->clock(),
            self::MASTER,
        );
    }

    private function credit(): StepUpCompletionCredit
    {
        return new StepUpCompletionCredit($this->reporter, self::MASTER);
    }

    private function clock(): \Closure
    {
        return function (): int {
            return $this->now;
        };
    }

    private function context(string $principal = self::PRINCIPAL, string $mode = StepUpContext::MODE_HTML): StepUpContext
    {
        return new StepUpContext($principal, self::TARGET, 'login', '/back', 'post_solve_step_up_required', $mode, true);
    }

    private function contextNoTarget(): StepUpContext
    {
        return $this->contextNoTargetFor(self::PRINCIPAL);
    }

    private function contextNoTargetFor(string $principal): StepUpContext
    {
        return new StepUpContext($principal, null, 'login', null, 'post_solve_step_up_required');
    }

    private const SESSION = 'handlers-test-session-000000000001';

    private function withSession(Request $request, string $sessionId = self::SESSION): Request
    {
        $storage = new \Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage();
        $storage->setId($sessionId);
        $session = new \Symfony\Component\HttpFoundation\Session\Session($storage);
        $session->start();
        $request->setSession($session);

        return $request;
    }

    private function beginRequest(): Request
    {
        return $this->withSession(Request::create('https://example.com/kiwi/step-up/begin'));
    }

    private function completeRequest(string $ticket, string $code): Request
    {
        return $this->completeRequestFor(self::PRINCIPAL, $ticket, $code);
    }

    private function completeRequestFor(string $principal, string $ticket, string $code): Request
    {
        $request = $this->withSession(Request::create('https://example.com/kiwi/step-up/complete', 'POST', [
            EmailOtpStepUpHandler::TICKET_FIELD => $ticket,
            EmailOtpStepUpHandler::CODE_FIELD => $code,
        ]));
        // The controller binds the re-resolved principal before the
        // handler runs; direct handler calls bind it the same way.
        \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpSessionBinding::bind($request, $principal);

        return $request;
    }

    private function ticketOf(\Symfony\Component\HttpFoundation\Response $response): string
    {
        self::assertSame(1, preg_match('/name="kiwi_step_up_ticket" value="([^"]+)"/', (string) $response->getContent(), $m));

        return html_entity_decode($m[1]);
    }
}
