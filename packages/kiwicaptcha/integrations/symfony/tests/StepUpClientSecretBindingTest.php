<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOtpStepUpHandler;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpCompletionCredit;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpContext;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpResult;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpResultStatus;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpSessionBinding;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpTicket;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\CapturingStepUpCodeSender;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * The step-up completion bindings (finding 6): exactly one binding per
 * challenge. A session-bound challenge stores no client secret and can
 * never be completed from another session, whatever the request
 * presents. A stateless challenge stores only the SHA-256 of its
 * one-time secret, completes with the right secret and refuses a wrong
 * one.
 */
final class StepUpClientSecretBindingTest extends TestCase
{
    private const MASTER = '0123456789abcdef0123456789abcdef';
    private const PRINCIPAL = '00112233445566778899aabbccddeeff';

    private int $now = 1700000000;

    private ArrayStepUpChallengeStore $store;

    private CapturingStepUpCodeSender $sender;

    private StepUpTicket $ticket;

    protected function setUp(): void
    {
        $this->store = new ArrayStepUpChallengeStore($this->clock());
        $this->sender = new CapturingStepUpCodeSender();
        $this->ticket = new StepUpTicket(self::MASTER);
    }

    /**
     * A session-bound challenge mints no client secret at all (exactly
     * one binding: the session). A completion presented under a
     * different session is refused even when the request carries a
     * perfectly valid secret — session binding is never optional.
     */
    public function testASessionBoundChallengeRefusesAnotherSessionEvenWithASecret(): void
    {
        $challenge = $this->sessionBoundChallenge('session-alpha');
        self::assertNull($challenge->issuedClientSecret(), 'a session-bound begin mints no client secret');
        self::assertNull($challenge->clientSecretHash, 'a session-bound challenge stores no secret hash');
        self::assertNull($challenge->toArray()['client_secret_hash'], 'the wire form carries no secret hash');

        // A real, valid secret (one that would complete a stateless
        // challenge) presented under a different session: refused.
        $otherSecret = StepUpChallenge::clientSecret();
        $foreign = $this->boundRequest('session-beta', self::PRINCIPAL);
        $foreign->request->set(StepUpSessionBinding::CLIENT_SECRET_FIELD, $otherSecret);
        self::assertFalse(
            StepUpSessionBinding::matches($foreign, $challenge),
            'a stolen ticket must never complete under another session, secret or no secret',
        );

        // The originating session still completes (the session binding
        // is the one minted binding).
        $own = $this->boundRequest('session-alpha', self::PRINCIPAL);
        $own->request->set(StepUpSessionBinding::CLIENT_SECRET_FIELD, $otherSecret);
        self::assertTrue(StepUpSessionBinding::matches($own, $challenge));
    }

    /**
     * A stateless challenge (a begin request with no session) mints a
     * one-time secret, stores only its SHA-256 hash, and completes with
     * the right secret only. The plaintext never reaches the wire form.
     */
    public function testAStatelessChallengeCompletesWithTheRightSecretAndRefusesAWrongOne(): void
    {
        $challenge = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::EmailOtp,
            self::PRINCIPAL,
            null,
            'login',
            null,
            'post_solve_step_up_required',
            $this->now,
            300,
            5,
            'hash',
            null,
            null,
        );
        $secret = $challenge->issuedClientSecret();
        self::assertIsString($secret);
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/D', $secret);
        self::assertSame(hash('sha256', $secret), $challenge->clientSecretHash, 'only the hash is stored');
        $wire = $challenge->toArray();
        self::assertSame(hash('sha256', $secret), $wire['client_secret_hash']);
        self::assertStringNotContainsString($secret, (string) json_encode($wire), 'the plaintext secret must never reach the wire form');
        self::assertNull($wire['session_hash'], 'a stateless challenge carries no session binding');

        $presented = $this->boundRequest('', self::PRINCIPAL);
        $presented->request->set(StepUpSessionBinding::CLIENT_SECRET_FIELD, $secret);
        self::assertTrue(StepUpSessionBinding::matches($presented, $challenge), 'the right secret completes');

        $wrong = $this->boundRequest('', self::PRINCIPAL);
        $wrong->request->set(StepUpSessionBinding::CLIENT_SECRET_FIELD, StepUpChallenge::clientSecret());
        self::assertFalse(StepUpSessionBinding::matches($wrong, $challenge), 'a wrong secret is refused');

        $absent = $this->boundRequest('', self::PRINCIPAL);
        self::assertFalse(StepUpSessionBinding::matches($absent, $challenge), 'no secret is refused');
    }

    /**
     * The full stateless completion path over a handler: the begin
     * response returns the secret exactly once, and only a completion
     * presenting it succeeds. A record carrying both bindings is
     * malformed (exactly one per challenge).
     */
    public function testTheHandlerCompletesAStatelessChallengeOnlyWithItsSecret(): void
    {
        $handler = $this->handler();
        $begin = $handler->begin($this->beginRequest(noSession: true), $this->context(mode: StepUpContext::MODE_JSON));
        self::assertSame(200, $begin->getStatusCode());
        $document = json_decode((string) $begin->getContent(), true);
        self::assertIsArray($document);
        $secret = $document['client_secret'] ?? null;
        self::assertIsString($secret, 'a stateless begin returns its one-time secret');
        self::assertArrayNotHasKey('client_secret_hash', $document, 'the begin document carries the secret, never the hash');

        $code = (string) $this->sender->lastCode();
        $ticket = (string) $document['challenge'];

        $wrong = $handler->complete($this->completeRequest(noSession: true, ticket: $ticket, code: $code, secret: StepUpChallenge::clientSecret()));
        self::assertSame(StepUpResultStatus::Failed, $wrong->status);
        self::assertSame(StepUpResult::FAIL_SESSION_MISMATCH, $wrong->failureCode);

        $ok = $handler->complete($this->completeRequest(noSession: true, ticket: $ticket, code: $code, secret: $secret));
        self::assertSame(StepUpResultStatus::Succeeded, $ok->status, 'the right secret completes the stateless challenge');

        // Exactly one binding per challenge: a record carrying both a
        // session hash and a secret hash is refused at decode.
        $dual = $this->sessionBoundChallenge('session-alpha')->toArray();
        $dual['client_secret_hash'] = hash('sha256', 'irrelevant');
        try {
            StepUpChallenge::fromArray($dual);
            self::fail('HOLE: a dual-binding challenge record was accepted');
        } catch (\BelConsulting\KiwiCaptchaBundle\Security\StepUp\MalformedStepUpChallengeException) {
            // fail closed
        }
    }

    private function sessionBoundChallenge(string $sessionId): StepUpChallenge
    {
        return StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::EmailOtp,
            self::PRINCIPAL,
            null,
            'login',
            null,
            'post_solve_step_up_required',
            $this->now,
            300,
            5,
            'hash',
            null,
            $sessionId,
        );
    }

    private function boundRequest(string $sessionId, string $principal): Request
    {
        $request = Request::create('https://example.com/kiwi/step-up/complete', 'POST');
        if ($sessionId !== '') {
            $storage = new \Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage();
            $storage->setId($sessionId);
            $session = new \Symfony\Component\HttpFoundation\Session\Session($storage);
            $session->start();
            $request->setSession($session);
        }
        StepUpSessionBinding::bind($request, $principal);

        return $request;
    }

    private function beginRequest(bool $noSession = false): Request
    {
        $request = Request::create('https://example.com/kiwi/step-up/begin');
        if (!$noSession) {
            $storage = new \Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage();
            $storage->setId('bound-session-00000000000000001');
            $session = new \Symfony\Component\HttpFoundation\Session\Session($storage);
            $session->start();
            $request->setSession($session);
        }

        return $request;
    }

    private function completeRequest(bool $noSession, string $ticket, string $code, string $secret): Request
    {
        $request = Request::create('https://example.com/kiwi/step-up/complete', 'POST', [], [], [], [], null);
        $request->request->set(EmailOtpStepUpHandler::TICKET_FIELD, $ticket);
        $request->request->set(EmailOtpStepUpHandler::CODE_FIELD, $code);
        $request->request->set(StepUpSessionBinding::CLIENT_SECRET_FIELD, $secret);
        if (!$noSession) {
            $storage = new \Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage();
            $storage->setId('bound-session-00000000000000001');
            $session = new \Symfony\Component\HttpFoundation\Session\Session($storage);
            $session->start();
            $request->setSession($session);
        }
        StepUpSessionBinding::bind($request, self::PRINCIPAL);

        return $request;
    }

    private function handler(): EmailOtpStepUpHandler
    {
        return new EmailOtpStepUpHandler(
            $this->store,
            $this->ticket,
            new StepUpCompletionCredit(new SpyOutcomeReporter(), self::MASTER),
            $this->sender,
            self::MASTER,
            maxBegins: 50,
            now: $this->clock(),
        );
    }

    private function context(string $mode = StepUpContext::MODE_HTML): StepUpContext
    {
        return new StepUpContext(self::PRINCIPAL, null, 'login', '/back', 'post_solve_step_up_required', $mode);
    }

    private function clock(): \Closure
    {
        return function (): int {
            return $this->now;
        };
    }
}
