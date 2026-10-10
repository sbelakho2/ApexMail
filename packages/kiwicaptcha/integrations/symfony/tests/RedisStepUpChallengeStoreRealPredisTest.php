<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\RedisStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpContext;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpResult;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpResultStatus;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpTicket;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpCompletionCredit;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\TotpCode;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\TotpStepUpHandler;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * The Redis step-up store over a real Predis client against a live
 * redis-server: the exact deployment reply surface. The finding this
 * pins: the SET NX reply of a real client is a
 * Predis\Response\Status object, so a strict 'OK'/bool comparison
 * threw on every create() and every step-up begin failed closed. The
 * fake-client suite cannot see that shape; this leg boots the real
 * client (KC_REDIS_URL) and walks begin() through complete().
 */
final class RedisStepUpChallengeStoreRealPredisTest extends TestCase
{
    private const PRINCIPAL = '00112233445566778899aabbccddeeff';

    private const NOW = 1700000000;

    private const PREFIX = '{kiwi:rpreal}:stepup:';

    private const MASTER = 'real-predis-leg-master-key-0123456789abcdef';

    private \Predis\Client $client;

    private RedisStepUpChallengeStore $store;

    private TotpStepUpHandler $handler;

    protected function setUp(): void
    {
        $url = getenv('KC_REDIS_URL');
        if ($url === false || $url === '') {
            self::markTestSkipped('KC_REDIS_URL not set — real-Predis step-up leg skipped');
        }
        if (!class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis not installed');
        }
        $this->client = new \Predis\Client($url, ['timeout' => 2.0]);
        try {
            $this->client->ping();
        } catch (\Throwable $e) {
            self::markTestSkipped('Redis unreachable: '.$e->getMessage());
        }
        $this->store = new RedisStepUpChallengeStore($this->client, self::PREFIX);
        $this->handler = new TotpStepUpHandler(
            $this->store,
            new StepUpTicket(self::MASTER),
            new StepUpCompletionCredit(new SpyOutcomeReporter(), self::MASTER),
            'sha1', 6, 1, 300, 5, 100, 900, '/kiwi/step-up/complete',
            static fn (): int => self::NOW,
            self::MASTER,
        );
    }

    protected function tearDown(): void
    {
        // The leg owns only its hash-tagged family; the sweep never
        // reaches another suite's keys on the shared instance.
        if (!isset($this->client)) {
            return;
        }
        try {
            $keys = $this->client->keys(self::PREFIX.'*');
            if ($keys !== []) {
                $this->client->del(...$keys);
            }
        } catch (\Throwable) {
            // a dead instance must not fail the shutdown path
        }
    }

    public function testTheRealClientAnswersAStatusObjectThatTheStoreAccepts(): void
    {
        $reply = $this->client->set(self::PREFIX.'reply-shape', 'x', 'EX', 60, 'NX');
        self::assertInstanceOf(\Predis\Response\Status::class, $reply, 'a real Predis SET answers the Status object, the exact shape the store must normalize');
        self::assertSame('OK', (string) $reply);

        $refused = $this->client->set(self::PREFIX.'reply-shape', 'y', 'EX', 60, 'NX');
        self::assertNull($refused, 'a lost NX race answers nil and must stay a refusal');
        $this->client->del(self::PREFIX.'reply-shape');
    }

    public function testBeginThroughCompleteWorksEndToEndOnTheRealClient(): void
    {
        $base32 = $this->enrollFirstTime();
        $secretRaw = (string) TotpCode::base32Decode($base32);

        $response = $this->handler->begin(
            Request::create('https://captcha.example.com/kiwi/step-up/begin'),
            new StepUpContext(self::PRINCIPAL, null, 'login', null, 'post_solve_step_up_required', StepUpContext::MODE_JSON),
        );
        self::assertSame(200, $response->getStatusCode(), 'begin() must persist its record through the real client');

        $body = json_decode((string) $response->getContent(), true);
        self::assertIsArray($body);
        $ticket = (string) $body['challenge'];

        $code = TotpCode::at($secretRaw, TotpCode::stepOf(self::NOW), 'sha1', 6);
        $result = $this->handler->complete($this->completeRequest($ticket, $code));
        self::assertSame(StepUpResultStatus::Succeeded, $result->status, 'the record was persisted, consumed and credited end to end');
        self::assertTrue($result->creditedPrincipal);
    }

    public function testTheConsumedRecordStaysSingleUseOnTheRealClient(): void
    {
        $this->enrollFirstTime();
        $response = $this->handler->begin(
            Request::create('https://captcha.example.com/kiwi/step-up/begin'),
            new StepUpContext(self::PRINCIPAL, null, 'login', null, 'post_solve_step_up_required', StepUpContext::MODE_JSON),
        );
        $ticket = (string) json_decode((string) $response->getContent(), true)['challenge'];
        self::assertNotNull($this->store->read($this->challengeIdOf($ticket)), 'the record is readable before consumption');

        self::assertNotNull($this->store->consume($this->challengeIdOf($ticket)));
        $result = $this->handler->complete($this->completeRequest($ticket, '000000'));
        self::assertSame(StepUpResultStatus::Failed, $result->status);
        self::assertSame(StepUpResult::FAIL_UNKNOWN_CHALLENGE, $result->failureCode, 'the GETDEL boundary holds over the real client');
    }

    public function testACollidingMintedIdStillRefusesAndThrows(): void
    {
        $id = 'ccccccccccccccccccccccc';
        $this->store->create($this->challenge($id), 300);
        $this->expectException(\RuntimeException::class);
        $this->store->create($this->challenge($id), 300);
    }

    /**
     * First-time totp enrollment under the enrollment gate: the handler
     * refuses it without a session-scoped step-up completed in the
     * enrolling session, so the test books that proof first (the
     * established-factor floor accepts the email_otp completion).
     */
    private function enrollFirstTime(): string
    {
        $this->store->markSessionStepUpSuccess('sess-real', self::PRINCIPAL, 'email_otp', 900, self::NOW);

        return $this->handler->enroll(self::PRINCIPAL, 'sess-real');
    }

    private function challengeIdOf(string $ticket): string
    {
        $payload = (new StepUpTicket(self::MASTER))->verify($ticket, self::NOW);
        self::assertIsArray($payload);

        return (string) $payload['challengeId'];
    }

    private function challenge(string $id): StepUpChallenge
    {
        return StepUpChallenge::begin(
            $id,
            StepUpChallengeKind::EmailOtp,
            self::PRINCIPAL,
            null,
            'login',
            null,
            'post_solve_step_up_required',
            self::NOW,
            300,
            5,
            str_repeat('a', 64),
        );
    }

    private function completeRequest(string $ticket, string $code): Request
    {
        $request = Request::create('https://captcha.example.com/kiwi/step-up/complete', 'POST', [
            TotpStepUpHandler::TICKET_FIELD => $ticket,
            TotpStepUpHandler::CODE_FIELD => $code,
        ]);
        // The controller binds the re-resolved principal before the
        // handler runs; direct handler calls bind it the same way.
        \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpSessionBinding::bind($request, self::PRINCIPAL);

        return $request;
    }
}
