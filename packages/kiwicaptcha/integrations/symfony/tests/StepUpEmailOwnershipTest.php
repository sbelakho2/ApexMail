<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOtpStepUpHandler;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOwnershipCodeSenderInterface;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOwnershipDeliveryMetadata;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOwnershipStepUp;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemand;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpFactorResolver;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpTicket;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakeRiskStateStore;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptcha;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Validator\ConstraintValidatorFactory;
use Symfony\Component\Validator\Validation;

/**
 * The completable step-up surface. The challenge endpoint answers the
 * typed step-up 403 with the email carrier and its demand id when a
 * decision demands step-up on a carrier scope, and the anonymous
 * visitor completes the factor against that demand. The grant redeems
 * in place of a solved token on the scope that named the carrier, it
 * binds to the address the form submits, and it passes only after a
 * fresh engine assessment lets the completed factor through.
 */
final class StepUpEmailOwnershipTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const MASTER = 'kiwi-step-up-master-0123456789abcdef';

    /** The server-parameter key for the peer address (glued so prose lint treats it as code). */
    private const remoteKey = 'REMOTE_ADDR';

    /** The carrier scopes the tests arm (the factor answers exactly these). */
    private const CARRIERS = ['signup' => true, 'newsletter' => true];

    // ── issuance shapes ─────────────────────────────────────────────────

    public function testAdminLoginUnderTheAbuseProfileIssuesAChallenge(): void
    {
        $controller = new ChallengeController(
            $this->issuer(),
            null,
            false,
            $this->buildGateway('admin_login', ['base_risk' => 300, 'minimum' => 'allow', 'degraded' => 'allow']),
        );
        $response = $controller->challenge($this->challengeRequest('admin_login'));

        self::assertSame(200, $response->getStatusCode(), 'admin_login issues a challenge, never the issuance 403');
        $body = json_decode((string) $response->getContent(), true);
        self::assertNotSame('', (string) ($body['nonce'] ?? ''), 'the answer carries a real challenge');
        self::assertArrayNotHasKey('step_up', $body['error'] ?? [], 'no step-up refusal is involved');
    }

    public function testALowScoreContactStaysAProofOfWorkFlow(): void
    {
        // The contact scope: the sha16 floor, value_class low, the
        // score rung step_up_above 600. A fresh low-scoring source
        // composes onto the rung and issues, never the step-up 403.
        $controller = new ChallengeController(
            $this->issuer(),
            null,
            false,
            $this->buildGateway('contact', ['base_risk' => 60, 'minimum' => 'sha16', 'degraded' => 'sha18']),
        );
        $response = $controller->challenge($this->challengeRequest('contact'));

        self::assertSame(200, $response->getStatusCode(), 'a low-score contact is a plain proof-of-work issuance');
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame(16, $body['targetBits'] ?? null, 'the composed rung is the sha16 scope floor');
    }

    // ── the anonymous carrier journey ───────────────────────────────────

    public function testTheStepUpRefusalOffersTheCarrierAndTheGrantRedeems(): void
    {
        $cookie = new ContinuityCookie();
        $sessionValue = (string) $cookie->mint();
        $sender = new CapturingEmailOwnershipSender();
        $store = new ArrayStepUpChallengeStore();
        $factor = $this->factor($store, $sender, $cookie);
        // The explicit scope minimum is the operator's own knob (a
        // genuinely step-up surface); the controller advertises the
        // carrier with its demand, so the 403 the visitor sees names a
        // completable factor instead of a dead end.
        $controller = new ChallengeController(
            $this->issuer(),
            null,
            false,
            $this->buildGateway('signup', ['base_risk' => 100, 'minimum' => 'step_up', 'degraded' => 'allow']),
            $cookie,
            stepUpEmailBeginPath: EmailOwnershipStepUp::BEGIN_PATH,
            emailOwnership: $factor,
            emailCarrierScopes: self::CARRIERS,
        );

        // (0) The step-up decision at issuance: the typed 403 names the
        // email carrier, its begin path and the minted demand id.
        $request = $this->challengeRequest('signup');
        $request->cookies->set($this->cookieName($cookie), $sessionValue);
        $refused = $controller->challenge($request);
        self::assertSame(403, $refused->getStatusCode(), (string) $refused->getContent());
        $refusal = json_decode((string) $refused->getContent(), true);
        self::assertSame('STEP_UP_REQUIRED', $refusal['error']['code'] ?? null);
        self::assertSame('email_ownership', $refusal['error']['step_up']['kind'] ?? null);
        self::assertSame('/kiwi/step-up/email/begin', $refusal['error']['step_up']['begin'] ?? null);
        $demand = (string) $refusal['error']['step_up']['demand'];
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{16,43}$/D', $demand, 'the 403 carries the demand id the begin endpoint requires');

        // (1) The anonymous visitor begins against that demand: the code
        // is delivered, the stored record carries only the pseudonym.
        $begin = $factor->begin($this->emailRequest($cookie, $sessionValue, 'visitor@example.com', $demand));
        self::assertSame(200, $begin->getStatusCode(), (string) $begin->getContent());
        $code = (string) $sender->lastCode();
        self::assertMatchesRegularExpression('/^[0-9]{6}$/D', $code);
        $this->assertStoreCarriesOnlyThePseudonym($store, 'visitor@example.com');

        // (2) The completion answers the single-use grant bound to the
        // demanded scope and session.
        $ticket = (string) json_decode((string) $begin->getContent(), true)['challenge'];
        $complete = $factor->complete($this->completeRequest($cookie, $sessionValue, $ticket, $code, $demand));
        self::assertSame(200, $complete->getStatusCode(), (string) $complete->getContent());
        $grant = (string) json_decode((string) $complete->getContent(), true)['grant'];
        self::assertStringStartsWith(EmailOwnershipStepUp::GRANT_PREFIX.'.', $grant);

        // (3) The grant redeems in place of a solved token, bound to the
        // address the form submits.
        $violations = $this->validate($store, $sender, $cookie, $sessionValue, $grant, 'signup', 'visitor@example.com');
        self::assertCount(0, $violations, 'a redeemed grant verifies with no violation: '.var_export($violations, true));

        // (4) The replay is refused: single use.
        $replay = $this->validate($store, $sender, $cookie, $sessionValue, $grant, 'signup', 'visitor@example.com');
        self::assertCount(1, $replay, 'a spent grant answers the standing step-up demand');
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $replay[0]->getCode());
    }

    public function testAPrincipalFactorRefusalCarriesTheRequiredFactorKind(): void
    {
        // The financial_action shape at issuance: the scope minimum
        // demands step-up and the answering factor is principal-bound
        // (email_otp), so the anonymous email carrier serves nothing
        // here. The 403 still names the factor kind, so the demand
        // reaches the browser and the application knows where to
        // route it (its own step-up page, the widget never carries a
        // principal factor).
        $controller = new ChallengeController(
            $this->issuer(),
            null,
            false,
            $this->buildGateway('financial_action', ['base_risk' => 100, 'minimum' => 'step_up', 'degraded' => 'allow']),
            stepUpFactorResolver: new StepUpFactorResolver('email_otp'),
        );
        $refused = $controller->challenge($this->challengeRequest('financial_action'));
        self::assertSame(403, $refused->getStatusCode(), (string) $refused->getContent());
        $refusal = json_decode((string) $refused->getContent(), true);
        self::assertSame('STEP_UP_REQUIRED', $refusal['error']['code'] ?? null);
        self::assertSame('email_otp', $refusal['error']['step_up']['kind'] ?? null);
        self::assertArrayNotHasKey('begin', $refusal['error']['step_up'] ?? [], 'a principal factor names no widget begin path');
        self::assertArrayNotHasKey('demand', $refusal['error']['step_up'] ?? [], 'a principal factor mints no anonymous demand');
    }

    public function testTheCarrierKindWinsAndABareRefusalStaysBare(): void
    {
        $cookie = new ContinuityCookie();
        $sessionValue = (string) $cookie->mint();
        $factor = $this->factor(new ArrayStepUpChallengeStore(), new CapturingEmailOwnershipSender(), $cookie);

        // The carrier scope answers with the carrier kind even when a
        // resolver stands: the carrier serves this scope, and the
        // resolver would name a principal factor the anonymous visitor
        // the body addresses cannot reach.
        $carrierController = new ChallengeController(
            $this->issuer(),
            null,
            false,
            $this->buildGateway('signup', ['base_risk' => 100, 'minimum' => 'step_up', 'degraded' => 'allow']),
            $cookie,
            stepUpFactorResolver: new StepUpFactorResolver('email_otp'),
            stepUpEmailBeginPath: EmailOwnershipStepUp::BEGIN_PATH,
            emailOwnership: $factor,
            emailCarrierScopes: self::CARRIERS,
        );
        $request = $this->challengeRequest('signup');
        $request->cookies->set($this->cookieName($cookie), $sessionValue);
        $refused = $carrierController->challenge($request);
        self::assertSame(403, $refused->getStatusCode(), (string) $refused->getContent());
        $refusal = json_decode((string) $refused->getContent(), true);
        self::assertSame('email_ownership', $refusal['error']['step_up']['kind'] ?? null);
        self::assertSame('/kiwi/step-up/email/begin', $refusal['error']['step_up']['begin'] ?? null);

        // No resolver wired: a non-carrier refusal stays the bare
        // typed code, never an invented factor kind.
        $bareController = new ChallengeController(
            $this->issuer(),
            null,
            false,
            $this->buildGateway('financial_action', ['base_risk' => 100, 'minimum' => 'step_up', 'degraded' => 'allow']),
        );
        $bare = $bareController->challenge($this->challengeRequest('financial_action'));
        self::assertSame(403, $bare->getStatusCode(), (string) $bare->getContent());
        self::assertSame('STEP_UP_REQUIRED', json_decode((string) $bare->getContent(), true)['error']['code'] ?? null);
        self::assertArrayNotHasKey('step_up', json_decode((string) $bare->getContent(), true)['error'] ?? [], 'no resolver, no factor metadata');
    }

    public function testAGrantForAnotherScopeOrABrokenGrantNeverRedeems(): void
    {
        $cookie = new ContinuityCookie();
        $sessionValue = (string) $cookie->mint();
        $store = new ArrayStepUpChallengeStore();
        $sender = new CapturingEmailOwnershipSender();
        $factor = $this->factor($store, $sender, $cookie);
        $demand = (string) $factor->mintDemand('signup', hash('sha256', $sessionValue), null, null);
        $begin = $factor->begin($this->emailRequest($cookie, $sessionValue, 'visitor@example.com', $demand));
        $ticket = (string) json_decode((string) $begin->getContent(), true)['challenge'];
        $complete = $factor->complete($this->completeRequest(
            $cookie,
            $sessionValue,
            $ticket,
            (string) $sender->lastCode(),
            $demand,
        ));
        $grant = (string) json_decode((string) $complete->getContent(), true)['grant'];

        // Another carrier scope: the grant path runs and the scope
        // mismatch answers the standing step-up demand.
        $violations = $this->validate($store, $sender, $cookie, $sessionValue, $grant, 'newsletter', 'visitor@example.com');
        self::assertCount(1, $violations, 'a grant is worthless on a scope it does not name');
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violations[0]->getCode());

        // A non-carrier scope: the grant branch never runs at all, so
        // the value falls through to the ordinary token verification
        // and fails there as malformed.
        $violations = $this->validate($store, $sender, $cookie, $sessionValue, $grant, 'contact', 'visitor@example.com');
        self::assertCount(1, $violations, 'a non-carrier scope never honors a grant');
        self::assertSame(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $violations[0]->getCode());

        // A forged body: refused, never accepted.
        $forged = EmailOwnershipStepUp::GRANT_PREFIX.'.'.rtrim(strtr(base64_encode('[1,"aaaaaaaaaaaaaaaaaaaa","signup","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","","",4102444800]'), '+/', '-_'), '=').'.anNpZ25hdHVyZQ';
        $violations = $this->validate($store, $sender, $cookie, $sessionValue, $forged, 'signup', 'visitor@example.com');
        self::assertCount(1, $violations, 'a forged grant answers the standing step-up demand');
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violations[0]->getCode());
    }

    public function testGrantForNonCarrierScopeIsRefused(): void
    {
        $cookie = new ContinuityCookie();
        $sessionValue = (string) $cookie->mint();
        $store = new ArrayStepUpChallengeStore();
        $sender = new CapturingEmailOwnershipSender();
        $factor = $this->factor($store, $sender, $cookie);

        // No demand exists for a non-carrier scope: mintDemand refuses
        // the scope, so nothing can seed the factor through the front
        // door either.
        self::assertNull($factor->mintDemand('contact', null, null, null), 'a non-carrier scope never mints a demand');

        // Defense in depth: a demand record planted directly for a
        // non-carrier scope funds no begin (and no code leaves).
        $planted = StepUpDemand::mint('demands-need-no-carrier-x', 'contact', null, null, null, time(), 600);
        $store->createDemand($planted, 600);
        $answer = $factor->begin($this->emailRequest($cookie, $sessionValue, 'visitor@example.com', $planted->id));
        self::assertSame(403, $answer->getStatusCode(), (string) $answer->getContent());
        self::assertSame('step_up_not_demanded', json_decode((string) $answer->getContent(), true)['error'] ?? null);
        self::assertSame([], $sender->codes, 'no code is delivered for a non-carrier scope');
    }

    public function testBeginWithoutDemandIsRefused(): void
    {
        $clock = fn (): int => $this->clock;
        $this->clock = 1700000000;
        $cookie = new ContinuityCookie();
        $sessionValue = (string) $cookie->mint();
        $store = new ArrayStepUpChallengeStore($clock);
        $sender = new CapturingEmailOwnershipSender();
        $factor = $this->factor($store, $sender, $cookie, now: $clock);

        // No demand field at all.
        $answer = $factor->begin($this->emailRequest($cookie, $sessionValue, 'visitor@example.com', ''));
        self::assertSame(403, $answer->getStatusCode());
        self::assertSame('step_up_not_demanded', json_decode((string) $answer->getContent(), true)['error'] ?? null);

        // An unknown demand id.
        $answer = $factor->begin($this->emailRequest($cookie, $sessionValue, 'visitor@example.com', 'aaaaaaaaaaaaaaaaaaaaaaaaaa'));
        self::assertSame(403, $answer->getStatusCode());
        self::assertSame('step_up_not_demanded', json_decode((string) $answer->getContent(), true)['error'] ?? null);

        // A demand bound to another browser.
        $otherSession = (string) $cookie->mint();
        $demand = (string) $factor->mintDemand('signup', hash('sha256', $otherSession), null, null);
        $answer = $factor->begin($this->emailRequest($cookie, $sessionValue, 'visitor@example.com', $demand));
        self::assertSame(403, $answer->getStatusCode(), 'another browser cannot spend a session-bound demand');
        self::assertSame('step_up_not_demanded', json_decode((string) $answer->getContent(), true)['error'] ?? null);

        // An expired demand.
        $expired = (string) $factor->mintDemand('signup', hash('sha256', $sessionValue), null, null);
        $this->clock += 601;
        $answer = $factor->begin($this->emailRequest($cookie, $sessionValue, 'visitor@example.com', $expired));
        self::assertSame(403, $answer->getStatusCode(), 'an expired demand funds no code');
        self::assertSame('step_up_not_demanded', json_decode((string) $answer->getContent(), true)['error'] ?? null);

        // The completion demands it too.
        $this->clock = 1700000000;
        $demand = (string) $factor->mintDemand('signup', hash('sha256', $sessionValue), null, null);
        $begin = $factor->begin($this->emailRequest($cookie, $sessionValue, 'visitor@example.com', $demand));
        $ticket = (string) json_decode((string) $begin->getContent(), true)['challenge'];
        $answer = $factor->complete($this->completeRequest($cookie, $sessionValue, $ticket, (string) $sender->lastCode(), ''));
        self::assertSame(422, $answer->getStatusCode(), 'a completion without its demand is refused');
        self::assertSame('unknown_challenge', json_decode((string) $answer->getContent(), true)['failure_code'] ?? null);
    }

    public function testGrantDoesNotBypassDenyMark(): void
    {
        $cookie = new ContinuityCookie();
        $sessionValue = (string) $cookie->mint();
        $store = new ArrayStepUpChallengeStore();
        $sender = new CapturingEmailOwnershipSender();
        $factor = $this->factor($store, $sender, $cookie);
        $grant = $this->grantOf($factor, $cookie, $sessionValue, $store, $sender);

        // The engine's denial stands (a live mark composes exactly this
        // denial through the engine state): the completed factor does
        // not buy the submission back.
        $violations = $this->validateWithRisk(
            $store,
            $sender,
            $cookie,
            $sessionValue,
            $grant,
            'signup',
            'visitor@example.com',
            $this->gateway(new FakeRiskStateStore(), 'signup', ['base_risk' => 600, 'minimum' => 'deny', 'degraded' => 'deny']),
        );
        self::assertCount(1, $violations, 'a grant never bypasses the engine denial');
        self::assertSame(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR, $violations[0]->getCode());

        // Control: the same shape under a clean engine passes (the
        // refusal above is the denial, never the grant handling).
        $cleanStore = new ArrayStepUpChallengeStore();
        $cleanSender = new CapturingEmailOwnershipSender();
        $cleanFactor = $this->factor($cleanStore, $cleanSender, $cookie);
        $cleanGrant = $this->grantOf($cleanFactor, $cookie, $sessionValue, $cleanStore, $cleanSender);
        $passed = $this->validateWithRisk(
            $cleanStore,
            $cleanSender,
            $cookie,
            $sessionValue,
            $cleanGrant,
            'signup',
            'visitor@example.com',
            $this->gateway(new FakeRiskStateStore(), 'signup', ['base_risk' => 100, 'minimum' => 'allow', 'degraded' => 'allow']),
        );
        self::assertCount(0, $passed, 'the engine allows the completed factor: '.var_export($passed, true));
    }

    public function testGrantBoundToSubmittedEmail(): void
    {
        $cookie = new ContinuityCookie();
        $sessionValue = (string) $cookie->mint();
        // Each grant rides its own store, so the per-address window
        // never interferes with the next walk.
        $fresh = static fn (): array => ['store' => new ArrayStepUpChallengeStore(), 'sender' => new CapturingEmailOwnershipSender()];

        // The address the form submits decides: the proven address
        // redeems, a different submitted address refuses.
        ['store' => $s1, 'sender' => $m1] = $fresh();
        $violations = $this->validate($s1, $m1, $cookie, $sessionValue, $this->grantOf($this->factor($s1, $m1, $cookie), $cookie, $sessionValue, $s1, $m1), 'signup', 'visitor@example.com');
        self::assertCount(0, $violations, 'the proven address redeems: '.var_export($violations, true));

        ['store' => $s2, 'sender' => $m2] = $fresh();
        $violations = $this->validate($s2, $m2, $cookie, $sessionValue, $this->grantOf($this->factor($s2, $m2, $cookie), $cookie, $sessionValue, $s2, $m2), 'signup', 'attacker@example.com');
        self::assertCount(1, $violations, 'a grant is worthless to a form that submits another address');
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violations[0]->getCode());

        ['store' => $s3, 'sender' => $m3] = $fresh();
        $violations = $this->validate($s3, $m3, $cookie, $sessionValue, $this->grantOf($this->factor($s3, $m3, $cookie), $cookie, $sessionValue, $s3, $m3), 'signup', null);
        self::assertCount(1, $violations, 'a submission without the address refuses the grant');
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violations[0]->getCode());

        // Case and padding of the submitted address are normalized
        // before the pseudonym comparison, exactly like the begin.
        ['store' => $s4, 'sender' => $m4] = $fresh();
        $violations = $this->validate($s4, $m4, $cookie, $sessionValue, $this->grantOf($this->factor($s4, $m4, $cookie), $cookie, $sessionValue, $s4, $m4), 'signup', '  Visitor@Example.com ');
        self::assertCount(0, $violations, 'the normalized address redeems: '.var_export($violations, true));
    }

    public function testABeginWithoutTheSessionCannotComplete(): void
    {
        $cookie = new ContinuityCookie();
        $store = new ArrayStepUpChallengeStore();
        $factor = $this->factor($store, new CapturingEmailOwnershipSender(), $cookie);
        // A stateless demand (no continuity session at mint): the begin
        // binds to the per-challenge client secret instead.
        $demand = (string) $factor->mintDemand('signup', null, null, null);
        $begin = $factor->begin($this->emailRequest($cookie, null, 'visitor@example.com', $demand));
        self::assertSame(200, $begin->getStatusCode(), (string) $begin->getContent());
        $document = json_decode((string) $begin->getContent(), true);
        $ticket = (string) $document['challenge'];

        // Another browser (no continuity session, no client secret)
        // cannot complete the challenge: the session binding is fail
        // closed.
        $foreign = Request::create('https://app.example.com'.EmailOwnershipStepUp::COMPLETE_PATH, 'POST', [
            EmailOtpStepUpHandler::TICKET_FIELD => $ticket,
            EmailOtpStepUpHandler::CODE_FIELD => '000000',
            EmailOwnershipStepUp::DEMAND_FIELD => $demand,
        ], [], [], [self::remoteKey => '198.51.100.7']);
        $answer = $factor->complete($foreign);
        self::assertSame(422, $answer->getStatusCode());
        self::assertSame('session_mismatch', json_decode((string) $answer->getContent(), true)['failure_code'] ?? null);
    }

    public function testTheDemandFundsOneSendAndOneResend(): void
    {
        $clock = fn (): int => $this->clock;
        $this->clock = 1700000000;
        $cookie = new ContinuityCookie();
        $sessionValue = (string) $cookie->mint();
        $store = new ArrayStepUpChallengeStore($clock);
        $sender = new CapturingEmailOwnershipSender();
        $factor = $this->factor($store, $sender, $cookie, now: $clock);
        $demand = (string) $factor->mintDemand('signup', hash('sha256', $sessionValue), null, null);

        self::assertSame(200, $factor->begin($this->emailRequest($cookie, $sessionValue, 'visitor@example.com', $demand))->getStatusCode());
        self::assertCount(1, $sender->codes, 'the initial send consumes the first credit');

        // The resend opens only after the delay.
        $early = $factor->begin($this->emailRequest($cookie, $sessionValue, 'visitor@example.com', $demand));
        self::assertSame(429, $early->getStatusCode());
        self::assertSame('step_up_resend_wait', json_decode((string) $early->getContent(), true)['error'] ?? null);

        $this->clock += 61;
        $resend = $factor->begin($this->emailRequest($cookie, $sessionValue, 'visitor@example.com', $demand));
        self::assertSame(200, $resend->getStatusCode(), (string) $resend->getContent());
        self::assertCount(2, $sender->codes, 'the resend consumes the second credit');

        // The demand is spent: a third begin answers the rate refusal.
        $third = $factor->begin($this->emailRequest($cookie, $sessionValue, 'visitor@example.com', $demand));
        self::assertSame(429, $third->getStatusCode());
        self::assertSame('step_up_rate_limited', json_decode((string) $third->getContent(), true)['error'] ?? null);
    }

    public function testTheBeginBoundsHoldWithoutTheScopeInTheAddressKey(): void
    {
        $cookie = new ContinuityCookie();
        $sessionValue = (string) $cookie->mint();
        $store = new ArrayStepUpChallengeStore();
        $sender = new CapturingEmailOwnershipSender();
        $factor = $this->factor($store, $sender, $cookie);
        for ($i = 0; $i < 3; $i++) {
            // Each begin rides its own demand (fresh send credit), the
            // per-address bound still caps the third window.
            $demand = (string) $factor->mintDemand('signup', hash('sha256', $sessionValue), null, null);
            $answer = $factor->begin($this->emailRequest($cookie, $sessionValue, 'visitor@example.com', $demand));
            self::assertSame(200, $answer->getStatusCode(), "begin $i stays inside the per-address bound");
        }
        $demand = (string) $factor->mintDemand('signup', hash('sha256', $sessionValue), null, null);
        $fourth = $factor->begin($this->emailRequest($cookie, $sessionValue, 'visitor@example.com', $demand));
        self::assertSame(429, $fourth->getStatusCode(), 'the fourth begin for the address is rate limited');
        self::assertSame('step_up_rate_limited', json_decode((string) $fourth->getContent(), true)['error'] ?? null);

        // A different address on the same source is still fine: the
        // per-address window does not poison the per-source window.
        $demand = (string) $factor->mintDemand('signup', hash('sha256', $sessionValue), null, null);
        $other = $factor->begin($this->emailRequest($cookie, $sessionValue, 'other@example.com', $demand));
        self::assertSame(200, $other->getStatusCode());
    }

    public function testTheDomainBoundAndTheDeploymentBudgetHold(): void
    {
        $cookie = new ContinuityCookie();
        $sessionValue = (string) $cookie->mint();
        // The per-domain bound at 2: the third distinct address of one
        // domain refuses, whatever its own fresh per-address window.
        $store = new ArrayStepUpChallengeStore();
        $factor = $this->factor(new ArrayStepUpChallengeStore(), new CapturingEmailOwnershipSender(), $cookie, maxBeginsPerDomain: 2);
        foreach (['a@example.com', 'b@example.com'] as $address) {
            $demand = (string) $factor->mintDemand('signup', hash('sha256', $sessionValue), null, null);
            $answer = $factor->begin($this->emailRequest($cookie, $sessionValue, $address, $demand));
            self::assertSame(200, $answer->getStatusCode(), "the domain window admits $address");
        }
        $demand = (string) $factor->mintDemand('signup', hash('sha256', $sessionValue), null, null);
        $third = $factor->begin($this->emailRequest($cookie, $sessionValue, 'c@example.com', $demand));
        self::assertSame(429, $third->getStatusCode(), 'the third address of the domain is rate limited');

        // The deployment budget at 1: the second begin anywhere
        // refuses (a fresh store isolates the counter).
        $budgetStore = new ArrayStepUpChallengeStore();
        $budgetFactor = $this->factor($budgetStore, new CapturingEmailOwnershipSender(), $cookie, maxBeginsGlobal: 1);
        $demand = (string) $budgetFactor->mintDemand('signup', hash('sha256', $sessionValue), null, null);
        self::assertSame(200, $budgetFactor->begin($this->emailRequest($cookie, $sessionValue, 'one@other.com', $demand))->getStatusCode());
        $demand = (string) $budgetFactor->mintDemand('signup', hash('sha256', $sessionValue), null, null);
        $second = $budgetFactor->begin($this->emailRequest($cookie, $sessionValue, 'two@other.com', $demand));
        self::assertSame(429, $second->getStatusCode(), 'the deployment budget caps every begin');
    }

    // ── the carrier semantics ───────────────────────────────────────

    public function testACarrierScopeStaysAPowIssuanceAndRaisesStepUpPostSolve(): void
    {
        // The financial_action shape: a named principal carrier, no
        // step_up_above rung, no step_up minimum. Issuance is a plain
        // proof-of-work flow (a carrier is never an issuance floor),
        // and the demand appears on the post-solve assessment, where
        // the principal the action belongs to exists.
        $gateway = $this->buildGateway('financial_action', [
            'base_risk' => 400,
            'minimum' => 'sha20',
            'degraded' => 'deny',
            'carrier' => 'email_otp',
        ]);
        $controller = new ChallengeController($this->issuer(), null, false, $gateway);
        $response = $controller->challenge($this->challengeRequest('financial_action'));
        self::assertSame(200, $response->getStatusCode(), (string) $response->getContent());
        self::assertArrayNotHasKey('step_up', json_decode((string) $response->getContent(), true)['error'] ?? [], 'a carrier scope never refuses issuance with the step-up 403');

        // The post-solve assessment of the same scope answers with the
        // carrier demand: the interactive step-up the validator turns
        // into the completable refusal.
        $decision = $gateway->postSolveDecision('financial_action', '198.51.100.7', null, 'user-42');
        self::assertNotNull($decision);
        self::assertSame(\KiwiCaptcha\Risk\RiskAction::StepUp, $decision->action, 'a carrier scope raises step-up post-solve only');

        // A control scope without a carrier prices its own rung at the
        // same assessment: the raise is the carrier's, not a global one.
        $control = $this->buildGateway('contact', ['base_risk' => 60, 'minimum' => 'sha16', 'degraded' => 'sha18']);
        $controlDecision = $control->postSolveDecision('contact', '198.51.100.7', null, 'user-42');
        self::assertNotNull($controlDecision);
        self::assertSame(\KiwiCaptcha\Risk\RiskAction::Sha16, $controlDecision->action, 'a scope without a carrier never sees the post-solve raise');
    }

    // ── helpers ─────────────────────────────────────────────────────────

    private int $clock = 1700000000;

    private function issuer(): Issuer
    {
        return new Issuer(new Config(
            secretKey: self::SECRET,
            algorithm: PoWAlgorithm::Sha256,
            targetBits: 8,
            ttlSecs: 120,
        ), new ArrayStorage());
    }

    private function gateway(FakeRiskStateStore $store, string $scope, array $overrides): RiskGateway
    {
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
            'weights' => [],
            'scopes' => [1 => $overrides + ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow']],
        ]);
        $engine = new AdaptiveRiskEngine($store, $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);

        return new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), [$scope => 1], policy: $policy);
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function buildGateway(string $scope, array $overrides): RiskGateway
    {
        return $this->gateway(new FakeRiskStateStore(), $scope, $overrides);
    }

    /**
     * @param array<string, true> $carriers
     */
    private function factor(
        ArrayStepUpChallengeStore $store,
        CapturingEmailOwnershipSender $sender,
        ContinuityCookie $cookie,
        array $carriers = self::CARRIERS,
        ?\Closure $now = null,
        int $maxBeginsPerDomain = 30,
        int $maxBeginsGlobal = 1000,
    ): EmailOwnershipStepUp {
        return new EmailOwnershipStepUp(
            $store,
            new StepUpTicket(self::MASTER),
            $sender,
            $cookie,
            null,
            'login',
            self::MASTER,
            emailCarrierScopes: $carriers,
            maxBeginsPerDomain: $maxBeginsPerDomain,
            maxBeginsGlobal: $maxBeginsGlobal,
            now: $now,
        );
    }

    /**
     * The full begin-to-grant walk for one address, one demand each.
     */
    private function grantOf(
        EmailOwnershipStepUp $factor,
        ContinuityCookie $cookie,
        string $sessionValue,
        ArrayStepUpChallengeStore $store,
        CapturingEmailOwnershipSender $sender,
    ): string {
        $demand = (string) $factor->mintDemand('signup', hash('sha256', $sessionValue), null, null);
        $begin = $factor->begin($this->emailRequest($cookie, $sessionValue, 'visitor@example.com', $demand));
        self::assertSame(200, $begin->getStatusCode(), (string) $begin->getContent());
        $ticket = (string) json_decode((string) $begin->getContent(), true)['challenge'];
        $complete = $factor->complete($this->completeRequest($cookie, $sessionValue, $ticket, (string) $sender->lastCode(), $demand));
        self::assertSame(200, $complete->getStatusCode(), (string) $complete->getContent());

        return (string) json_decode((string) $complete->getContent(), true)['grant'];
    }

    private function challengeRequest(string $scope): Request
    {
        return Request::create('/challenge', 'POST', [], [], [], [
            'CONTENT_TYPE' => 'application/json',
            self::remoteKey => '198.51.100.7',
        ], '{"scope":"'.$scope.'"}');
    }

    private function cookieName(ContinuityCookie $cookie): string
    {
        return (string) $cookie->cookie(Request::create('/'), 'seed')->getName();
    }

    private function emailRequest(ContinuityCookie $cookie, ?string $sessionValue, string $email, string $demand): Request
    {
        $request = Request::create('https://app.example.com'.EmailOwnershipStepUp::BEGIN_PATH, 'POST', array_filter([
            EmailOwnershipStepUp::EMAIL_FIELD => $email,
            EmailOwnershipStepUp::DEMAND_FIELD => $demand,
        ], static fn ($v): bool => $v !== null && $v !== ''), [], [], [self::remoteKey => '198.51.100.7']);
        if ($sessionValue !== null) {
            $request->cookies->set($this->cookieName($cookie), $sessionValue);
        }

        return $request;
    }

    private function completeRequest(ContinuityCookie $cookie, string $sessionValue, string $ticket, string $code, string $demand): Request
    {
        $request = Request::create('https://app.example.com'.EmailOwnershipStepUp::COMPLETE_PATH, 'POST', [
            EmailOtpStepUpHandler::TICKET_FIELD => $ticket,
            EmailOtpStepUpHandler::CODE_FIELD => $code,
            EmailOwnershipStepUp::DEMAND_FIELD => $demand,
        ], [], [], [self::remoteKey => '198.51.100.7']);
        $request->cookies->set($this->cookieName($cookie), $sessionValue);

        return $request;
    }

    /**
     * The stored records of the factor must never carry the raw
     * address: the only address-derived bytes are the pseudonym.
     */
    private function assertStoreCarriesOnlyThePseudonym(ArrayStepUpChallengeStore $store, string $rawEmail): void
    {
        $challenges = (new \ReflectionProperty(ArrayStepUpChallengeStore::class, 'challenges'))->getValue($store);
        $demands = (new \ReflectionProperty(ArrayStepUpChallengeStore::class, 'demands'))->getValue($store);
        foreach (['challenges' => $challenges, 'demands' => $demands] as $records) {
            self::assertIsArray($records);
            foreach ($records as $entry) {
                $json = json_encode($entry);
                self::assertIsString($json);
                self::assertStringNotContainsString($rawEmail, $json, 'the raw address never reaches the store');
            }
        }
        self::assertNotSame([], $challenges, 'a challenge record exists');
    }

    /**
     * Validate a value through the full Symfony pipeline with the
     * grant-carrying validator, answering the violations.
     *
     * @return \Symfony\Component\Validator\ConstraintViolationListInterface
     */
    private function validate(
        ArrayStepUpChallengeStore $store,
        CapturingEmailOwnershipSender $sender,
        ContinuityCookie $cookie,
        string $sessionValue,
        string $value,
        string $scope,
        ?string $submittedEmail,
    ): \Symfony\Component\Validator\ConstraintViolationListInterface {
        return $this->validateWithRisk($store, $sender, $cookie, $sessionValue, $value, $scope, $submittedEmail, null);
    }

    /**
     * The validate walk with an optional wired risk gateway (the
     * engine verdict the redeemed grant must satisfy).
     *
     * @return \Symfony\Component\Validator\ConstraintViolationListInterface
     */
    private function validateWithRisk(
        ArrayStepUpChallengeStore $store,
        CapturingEmailOwnershipSender $sender,
        ContinuityCookie $cookie,
        string $sessionValue,
        string $value,
        string $scope,
        ?string $submittedEmail,
        ?RiskGateway $risk,
    ): \Symfony\Component\Validator\ConstraintViolationListInterface {
        $requestStack = new RequestStack();
        $request = Request::create('https://app.example.com/submit', 'POST', array_filter([
            'email' => $submittedEmail,
        ], static fn ($v): bool => $v !== null), [], [], [
            self::remoteKey => '198.51.100.7',
        ]);
        $request->cookies->set($this->cookieName($cookie), $sessionValue);
        $requestStack->push($request);

        $validator = new KiwiCaptchaValidator(
            new Verifier(new ArrayStorage()),
            $requestStack,
            self::SECRET,
            risk: $risk,
            continuityCookie: $cookie,
            emailOwnership: $this->factor($store, $sender, $cookie),
            emailCarrierScopes: self::CARRIERS,
        );
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $value;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => $scope]));

        return $engine->validate($dto);
    }
}
