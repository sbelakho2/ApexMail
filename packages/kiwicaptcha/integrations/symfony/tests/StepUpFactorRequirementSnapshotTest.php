<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOwnershipStepUp;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\FactorRequirement;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemand;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandState;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpFactorResolver;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationBindingKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpTicket;
use BelConsulting\KiwiCaptchaBundle\Tests\CapturingEmailOwnershipSender;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FailingCreateStepUpChallengeStore;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * The strictly-stronger-factor rule over one continuity session. A
 * demand snapshots the factor it requires, the atomic completion
 * records the completed factor under the session hash and scope, and
 * the next demand of the same session demands a strictly stronger
 * family than the factor already proven. The two-record state moves in
 * one transition. A completion can therefore never strand a consumed
 * challenge beside an open demand, nor the reverse.
 */
final class StepUpFactorRequirementSnapshotTest extends TestCase
{
    private const MASTER = 'kiwi-snapshot-master-0123456789ab';

    private const remoteKey = 'REMOTE_ADDR';

    private ArrayStepUpChallengeStore $store;

    private CapturingEmailOwnershipSender $sender;

    private ContinuityCookie $cookie;

    private int $now = 1700000000;

    private string $sessionValue;

    protected function setUp(): void
    {
        $this->store = new ArrayStepUpChallengeStore(fn (): int => $this->now);
        $this->sender = new CapturingEmailOwnershipSender();
        $this->cookie = new ContinuityCookie();
        $this->sessionValue = $this->cookie->mint();
    }

    public function testTheDemandCarriesTheFactorSnapshotTheMintResolved(): void
    {
        $factor = $this->factor(new StepUpFactorResolver('email_otp'));
        $sessionHash = hash('sha256', $this->sessionValue);

        $demandId = (string) $factor->mintDemand('signup', $sessionHash, null, null);
        $demand = $this->store->readDemand($demandId);

        self::assertNotNull($demand);
        self::assertNotNull($demand->requiredFactor, 'the mint snapshots the resolved factor onto the demand');
        self::assertSame(FactorRequirement::EMAIL_OTP, $demand->requiredFactor->family);
        self::assertSame('email_otp', $demand->requiredFactor->factorId);
        self::assertSame(1, $demand->requiredFactor->assuranceRank);
    }

    public function testASecondOperationOfACompletedSessionDemandsTheStrictlyStrongerFactor(): void
    {
        $factor = $this->factor(new StepUpFactorResolver('email_otp'));
        $sessionHash = hash('sha256', $this->sessionValue);

        $first = (string) $factor->mintDemand('signup', $sessionHash, null, null);
        $this->complete($factor, $first);
        self::assertSame(FactorRequirement::EMAIL_OTP, $this->store->completedFactorOf($sessionHash, 'signup', $this->now), 'the completion records the proven factor for the session');

        // The next step-up of the same session under a fresh operation
        // mints its own demand: the completion marker escalates its
        // requirement strictly past the proven factor.
        $secondDigest = \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationDigest::formFields('signup', ['email' => 'visitor@example.com', 'nonce' => 'second']);
        $secondId = (string) $factor->mintDemand('signup', $sessionHash, null, null, \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationBindingKind::FormFields, $secondDigest);
        $second = $this->store->readDemand($secondId);
        self::assertNotSame($first, $secondId, 'the second operation mints its own demand');
        self::assertNotNull($second);
        self::assertNotNull($second->requiredFactor);
        self::assertSame(FactorRequirement::TOTP, $second->requiredFactor->family, 'the demand after a completed email otp demands the totp factor');
        self::assertSame(2, $second->requiredFactor->assuranceRank, 'totp is the strictly stronger rung');
    }

    public function testAReRaisedOperationEscalatesItsFamilyChild(): void
    {
        $factor = $this->factor(new StepUpFactorResolver('email_otp'));
        $sessionHash = hash('sha256', $this->sessionValue);

        $first = (string) $factor->mintDemand('signup', $sessionHash, null, null);
        $firstDemand = $this->store->readDemand($first);
        self::assertNotNull($firstDemand?->requiredFactor);
        self::assertSame(FactorRequirement::EMAIL_OTP, $firstDemand->requiredFactor->family);
        self::assertNull($this->store->completedFactorOf($sessionHash, 'signup', $this->now), 'no completion marker exists');

        $secondId = (string) $factor->mintDemand('signup', $sessionHash, null, null);
        $second = $this->store->readDemand($secondId);
        self::assertNotNull($second);
        self::assertNotSame($first, $secondId, 'the re-raised step-up supersedes the family with a child');
        self::assertNotNull($second->requiredFactor);
        self::assertSame(FactorRequirement::TOTP, $second->requiredFactor->family, 'the family child demands strictly more than its parent required');
        self::assertSame(2, $second->requiredFactor->assuranceRank);
        self::assertTrue($this->store->readDemand($first)?->superseded(), 'the parent handed its authorization to the child');
    }

    public function testTheCompletionConsumesBothRecordsInOneTransition(): void
    {
        $factor = $this->factor(new StepUpFactorResolver('email_otp'));
        $sessionHash = hash('sha256', $this->sessionValue);
        $demandId = (string) $factor->mintDemand('signup', $sessionHash, null, null);
        $demand = $this->store->readDemand($demandId);
        self::assertNotNull($demand);

        $this->complete($factor, $demandId);

        $completed = $this->store->readDemand($demandId);
        self::assertNotNull($completed, 'the completed demand stays as the consumption proof');
        self::assertTrue($completed->state === StepUpDemandState::Completed, 'the demand reached the completed state in the same script');
        self::assertSame(0, $this->liveChallengeCount(), 'the challenge record was consumed by the same transition');
        self::assertNull($this->store->read($this->challengeIds[0] ?? ''), 'the consumed challenge is gone');
    }

    public function testAWebAuthnRequiredDemandRefusesTheWeakerEmailGrant(): void
    {
        // The bypass test: a demand whose stored requirement names
        // webauthn (rank 3) attempted with the email grant (the stored
        // challenge's kind proves the email_otp rung, rank 1). The
        // atomic completion judges the requirement against the factor
        // identity the challenge record carries, never a caller
        // argument, and refuses with both records untouched.
        $demand = StepUpDemand::mint(
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::mintId(),
            'signup',
            hash('sha256', $this->sessionValue),
            null,
            null,
            $this->now,
            600,
            StepUpOperationBindingKind::None,
            '',
            null,
            null,
            false,
            null,
            new FactorRequirement(FactorRequirement::WEBAUTHN, FactorRequirement::WEBAUTHN, 3),
        );
        $challenge = \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::begin(
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::mintId(),
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind::EmailOwnership,
            '00112233445566778899aabbccddeeff',
            null,
            'signup',
            null,
            'email_ownership',
            $this->now,
            600,
            5,
            str_repeat('a', 64),
            null,
            $this->sessionValue,
            false,
            false,
            null,
            $demand->id,
        );
        $this->store->create($challenge, 600);
        $this->store->createDemand($demand, 600);

        $binding = hash('sha256', $this->sessionValue);
        self::assertNull($this->store->completeFactor($challenge->id, $demand->id, $binding, $this->now, $challenge->sessionHash), 'the weaker factor completes nothing');
        self::assertNotNull($this->store->read($challenge->id), 'the weaker-factor refusal consumed no challenge');
        self::assertTrue($this->store->readDemand($demand->id)?->state->isOpen(), 'the weaker-factor refusal completed no demand');
    }

    /**
     * The end-to-end shape of the same refusal: the factor's completion
     * lane answers the typed failure, never a grant, when the demand
     * requires a strictly stronger factor than the grant proves.
     */
    public function testTheGrantCompletionRefusesAWebAuthnRequiredDemand(): void
    {
        $factor = $this->factor(new StepUpFactorResolver('email_otp'));
        $sessionHash = hash('sha256', $this->sessionValue);
        $demand = StepUpDemand::mint(
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::mintId(),
            'signup',
            $sessionHash,
            null,
            null,
            $this->now,
            600,
            StepUpOperationBindingKind::None,
            '',
            null,
            null,
            false,
            null,
            new FactorRequirement(FactorRequirement::WEBAUTHN, FactorRequirement::WEBAUTHN, 3),
        );
        $this->store->createDemand($demand, 600);

        $begin = $factor->begin($this->emailRequest($demand->id));
        self::assertSame(200, $begin->getStatusCode(), (string) $begin->getContent());
        $body = json_decode((string) $begin->getContent(), true);
        $code = (string) $this->sender->lastCode();
        $delivered = \count($this->sender->codes);
        $request = Request::create('https://example.com/kiwi/step-up/email/complete', 'POST', [
            EmailOwnershipStepUp::EMAIL_FIELD => 'visitor@example.com',
            EmailOwnershipStepUp::DEMAND_FIELD => $demand->id,
            'kiwi_step_up_ticket' => (string) $body['challenge'],
            'kiwi_step_up_code' => $code,
        ]);
        $request->cookies->set($this->cookie->cookie($request, 'seed')->getName(), $this->sessionValue);
        $response = $factor->complete($request);

        self::assertSame(422, $response->getStatusCode(), (string) $response->getContent(), 'the weaker grant completes nothing');
        self::assertSame('unknown_challenge', json_decode((string) $response->getContent(), true)['failure_code'] ?? null);
        self::assertSame($delivered, \count($this->sender->codes), 'no second code is delivered for a refused completion');
    }

    public function testTheStoreCompletesACrossedPairForNoOne(): void
    {
        // The challenge of one demand can never complete through
        // another: the script asserts the challenge names exactly the
        // demand id it is driven with, and a refusal consumes nothing.
        $demand = StepUpDemand::mint(
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::mintId(),
            'signup',
            hash('sha256', $this->sessionValue),
            null,
            null,
            $this->now,
            600,
        );
        $challenge = \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::begin(
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::mintId(),
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind::EmailOwnership,
            '00112233445566778899aabbccddeeff',
            null,
            'signup',
            null,
            'email_ownership',
            $this->now,
            600,
            5,
            str_repeat('a', 64),
            null,
            $this->sessionValue,
            false,
            false,
            null,
            $demand->id,
        );
        $this->store->create($challenge, 600);
        $this->store->createDemand($demand, 600);
        $other = StepUpDemand::mint(
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::mintId(),
            'signup',
            null,
            null,
            null,
            $this->now,
            600,
        );
        $this->store->createDemand($other, 600);

        $completion = $this->store->completeFactor($challenge->id, $other->id, hash('sha256', $this->sessionValue), $this->now, $challenge->sessionHash);
        self::assertNull($completion, 'a crossed pair completes nothing');
        self::assertNotNull($this->store->read($challenge->id), 'the refused transition consumed no challenge');
        self::assertTrue($this->store->readDemand($demand->id)?->state->isOpen(), 'the refused transition completed no demand');

        // The right pair, the wrong browser: the binding hash is
        // checked inside the script.
        $wrong = $this->store->completeFactor($challenge->id, $demand->id, str_repeat('b', 64), $this->now, $challenge->sessionHash);
        self::assertNull($wrong, 'a completion without the session binding is refused');
        self::assertNotNull($this->store->read($challenge->id), 'the binding refusal consumed nothing');

        // The right pair, the right browser: exactly one transition.
        $right = $this->store->completeFactor($challenge->id, $demand->id, hash('sha256', $this->sessionValue), $this->now, $challenge->sessionHash);
        self::assertNotNull($right);
        self::assertSame($demand->id, $right->demandId);
        self::assertSame('00112233445566778899aabbccddeeff', $right->verifiedSubjectPseudonym, 'the verified subject derives from the stored challenge');
        self::assertNull($this->store->read($challenge->id), 'the challenge is consumed');
        self::assertTrue($this->store->readDemand($demand->id)?->state === StepUpDemandState::Completed, 'the demand is completed');

        // A replay of the transition answers nothing.
        self::assertNull($this->store->completeFactor($challenge->id, $demand->id, hash('sha256', $this->sessionValue), $this->now, $challenge->sessionHash), 'a spent pair completes no one twice');
    }

    public function testTheChallengeCarriesTheServerHeldFactorSnapshotOfItsKind(): void
    {
        // The trust boundary of the completion gate is the record
        // itself: every begun challenge carries the factor identity its
        // kind proves, resolved once at begin and stored on the wire.
        // The decode derives the same rung for a record minted before
        // the snapshot rode the wire.
        $grant = \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::begin(
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::mintId(),
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind::EmailOwnership,
            '00112233445566778899aabbccddeeff',
            null,
            'signup',
            null,
            'email_ownership',
            $this->now,
            600,
            5,
            str_repeat('a', 64),
            null,
            $this->sessionValue,
        );
        self::assertNotNull($grant->factor);
        self::assertSame(FactorRequirement::EMAIL_OTP, $grant->factor->family, 'the grant proves the email_otp rung');
        self::assertSame(\BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpFactorAssurance::EMAIL_OWNERSHIP, $grant->factor->factorId, 'the lane identity rides as the factor id');
        self::assertSame(1, $grant->factor->assuranceRank);

        $round = \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::fromJson((string) json_encode($grant->toArray(), JSON_UNESCAPED_SLASHES));
        self::assertSame($grant->toArray(), $round->toArray(), 'the snapshot round-trips the strict wire decode');

        // The drain-period shape: a record without the snapshot decodes
        // and derives the kind's own rung.
        $bare = $grant->toArray();
        unset($bare['factor_family'], $bare['factor_id'], $bare['factor_rank']);
        $derived = \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::fromArray($bare);
        self::assertNotNull($derived->factor);
        self::assertSame($grant->factor->family, $derived->factor->family, 'the decode derives the kind rung the begin snapshotted');
        self::assertSame($grant->factor->factorId, $derived->factor->factorId);
        self::assertSame($grant->factor->assuranceRank, $derived->factor->assuranceRank);

        // A half snapshot is not a decodable record.
        $half = $grant->toArray();
        unset($half['factor_id'], $half['factor_rank']);
        $threw = false;
        try {
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::fromArray($half);
        } catch (\BelConsulting\KiwiCaptchaBundle\Security\StepUp\MalformedStepUpChallengeException) {
            $threw = true;
        }
        self::assertTrue($threw, 'a half snapshot refuses the strict decode');
    }

    public function testASnapshotClaimingAnotherFamilyThanItsKindProvesIsRefused(): void
    {
        // The kind decides what proof material the completion verified:
        // a record may name a custom handler id inside its kind's
        // family rung, never claim another family's (stronger) rung.
        $alien = [
            'v' => 2,
            'id' => \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::mintId(),
            'kind' => 'email_otp',
            'principal' => '00112233445566778899aabbccddeeff',
            'scope' => 'signup',
            'reason' => 'post_solve_step_up_required',
            'created_at' => $this->now,
            'expires_at' => $this->now + 600,
            'attempts' => 0,
            'max_attempts' => 5,
            'code_hash' => str_repeat('a', 64),
            'session_hash' => hash('sha256', $this->sessionValue),
            'factor_family' => FactorRequirement::WEBAUTHN,
            'factor_id' => FactorRequirement::WEBAUTHN,
            'factor_rank' => 3,
        ];
        $threw = false;
        try {
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::fromArray($alien);
        } catch (\BelConsulting\KiwiCaptchaBundle\Security\StepUp\MalformedStepUpChallengeException) {
            $threw = true;
        }
        self::assertTrue($threw, 'a snapshot claiming another family than its kind proves refuses the decode');
    }

    public function testABeginNamingAnotherFamilyThanItsKindProvesIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::begin(
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::mintId(),
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind::EmailOtp,
            '00112233445566778899aabbccddeeff',
            null,
            'signup',
            null,
            'post_solve_step_up_required',
            $this->now,
            600,
            5,
            str_repeat('a', 64),
            null,
            $this->sessionValue,
            false,
            false,
            null,
            null,
            new FactorRequirement(FactorRequirement::WEBAUTHN, FactorRequirement::WEBAUTHN, 3),
        );
    }

    public function testACustomFactorIdServesItsFamilysRungOnTheArrayStore(): void
    {
        // The contract that admits custom factors: the demand names the
        // custom id, the challenge carries it in its server-held
        // snapshot, and the completion gate answers the pair while the
        // reference factor of the same family stays foreign.
        $demand = StepUpDemand::mint(
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::mintId(),
            'signup',
            hash('sha256', $this->sessionValue),
            null,
            null,
            $this->now,
            600,
            StepUpOperationBindingKind::None,
            '',
            null,
            null,
            false,
            null,
            new FactorRequirement(FactorRequirement::TOTP, 'acme_otp', 2),
        );
        $this->store->createDemand($demand, 600);
        $custom = new FactorRequirement(FactorRequirement::TOTP, 'acme_otp', 2);
        $challenge = \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::begin(
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::mintId(),
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind::Totp,
            '00112233445566778899aabbccddeeff',
            null,
            'signup',
            null,
            'acme_otp',
            $this->now,
            600,
            5,
            null,
            null,
            $this->sessionValue,
            false,
            false,
            null,
            $demand->id,
            $custom,
        );
        $this->store->create($challenge, 600);

        $completion = $this->store->completeFactor($challenge->id, $demand->id, hash('sha256', $this->sessionValue), $this->now, $challenge->sessionHash);
        self::assertNotNull($completion, 'the custom factor the snapshot names answers the demand naming it');
        self::assertSame(FactorRequirement::TOTP, $completion->completedFactor, 'the completed factor is the family the record proves');
        self::assertSame(FactorRequirement::TOTP, $this->store->completedFactorOf(hash('sha256', $this->sessionValue), 'signup', $this->now), 'the escalation marker stores the record-derived family');

        $reference = \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::begin(
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::mintId(),
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind::Totp,
            '00112233445566778899aabbccddeeff',
            null,
            'signup',
            null,
            'post_solve_step_up_required',
            $this->now,
            600,
            5,
            null,
            null,
            $this->sessionValue,
            false,
            false,
            null,
            $demand->id,
        );
        $this->store->create($reference, 600);
        self::assertNull($this->store->completeFactor($reference->id, $demand->id, hash('sha256', $this->sessionValue), $this->now, $reference->sessionHash), 'the reference factor never answers a demand bound to the custom id');
    }

    public function testAMintWithAnUnavailableAssuranceStoreRefusesAndAnEmptyHistoryMintsNormally(): void
    {
        $sessionHash = hash('sha256', $this->sessionValue);
        $principal = '00112233445566778899aabbccddeeff';
        $resolver = new StepUpFactorResolver('email_otp');

        // The failing store: the mint cannot know what the demand must
        // require, so it refuses (no demand id, nothing stored) instead
        // of degrading the failure into a demand with no assurance
        // snapshot.
        $failing = new FailingCreateStepUpChallengeStore(new ArrayStepUpChallengeStore(fn (): int => $this->now));
        $failing->failAssuranceRead = true;
        $finalizer = new \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandFinalizer(
            $failing,
            new \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpCompletionCredit(new \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter(), self::MASTER),
            null,
            null,
            null,
            null,
            null,
            null,
            fn (): int => $this->now,
            self::MASTER,
            $resolver,
        );
        $refusalId = 'refusedmintdemandid0000001';
        self::assertNull($finalizer->mintLoginDemand('login', $principal, $sessionHash, 600, $refusalId), 'the login mint refuses on an unavailable completion history');
        self::assertNull($failing->readDemand($refusalId), 'the refused login mint stored no demand record');
        self::assertNull($finalizer->mintFinancialDemand('financial_action', 'op-1', ['amount' => '1.00', 'currency' => 'USD'], $sessionHash), 'the financial mint refuses on an unavailable completion history');

        $grantFactor = new EmailOwnershipStepUp(
            $failing,
            new StepUpTicket(self::MASTER),
            $this->sender,
            $this->cookie,
            null,
            'login',
            self::MASTER,
            emailCarrierScopes: ['signup' => true],
            now: fn (): int => $this->now,
            factorResolver: $resolver,
        );
        self::assertNull($grantFactor->mintDemand('signup', $sessionHash, null, null), 'the grant mint refuses on an unavailable completion history');

        // The working store with no prior factor: "no stronger factor is
        // owed" is a genuine answer there, and every mint proceeds
        // normally with its base snapshot.
        $working = new \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandFinalizer(
            $this->store,
            new \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpCompletionCredit(new \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter(), self::MASTER),
            null,
            null,
            null,
            null,
            null,
            null,
            fn (): int => $this->now,
            self::MASTER,
            $resolver,
        );
        $loginId = $working->mintLoginDemand('login', $principal, $sessionHash, 600);
        self::assertNotNull($loginId, 'the login mint proceeds on a working store with no prior factor');
        $loginDemand = $this->store->readDemand($loginId);
        self::assertNotNull($loginDemand?->requiredFactor);
        self::assertSame(FactorRequirement::EMAIL_OTP, $loginDemand->requiredFactor->family, 'the empty history resolves the base requirement');

        self::assertNotNull($this->factor($resolver)->mintDemand('signup', $sessionHash, null, null), 'the grant mint proceeds on a working store with no prior factor');
    }

    /** @var list<string> */
    private array $challengeIds = [];

    private function complete(EmailOwnershipStepUp $factor, string $demandId): void
    {
        $begin = $factor->begin($this->emailRequest($demandId));
        self::assertSame(200, $begin->getStatusCode(), (string) $begin->getContent());
        $body = json_decode((string) $begin->getContent(), true);
        $this->challengeIds[] = $this->challengeIdOfTicket((string) $body['challenge']);
        $code = (string) $this->sender->lastCode();
        $request = Request::create('https://example.com/kiwi/step-up/email/complete', 'POST', [
            EmailOwnershipStepUp::EMAIL_FIELD => 'visitor@example.com',
            EmailOwnershipStepUp::DEMAND_FIELD => $demandId,
            'kiwi_step_up_ticket' => (string) $body['challenge'],
            'kiwi_step_up_code' => $code,
        ]);
        $request->cookies->set($this->cookie->cookie($request, 'seed')->getName(), $this->sessionValue);
        $response = $factor->complete($request);
        self::assertSame(200, $response->getStatusCode(), (string) $response->getContent());
    }

    /**
     * The challenge id the signed ticket names: decoded through the
     * ticket service, the same id the store keyed the record under.
     */
    private function challengeIdOfTicket(string $ticket): string
    {
        $payload = (new StepUpTicket(self::MASTER))->look($ticket);
        self::assertIsArray($payload);

        return (string) $payload['challengeId'];
    }

    private function liveChallengeCount(): int
    {
        $live = 0;
        foreach ($this->challengeIds as $id) {
            if ($this->store->read($id) !== null) {
                $live++;
            }
        }

        return $live;
    }

    private function emailRequest(string $demandId): Request
    {
        $request = Request::create('https://example.com/kiwi/step-up/email/begin', 'POST', [
            EmailOwnershipStepUp::EMAIL_FIELD => 'visitor@example.com',
            EmailOwnershipStepUp::DEMAND_FIELD => $demandId,
        ], [], [], [self::remoteKey => '198.51.100.7']);
        $request->cookies->set($this->cookie->cookie($request, 'seed')->getName(), $this->sessionValue);

        return $request;
    }

    private function factor(StepUpFactorResolver $resolver): EmailOwnershipStepUp
    {
        return new EmailOwnershipStepUp(
            $this->store,
            new StepUpTicket(self::MASTER),
            $this->sender,
            $this->cookie,
            null,
            'login',
            self::MASTER,
            emailCarrierScopes: ['signup' => true],
            now: fn (): int => $this->now,
            factorResolver: $resolver,
        );
    }
}
