<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\RedisStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemand;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandState;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationBindingKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\FactorRequirement;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use PHPUnit\Framework\TestCase;

/**
 * The Redis step-up store over the emulated Predis client: the exact
 * command surface (SET EX NX records, GETDEL consumption, the attempt
 * and window and replay-guard scripts) with real key shapes under the
 * deployment namespace family. The atomic factor completion is
 * exercised over its two-key script: identity, state, liveness and
 * binding are judged in one step. The winner consumes the challenge
 * and completes the demand together, and the escalation marker lands
 * under the session hash and scope.
 */
final class RedisStepUpChallengeStoreTest extends TestCase
{
    private const PRINCIPAL = '00112233445566778899aabbccddeeff';

    private const DEMAND_ID = 'demandid0000000000000000000';

    private const SESSION_ID = 'kernel-test-session-00000001';

    private FakePredisClient $redis;

    private RedisStepUpChallengeStore $store;

    protected function setUp(): void
    {
        $this->redis = new FakePredisClient();
        $this->store = new RedisStepUpChallengeStore($this->redis, '{kiwi:test-ns}:stepup:');
    }

    public function testThePrefixMustBeAHashTaggedFamily(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new RedisStepUpChallengeStore($this->redis, 'stepup:');
    }

    public function testRecordsAreSingleUse(): void
    {
        $challenge = $this->challenge('aaaaaaaaaaaaaaaaaaaaaaa');
        $this->store->create($challenge, 300);
        $key = '{kiwi:test-ns}:stepup:challenge:aaaaaaaaaaaaaaaaaaaaaaa';
        self::assertArrayHasKey($key, $this->redis->strings);
        self::assertStringContainsString('"principal":"'.self::PRINCIPAL.'"', $this->redis->strings[$key]);
        self::assertArrayHasKey($key, $this->redis->expirations, 'the record carries its TTL');

        self::assertNotNull($this->store->read('aaaaaaaaaaaaaaaaaaaaaaa'));
        self::assertNotNull($consumed = $this->store->consume('aaaaaaaaaaaaaaaaaaaaaaa'));
        self::assertSame(self::PRINCIPAL, $consumed->principalPseudonym);
        self::assertNull($this->store->read('aaaaaaaaaaaaaaaaaaaaaaa'), 'the consumed record is gone');
        self::assertNull($this->store->consume('aaaaaaaaaaaaaaaaaaaaaaa'), 'a second consumption answers null');
    }

    public function testTheAttemptScriptCountsAndRemovesAtTheCap(): void
    {
        $id = 'bbbbbbbbbbbbbbbbbbbbbbb';
        $this->store->create($this->challenge($id), 300);
        self::assertSame(1, $this->store->recordFailure($id, 3));
        self::assertSame(2, $this->store->recordFailure($id, 3));
        self::assertSame(0, $this->store->recordFailure($id, 3), 'the cap removes the record');
        self::assertSame(-1, $this->store->recordFailure($id, 3), 'a missing record answers -1');
    }

    public function testTheBeginWindowCountsPerPrincipal(): void
    {
        self::assertSame(1, $this->store->countBegin(self::PRINCIPAL, 900));
        self::assertSame(2, $this->store->countBegin(self::PRINCIPAL, 900));
        $other = 'ffffffffffffffffffffffffffffffff';
        self::assertSame(1, $this->store->countBegin($other, 900));
        self::assertArrayHasKey('{kiwi:test-ns}:stepup:begins:'.self::PRINCIPAL, $this->redis->counters);
    }

    public function testAReleasedReservationRefundsItsBudgets(): void
    {
        // The pre-handoff release must roll the reservation's own
        // increments back: the marker names the counters, the settle
        // script refunds exactly those. A release that only dropped the
        // marker would strand the spend and starve the budget window.
        $dom = 'dom:'.str_repeat('a', 32);
        self::assertTrue($this->store->reserveMailQuota('rel.0.1', [$dom, 'global:'], [1, 1000], 3600, 30));
        self::assertFalse($this->store->reserveMailQuota('rel.0.2', [$dom, 'global:'], [1, 1000], 3600, 30), 'the second reservation passes the limit of one');
        self::assertTrue($this->store->releaseMailQuota('rel.0.1'), 'the pre-handoff release refunds the counters');
        self::assertTrue($this->store->reserveMailQuota('rel.0.3', [$dom, 'global:'], [1, 1000], 3600, 30), 'the freed capacity serves again');
        // A committed reservation never releases: the spend stands.
        $this->store->commitMailQuota('rel.0.3');
        self::assertFalse($this->store->releaseMailQuota('rel.0.3'), 'a committed reservation never releases');
        self::assertFalse($this->store->reserveMailQuota('rel.0.4', [$dom, 'global:'], [1, 1000], 3600, 30), 'the committed spend counts');
        self::assertFalse($this->store->releaseMailQuota('rel.unknown.0.1'), 'an unknown reservation releases nothing');
    }

    public function testTheTotpStateIsDurableAndReplayGuarded(): void
    {
        $this->store->saveTotpSecret(self::PRINCIPAL, 'secret-bytes');
        self::assertSame('secret-bytes', $this->store->findTotpSecret(self::PRINCIPAL));
        self::assertNull($this->store->findTotpSecret('ffffffffffffffffffffffffffffffff'));
        self::assertArrayNotHasKey('{kiwi:test-ns}:stepup:totp:secret:'.self::PRINCIPAL, $this->redis->expirations, 'the enrollment carries no TTL');

        self::assertTrue($this->store->markTotpStep(self::PRINCIPAL, 1000, 90));
        self::assertFalse($this->store->markTotpStep(self::PRINCIPAL, 1000, 90), 'the same step is a replay');
        self::assertFalse($this->store->markTotpStep(self::PRINCIPAL, 999, 90), 'an earlier step is a replay');
        self::assertTrue($this->store->markTotpStep(self::PRINCIPAL, 1001, 90), 'a strictly newer step wins');
    }

    public function testTheLockArmArmsAndNeverShortensALiveLock(): void
    {
        // The differential sweep leaves the lockout deadline out of
        // its projection, so this pin walks the emulated lock-arm
        // lane: the epoch-second deadline the interface names, the
        // no-shorten rule and the expiry read.
        $dimension = 'principal';
        $pseudonym = 'aabbccddeeff00112233445566778899';
        $lockKey = '{kiwi:test-ns}:stepup:lockout:lock:'.$dimension.':'.$pseudonym;
        $now = 1700000000;
        $this->redis->setTimeMs($now * 1000);

        $this->store->armLockout($dimension, $pseudonym, $now, 600);

        self::assertSame($now + 600, $this->store->lockoutUntil($dimension, $pseudonym, $now), 'the lock answers the epoch-second deadline');
        self::assertSame((string) ($now + 600), $this->redis->strings[$lockKey] ?? null, 'the stored value is the deadline itself');
        self::assertSame(600 * 1000 + 60_000, $this->redis->expirations[$lockKey] ?? null, 'the key carries the millisecond PX budget');

        // A shorter request never shortens a live lock: the stored
        // deadline and its budget survive untouched.
        $this->store->armLockout($dimension, $pseudonym, $now + 10, 300);
        self::assertSame($now + 600, $this->store->lockoutUntil($dimension, $pseudonym, $now + 10), 'the shorter arm leaves the deadline standing');
        self::assertSame((string) ($now + 600), $this->redis->strings[$lockKey] ?? null, 'the shorter arm wrote nothing');
        self::assertSame(600 * 1000 + 60_000, $this->redis->expirations[$lockKey] ?? null, 'the shorter arm left the budget alone');

        // Past the deadline the lock reads dead on the advanced clock.
        $this->redis->setTimeMs($this->redis->timeMs() + 601 * 1000);
        self::assertSame(0, $this->store->lockoutUntil($dimension, $pseudonym, $now + 601), 'a passed deadline reads 0');
    }

    public function testTheAtomicFactorCompletionConsumesBothRecordsTogether(): void
    {
        $id = 'ccccccccccccccccccccccc';
        $this->store->create($this->challenge($id), 300);
        $this->store->createDemand($this->demand(self::DEMAND_ID, null), 300);
        // The emulated challenge helper binds no session; drive the
        // stateless secret hash so the script's binding lane runs.
        $challenge = $this->store->read($id);
        self::assertNotNull($challenge);
        $secretHash = (string) $challenge->clientSecretHash;

        $completion = $this->store->completeFactor($id, self::DEMAND_ID, $secretHash, 1700000000, null);

        self::assertNotNull($completion, 'the atomic transition answers the completion');
        self::assertSame($id, $completion->challengeId);
        self::assertSame(self::DEMAND_ID, $completion->demandId);
        self::assertSame(self::PRINCIPAL, $completion->verifiedSubjectPseudonym, 'the verified subject derives from the stored challenge');
        self::assertSame(StepUpChallengeKind::EmailOtp, $completion->kind);
        self::assertNull($this->store->read($id), 'the challenge is consumed');
        $demand = $this->store->readDemand(self::DEMAND_ID);
        self::assertNotNull($demand, 'the completed demand stays as the consumption proof');
        self::assertTrue($demand->state === StepUpDemandState::Completed, 'the demand completed in the same script');
        // A replay of the transition answers nothing.
        self::assertNull($this->store->completeFactor($id, self::DEMAND_ID, $secretHash, 1700000000, null), 'a spent pair completes no one twice');
    }

    public function testTheAtomicFactorCompletionRefusesACrossedOrUnboundPair(): void
    {
        $id = 'ddddddddddddddddddddddd';
        $this->store->create($this->challenge($id), 300);
        $this->store->createDemand($this->demand(self::DEMAND_ID, null), 300);
        $challenge = $this->store->read($id);
        self::assertNotNull($challenge);
        $secretHash = (string) $challenge->clientSecretHash;

        // The challenge names one demand exactly: another open demand
        // of the same scope completes nothing, and the pair survives.
        $other = $this->store->createDemand($this->demand('otherdemandid0000000000001', null), 300);
        self::assertNull($this->store->completeFactor($id, $other, $secretHash, 1700000000, null), 'a crossed pair completes nothing');
        self::assertNotNull($this->store->read($id), 'the crossed refusal consumed nothing');

        // The binding hash is judged inside the script: a browser that
        // presents no client secret completes nothing.
        self::assertNull($this->store->completeFactor($id, self::DEMAND_ID, str_repeat('b', 64), 1700000000, null), 'a wrong binding completes nothing');
        self::assertNotNull($this->store->read($id), 'the binding refusal consumed nothing');
        self::assertTrue($this->store->readDemand(self::DEMAND_ID)?->state->isOpen(), 'the binding refusal completed no demand');
    }

    public function testAWebAuthnRequiredDemandRefusesTheWeakerEmailOtpCompletion(): void
    {
        // The bypass test: a demand whose stored requirement names
        // webauthn (rank 3) attempted with the email_otp factor (the
        // challenge record's kind proves rank 1). The script reads the
        // requirement off the demand and the factor identity off the
        // stored challenge, never a caller argument, and refuses with
        // both records untouched.
        $id = 'fffffffffffffffffffffff';
        $this->store->create($this->challenge($id), 300);
        $required = new FactorRequirement(FactorRequirement::WEBAUTHN, FactorRequirement::WEBAUTHN, 3);
        $demand = StepUpDemand::mint(self::DEMAND_ID, 'login', null, null, null, 1700000000, 300, StepUpOperationBindingKind::None, '', null, null, false, null, $required);
        $this->store->createDemand($demand, 300);
        $challenge = $this->store->read($id);
        self::assertNotNull($challenge);
        $secretHash = (string) $challenge->clientSecretHash;

        self::assertNull($this->store->completeFactor($id, self::DEMAND_ID, $secretHash, 1700000000, null), 'the weaker factor completes nothing');
        self::assertNotNull($this->store->read($id), 'the weaker-factor refusal consumed no challenge');
        self::assertTrue($this->store->readDemand(self::DEMAND_ID)?->state->isOpen(), 'the weaker-factor refusal completed no demand');
    }

    public function testTheExactFactorIdRuleRefusesAnImposterAtTheRequiredRank(): void
    {
        // At the required rank a factor id other than the one the
        // requirement names refuses: a deployment that binds its demand
        // to a custom handler id is never answered by the reference
        // factor of the same family.
        $demandId = 'exactiddemandid00000000001';
        $challengeId = 'exactidchallllllllllllll1';
        $totpChallenge = StepUpChallenge::begin(
            $challengeId,
            StepUpChallengeKind::Totp,
            self::PRINCIPAL,
            null,
            'login',
            null,
            'post_solve_step_up_required',
            1700000000,
            300,
            5,
            null,
            null,
            null,
            false,
            false,
            null,
            $demandId,
        );
        $this->store->create($totpChallenge, 300);
        $customRequired = new FactorRequirement(FactorRequirement::TOTP, 'acme_otp', 2);
        $demand = StepUpDemand::mint($demandId, 'login', null, null, null, 1700000000, 300, StepUpOperationBindingKind::None, '', null, null, false, null, $customRequired);
        $this->store->createDemand($demand, 300);
        $secretHash = (string) $totpChallenge->clientSecretHash;

        self::assertNull($this->store->completeFactor($challengeId, $demandId, $secretHash, 1700000000, null), 'the reference factor never answers a custom factor id at its own rank');
        self::assertNotNull($this->store->read($challengeId), 'the exact-id refusal consumed no challenge');

        // A strictly stronger completion satisfies a weaker floor: the
        // webauthn proof answers an email_otp demand, the ladder is a
        // floor.
        $strongerChallengeId = 'exactidchallllllllllllll3';
        $webauthnChallenge = StepUpChallenge::begin(
            $strongerChallengeId,
            StepUpChallengeKind::WebAuthn,
            self::PRINCIPAL,
            null,
            'login',
            null,
            'post_solve_step_up_required',
            1700000000,
            300,
            5,
            str_repeat('a', 64),
            'assertion',
            null,
            false,
            false,
            null,
            'exactiddemandid00000000003',
        );
        $this->store->create($webauthnChallenge, 300);
        $emailRequired = new FactorRequirement(FactorRequirement::EMAIL_OTP, FactorRequirement::EMAIL_OTP, 1);
        $weakerFloor = StepUpDemand::mint('exactiddemandid00000000003', 'login', null, null, null, 1700000000, 300, StepUpOperationBindingKind::None, '', null, null, false, null, $emailRequired);
        $this->store->createDemand($weakerFloor, 300);
        self::assertNotNull($this->store->completeFactor($strongerChallengeId, 'exactiddemandid00000000003', (string) $webauthnChallenge->clientSecretHash, 1700000000, null), 'the strictly stronger completion satisfies the weaker floor');

        // The matching requirement completes: the same kind satisfies
        // the requirement the demand stored.
        $totpRequired = new FactorRequirement(FactorRequirement::TOTP, FactorRequirement::TOTP, 2);
        $totpDemand = StepUpDemand::mint('exactiddemandid00000000002', 'login', null, null, null, 1700000000, 300, StepUpOperationBindingKind::None, '', null, null, false, null, $totpRequired);
        $totpChallenge = StepUpChallenge::begin(
            'exactidchallllllllllllll2',
            StepUpChallengeKind::Totp,
            self::PRINCIPAL,
            null,
            'login',
            null,
            'post_solve_step_up_required',
            1700000000,
            300,
            5,
            null,
            null,
            null,
            false,
            false,
            null,
            'exactiddemandid00000000002',
        );
        $this->store->create($totpChallenge, 300);
        $this->store->createDemand($totpDemand, 300);
        self::assertNotNull($this->store->completeFactor('exactidchallllllllllllll2', 'exactiddemandid00000000002', (string) $totpChallenge->clientSecretHash, 1700000000, null), 'the matching requirement completes');
    }

    public function testTheCompletionWritesTheEscalationMarkerForTheSession(): void
    {
        $id = 'eeeeeeeeeeeeeeeeeeeeeee';
        // A session-bound challenge writes the marker under its session
        // hash and scope; the stateless one writes none.
        $sessionChallenge = StepUpChallenge::begin(
            $id,
            StepUpChallengeKind::EmailOtp,
            self::PRINCIPAL,
            null,
            'login',
            null,
            'post_solve_step_up_required',
            1700000000,
            300,
            5,
            str_repeat('a', 64),
            null,
            'kernel-test-session-00000001',
            false,
            false,
            null,
            self::DEMAND_ID,
        );
        $this->store->create($sessionChallenge, 300);
        $binding = StepUpChallenge::sessionHash(self::SESSION_ID);
        $this->store->createDemand($this->demand(self::DEMAND_ID, $binding), 300);
        self::assertNotNull($this->store->completeFactor($id, self::DEMAND_ID, (string) $binding, 1700000000, $sessionChallenge->sessionHash));
        self::assertSame(FactorRequirement::EMAIL_OTP, $this->store->completedFactorOf((string) $binding, 'login', 1700000000), 'the marker names the completed factor');
        self::assertNull($this->store->completedFactorOf((string) $binding, 'signup', 1700000000), 'the marker is scoped');
        self::assertNull($this->store->completedFactorOf((string) $binding, 'login', 1700003001), 'the marker dies with the demand lifetime');
        self::assertNull($this->store->completedFactorOf(str_repeat('2', 64), 'login', 1700000000), 'an unmarked session answers nothing');
    }

    public function testTheCompletionAnswersAndRecordsTheFactorTheRecordProves(): void
    {
        // The lane identity of the anonymous grant is email_ownership;
        // the completion and the escalation marker carry the factor the
        // consumed record itself proves (its kind's email_otp rung),
        // never a caller label. No completion can poison the future
        // assurance escalation by claiming a stronger factor than its
        // challenge was begun under.
        $id = 'poisonlabelchallenged000001';
        $challenge = StepUpChallenge::begin(
            $id,
            StepUpChallengeKind::EmailOwnership,
            self::PRINCIPAL,
            null,
            'login',
            null,
            'step_up_email',
            1700000000,
            300,
            5,
            str_repeat('a', 64),
            null,
            self::SESSION_ID,
            false,
            false,
            null,
            self::DEMAND_ID,
        );
        $this->store->create($challenge, 300);
        $binding = StepUpChallenge::sessionHash(self::SESSION_ID);
        $this->store->createDemand($this->demand(self::DEMAND_ID, $binding), 300);

        $completion = $this->store->completeFactor($id, self::DEMAND_ID, (string) $binding, 1700000000, $challenge->sessionHash);

        self::assertNotNull($completion);
        self::assertSame(FactorRequirement::EMAIL_OTP, $completion->completedFactor, 'the completion answers the factor the record proves, not the lane identity');
        self::assertSame(FactorRequirement::EMAIL_OTP, $this->store->completedFactorOf((string) $binding, 'login', 1700000000), 'the marker stores the record-derived family');
    }

    public function testASnapshotDisagreeingWithItsKindIsRemovedFailClosed(): void
    {
        // A record whose snapshot claims a stronger family than its
        // kind proves is incoherent: the script removes it and refuses
        // the completion with both records untouched. Even a corrupted
        // writer can never inflate the assurance a completion books.
        $id = 'poisonedsnapshotid00000001';
        $this->store->create($this->challenge($id), 300);
        $this->store->createDemand($this->demand(self::DEMAND_ID, null), 300);
        $key = '{kiwi:test-ns}:stepup:challenge:'.$id;
        $record = json_decode((string) $this->redis->strings[$key], true);
        self::assertIsArray($record);
        $secretHash = (string) ($record['client_secret_hash'] ?? '');
        $record['factor_family'] = FactorRequirement::WEBAUTHN;
        $record['factor_id'] = FactorRequirement::WEBAUTHN;
        $record['factor_rank'] = 3;
        $this->redis->strings[$key] = (string) json_encode($record, JSON_UNESCAPED_SLASHES);

        self::assertNull($this->store->completeFactor($id, self::DEMAND_ID, $secretHash, 1700000000, null), 'the incoherent snapshot completes nothing');
        self::assertNull($this->redis->strings[$key] ?? null, 'the incoherent record was removed');
        self::assertTrue($this->store->readDemand(self::DEMAND_ID)?->state->isOpen(), 'the incoherent-snapshot refusal completed no demand');
    }

    public function testACustomFactorIdServesItsFamilysRung(): void
    {
        // The contract that admits custom factors: the record carries
        // the server-held factor snapshot resolved at begin, and the
        // gate judges the demand's requirement against that snapshot.
        // A custom handler names its identity inside its kind's family
        // rung (never another family's), and the demand naming that
        // exact id is answered by it, never by the reference factor.
        $demandId = 'customfactoriddemand000001';
        $custom = new FactorRequirement(FactorRequirement::TOTP, 'acme_otp', 2);
        $this->store->createDemand(
            StepUpDemand::mint($demandId, 'login', null, null, null, 1700000000, 300, StepUpOperationBindingKind::None, '', null, null, false, null, $custom),
            300,
        );
        $customChallenge = StepUpChallenge::begin(
            'customfactoridchallenged01',
            StepUpChallengeKind::Totp,
            self::PRINCIPAL,
            null,
            'login',
            null,
            'acme_otp',
            1700000000,
            300,
            5,
            null,
            null,
            null,
            false,
            false,
            null,
            $demandId,
            $custom,
        );
        $this->store->create($customChallenge, 300);
        $completion = $this->store->completeFactor('customfactoridchallenged01', $demandId, (string) $customChallenge->clientSecretHash, 1700000000, null);
        self::assertNotNull($completion, 'the custom factor the snapshot names answers the demand naming it');
        self::assertSame(FactorRequirement::TOTP, $completion->completedFactor);

        // The reference factor of the same family stays foreign to a
        // demand bound to the custom id (the exact-id rule of the same
        // gate), and a demand naming the reference id stays foreign to
        // the custom factor.
        $reference = StepUpChallenge::begin(
            'customfactoridchallenged02',
            StepUpChallengeKind::Totp,
            self::PRINCIPAL,
            null,
            'login',
            null,
            'post_solve_step_up_required',
            1700000000,
            300,
            5,
            null,
            null,
            null,
            false,
            false,
            null,
            $demandId,
        );
        $this->store->create($reference, 300);
        self::assertNull($this->store->completeFactor('customfactoridchallenged02', $demandId, (string) $reference->clientSecretHash, 1700000000, null), 'the reference factor never answers a demand bound to the custom id');

        $referenceDemandId = 'customfactoriddemand000002';
        $this->store->createDemand(
            StepUpDemand::mint($referenceDemandId, 'login', null, null, null, 1700000000, 300, StepUpOperationBindingKind::None, '', null, null, false, null, new FactorRequirement(FactorRequirement::TOTP, FactorRequirement::TOTP, 2)),
            300,
        );
        self::assertNull($this->store->completeFactor('customfactoridchallenged01', $referenceDemandId, (string) $customChallenge->clientSecretHash, 1700000000, null), 'the custom factor never answers a demand bound to the reference id');
    }

    public function testASupersededDemandCompletesNoChallenge(): void
    {
        // The finding this pins: the escalation supersede wrote the
        // parent's child link but left its state open, so the completion
        // script's open-state gate passed and the weak proof landed
        // behind the family's back, past the rung the reassessment had
        // escalated to.
        $this->store->createDemand($this->demand(self::DEMAND_ID, null), 300);
        $challenge = StepUpChallenge::begin(
            'supersededcompletechallenge001',
            StepUpChallengeKind::EmailOtp,
            self::PRINCIPAL,
            null,
            'login',
            null,
            'post_solve_step_up_required',
            1700000000,
            300,
            5,
            str_repeat('a', 64),
            null,
            null,
            false,
            false,
            null,
            self::DEMAND_ID,
        );
        $this->store->create($challenge, 300);
        $child = $this->store->readDemand(self::DEMAND_ID)->spawnChild('supersededcompletechild0000001', 1700000000, 'decision-2');
        self::assertNotNull($this->store->supersedeDemandWithChild(self::DEMAND_ID, $child), 'the escalation replaces the open parent');
        self::assertNull($this->store->completeFactor('supersededcompletechallenge001', self::DEMAND_ID, (string) $challenge->clientSecretHash, 1700000001, null), 'the superseded parent completes no challenge');
        self::assertNotNull($this->store->read('supersededcompletechallenge001'), 'the refusal never consumes the challenge');
        self::assertNull($this->store->claimDemandFinalization(self::DEMAND_ID, 1700000002, 30), 'the superseded parent is never claimed for finalization');
    }

    public function testATerminalDemandIsNeverSupersededIntoAFreshSibling(): void
    {
        // The finding this pins: the supersede script accepted parents
        // in any non-superseded state, handing an already-settled
        // operation a fresh live sibling demand.
        $this->store->createDemand($this->demand(self::DEMAND_ID, null), 300);
        self::assertNotNull($this->store->completeDemand(self::DEMAND_ID, 1700000001, 300));
        self::assertNotNull($this->store->claimDemandFinalization(self::DEMAND_ID, 1700000002, 30));
        self::assertNotNull($this->store->settleDemandFinalization(self::DEMAND_ID, StepUpDemandState::Authorized, 1700000003));
        $child = $this->store->readDemand(self::DEMAND_ID)->spawnChild('supersededterminalchild00001', 1700000003, 'decision-2');
        self::assertNull($this->store->supersedeDemandWithChild(self::DEMAND_ID, $child), 'an authorized demand is history, not a family head');
        self::assertNull($this->store->readDemand('supersededterminalchild00001'), 'the refused child was never written');
    }

    public function testASupersededFinalizingDemandAuthorizesThroughNothing(): void
    {
        // The finding this pins: a stale claimant retaking a finalizing
        // demand that escalation had already superseded could drive it
        // to the authorized terminal past the stronger child.
        $this->store->createDemand($this->demand(self::DEMAND_ID, null), 300);
        self::assertNotNull($this->store->completeDemand(self::DEMAND_ID, 1700000001, 300));
        self::assertNotNull($this->store->claimDemandFinalization(self::DEMAND_ID, 1700000002, 30));
        $child = $this->store->readDemand(self::DEMAND_ID)->spawnChild('supersededfinalizingchild0001', 1700000002, 'decision-2');
        self::assertNotNull($this->store->supersedeDemandWithChild(self::DEMAND_ID, $child), 'the escalator holding its claim supersedes');
        self::assertNull($this->store->settleDemandFinalization(self::DEMAND_ID, StepUpDemandState::Authorized, 1700000003), 'a superseded demand never settles authorized');
        self::assertNull($this->store->claimDemandFinalization(self::DEMAND_ID, 1700000040, 30), 'a stale claimant never retakes a superseded demand');
        self::assertNull($this->store->settleDemandFinalization(self::DEMAND_ID, StepUpDemandState::Superseded, 1700000004), 'the superseded terminal already landed inside the supersede transaction; no follow-up settlement exists');
        self::assertNull($this->store->completeDemand(self::DEMAND_ID, 1700000005, 300), 'a superseded demand never completes');
    }

    private function demand(string $id, ?string $sessionHash): StepUpDemand
    {
        return StepUpDemand::mint($id, 'login', $sessionHash, null, null, 1700000000, 300);
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
            1700000000,
            300,
            5,
            str_repeat('a', 64),
            null,
            null,
            false,
            false,
            null,
            self::DEMAND_ID,
        );
    }
}
