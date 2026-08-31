<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\ArrayChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainIssuedResult;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainReservationResult;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainVerifiedResult;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\ArrayChainDriver;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\ChainModel;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\ChainStateWalk;
use KiwiCaptcha\Risk\RiskAction;
use PHPUnit\Framework\TestCase;

/**
 * Model checking of the chained-challenge state machine (risk.chaining,
 * the obligation-anchored transactional contract).
 *
 * The machine (docs/chained-challenges.md):
 *
 *  - States: absent -> available -> reserved(owner, short lease) ->
 *    issued(stage2Nonce). The terminal states: verified(nonce) (the
 *    Pass, obligation cleared atomically), step_up_required(nonce|null)
 *    and denied(nonce|null) (obligation kept). The rearm is nonce-pinned:
 *    issued(nonce) -> available, and the nonce-agnostic
 *    obligation-bound transaction terminalizations apply to an open
 *    obligation.
 *  - Transitions: create-or-get (issue), reserve, release, markIssued,
 *    markVerified, markStepUpRequired, markDenied,
 *    markTransactionDenied, markTransactionStepUpRequired, rearmIssued,
 *    deleteObligation, expire (TTL), advanceLease.
 *  - Guards: the owner token (reserve/issue/release), the exact pinned
 *    stage-2 nonce (terminal transitions + rearm), the obligation id +
 *    mapping agreement (transaction terminalizations), and the TTL/expiry
 *    (a record without an expiry fails closed). The identity triple
 *    (scope, authoritative binding, policy epoch) derives the obligation
 *    id.
 *
 * The invariants asserted after every transition of every explored
 * sequence (ChainModel::assertInvariants):
 *
 *  I1 single-use per challenge: a stage-2 nonce can be consumed by a
 *     Pass at most once; a chain generation succeeds at most once (no
 *     double success).
 *  I2 a consumed chain never mints again: after a terminal state, no
 *     fresh stage-2 issuance, no reservation, no rearm.
 *  I3 the issued nonce is immutable until the nonce-pinned rearm.
 *  I4 an expired chain answers missing/false only and is never mutated.
 *  I5 terminal states are absorbing (only the TTL removes them).
 *  I6 the obligation lifecycle (cleared by Pass/expiry, kept by the
 *     disposition terminalizations, never resurrected).
 *  I7 the strict v2 record schema invariants.
 *  I8 the identity triple is immutable (a ticket can never be replayed
 *     under a different scope/binding/epoch).
 *  I9 the required-rank floor is monotone (never lowered).
 *
 * Every hand-enumerated sequence and the bounded random walk (fixed
 * seed) run in lockstep against the clean-room {@see ChainModel} and the
 * concrete in-memory store, asserting outcome parity and record-level
 * state equality after every step.
 */
final class ChainStateMachineModelTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    /**
     * Exhaustive reachability: a BFS over the abstract machine's full
     * configuration space (state x owner x lease x nonce x obligation x
     * lifetime x rank x per-generation history), applying every
     * transition with every argument combination from every reachable
     * configuration. The invariant suite is asserted on every edge. The
     * visited set makes the enumeration complete over reachable
     * configurations, so any reachable sequence that could violate an
     * invariant is explored.
     */
    public function testExhaustiveReachabilitySatisfiesTheInvariants(): void
    {
        $start = ChainModel::fresh(ChainStateWalk::OBLIGATION);
        $visited = [];
        $queue = [$start];
        $edges = 0;
        while ($queue !== []) {
            $config = array_shift($queue);
            $key = $config->configKey();
            if (isset($visited[$key])) {
                continue;
            }
            $visited[$key] = true;
            foreach (self::bfsTransitions($config) as [$name, $args]) {
                $to = clone $config;
                $outcome = $to->apply($name, $args);
                ChainModel::assertInvariants($config, $to, $outcome, $name, $args, sprintf('bfs %s --%s-->', $key, $name));
                ++$edges;
                $next = $to->configKey();
                if (!isset($visited[$next])) {
                    $queue[] = $to;
                }
            }
        }
        self::assertGreaterThan(50, \count($visited), 'the machine has a non-trivial reachable configuration space');
        self::assertGreaterThan(1000, $edges, 'the machine has a non-trivial reachable transition space');
    }

    // ── Hand-enumerated sequences (each on the model + the Array store) ──

    public function testHappyPathConsumesTheChainExactlyOnce(): void
    {
        ChainStateWalk::run('hand-happy', new ArrayChainDriver(), [
            ['createOrGet', ['rank' => 1]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[0]]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[0]]],
            ['markIssued', ['owner' => ChainStateWalk::OWNERS[0], 'nonce' => ChainStateWalk::NONCES[0]]],
            ['markIssued', ['owner' => ChainStateWalk::OWNERS[0], 'nonce' => ChainStateWalk::NONCES[0]]],
            ['markVerified', ['nonce' => ChainStateWalk::NONCES[0]]],
            ['markVerified', ['nonce' => ChainStateWalk::NONCES[0]]],
            ['markVerified', ['nonce' => ChainStateWalk::NONCES[1]]],
            ['markIssued', ['owner' => ChainStateWalk::OWNERS[0], 'nonce' => ChainStateWalk::NONCES[0]]],
            ['rearmIssued', ['nonce' => ChainStateWalk::NONCES[0]]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[1]]],
        ]);
    }

    public function testReservationContentionReleaseAndExpiredLeaseTakeover(): void
    {
        ChainStateWalk::run('hand-contention', new ArrayChainDriver(), [
            ['createOrGet', ['rank' => 1]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[0]]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[1]]],
            ['release', ['owner' => ChainStateWalk::OWNERS[1]]],
            ['markIssued', ['owner' => ChainStateWalk::OWNERS[1], 'nonce' => ChainStateWalk::NONCES[0]]],
            ['advanceLease', []],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[1]]],
            ['markIssued', ['owner' => ChainStateWalk::OWNERS[0], 'nonce' => ChainStateWalk::NONCES[0]]],
            ['markIssued', ['owner' => ChainStateWalk::OWNERS[1], 'nonce' => ChainStateWalk::NONCES[0]]],
        ]);
    }

    public function testFailedIssuanceReleasesTheReservationAndKeepsTheTicketReusable(): void
    {
        ChainStateWalk::run('hand-release-reuse', new ArrayChainDriver(), [
            ['createOrGet', ['rank' => 1]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[0]]],
            ['release', ['owner' => ChainStateWalk::OWNERS[0]]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[1]]],
            ['markIssued', ['owner' => ChainStateWalk::OWNERS[1], 'nonce' => ChainStateWalk::NONCES[0]]],
        ]);
    }

    public function testTerminalDeniedChainIsAbsorbing(): void
    {
        ChainStateWalk::run('hand-denied', new ArrayChainDriver(), [
            ['createOrGet', ['rank' => 1]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[0]]],
            ['markIssued', ['owner' => ChainStateWalk::OWNERS[0], 'nonce' => ChainStateWalk::NONCES[0]]],
            ['markDenied', ['nonce' => ChainStateWalk::NONCES[0]]],
            ['markDenied', ['nonce' => ChainStateWalk::NONCES[0]]],
            ['markVerified', ['nonce' => ChainStateWalk::NONCES[0]]],
            ['markStepUpRequired', ['nonce' => ChainStateWalk::NONCES[0]]],
            ['markIssued', ['owner' => ChainStateWalk::OWNERS[1], 'nonce' => ChainStateWalk::NONCES[0]]],
            ['markIssued', ['owner' => ChainStateWalk::OWNERS[1], 'nonce' => ChainStateWalk::NONCES[1]]],
            ['rearmIssued', ['nonce' => ChainStateWalk::NONCES[0]]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[1]]],
            ['markTransactionDenied', ['obligationId' => ChainStateWalk::OBLIGATION]],
            ['markTransactionStepUpRequired', ['obligationId' => ChainStateWalk::OBLIGATION]],
            ['deleteObligation', []],
            ['markTransactionDenied', ['obligationId' => ChainStateWalk::OBLIGATION]],
        ]);
    }

    public function testRearmIsNoncePinnedAndTheRearmedAwayChallengeNeverVerifies(): void
    {
        ChainStateWalk::run('hand-rearm', new ArrayChainDriver(), [
            ['createOrGet', ['rank' => 1]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[0]]],
            ['markIssued', ['owner' => ChainStateWalk::OWNERS[0], 'nonce' => ChainStateWalk::NONCES[0]]],
            ['rearmIssued', ['nonce' => ChainStateWalk::NONCES[1]]],
            ['rearmIssued', ['nonce' => ChainStateWalk::NONCES[0]]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[0]]],
            ['markIssued', ['owner' => ChainStateWalk::OWNERS[0], 'nonce' => ChainStateWalk::NONCES[1]]],
            ['markVerified', ['nonce' => ChainStateWalk::NONCES[0]]],
            ['markVerified', ['nonce' => ChainStateWalk::NONCES[1]]],
            ['markVerified', ['nonce' => ChainStateWalk::NONCES[0]]],
            ['rearmIssued', ['nonce' => ChainStateWalk::NONCES[1]]],
        ]);
    }

    public function testTransactionTerminalizationPreservesTheIssuedNonceAndThePassStaysRefused(): void
    {
        ChainStateWalk::run('hand-txn-deny', new ArrayChainDriver(), [
            ['createOrGet', ['rank' => 1]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[0]]],
            ['markIssued', ['owner' => ChainStateWalk::OWNERS[0], 'nonce' => ChainStateWalk::NONCES[0]]],
            ['markTransactionDenied', ['obligationId' => ChainStateWalk::OBLIGATION]],
            ['markVerified', ['nonce' => ChainStateWalk::NONCES[0]]],
            ['markDenied', ['nonce' => ChainStateWalk::NONCES[0]]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[1]]],
        ]);
    }

    public function testAForeignObligationIdIsRefusedByTheTransactionTerminalizations(): void
    {
        ChainStateWalk::run('hand-foreign', new ArrayChainDriver(), [
            ['createOrGet', ['rank' => 1]],
            ['markTransactionDenied', ['obligationId' => ChainStateWalk::OTHER_OBLIGATION]],
            ['markTransactionStepUpRequired', ['obligationId' => ChainStateWalk::OTHER_OBLIGATION]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[0]]],
        ]);
    }

    public function testCompareDeleteOfTheObligationNeverRevivesIt(): void
    {
        ChainStateWalk::run('hand-delete-obligation', new ArrayChainDriver(), [
            ['createOrGet', ['rank' => 1]],
            ['deleteObligation', []],
            ['markTransactionDenied', ['obligationId' => ChainStateWalk::OBLIGATION]],
            ['markTransactionStepUpRequired', ['obligationId' => ChainStateWalk::OBLIGATION]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[0]]],
            ['markIssued', ['owner' => ChainStateWalk::OWNERS[0], 'nonce' => ChainStateWalk::NONCES[0]]],
            ['markVerified', ['nonce' => ChainStateWalk::NONCES[0]]],
        ]);
    }

    public function testLegacyCompleteIsTheSemanticAliasOfIssued(): void
    {
        ChainStateWalk::run('hand-complete', new ArrayChainDriver(), [
            ['createOrGet', ['rank' => 1]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[0]]],
            ['complete', ['owner' => ChainStateWalk::OWNERS[0], 'nonce' => ChainStateWalk::NONCES[0]]],
            ['markIssued', ['owner' => ChainStateWalk::OWNERS[0], 'nonce' => ChainStateWalk::NONCES[0]]],
            ['markVerified', ['nonce' => ChainStateWalk::NONCES[0]]],
            ['markVerified', ['nonce' => ChainStateWalk::NONCES[0]]],
            ['markIssued', ['owner' => ChainStateWalk::OWNERS[1], 'nonce' => ChainStateWalk::NONCES[1]]],
        ]);
    }

    public function testRequiredRankFloorIsMonotonic(): void
    {
        // The parity assertions of the walk itself prove the concrete
        // rank equals the model rank after every step; the model
        // invariants prove the floor never lowers (I9). The explicit
        // read confirms the raised floor on the concrete record.
        $driver = new ArrayChainDriver();
        ChainStateWalk::run('hand-rank', $driver, [
            ['createOrGet', ['rank' => 1]],
            ['createOrGet', ['rank' => 6]],
            ['createOrGet', ['rank' => 1]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[0]]],
            ['markIssued', ['owner' => ChainStateWalk::OWNERS[0], 'nonce' => ChainStateWalk::NONCES[0]]],
        ]);
        $chainId = $driver->obligationChainId(ChainStateWalk::OBLIGATION);
        self::assertIsString($chainId);
        $record = $driver->read($chainId);
        self::assertIsArray($record);
        self::assertSame(6, $record['requiredRank'], 'a weaker reassessment never lowers the floor');
        self::assertSame('argon64', $record['requiredAction'], 'the action follows the raised floor');
    }

    public function testFreshCreationAfterExpiryStartsANewGenerationAndSealsTheOld(): void
    {
        // The expired chain's generation is sealed (its invariants held on
        // every step), and the fresh chain of the same obligation starts a
        // brand-new generation at the available state — never a stage-1
        // downgrade, never a resurrection of the prior chain's state.
        ChainStateWalk::run('hand-generation', new ArrayChainDriver(), [
            ['createOrGet', ['rank' => 1]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[0]]],
            ['markIssued', ['owner' => ChainStateWalk::OWNERS[0], 'nonce' => ChainStateWalk::NONCES[0]]],
            ['markVerified', ['nonce' => ChainStateWalk::NONCES[0]]],
            ['expire', []],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[0]]],
            ['markIssued', ['owner' => ChainStateWalk::OWNERS[0], 'nonce' => ChainStateWalk::NONCES[0]]],
            ['createOrGet', ['rank' => 1]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[1]]],
        ]);
    }

    // ── The bounded random walk (fixed seed) ───────────────────────────

    public function testBoundedRandomWalkKeepsEveryInvariantAgainstTheArrayStore(): void
    {
        $driver = new ArrayChainDriver();
        $result = ChainStateWalk::run('array-walk', $driver, ChainStateWalk::steps(0x5EED, 1500));
        self::assertSame(1500, $result['steps']);
        self::assertGreaterThan(1, $result['generations'], 'the walk must exercise fresh chain creations after expiry');
    }

    // ── Ticket-level invariants (the service surface) ──────────────────

    public function testExpiredChainTicketCanNeverBeRedeemed(): void
    {
        $clock = 1_000_000;
        $store = new ArrayChainedChallengeStateStore(static function () use (&$clock): float {
            return (float) $clock;
        });
        $service = new ChainedChallengeTicketService($store, self::SECRET, 300, 15, null, static function () use (&$clock): int {
            return $clock;
        });

        $requirement = $service->requireStage2(self::stageNonce('stage1'), 'login', '', 1, RiskAction::Argon32, $clock + 300);
        $ticket = $service->ticketFor($requirement->chainId, $requirement->expiresAt);
        self::assertIsArray($service->verify($ticket), 'the ticket verifies while the chain is live');
        self::assertSame($requirement->expiresAt, (int) $service->verify($ticket)['expiresAt'], 'the signed expiry equals the server-held expiry');

        $clock = $requirement->expiresAt + 1;
        self::assertNull($service->verify($ticket), 'an expired ticket fails signature-bound verification');
        self::assertSame(ChainReservationResult::Missing, $service->reserveStage2($requirement->chainId, 'owner-a'), 'an expired chain can never be reserved');
        self::assertSame(ChainIssuedResult::Missing, $service->markIssued($requirement->chainId, 'owner-a', self::stageNonce('stage2')), 'an expired chain can never mint');
        self::assertSame(ChainVerifiedResult::Missing, $service->markVerified($requirement->chainId, self::stageNonce('stage2')), 'an expired chain can never verify');
        self::assertFalse($service->rearmIssued($requirement->chainId, self::stageNonce('stage2')), 'an expired chain can never rearm');
        self::assertNull($service->requirementFor($requirement->chainId), 'the expired chain state is gone');
        self::assertNull($service->findOpenRequirement('login', '', 1), 'the expired obligation is gone');
    }

    public function testAPolicyEpochChangeInvalidatesOutstandingChainTickets(): void
    {
        $clock = 1_000_000;
        $store = new ArrayChainedChallengeStateStore(static function () use (&$clock): float {
            return (float) $clock;
        });
        $service = new ChainedChallengeTicketService($store, self::SECRET, 300, 15, null, static function () use (&$clock): int {
            return $clock;
        });

        $chain = $service->requireStage2(self::stageNonce('stage1'), 'login', 'txn-alpha', 1, RiskAction::Argon32, $clock + 300);
        $obligationEpoch1 = $service->obligationIdFor('login', 'txn-alpha', 1);
        $obligationEpoch2 = $service->obligationIdFor('login', 'txn-alpha', 2);

        self::assertNotSame($obligationEpoch1, $obligationEpoch2, 'the policy epoch participates in the obligation id');
        self::assertSame($chain->chainId, $store->obligationChainId($obligationEpoch1), 'the epoch-1 obligation maps the chain');
        self::assertNull($store->obligationChainId($obligationEpoch2), 'the epoch-2 obligation does not exist');
        self::assertNull($service->findOpenRequirement('login', 'txn-alpha', 2), 'the new epoch sees no open chain — the outstanding ticket is invalidated');
        self::assertSame(1, $service->requirementFor($chain->chainId)?->policyVersion, 'the chain record carries the prior epoch, which the new-epoch admission refuses');
    }

    public function testATicketCannotBeReplayedUnderADifferentOperationIdentity(): void
    {
        $clock = 1_000_000;
        $store = new ArrayChainedChallengeStateStore(static function () use (&$clock): float {
            return (float) $clock;
        });
        $service = new ChainedChallengeTicketService($store, self::SECRET, 300, 15, null, static function () use (&$clock): int {
            return $clock;
        });

        $chainAlpha = $service->requireStage2(self::stageNonce('stage1'), 'login', 'txn-alpha', 1, RiskAction::Argon32, $clock + 300);
        $ticketAlpha = $service->ticketFor($chainAlpha->chainId, $chainAlpha->expiresAt);
        self::assertSame($chainAlpha->chainId, $service->findOpenRequirement('login', 'txn-alpha', 1)?->chainId, 'the ticket\'s transaction resolves its chain');

        // The same ticket under a different authoritative binding, scope
        // or epoch computes a different obligation: no chain resolves.
        self::assertNull($service->findOpenRequirement('login', 'txn-beta', 1), 'a different binding resolves no chain');
        self::assertNull($service->findOpenRequirement('signup', 'txn-alpha', 1), 'a different scope resolves no chain');
        self::assertNull($service->findOpenRequirement('login', 'txn-alpha', 2), 'a different epoch resolves no chain');

        // A different identity gets its own chain; the foreign ticket can
        // never mint on it (the record binds txn-alpha, the obligation of
        // txn-beta points at txn-beta's chain).
        $chainBeta = $service->requireStage2(self::stageNonce('stage1b'), 'login', 'txn-beta', 1, RiskAction::Argon32, $clock + 300);
        self::assertNotSame($chainAlpha->chainId, $chainBeta->chainId, 'different identities get different chains');
        self::assertSame('txn-alpha', $service->requirementFor($chainAlpha->chainId)?->requestBinding, 'the record binds the identity it was created under');
    }

    public function testTheChainedRedemptionConsumesExactlyOneTicket(): void
    {
        $clock = 1_000_000;
        $store = new ArrayChainedChallengeStateStore(static function () use (&$clock): float {
            return (float) $clock;
        });
        $service = new ChainedChallengeTicketService($store, self::SECRET, 300, 15, null, static function () use (&$clock): int {
            return $clock;
        });
        $stage2 = self::stageNonce('stage2');

        $requirement = $service->requireStage2(self::stageNonce('stage1'), 'login', 'txn-alpha', 1, RiskAction::Argon32, $clock + 300);
        $ticket = $service->ticketFor($requirement->chainId, $requirement->expiresAt);

        // One redemption: exactly one fresh mint, then exactly one Pass,
        // then the obligation is cleared and nothing can mint or verify
        // again — the ticket is consumed exactly once.
        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($requirement->chainId, 'owner-a', $stage2));
        self::assertSame(ChainReservationResult::Issued, $service->reserveStage2($requirement->chainId, 'owner-b'), 'a second reservation finds the chain issued — never a second mint');
        self::assertSame(ChainIssuedResult::IssuedSame, $service->markIssued($requirement->chainId, 'owner-b', $stage2), 'a retry recovers the SAME challenge — never a second mint');
        self::assertSame(ChainVerifiedResult::VerifiedNew, $service->markVerified($requirement->chainId, $stage2));
        self::assertNull($store->obligationChainId($service->obligationIdFor('login', 'txn-alpha', 1)), 'the Pass cleared the obligation exactly once');

        // The consumed chain: every redemption surface reports the
        // terminal state, never a fresh authorization.
        self::assertSame(ChainReservationResult::Verified, $service->reserveStage2($requirement->chainId, 'owner-b'));
        self::assertSame(ChainIssuedResult::VerifiedSame, $service->markIssued($requirement->chainId, 'owner-b', $stage2));
        self::assertSame(ChainVerifiedResult::VerifiedSame, $service->markVerified($requirement->chainId, $stage2));
        self::assertSame(ChainVerifiedResult::Conflict, $service->markVerified($requirement->chainId, self::stageNonce('other')), 'a different nonce on the consumed chain is a conflict');
        self::assertFalse($service->rearmIssued($requirement->chainId, $stage2), 'a consumed chain can never rearm');
    }

    /** A deterministic Kiwi-shaped nonce for a seed. */
    private static function stageNonce(string $seed): string
    {
        return base64_encode(hash('sha256', 'model:'.$seed, true));
    }

    /**
     * Every transition with every argument combination, filtered by
     * applicability (the create-or-get never runs against a live
     * generation whose obligation is gone — that is the fresh-generation
     * path the walk covers with a new chain id).
     *
     * @return list<array{0: string, 1: array<string, mixed>}>
     */
    private static function bfsTransitions(ChainModel $config): array
    {
        $transitions = [];
        if ($config->alive && ($config->state === ChainModel::ABSENT || $config->obligationPresent)) {
            $transitions[] = ['createOrGet', ['rank' => 1]];
            $transitions[] = ['createOrGet', ['rank' => 6]];
        }
        foreach (ChainStateWalk::OWNERS as $owner) {
            $transitions[] = ['reserve', ['owner' => $owner]];
            $transitions[] = ['release', ['owner' => $owner]];
            foreach (ChainStateWalk::NONCES as $nonce) {
                $transitions[] = ['markIssued', ['owner' => $owner, 'nonce' => $nonce]];
            }
        }
        foreach (ChainStateWalk::NONCES as $nonce) {
            $transitions[] = ['markVerified', ['nonce' => $nonce]];
            $transitions[] = ['markStepUpRequired', ['nonce' => $nonce]];
            $transitions[] = ['markDenied', ['nonce' => $nonce]];
            $transitions[] = ['rearmIssued', ['nonce' => $nonce]];
        }
        $transitions[] = ['markTransactionDenied', ['obligationId' => ChainStateWalk::OBLIGATION]];
        $transitions[] = ['markTransactionDenied', ['obligationId' => ChainStateWalk::OTHER_OBLIGATION]];
        $transitions[] = ['markTransactionStepUpRequired', ['obligationId' => ChainStateWalk::OBLIGATION]];
        $transitions[] = ['markTransactionStepUpRequired', ['obligationId' => ChainStateWalk::OTHER_OBLIGATION]];
        $transitions[] = ['deleteObligation', []];
        $transitions[] = ['advanceLease', []];
        $transitions[] = ['expire', []];

        return $transitions;
    }
}
