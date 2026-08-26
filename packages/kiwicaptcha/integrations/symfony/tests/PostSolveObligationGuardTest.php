<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDisposition;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionKind;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveFinalizeOutcome;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisPostSolveDispositionStore;
use PHPUnit\Framework\TestCase;

/**
 * The transaction acceptance guard: the CAS ordering across the
 * transaction-level chain machine and the nonce-level disposition
 * machine. The validator resolves the requirement snapshot once, then
 * claims and finalizes; a concurrent requireStage2 or terminalization
 * can advance the transaction between the snapshot and the acceptance.
 * These tests force that exact ordering deterministically, without
 * probabilistic parallelism: the snapshot state is fixed, the
 * transaction advances, and the acceptance must refuse the stale Pass
 * with the typed outcome. A Pass is never committed (or replayed) once
 * the transaction no longer authorizes it.
 */
final class PostSolveObligationGuardTest extends TestCase
{
    private const NAMESPACE = 'kiwi-guard-test';

    private const OBLIGATION_ID = 'a000000000000000000000000000000000000000000000000000000000000000';

    private const CHAIN_ID = 'chain-guard-a';

    /** The chain v2 record wire (the guard's read surface). */
    private function chainRecord(string $state, ?string $stage2Nonce = null): string
    {
        return (string) json_encode([
            'v' => 2,
            'stage1Nonce' => 'nonce-a',
            'scope' => 'login',
            'obligationId' => self::OBLIGATION_ID,
            'requiredAction' => 'sha20',
            'requiredRank' => 8,
            'policyVersion' => 1,
            'chainDepth' => 2,
            'state' => $state,
            'owner' => null,
            'leaseUntil' => null,
            'stage2Nonce' => $stage2Nonce,
            'requestBinding' => 'auth',
            'expiresAt' => time() + 300,
        ], JSON_THROW_ON_ERROR);
    }

    private function obligationKey(): string
    {
        return '{kiwi:'.self::NAMESPACE.'}:chain-obligation:'.self::OBLIGATION_ID;
    }

    private function chainKey(): string
    {
        return '{kiwi:'.self::NAMESPACE.'}:chain:'.self::CHAIN_ID;
    }

    private function store(DispositionWaitRedisFake $fake, int $waitReplicas = 0): RedisPostSolveDispositionStore
    {
        return new RedisPostSolveDispositionStore($fake, self::NAMESPACE, 300, $waitReplicas, 100);
    }

    /**
     * Worker B: claim (snapshot: no chain), then a pause. Worker A:
     * requireStage2 opens the transaction's chain. Worker B continues
     * with its stale snapshot and attempts the Pass finalize: the guard
     * must refuse atomically with ChainRequired, and the stale Pass is
     * never committed.
     */
    public function testFreshPassAgainstConcurrentChainRequiredIsRefused(): void
    {
        $fake = new DispositionWaitRedisFake();
        $store = $this->store($fake);
        $nonce = bin2hex(random_bytes(16));

        // Worker B wins the claim with the no-chain snapshot.
        [$claim, , $guard] = $store->claim($nonce, 'owner-b', 300, null, self::OBLIGATION_ID, null, null);
        self::assertSame('claimed', $claim);
        self::assertSame(PostSolveFinalizeOutcome::Finalized, $guard);

        // Worker A: requireStage2 -> the obligation maps to an open
        // (available) chain.
        $fake->strings[$this->obligationKey()] = self::CHAIN_ID;
        $fake->strings[$this->chainKey()] = $this->chainRecord('available');

        // Worker B continues: the stale Pass must be refused.
        $outcome = $store->finalizeGuarded($nonce, 'owner-b', new PostSolveDisposition(PostSolveDispositionKind::Pass), self::OBLIGATION_ID, null, null);
        self::assertSame(PostSolveFinalizeOutcome::ChainRequired, $outcome, 'B must not commit the stale Pass after A opened the chain');
        $record = json_decode((string) $fake->strings['{kiwi:'.self::NAMESPACE.'}:postsolve:'.$nonce], true, 8, JSON_THROW_ON_ERROR);
        self::assertSame('pending', $record['state'], 'the refused Pass performs no write: the record stays pending');
        self::assertNull($record['disposition'], 'no stale Pass is ever persisted');
    }

    /**
     * The issued-chain variant: the chain's current stage-2 nonce is a
     * different nonce, so this nonce's Pass is refused ChainRequired.
     */
    public function testFreshPassAgainstIssuedChainForAnotherNonceIsRefused(): void
    {
        $fake = new DispositionWaitRedisFake();
        $store = $this->store($fake);
        $nonce = bin2hex(random_bytes(16));
        $otherNonce = bin2hex(random_bytes(16));

        self::assertSame('claimed', $store->claim($nonce, 'owner-b', 300, null, self::OBLIGATION_ID, null, null)[0]);
        $fake->strings[$this->obligationKey()] = self::CHAIN_ID;
        $fake->strings[$this->chainKey()] = $this->chainRecord('issued', $otherNonce);

        $outcome = $store->finalizeGuarded($nonce, 'owner-b', new PostSolveDisposition(PostSolveDispositionKind::Pass), self::OBLIGATION_ID, null, null);
        self::assertSame(PostSolveFinalizeOutcome::ChainRequired, $outcome, 'a Pass for a nonce that is not the chain current stage-2 nonce is refused');
    }

    /**
     * The transaction's OWN stage-2 nonce Pass commits: the chain is
     * issued with exactly this nonce, so the guarded finalize proceeds.
     */
    public function testAuthorizedStage2PassCommits(): void
    {
        $fake = new DispositionWaitRedisFake();
        $store = $this->store($fake);
        $nonce = bin2hex(random_bytes(16));

        self::assertSame('claimed', $store->claim($nonce, 'owner-b', 300, null, self::OBLIGATION_ID, null, null)[0]);
        $fake->strings[$this->obligationKey()] = self::CHAIN_ID;
        $fake->strings[$this->chainKey()] = $this->chainRecord('issued', $nonce);

        $outcome = $store->finalizeGuarded($nonce, 'owner-b', new PostSolveDisposition(PostSolveDispositionKind::Pass), self::OBLIGATION_ID, self::CHAIN_ID, $nonce);
        self::assertSame(PostSolveFinalizeOutcome::Finalized, $outcome, 'the chain own stage-2 nonce is authorized');
        $record = json_decode((string) $fake->strings['{kiwi:'.self::NAMESPACE.'}:postsolve:'.$nonce], true, 8, JSON_THROW_ON_ERROR);
        self::assertSame('complete', $record['state']);
    }

    /**
     * Worker B snapshots no terminal state; Worker A terminalizes the
     * transaction (denied); B attempts the fresh Pass finalize: refused
     * TransactionDenied.
     */
    public function testFreshPassAgainstConcurrentTerminalDenialIsRefused(): void
    {
        $fake = new DispositionWaitRedisFake();
        $store = $this->store($fake);
        $nonce = bin2hex(random_bytes(16));

        self::assertSame('claimed', $store->claim($nonce, 'owner-b', 300, null, self::OBLIGATION_ID, null, null)[0]);
        $fake->strings[$this->obligationKey()] = self::CHAIN_ID;
        $fake->strings[$this->chainKey()] = $this->chainRecord('denied');

        $outcome = $store->finalizeGuarded($nonce, 'owner-b', new PostSolveDisposition(PostSolveDispositionKind::Pass), self::OBLIGATION_ID, null, null);
        self::assertSame(PostSolveFinalizeOutcome::TransactionDenied, $outcome, 'a terminal denial dominates the stale Pass');
        $record = json_decode((string) $fake->strings['{kiwi:'.self::NAMESPACE.'}:postsolve:'.$nonce], true, 8, JSON_THROW_ON_ERROR);
        self::assertSame('pending', $record['state']);
    }

    /**
     * Worker B snapshots no terminal state; Worker A terminalizes the
     * transaction (step_up_required); B attempts the fresh Pass:
     * refused TransactionStepUp.
     */
    public function testFreshPassAgainstConcurrentTerminalStepUpIsRefused(): void
    {
        $fake = new DispositionWaitRedisFake();
        $store = $this->store($fake);
        $nonce = bin2hex(random_bytes(16));

        self::assertSame('claimed', $store->claim($nonce, 'owner-b', 300, null, self::OBLIGATION_ID, null, null)[0]);
        $fake->strings[$this->obligationKey()] = self::CHAIN_ID;
        $fake->strings[$this->chainKey()] = $this->chainRecord('step_up_required');

        $outcome = $store->finalizeGuarded($nonce, 'owner-b', new PostSolveDisposition(PostSolveDispositionKind::Pass), self::OBLIGATION_ID, null, null);
        self::assertSame(PostSolveFinalizeOutcome::TransactionStepUp, $outcome);
    }

    /**
     * The terminal replay variant: Worker A durably persisted Pass, then
     * the transaction terminalized (denied). Worker B's guarded
     * complete-claim must refuse the stored Pass with
     * TransactionDenied — B must not reach application success.
     */
    public function testCompletePassReplayAgainstConcurrentTerminalDenialIsRefused(): void
    {
        $fake = new DispositionWaitRedisFake();
        $store = $this->store($fake);
        $nonce = bin2hex(random_bytes(16));

        // Worker A: claim + finalize the Pass.
        self::assertSame('claimed', $store->claim($nonce, 'owner-a', 300)[0]);
        self::assertTrue($store->finalize($nonce, 'owner-a', new PostSolveDisposition(PostSolveDispositionKind::Pass)));

        // Worker A (or another worker) terminalizes the transaction.
        $fake->strings[$this->obligationKey()] = self::CHAIN_ID;
        $fake->strings[$this->chainKey()] = $this->chainRecord('denied');

        // Worker B replays the claim with the no-chain snapshot: the
        // atomic guard refuses the stored Pass.
        [$claim, , $guard] = $store->claim($nonce, 'owner-b', 300, null, self::OBLIGATION_ID, null, null);
        self::assertSame('complete', $claim);
        self::assertSame(PostSolveFinalizeOutcome::TransactionDenied, $guard, 'the stored Pass must never surface after the transaction terminalized');
    }

    /**
     * The open-chain replay variant: a Pass was persisted before a chain
     * opened; the guarded complete-claim refuses it ChainRequired.
     */
    public function testCompletePassReplayAgainstConcurrentOpenedChainIsRefused(): void
    {
        $fake = new DispositionWaitRedisFake();
        $store = $this->store($fake);
        $nonce = bin2hex(random_bytes(16));

        self::assertSame('claimed', $store->claim($nonce, 'owner-a', 300)[0]);
        self::assertTrue($store->finalize($nonce, 'owner-a', new PostSolveDisposition(PostSolveDispositionKind::Pass)));
        $fake->strings[$this->obligationKey()] = self::CHAIN_ID;
        $fake->strings[$this->chainKey()] = $this->chainRecord('available');

        [$claim, , $guard] = $store->claim($nonce, 'owner-b', 300, null, self::OBLIGATION_ID, null, null);
        self::assertSame('complete', $claim);
        self::assertSame(PostSolveFinalizeOutcome::ChainRequired, $guard);
    }

    /**
     * The transaction own stage-2 replay: the chain is issued with
     * exactly this nonce, so its stored Pass remains authoritative.
     */
    public function testCompletePassReplayOfAuthorizedStage2RemainsAuthoritative(): void
    {
        $fake = new DispositionWaitRedisFake();
        $store = $this->store($fake);
        $nonce = bin2hex(random_bytes(16));

        self::assertSame('claimed', $store->claim($nonce, 'owner-a', 300)[0]);
        self::assertTrue($store->finalize($nonce, 'owner-a', new PostSolveDisposition(PostSolveDispositionKind::Pass)));
        $fake->strings[$this->obligationKey()] = self::CHAIN_ID;
        $fake->strings[$this->chainKey()] = $this->chainRecord('issued', $nonce);

        [$claim, , $guard] = $store->claim($nonce, 'owner-b', 300, null, self::OBLIGATION_ID, self::CHAIN_ID, $nonce);
        self::assertSame('complete', $claim);
        self::assertSame(PostSolveFinalizeOutcome::Finalized, $guard, 'the chain own stage-2 replay stays authoritative');
    }

    /**
     * The obligation moved since the snapshot (the mapping now points at
     * a different chain): never accepted — ObligationChanged.
     */
    public function testObligationMovedIsRefused(): void
    {
        $fake = new DispositionWaitRedisFake();
        $store = $this->store($fake);
        $nonce = bin2hex(random_bytes(16));

        self::assertSame('claimed', $store->claim($nonce, 'owner-b', 300, null, self::OBLIGATION_ID, self::CHAIN_ID, null)[0]);
        $fake->strings[$this->obligationKey()] = 'chain-moved';
        $fake->strings['{kiwi:'.self::NAMESPACE.'}:chain:chain-moved'] = $this->chainRecord('available');

        $outcome = $store->finalizeGuarded($nonce, 'owner-b', new PostSolveDisposition(PostSolveDispositionKind::Pass), self::OBLIGATION_ID, self::CHAIN_ID, null);
        self::assertSame(PostSolveFinalizeOutcome::ObligationChanged, $outcome);
    }

    /**
     * A Deny/StepUp/ChainRequired candidate is a terminal or contract
     * response: never weaker than required, so the guard lets it
     * finalize on the record checks alone.
     */
    public function testTerminalCandidatesFinalizeEvenAgainstAnOpenChain(): void
    {
        $fake = new DispositionWaitRedisFake();
        $store = $this->store($fake);
        $nonce = bin2hex(random_bytes(16));

        self::assertSame('claimed', $store->claim($nonce, 'owner-b', 300, null, self::OBLIGATION_ID, null, null)[0]);
        $fake->strings[$this->obligationKey()] = self::CHAIN_ID;
        $fake->strings[$this->chainKey()] = $this->chainRecord('available');

        $nonce2 = bin2hex(random_bytes(16));
        self::assertSame('claimed', $store->claim($nonce2, 'owner-b', 300, null, self::OBLIGATION_ID, null, null)[0]);
        $outcome = $store->finalizeGuarded($nonce2, 'owner-b', new PostSolveDisposition(PostSolveDispositionKind::Deny), self::OBLIGATION_ID, null, null);
        self::assertSame(PostSolveFinalizeOutcome::Finalized, $outcome, 'deny is a terminal response and commits');
        $nonce3 = bin2hex(random_bytes(16));
        self::assertSame('claimed', $store->claim($nonce3, 'owner-b', 300, null, self::OBLIGATION_ID, null, null)[0]);
        $outcome = $store->finalizeGuarded($nonce3, 'owner-b', new PostSolveDisposition(PostSolveDispositionKind::StepUp), self::OBLIGATION_ID, null, null);
        self::assertSame(PostSolveFinalizeOutcome::Finalized, $outcome, 'step-up is a terminal response and commits');
        $nonce4 = bin2hex(random_bytes(16));
        self::assertSame('claimed', $store->claim($nonce4, 'owner-b', 300, null, self::OBLIGATION_ID, null, null)[0]);
        $outcome = $store->finalizeGuarded($nonce4, 'owner-b', new PostSolveDisposition(PostSolveDispositionKind::ChainRequired, null, self::CHAIN_ID), self::OBLIGATION_ID, null, null);
        self::assertSame(PostSolveFinalizeOutcome::Finalized, $outcome, 'chain-required is a contract response and commits');
    }

    /**
     * Without chaining wired (no guard args) the acceptance behaves
     * exactly as before: the plain record checks decide.
     */
    public function testUnguardedAcceptanceBehavesAsBefore(): void
    {
        $fake = new DispositionWaitRedisFake();
        $store = $this->store($fake);
        $nonce = bin2hex(random_bytes(16));

        self::assertSame('claimed', $store->claim($nonce, 'owner-b', 300)[0]);
        $outcome = $store->finalizeGuarded($nonce, 'owner-b', new PostSolveDisposition(PostSolveDispositionKind::Pass), null, null, null);
        self::assertSame(PostSolveFinalizeOutcome::Finalized, $outcome, 'no chaining, no guard: the acceptance commits');
        self::assertSame(PostSolveFinalizeOutcome::Corrupt, $store->finalizeGuarded($nonce, 'owner-x', new PostSolveDisposition(PostSolveDispositionKind::Pass), null, null, null), 'a guarded finalize against a complete record is fail-closed corrupt');
    }
}
