<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * In-memory step-up store for test and dev semantics: single-process
 * only. The production wiring of the step-up plane always sits on the
 * Redis store (risk.enabled requires a risk Redis client), so this
 * implementation exists for unit tests and offline kernels.
 *
 * Mirrors the Redis store exactly, with an explicit clock: expiry is
 * evaluated on read, consume is a read-and-remove, and the attempt
 * accounting answers the same contract. Every record round-trips
 * through the strict wire decode, so this store observes the identical
 * schema the Redis store persists.
 */
final class ArrayStepUpChallengeStore implements StepUpChallengeStore
{
    /** @var array<string, array{record: StepUpChallenge, expiresAt: int}> */
    private array $challenges = [];

    /** @var array<string, int> */
    private array $beginWindows = [];

    /** @var array<string, string> */
    private array $totpSecrets = [];

    /** @var array<string, int> */
    private array $totpSteps = [];

    /** @var array<string, array{at: int, expires: int}> principal -> completion marker */
    private array $stepUpSuccess = [];

    /** @var array<string, int> "<dimension>:<pseudonym>" -> failure count */
    private array $lockoutFailures = [];

    /** @var array<string, int> "<dimension>:<pseudonym>" -> lockout deadline (epoch secs) */
    private array $lockoutUntil = [];

    public function __construct(
        private readonly ?\Closure $now = null,
    ) {
    }

    public function create(StepUpChallenge $challenge, int $ttlSecs): string
    {
        $this->challenges[$challenge->id] = [
            'record' => StepUpChallenge::fromJson((string) json_encode($challenge->toArray(), JSON_UNESCAPED_SLASHES)),
            'expiresAt' => ($this->now()) + max(1, $ttlSecs),
        ];

        return $challenge->id;
    }

    public function read(string $challengeId): ?StepUpChallenge
    {
        return $this->live($challengeId);
    }

    public function consume(string $challengeId): ?StepUpChallenge
    {
        $record = $this->live($challengeId);
        if ($record !== null) {
            unset($this->challenges[$challengeId]);
        }

        return $record;
    }

    public function recordFailure(string $challengeId, int $maxAttempts): int
    {
        $record = $this->live($challengeId);
        if ($record === null) {
            return -1;
        }
        $attempts = $record->attempts + 1;
        if ($attempts >= max(1, $maxAttempts)) {
            unset($this->challenges[$challengeId]);

            return 0;
        }
        $this->challenges[$challengeId]['record'] = $record->withAttempts($attempts);

        return $attempts;
    }

    public function countBegin(string $principalPseudonym, int $windowSecs): int
    {
        $this->beginWindows[$principalPseudonym] = ($this->beginWindows[$principalPseudonym] ?? 0) + 1;

        return $this->beginWindows[$principalPseudonym];
    }

    /** @var array<string, array{record: StepUpDemand, expiresAt: int}> */
    private array $demands = [];

    public function createDemand(StepUpDemand $demand, int $ttlSecs): string
    {
        if (isset($this->demands[$demand->id])) {
            throw new \RuntimeException('The step-up demand record could not be persisted (id collision)');
        }
        $this->demands[$demand->id] = [
            'record' => StepUpDemand::fromJson((string) json_encode($demand->toArray(), JSON_UNESCAPED_SLASHES))
                ?? throw new \RuntimeException('The step-up demand record could not be persisted (undecodable shape)'),
            'expiresAt' => ($this->now()) + max(1, $ttlSecs),
        ];

        return $demand->id;
    }

    public function readDemand(string $demandId): ?StepUpDemand
    {
        return $this->liveDemand($demandId);
    }

    public function consumeDemand(string $demandId): ?StepUpDemand
    {
        $demand = $this->liveDemand($demandId);
        if ($demand !== null) {
            unset($this->demands[$demandId]);
        }

        return $demand;
    }

    public function completeDemand(string $demandId, int $now, int $ttlSecs): ?StepUpDemand
    {
        $entry = $this->demands[$demandId] ?? null;
        if ($entry === null || $this->now() >= $entry['expiresAt']) {
            unset($this->demands[$demandId]);

            return null;
        }
        if (!$entry['record']->state->isOpen() || $entry['record']->superseded()) {
            return null;
        }
        $completed = $entry['record']->withState(StepUpDemandState::Completed, $now);
        $this->demands[$demandId] = [
            'record' => $completed,
            'expiresAt' => $now + max(1, $ttlSecs),
        ];

        return $completed;
    }

    public function completeFactor(string $challengeId, string $demandId, string $presentedBindingHash, int $now, ?string $sessionHash = null): ?StepUpFactorCompletion
    {
        // The same gate order the Redis script runs: presence, decode
        // (the records round-trip through the strict wire decode at
        // write time here), identity, state, liveness, binding, factor
        // requirement.
        $challenge = $this->live($challengeId);
        if ($challenge === null) {
            return null;
        }
        $demand = $this->liveDemand($demandId);
        if ($demand === null) {
            return null;
        }
        if ($challenge->demandId !== $demandId || $demand->id !== $demandId) {
            return null;
        }
        // A superseded demand completes nothing, whatever its state
        // field still says: escalation replaced it with a stronger
        // child. Same gate the Redis script runs.
        if (!$demand->state->isOpen() || $demand->superseded()) {
            return null;
        }
        if ($challenge->expired($now) || $demand->expired($now)) {
            return null;
        }
        $bound = ($challenge->sessionHash !== null && $challenge->sessionHash === $presentedBindingHash)
            || ($challenge->clientSecretHash !== null && $challenge->clientSecretHash === $presentedBindingHash);
        if (!$bound) {
            return null;
        }
        // The factor requirement gate, the script's own rule: the
        // demand's stored requirement is judged against the factor
        // identity the stored challenge record carries (its server-held
        // snapshot, resolved at begin), never a caller argument. A
        // completion below the required assurance rank refuses, and so
        // does a factor neither the snapshot's family nor its exact id
        // answers at or below that rank. A strictly stronger completion
        // satisfies a weaker floor, the ladder is a floor. Nothing
        // moves on a refusal.
        $required = $demand->requiredFactor;
        $snapshot = $challenge->factor;
        if ($required !== null) {
            if ($snapshot === null || $snapshot->assuranceRank < $required->assuranceRank) {
                return null;
            }
            if ($snapshot->family !== $required->factorId
                && $snapshot->factorId !== $required->factorId
                && $snapshot->assuranceRank <= $required->assuranceRank) {
                return null;
            }
        }
        // The transition: consume the challenge, complete the demand,
        // record the escalation marker, all or nothing. The marker
        // stores the factor identity the record itself carries, never a
        // caller argument: a completion cannot poison the future
        // assurance escalation by claiming a stronger factor than its
        // challenge proves.
        unset($this->challenges[$challengeId]);
        $completed = $demand->withState(StepUpDemandState::Completed, $now);
        $this->demands[$demandId] = ['record' => $completed, 'expiresAt' => $demand->expiresAt];
        $family = $snapshot?->family;
        if ($sessionHash !== null && $challenge->sessionHash !== null && $challenge->sessionHash === $sessionHash
            && \is_string($family) && $family !== '') {
            $this->completedIndex[$sessionHash] = [
                'value' => $challenge->scope.'|'.$family.'|'.$demand->expiresAt,
                'expiresAt' => $demand->expiresAt,
            ];
        }

        return StepUpFactorCompletion::fromRecords($challenge, $completed);
    }

    /** @var array<string, array{value: string, expiresAt: int}> session hash -> escalation marker */
    private array $completedIndex = [];

    public function completedFactorOf(string $sessionHash, string $scope, int $now): ?string
    {
        if (preg_match('/^[0-9a-f]{64}$/D', $sessionHash) !== 1) {
            return null;
        }
        $entry = $this->completedIndex[$sessionHash] ?? null;
        if ($entry === null || $now >= $entry['expiresAt']) {
            unset($this->completedIndex[$sessionHash]);

            return null;
        }
        $parts = explode('|', $entry['value']);
        if (\count($parts) !== 3 || $parts[0] !== $scope) {
            return null;
        }

        return FactorRequirement::isFamily($parts[1]) ? $parts[1] : null;
    }

    public function claimDemandFinalization(string $demandId, int $now, int $claimSecs): ?StepUpDemand
    {
        $entry = $this->demands[$demandId] ?? null;
        if ($entry === null || $this->now() >= $entry['expiresAt']) {
            unset($this->demands[$demandId]);

            return null;
        }
        $state = $entry['record']->state;
        // A superseded demand finalizes nothing: escalation replaced
        // it, so no retake may drive it to a terminal.
        if ($entry['record']->superseded()) {
            return null;
        }
        if ($state === StepUpDemandState::Finalizing) {
            // A claim inside its window is untouchable; a stale claim
            // (an owner that died inside the window) is retaken.
            $claimedAt = $entry['record']->stateAt;
            if ($claimedAt !== null && ($now - $claimedAt) < max(1, $claimSecs)) {
                return null;
            }
        } elseif ($state !== StepUpDemandState::Completed) {
            return null;
        }
        $claimed = $entry['record']->withState(StepUpDemandState::Finalizing, $now);
        $this->demands[$demandId] = ['record' => $claimed, 'expiresAt' => $entry['expiresAt']];

        return $claimed;
    }

    public function settleDemandFinalization(string $demandId, StepUpDemandState $state, int $now, ?string $factor = null): ?StepUpDemand
    {
        $entry = $this->demands[$demandId] ?? null;
        if ($entry === null || $this->now() >= $entry['expiresAt']) {
            unset($this->demands[$demandId]);

            return null;
        }
        if ($entry['record']->state !== StepUpDemandState::Finalizing) {
            return null;
        }
        if (!$state->isTerminal()) {
            throw new \InvalidArgumentException('A step-up demand finalization settles to a terminal state only');
        }
        // A superseded demand authorizes nothing ever again: only the
        // superseded settlement itself and the fail-closed denied
        // terminal may still land.
        if ($state === StepUpDemandState::Authorized && $entry['record']->superseded()) {
            return null;
        }
        $settled = $entry['record']->withState($state, $now, $factor);
        $this->demands[$demandId] = ['record' => $settled, 'expiresAt' => $entry['expiresAt']];

        return $settled;
    }

    public function recordDemandEffect(string $demandId, string $effect, int $now): ?StepUpDemand
    {
        // The same gate order the Redis op runs: presence, liveness,
        // terminal state, effect vocabulary.
        $entry = $this->demands[$demandId] ?? null;
        if ($entry === null || $this->now() >= $entry['expiresAt']) {
            unset($this->demands[$demandId]);

            return null;
        }
        if ($entry['record']->state !== StepUpDemandState::Authorized) {
            return null;
        }
        if (!StepUpEffectsJournal::isEffect($effect)) {
            return null;
        }
        $journal = ($entry['record']->effects ?? StepUpEffectsJournal::none())->withEffect($effect, $now);
        $record = $entry['record']->withEffects($journal);
        $this->demands[$demandId] = ['record' => $record, 'expiresAt' => $entry['expiresAt']];

        return $record;
    }

    private function liveDemand(string $demandId): ?StepUpDemand
    {
        $entry = $this->demands[$demandId] ?? null;
        if ($entry === null) {
            return null;
        }
        if ($this->now() >= $entry['expiresAt']) {
            unset($this->demands[$demandId]);

            return null;
        }

        return $entry['record'];
    }

    /** @var array<string, string> operation digest -> the family tip's demand id */
    private array $operationIndex = [];

    public function demandIdForOperation(string $operationDigest): ?string
    {
        $tipId = $this->operationIndex[$operationDigest] ?? null;
        if ($tipId === null) {
            return null;
        }
        // An expired tip leaves no family: the index dies with it.
        if (!$this->liveDemand($tipId) instanceof StepUpDemand) {
            unset($this->operationIndex[$operationDigest]);

            return null;
        }

        return $tipId;
    }

    public function createRootDemand(StepUpDemand $demand, int $ttlSecs): string
    {
        // One atomic decision, single-process by construction here: a
        // live family tip stands, a dead one is replaced. A standing
        // tip is answered as-is, never refreshed.
        $live = $this->demandIdForOperation($demand->operationDigest);
        if ($live !== null) {
            return $live;
        }
        $this->createDemand($demand, $ttlSecs);
        $this->operationIndex[$demand->operationDigest] = $demand->id;

        return $demand->id;
    }

    public function supersedeDemandWithChild(string $parentDemandId, StepUpDemand $child): ?StepUpDemand
    {
        $entry = $this->demands[$parentDemandId] ?? null;
        if ($entry === null || $this->now() >= $entry['expiresAt']) {
            unset($this->demands[$parentDemandId]);

            return null;
        }
        $parent = $entry['record'];
        if ($parent->superseded()) {
            return null;
        }
        // A terminal demand is history, not a family head: only an
        // open demand or a claimed finalizing one may be superseded.
        if (!$parent->state->isOpen() && $parent->state !== StepUpDemandState::Finalizing) {
            return null;
        }
        if (isset($this->demands[$child->id])) {
            return null;
        }
        // The child inherits the parent's remaining lifetime and its
        // exact authorization deadline: any other shape refuses.
        if ($child->expiresAt !== $parent->expiresAt || $child->parentDemandId !== $parent->id) {
            return null;
        }
        $expiresAt = $entry['expiresAt'];
        // The single atomic move: write the child, mark the parent,
        // repoint the family index. No intermediate state can lose the
        // child while the parent is already superseded.
        $this->demands[$child->id] = [
            'record' => StepUpDemand::fromJson((string) json_encode($child->toArray(), JSON_UNESCAPED_SLASHES))
                ?? throw new \RuntimeException('The step-up demand record could not be persisted (undecodable shape)'),
            'expiresAt' => $expiresAt,
        ];
        // The same terminal shape the Redis script writes in one
        // transaction: state superseded, stamped on this store's clock.
        // The order is load-bearing: withState stamps the terminal at
        // now, and supersededBy preserves an existing stateAt, so
        // reversing them would silently stamp createdAt instead.
        $this->demands[$parentDemandId] = ['record' => $parent->withState(StepUpDemandState::Superseded, $this->now())->supersededBy($child->id), 'expiresAt' => $expiresAt];
        $this->operationIndex[$child->operationDigest] = $child->id;

        return $this->demands[$parentDemandId]['record'];
    }

    public function claimDemandSendLease(string $demandId, int $resendAfterSecs, int $leaseSecs): ?StepUpDemandSendLease
    {
        $entry = $this->demands[$demandId] ?? null;
        if ($entry === null || $this->now() >= $entry['expiresAt']) {
            unset($this->demands[$demandId]);

            return null;
        }
        $now = $this->now();
        $record = $entry['record'];
        if (!$record->state->isOpen() || $record->superseded() || $record->expired($now)) {
            return null;
        }
        $nowMs = $now * 1000;
        $leaseUntil = $record->leaseUntilMs ?? 0;
        if ($leaseUntil > $nowMs) {
            // Another worker's live lease: nobody else claims now.
            return null;
        }
        $recovered = $leaseUntil > 0;
        $priorSends = $record->sends;
        $priorLastSentAt = $record->lastSentAt;
        if (!$recovered) {
            if (!$record->canSend()) {
                return null;
            }
            if ($record->nextSendIsResend() && $priorLastSentAt !== null && ($now - $priorLastSentAt) < $resendAfterSecs) {
                return null;
            }
            $record = $record->withSend($now);
        }
        $claimed = $record->withLease($nowMs + max(1, $leaseSecs) * 1000);
        $this->demands[$demandId] = ['record' => $claimed, 'expiresAt' => $entry['expiresAt']];

        return new StepUpDemandSendLease($claimed, $now, $claimed->leaseUntilMs ?? 0, $priorSends, $priorLastSentAt, $recovered);
    }

    public function settleDemandSendLease(StepUpDemandSendSettlement $settlement): bool
    {
        $entry = $this->demands[$settlement->demandId] ?? null;
        if ($entry === null || $this->now() >= $entry['expiresAt']) {
            return false;
        }
        $record = $entry['record'];
        // The compare-and-set: only the worker whose lease (and claim)
        // still stamps the record settles it. A recovered slot refuses
        // the crashed claimant's late outcome.
        if ($record->leaseUntilMs !== $settlement->leaseUntilMs) {
            return false;
        }
        $settled = $settlement->delivered
            ? $record
            : $record->withSends($settlement->priorSends, $settlement->priorLastSentAt);
        $this->demands[$settlement->demandId] = ['record' => $settled->withLease(null), 'expiresAt' => $entry['expiresAt']];

        return true;
    }

    /** @var array<string, int> budget key -> fixed-window count */
    private array $mailBudgets = [];

    /** @var array<string, array{keys: list<string>, leaseUntil: int}> reservation id -> its live reservation */
    private array $mailReservations = [];

    public function reserveMailQuota(string $reservationId, array $budgetKeys, array $limits, int $windowSecs, int $leaseSecs): bool
    {
        $budgetKeys = array_values($budgetKeys);
        $limits = array_values($limits);
        if (\count($budgetKeys) !== \count($limits) || $budgetKeys === []) {
            throw new \InvalidArgumentException('A mail quota reservation names a limit for every budget key');
        }
        $now = $this->now();
        // All or nothing: the whole reservation rolls back when any
        // budget is over its limit, so a refusal reserves nothing.
        $touched = [];
        foreach ($budgetKeys as $i => $key) {
            $entry = $this->mailBudgets[$key] ?? null;
            $count = ($entry['count'] ?? 0) + 1;
            $windowExpires = ($entry['windowExpires'] ?? 0) > $now ? $entry['windowExpires'] : $now + max(1, $windowSecs);
            $this->mailBudgets[$key] = ['count' => $count, 'windowExpires' => $windowExpires];
            $touched[] = $key;
            if ($count > $limits[$i]) {
                foreach ($touched as $touchedKey) {
                    $current = $this->mailBudgets[$touchedKey];
                    $this->mailBudgets[$touchedKey] = ['count' => max(0, $current['count'] - 1), 'windowExpires' => $current['windowExpires']];
                }

                return false;
            }
        }
        $this->mailReservations[$reservationId] = ['keys' => array_values($budgetKeys), 'leaseUntil' => $now + max(1, $leaseSecs)];

        return true;
    }

    public function commitMailQuota(string $reservationId): void
    {
        // Committed-by-default on lease expiry: an unknown reservation
        // commits trivially, the counters already carry the spend.
        unset($this->mailReservations[$reservationId]);
    }

    public function releaseMailQuota(string $reservationId): bool
    {
        $reservation = $this->mailReservations[$reservationId] ?? null;
        if ($reservation === null) {
            return false;
        }
        unset($this->mailReservations[$reservationId]);
        if ($this->now() > $reservation['leaseUntil']) {
            // Past its lease the reservation committed by default; a
            // late release never refunds a possibly-delivered message.
            return false;
        }
        foreach ($reservation['keys'] as $key) {
            $current = $this->mailBudgets[$key] ?? null;
            if ($current !== null && $current['count'] > 0) {
                $this->mailBudgets[$key] = ['count' => $current['count'] - 1, 'windowExpires' => $current['windowExpires']];
            }
        }

        return true;
    }

    public function saveTotpSecret(string $principalPseudonym, string $secretRaw): void
    {
        $this->totpSecrets[$principalPseudonym] = $secretRaw;
    }

    public function findTotpSecret(string $principalPseudonym): ?string
    {
        return $this->totpSecrets[$principalPseudonym] ?? null;
    }

    public function markTotpStep(string $principalPseudonym, int $step, int $ttlSecs): bool
    {
        if (($this->totpSteps[$principalPseudonym] ?? -1) >= $step) {
            return false;
        }
        $this->totpSteps[$principalPseudonym] = $step;

        return true;
    }

    private function now(): int
    {
        return ($this->now) ? ($this->now)() : time();
    }

    private function live(string $challengeId): ?StepUpChallenge
    {
        $entry = $this->challenges[$challengeId] ?? null;
        if ($entry === null) {
            return null;
        }
        if ($this->now() >= $entry['expiresAt']) {
            unset($this->challenges[$challengeId]);

            return null;
        }

        return $entry['record'];
    }
    public function markStepUpSuccess(string $principalPseudonym, int $ttlSecs, int $now): void
    {
        $this->stepUpSuccess[$principalPseudonym] = ['at' => $now, 'expires' => $now + $ttlSecs];
    }

    public function recentStepUpSuccess(string $principalPseudonym, int $withinSecs, int $now): bool
    {
        $marker = $this->stepUpSuccess[$principalPseudonym] ?? null;
        if ($marker === null || $marker['expires'] <= $now) {
            return false;
        }

        return ($now - $marker['at']) <= $withinSecs;
    }

    /** @var array<string, array{at: int, expires: int, factor: string}> */
    private array $sessionStepUpSuccess = [];

    public function markSessionStepUpSuccess(string $sessionId, string $principalPseudonym, string $factor, int $ttlSecs, int $now): void
    {
        if ($sessionId === '' || $principalPseudonym === '') {
            return;
        }
        $this->sessionStepUpSuccess[$sessionId."\0".$principalPseudonym] = [
            'at' => $now,
            'expires' => $now + $ttlSecs,
            'factor' => $factor,
        ];
    }

    public function recentSessionStepUpSuccess(string $sessionId, string $principalPseudonym, ?string $minFactor, int $withinSecs, int $now): bool
    {
        if ($sessionId === '' || $principalPseudonym === '') {
            return false;
        }
        $marker = $this->sessionStepUpSuccess[$sessionId."\0".$principalPseudonym] ?? null;
        if ($marker === null || $marker['expires'] <= $now || ($now - $marker['at']) > $withinSecs) {
            return false;
        }
        if ($minFactor !== null && self::factorRank($marker['factor']) < self::factorRank($minFactor)) {
            return false;
        }

        return true;
    }

    /** webauthn > totp > email_otp > unknown. */
    private static function factorRank(string $factor): int
    {
        return match ($factor) {
            'webauthn' => 3,
            'totp' => 2,
            'email_otp' => 1,
            default => 0,
        };
    }

    public function countLockoutFailure(string $dimension, string $pseudonym, int $windowSecs): int
    {
        $key = $dimension.':'.$pseudonym;
        $this->lockoutFailures[$key] = ($this->lockoutFailures[$key] ?? 0) + 1;

        return $this->lockoutFailures[$key];
    }

    public function lockoutUntil(string $dimension, string $pseudonym, int $now): int
    {
        $until = $this->lockoutUntil[$dimension.':'.$pseudonym] ?? 0;

        return $until > $now ? $until : 0;
    }

    public function armLockout(string $dimension, string $pseudonym, int $now, int $ttlSecs): void
    {
        $key = $dimension.':'.$pseudonym;
        $until = $now + max(1, $ttlSecs);
        if (($this->lockoutUntil[$key] ?? 0) < $until) {
            $this->lockoutUntil[$key] = $until;
        }
    }

    public function clearLockout(string $dimension, string $pseudonym): void
    {
        $key = $dimension.':'.$pseudonym;
        unset($this->lockoutFailures[$key], $this->lockoutUntil[$key]);
    }
}
