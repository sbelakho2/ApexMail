<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The server-side state of the step-up plane: challenge records, the
 * per-principal begin bound, the escalating verification lockout
 * budget and the durable principal state of the time-based handler,
 * its enrollment secret and its replay guard.
 *
 * The challenge lifecycle is single-use and replay safe by
 * construction. create() mints an unguessable id under a TTL.
 * consume() answers the record to exactly one caller, with getdel
 * semantics. recordFailure() is the atomic attempt-accounting
 * transition that removes the record when the attempt cap is reached.
 * countBegin() is the store-backed rate bound of begin(), a fixed
 * per-principal window counter whose admission the handler compares
 * against the configured cap. The demand family (createDemand /
 * readDemand / consumeDemand) holds the same contract for the
 * step-up demand records the email factor requires before it sends.
 *
 * The lockout budget is the cross-challenge brute-force bound: one
 * fixed-window failure counter and one lockout deadline per
 * (dimension, pseudonym) pair, where the dimension is "principal" or
 * "target". The handlers escalate the lockout from the failure count
 * and refuse both begin() and complete() while it holds, so the
 * per-challenge attempt cap can never be farmed across challenges.
 *
 * Keys carry only pseudonyms and opaque ids: every key of this store
 * is derived from the deployment namespace plus either a random
 * challenge id or the principal pseudonym, never a raw identifier.
 */
interface StepUpChallengeStore
{
    /**
     * Persist a fresh challenge record under its own unguessable id
     * (the challenge id the signed ticket names) and answer that id.
     * The record expires after the given TTL.
     */
    public function create(StepUpChallenge $challenge, int $ttlSecs): string;

    /**
     * The live record of a challenge id, or null when absent or
     * expired. Non-consuming.
     *
     * @throws MalformedStepUpChallengeException when the persisted record violates the strict schema
     */
    public function read(string $challengeId): ?StepUpChallenge;

    /**
     * Atomically answer and remove the record of a challenge id: the
     * single-use consumption. Exactly one caller of a concurrent pair
     * receives the record; every other caller receives null.
     *
     * @throws MalformedStepUpChallengeException when the persisted record violates the strict schema
     */
    public function consume(string $challengeId): ?StepUpChallenge;

    /**
     * The attempt-accounting transition: atomically count one failed
     * verification. Answers the attempt count now used (>= 1) while the
     * challenge stays live, 0 when the cap is reached and the record
     * was removed, and -1 when the challenge is absent. A record that
     * fails the strict decode is removed and answered -2, fail-closed:
     * corrupt state never becomes a verifiable challenge.
     */
    public function recordFailure(string $challengeId, int $maxAttempts): int;

    /**
     * Count one begun challenge for the principal inside the fixed
     * window and answer the window's new admission count. The handler
     * refuses begin() while the count exceeds its configured cap.
     */
    public function countBegin(string $principalPseudonym, int $windowSecs): int;

    /**
     * Persist a fresh step-up demand record under its own unguessable
     * id (the id the 403 body hands to the visitor) and answer that id.
     * The record expires after the given TTL. An id colliding with a
     * live demand refuses rather than overwriting it.
     */
    public function createDemand(StepUpDemand $demand, int $ttlSecs): string;

    /**
     * The live demand of a demand id, or null when absent, expired or
     * undecodable. Non-consuming. A corrupt record reads as absent,
     * fail-closed: a demand the store cannot decode never funds a
     * code delivery.
     */
    public function readDemand(string $demandId): ?StepUpDemand;

    /**
     * Atomically answer and remove the demand of a demand id: the
     * single-use consumption (the send-credit claim). Exactly one
     * caller of a concurrent pair receives the record; every other
     * caller receives null.
     */
    public function consumeDemand(string $demandId): ?StepUpDemand;

    /**
     * The factor+demand completion: an atomic compare-and-set of the
     * demand lifecycle state from open to completed. The record is
     * kept (never deleted) and re-armed for $ttlSecs, so the
     * finalizer can read the operation identity and the terminal
     * disposition after the completion. Exactly one caller of a
     * concurrent pair receives the completed record; every other
     * caller, and every caller naming an absent, expired, spent or
     * already-completed demand, receives null.
     */
    public function completeDemand(string $demandId, int $now, int $ttlSecs): ?StepUpDemand;

    /**
     * The atomic factor completion: the challenge consumption and the
     * demand completion are one script over the two records. The script
     * loads both records and decodes both. It asserts the identity (the
     * challenge's demand id equals the demand's id), the state (the
     * demand is open and both records live) and the binding (the
     * presented hash equals the stored session binding or the stateless
     * client secret). The factor requirement is asserted too: the
     * demand's stored requirement is judged against the factor identity
     * the stored challenge record carries (its server-held snapshot,
     * resolved at begin), never a caller argument. A completion below
     * the required assurance rank refuses, and so does a completed
     * factor other than the exact id the requirement names. It then
     * consumes the
     * challenge and moves the demand to completed in the same atomic
     * step. Exactly one caller of a concurrent pair receives the
     * completion; every other caller, and every caller naming an
     * absent, expired, crossed, spent, wrongly bound or weaker-factor
     * pair, receives null, with nothing left half-consumed. The
     * verified subject and the completed factor are both derived from
     * the stored challenge, never from a caller argument.
     *
     * $sessionHash is the completion index hint: when it names the
     * stored session binding, the script also records the completed
     * factor under that session hash and scope, the parent factor a
     * child demand escalates past. Null skips the index write.
     */
    public function completeFactor(string $challengeId, string $demandId, string $presentedBindingHash, int $now, ?string $sessionHash = null): ?StepUpFactorCompletion;

    /**
     * The factor family the live completion marker records for a
     * continuity session hash and scope, or null when none stands. The
     * marker is the strongest-factor history the escalation reads: a
     * demand minted after a completed one must require a strictly
     * stronger factor than the family this answers.
     */
    public function completedFactorOf(string $sessionHash, string $scope, int $now): ?string;

    /**
     * The finalizer's acquisition: an atomic compare-and-set of the
     * demand lifecycle state from completed to finalizing, stamped
     * with the claim time. A record already finalizing may be retaken
     * once its claim window of $claimSecs passed (an owner that died
     * inside the window), never earlier. Exactly one caller wins;
     * every other caller, and every caller naming a demand in any
     * other state, receives null.
     */
    public function claimDemandFinalization(string $demandId, int $now, int $claimSecs): ?StepUpDemand;

    /**
     * The terminal compare-and-set of the finalization: the demand
     * state moves from finalizing to authorized or refused, stamped
     * with the settle time. The record is kept within its remaining
     * lifetime. Answers the settled record, or null when the demand
     * is absent, expired or not in the finalizing state.
     */
    public function settleDemandFinalization(string $demandId, StepUpDemandState $state, int $now, ?string $factor = null): ?StepUpDemand;

    /**
     * The effects journal write of a durable authorized settlement: one
     * effect of the journal ({@see StepUpEffectsJournal}) moves to its
     * landed stamp, atomically, on the authorized terminal only. The
     * journal write follows its effect, so a crash between the effect
     * and its journaling retries exactly the missing one. Answers the
     * updated record, or null when the demand is absent, expired, not
     * authorized, or the effect name is not a journalable one.
     */
    public function recordDemandEffect(string $demandId, string $effect, int $now): ?StepUpDemand;

    /**
     * The live demand id bound to an operation digest (the escalation
     * family index), or null when the operation has no demand. The id
     * answers for the family's tip: a superseded parent's index entry
     * names its child, never the dead parent.
     */
    public function demandIdForOperation(string $operationDigest): ?string;

    /**
     * Mint the root demand of an operation family, atomically with the
     * family index write. When a live demand already stands for the
     * operation, nothing is created and the standing demand's id is
     * answered instead — a reassessment never refreshes the first
     * demand's authorization window by minting a second root. The
     * id colliding with a live demand (an unguessable mint) refuses.
     */
    public function createRootDemand(StepUpDemand $demand, int $ttlSecs): string;

    /**
     * Supersede a live parent demand with its pre-minted escalation
     * child in one atomic transaction. The script asserts the parent is
     * present, live (its expiry judged on the store's own clock), not
     * already superseded and carrying remaining lifetime. It asserts
     * the child key is absent, writes the child within the parent's
     * remaining lifetime, marks the parent superseded with that same
     * lifetime preserved, and repoints the operation index at the
     * child. A process that died after marking the parent and before
     * creating the child is exactly the state this transaction makes
     * impossible. Answers the superseded parent record, or null on any
     * refusal (a concurrent escalation won; the caller keeps reading
     * the family tip through {@see self::demandIdForOperation()}).
     */
    public function supersedeDemandWithChild(string $parentDemandId, StepUpDemand $child): ?StepUpDemand;

    /**
     * Claim the demand's next send lease, atomically, with every
     * liveness and timing decision taken on the store's own clock (the
     * Redis server time on the Redis store, the injected clock on the
     * array store, never an individual PHP worker's clock). The demand
     * must be open, unexpired, unsuperseded and within its send cap;
     * the bounded resend must respect its spacing from the stored last
     * delivery; a lease another worker still holds refuses. A lease
     * whose deadline passed (its holder crashed before settling) is
     * recovered: the same send slot is re-leased without being charged
     * a second credit. The claimed record keeps its remaining lifetime
     * exactly (never a fresh TTL). Answers the lease claim, or null
     * when the demand cannot fund a delivery now.
     */
    public function claimDemandSendLease(string $demandId, int $resendAfterSecs, int $leaseSecs): ?StepUpDemandSendLease;

    /**
     * Settle a claimed send lease: the compare-and-set on the lease
     * stamp. A delivery the claimer actually handed off commits the
     * advanced send state; a refusal before handoff restores the exact
     * pre-claim state the claim answered. A claimant whose lease moved
     * on (its window expired and another worker recovered the slot)
     * settles nothing and receives false: its delivery outcome is
     * worthless.
     */
    public function settleDemandSendLease(StepUpDemandSendSettlement $settlement): bool;

    /**
     * Reserve capacity on the named delivery budgets, all or nothing:
     * each budget increments inside its fixed window, or the whole
     * reservation rolls back and false is answered. The reservation
     * lives for $leaseSecs on the store's own clock; within it, the
     * reserving worker may commit or release; past it (a crashed
     * worker) the reservation commits by default — spent quota is the
     * fail-closed side, never free mail.
     */
    public function reserveMailQuota(string $reservationId, array $budgetKeys, array $limits, int $windowSecs, int $leaseSecs): bool;

    /**
     * Commit a quota reservation: the delivery was handed off (or the
     * handoff is ambiguous), so the reserved capacity counts. Idempotent.
     */
    public function commitMailQuota(string $reservationId): void;

    /**
     * Release a quota reservation before handoff: the increments roll
     * back. False when the reservation is unknown or already past its
     * lease (it committed by default then) — never an unbounded refund.
     */
    public function releaseMailQuota(string $reservationId): bool;

    /**
     * Persist the enrollment secret of the time-based handler for the
     * principal (durable: no TTL). The secret is the raw binary key,
     * stored server-side keyed by the principal pseudonym. Encryption
     * at rest is out of scope for this store: the deployment protects
     * its risk Redis like every other security state.
     */
    public function saveTotpSecret(string $principalPseudonym, string $secretRaw): void;

    /**
     * The enrollment secret of the principal, or null when the
     * principal is not enrolled.
     */
    public function findTotpSecret(string $principalPseudonym): ?string;

    /**
     * The replay guard of the time-based handler: claim one time-step
     * for the principal. True when the step was unclaimed (this
     * verification is the first to use it); false when the step was
     * already used, so the same code can never verify twice.
     */
    public function markTotpStep(string $principalPseudonym, int $step, int $ttlSecs): bool;

    /**
     * Record that the principal just completed a step-up (any handler):
     * the marker lives for $ttlSecs and gates the WebAuthn enrollment
     * precondition, so stolen credentials can never mint a first
     * credential on a victim's account.
     */
    public function markStepUpSuccess(string $principalPseudonym, int $ttlSecs, int $now): void;

    /**
     * Whether the same principal completed a step-up within the last
     * $withinSecs (a caller-supplied $now keeps the clock testable).
     */
    public function recentStepUpSuccess(string $principalPseudonym, int $withinSecs, int $now): bool;

    /**
     * Record a session-scoped step-up proof: the success marker is keyed
     * by both the session id and the principal, so another session of
     * the same account can never spend it. The $factor names the method
     * that completed the step-up (email_otp, totp, webauthn) and is the
     * strongest-factor floor for later enrollment.
     */
    public function markSessionStepUpSuccess(string $sessionId, string $principalPseudonym, string $factor, int $ttlSecs, int $now): void;

    /**
     * Whether this session completed a step-up within $withinSecs with
     * a factor at least as strong as $minFactor (null accepts any).
     * A principal-only marker never satisfies this.
     */
    public function recentSessionStepUpSuccess(string $sessionId, string $principalPseudonym, ?string $minFactor, int $withinSecs, int $now): bool;

    /**
     * Count one failed verification for the (dimension, pseudonym)
     * budget key inside the fixed window and answer the window's new
     * failure count. The dimension is "principal" or "target"; the
     * pseudonym is the canonical form of that dimension. The handler
     * escalates the lockout from the returned count.
     */
    public function countLockoutFailure(string $dimension, string $pseudonym, int $windowSecs): int;

    /**
     * The lockout deadline (epoch seconds) of the budget key, or 0
     * when the key is not locked.
     */
    public function lockoutUntil(string $dimension, string $pseudonym, int $now): int;

    /**
     * Arm (or extend) the lockout of the budget key to at least
     * $now + $ttlSecs. Never shortens an existing deadline.
     */
    public function armLockout(string $dimension, string $pseudonym, int $now, int $ttlSecs): void;

    /**
     * Clear the failure counter and the lockout of the budget key: the
     * reward of a completed step-up, so one verified identity is not
     * kept locked by its own earlier typos.
     */
    public function clearLockout(string $dimension, string $pseudonym): void;
}
