<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use BelConsulting\KiwiCaptchaBundle\Risk\ChainId;

/**
 * The server-held record that proves the engine raised the step-up
 * demand the factor answers. The challenge controller mints it when it
 * answers the typed step-up 403 for a carrier scope. The validator
 * mints it when a post-solve assessment lands on StepUp for one, and
 * the login plane mints it when a pending token begins its factor. The
 * factor refuses to send any code without it, so a grant can only ever
 * exist for a demand the engine actually raised.
 *
 * The record carries the whole demand binding. It names the carrier
 * scope, the continuity session hash of the refused browser, the chain
 * id of the transaction that was refused and the risk decision id that
 * demanded the step-up. It also carries the split operation binding of
 * the protected operation:
 *
 *  - operationIdentityDigest — HMAC over the server-owned unique
 *    logical operation id (the operation id attribute concept: an
 *    idempotency key the application mints, never a raw client value).
 *  - operationContentDigest — HMAC over the canonical operation
 *    contents (amount / currency / recipient / ...).
 *
 * Both digests are required to reproduce an authorization: the same
 * logical operation with the same contents is idempotent, a different
 * operation (even with identical contents) or changed contents is
 * rejected. A step-up for tx-001 never authorizes tx-002.
 *
 * The state field carries the demand lifecycle
 * ({@see StepUpDemandState}). The authorized terminal is durable and
 * retains the two operation digests, the decision id, the quarantine
 * flag, the completed factor and the settlement timestamp. Nothing is
 * destructively consumed at the terminal: the record stays as the
 * authorization's proof.
 *
 * begin() and complete() take every binding from this record, never
 * from the request. The record is single-send bounded: one initial code
 * delivery plus one resend after the resend delay, then the demand is
 * spent and stays only as the completion's consumption proof.
 *
 * Only pseudonyms and opaque ids ride the wire form, exactly like the
 * challenge records of the same store.
 */
final class StepUpDemand
{
    private const SCHEMA_VERSION = 3;

    /** The maximum deliveries one demand funds: the initial code plus one resend. */
    public const MAX_SENDS = 2;

    /**
     * The maximum escalation depth one operation funds: the root plus
     * this many children. Past the cap a reassessment keeps the live
     * demand standing (never a fresh TTL), so an actor able to steer
     * repeated reassessments still cannot outlive the first demand's
     * authorization window.
     */
    public const MAX_GENERATION = 4;

    private function __construct(
        public readonly string $id,
        public readonly string $scope,
        public readonly ?string $sessionHash,
        public readonly ?string $chainId,
        public readonly ?string $decisionId,
        public readonly int $createdAt,
        public readonly int $expiresAt,
        /** Deliveries used so far: 0, then 1 after the initial code, then 2 (spent). */
        public readonly int $sends = 0,
        /** The unix second of the last delivery, null before the first one. */
        public readonly ?int $lastSentAt = null,
        public readonly StepUpDemandState $state = StepUpDemandState::Open,
        /** The unix second of the last state move, null while the record is open. */
        public readonly ?int $stateAt = null,
        public readonly StepUpOperationBindingKind $operationBindingKind = StepUpOperationBindingKind::None,
        /** The recipe digest (the family-index key of the operation). */
        public readonly string $operationDigest = '',
        /** HMAC of the server-owned unique logical operation id. */
        public readonly ?string $operationIdentityDigest = null,
        /** HMAC of the canonical operation contents (amount/currency/recipient/...). */
        public readonly ?string $operationContentDigest = null,
        /** Whether the demand was raised under quarantine. */
        public readonly bool $quarantine = false,
        /** The factor that completed the demand, set on the authorized terminal. */
        public readonly ?string $factor = null,
        /** The unix second of the authorized settlement, null otherwise. */
        public readonly ?int $authorizedAt = null,
        /** The escalation parent this demand was superseded from, null on a root. */
        public readonly ?string $parentDemandId = null,
        /** The escalation child that superseded this demand, null while live. */
        public readonly ?string $supersededByDemandId = null,
        /** The send-lease deadline (epoch millis), null when no lease is held. */
        public readonly ?int $leaseUntilMs = null,
        /** The one active factor challenge of this demand, null when none. */
        public readonly ?string $activeChallengeId = null,
        /** The expiry of the active factor challenge, null when none. */
        public readonly ?int $activeChallengeExpiresAt = null,
        /**
         * The factor requirement snapshot the mint resolved
         * ({@see StepUpFactorResolver}), null when the mint carried no
         * resolver. The snapshot is the demand's factor identity: the
         * stored record, never the request, decides which factor
         * answers this demand.
         */
        public readonly ?FactorRequirement $requiredFactor = null,
        /** The generation of the escalation family: 0 for a root demand. */
        public readonly int $generation = 0,
        /**
         * The reassessment decision id that re-raised the step-up and
         * produced this child, null on a root demand. The authorizing
         * decision stays `decisionId`, inherited unchanged: the child
         * answers the original demand, not the reassessment.
         */
        public readonly ?string $raisedByDecisionId = null,
        /**
         * The effects journal of the durable authorized terminal
         * ({@see StepUpEffectsJournal}), null while no journal exists.
         * The journal rides the demand record itself, so the
         * authorization carries its own completion-effects state and a
         * crash between the terminal settlement and an effect retries
         * exactly the missing one.
         */
        public readonly ?StepUpEffectsJournal $effects = null,
    ) {
    }

    /**
     * Mint a fresh demand record. The id is the caller's unguessable
     * mint (the same id alphabet the challenge records use); the TTL
     * bounds the whole demand lifetime. The session hash arrives
     * precomputed (the presented continuity session's SHA-256 hex, the
     * same derivation the factor stores), never a raw session value.
     *
     * The split operation binding arrives as the pair of HMAC digests
     * {@see StepUpOperationDigest} minted: the identity digest over the
     * server-owned logical operation id, the content digest over the
     * canonical contents. Both null leaves the demand unbound (the
     * login plane and the non-financial carriers); both set is the
     * financial/action binding. A single non-null digest is refused:
     * the split is not optional half-way.
     */
    public static function mint(
        string $id,
        string $scope,
        ?string $sessionHash,
        ?string $chainId,
        ?string $decisionId,
        int $now,
        int $ttlSecs,
        StepUpOperationBindingKind $operationBindingKind = StepUpOperationBindingKind::None,
        string $operationDigest = '',
        ?string $operationIdentityDigest = null,
        ?string $operationContentDigest = null,
        bool $quarantine = false,
        ?string $parentDemandId = null,
        ?FactorRequirement $requiredFactor = null,
    ): self {
        if ($ttlSecs < 1) {
            throw new \InvalidArgumentException('A step-up demand TTL must be positive');
        }
        [$identityDigest, $contentDigest] = self::operationBinding($operationIdentityDigest, $operationContentDigest);
        $digest = $operationBindingKind === StepUpOperationBindingKind::None
            ? StepUpOperationDigest::none($scope)
            : self::operationDigest($operationDigest);
        if ($operationBindingKind !== StepUpOperationBindingKind::None && $digest === '') {
            throw new \InvalidArgumentException('A bound step-up demand must carry the operation digest its recipe minted');
        }
        // The family-index key is the logical operation identity when
        // the split binding is present, so two contents of one logical
        // operation share a family and two logical operations never do.
        if ($identityDigest !== null) {
            $digest = $identityDigest;
        }

        return new self(
            self::id($id),
            self::scope($scope),
            self::sessionHash($sessionHash),
            $chainId === null || $chainId === '' ? null : self::chainId($chainId),
            $decisionId === null || $decisionId === '' ? null : self::decisionId($decisionId),
            $now,
            $now + $ttlSecs,
            0,
            null,
            StepUpDemandState::Open,
            null,
            $operationBindingKind,
            $digest,
            $identityDigest,
            $contentDigest,
            $quarantine,
            null,
            null,
            $parentDemandId === null || $parentDemandId === '' ? null : self::id($parentDemandId),
            null,
            null,
            null,
            null,
            $requiredFactor,
            0,
            null,
        );
    }

    /** The demand after one delivery: the send counter advanced by one. */
    public function withSend(int $at): self
    {
        return new self(
            $this->id,
            $this->scope,
            $this->sessionHash,
            $this->chainId,
            $this->decisionId,
            $this->createdAt,
            $this->expiresAt,
            min(self::MAX_SENDS, $this->sends + 1),
            $at,
            $this->state,
            $this->stateAt,
            $this->operationBindingKind,
            $this->operationDigest,
            $this->operationIdentityDigest,
            $this->operationContentDigest,
            $this->quarantine,
            $this->factor,
            $this->authorizedAt,
            $this->parentDemandId,
            $this->supersededByDemandId,
            $this->leaseUntilMs,
            $this->activeChallengeId,
            $this->activeChallengeExpiresAt,
            $this->requiredFactor,
            $this->generation,
            $this->raisedByDecisionId,
            $this->effects,
        );
    }

    /** The demand restored to its exact pre-claim send state (a delivery refund). */
    public function withSends(int $sends, ?int $lastSentAt): self
    {
        return new self(
            $this->id,
            $this->scope,
            $this->sessionHash,
            $this->chainId,
            $this->decisionId,
            $this->createdAt,
            $this->expiresAt,
            $sends,
            $lastSentAt,
            $this->state,
            $this->stateAt,
            $this->operationBindingKind,
            $this->operationDigest,
            $this->operationIdentityDigest,
            $this->operationContentDigest,
            $this->quarantine,
            $this->factor,
            $this->authorizedAt,
            $this->parentDemandId,
            $this->supersededByDemandId,
            $this->leaseUntilMs,
            $this->activeChallengeId,
            $this->activeChallengeExpiresAt,
            $this->requiredFactor,
            $this->generation,
            $this->raisedByDecisionId,
            $this->effects,
        );
    }

    /** The demand after one lifecycle move: the state advanced, stamped with the move time. */
    public function withState(StepUpDemandState $state, int $at, ?string $factor = null): self
    {
        $settledFactor = $state === StepUpDemandState::Authorized
            ? ($factor ?? $this->factor)
            : $this->factor;

        return new self(
            $this->id,
            $this->scope,
            $this->sessionHash,
            $this->chainId,
            $this->decisionId,
            $this->createdAt,
            $this->expiresAt,
            $this->sends,
            $this->lastSentAt,
            $state,
            $at,
            $this->operationBindingKind,
            $this->operationDigest,
            $this->operationIdentityDigest,
            $this->operationContentDigest,
            $this->quarantine,
            $settledFactor,
            $state === StepUpDemandState::Authorized ? ($this->authorizedAt ?? $at) : $this->authorizedAt,
            $this->parentDemandId,
            $this->supersededByDemandId,
            $this->leaseUntilMs,
            $this->activeChallengeId,
            $this->activeChallengeExpiresAt,
            $this->requiredFactor,
            $this->generation,
            $this->raisedByDecisionId,
            $this->effects,
        );
    }

    /**
     * The durable authorized terminal: the two operation digests, the
     * decision, the quarantine flag, the completed factor and the
     * settlement timestamp are retained on the record. The same logical
     * operation with the same contents reproduces this authorization;
     * anything else is rejected.
     */
    public function withAuthorized(string $factor, int $at): self
    {
        return new self(
            $this->id,
            $this->scope,
            $this->sessionHash,
            $this->chainId,
            $this->decisionId,
            $this->createdAt,
            $this->expiresAt,
            $this->sends,
            $this->lastSentAt,
            StepUpDemandState::Authorized,
            $at,
            $this->operationBindingKind,
            $this->operationDigest,
            $this->operationIdentityDigest,
            $this->operationContentDigest,
            $this->quarantine,
            $factor,
            $at,
            $this->parentDemandId,
            $this->supersededByDemandId,
            $this->leaseUntilMs,
            $this->activeChallengeId,
            $this->activeChallengeExpiresAt,
            $this->requiredFactor,
            $this->generation,
            $this->raisedByDecisionId,
            $this->effects,
        );
    }

    /** The demand after a send-lease claim: the lease deadline stamped. */
    public function withLease(?int $leaseUntilMs): self
    {
        return new self(
            $this->id,
            $this->scope,
            $this->sessionHash,
            $this->chainId,
            $this->decisionId,
            $this->createdAt,
            $this->expiresAt,
            $this->sends,
            $this->lastSentAt,
            $this->state,
            $this->stateAt,
            $this->operationBindingKind,
            $this->operationDigest,
            $this->operationIdentityDigest,
            $this->operationContentDigest,
            $this->quarantine,
            $this->factor,
            $this->authorizedAt,
            $this->parentDemandId,
            $this->supersededByDemandId,
            $leaseUntilMs,
            $this->activeChallengeId,
            $this->activeChallengeExpiresAt,
            $this->requiredFactor,
            $this->generation,
            $this->raisedByDecisionId,
            $this->effects,
        );
    }

    /** The parent after its escalation child took over. */
    public function supersededBy(string $childDemandId): self
    {
        return new self(
            $this->id,
            $this->scope,
            $this->sessionHash,
            $this->chainId,
            $this->decisionId,
            $this->createdAt,
            $this->expiresAt,
            $this->sends,
            $this->lastSentAt,
            StepUpDemandState::Superseded,
            $this->stateAt ?? $this->createdAt,
            $this->operationBindingKind,
            $this->operationDigest,
            $this->operationIdentityDigest,
            $this->operationContentDigest,
            $this->quarantine,
            $this->factor,
            $this->authorizedAt,
            $this->parentDemandId,
            self::id($childDemandId),
            $this->leaseUntilMs,
            $this->activeChallengeId,
            $this->activeChallengeExpiresAt,
            $this->requiredFactor,
            $this->generation,
            $this->raisedByDecisionId,
            $this->effects,
        );
    }

    /** Whether an escalation child took this demand over. */
    public function superseded(): bool
    {
        return $this->supersededByDemandId !== null || $this->state === StepUpDemandState::Superseded;
    }

    /**
     * Whether this demand may still hand its authorization over to an
     * escalation child: a live, open, never-superseded record only. A
     * terminal demand is history, not a family head.
     */
    public function canEscalate(): bool
    {
        return $this->state === StepUpDemandState::Open && !$this->superseded() && $this->generation < self::MAX_GENERATION;
    }

    /**
     * The escalation child of one re-raised step-up: a fresh record of
     * the same operation family. The child inherits the parent's
     * remaining authorization lifetime exactly (the stores refuse a
     * child whose expiry differs), together with its scope, its browser
     * binding, its chain id, its operation binding and its parent
     * link. It carries the decision id of the raise that minted it.
     * The required factor rides as the caller resolved it: the child
     * of a completed weaker factor demands the strictly stronger one.
     */
    public function spawnChild(string $childId, int $now, ?string $raisedByDecisionId, ?FactorRequirement $requiredFactor = null): self
    {
        if ($this->generation >= self::MAX_GENERATION) {
            throw new \LogicException('A step-up demand family past its escalation depth spawns no children');
        }

        return new self(
            self::id($childId),
            $this->scope,
            $this->sessionHash,
            $this->chainId,
            // The authorizing decision is inherited unchanged: the
            // child answers the original demand. The reassessment that
            // re-raised it is recorded separately.
            $this->decisionId,
            $now,
            $this->expiresAt,
            0,
            null,
            StepUpDemandState::Open,
            null,
            $this->operationBindingKind,
            $this->operationDigest,
            $this->operationIdentityDigest,
            $this->operationContentDigest,
            $this->quarantine,
            null,
            null,
            $this->id,
            null,
            null,
            null,
            null,
            $requiredFactor ?? $this->requiredFactor,
            $this->generation + 1,
            $raisedByDecisionId === null || $raisedByDecisionId === '' ? null : self::decisionId($raisedByDecisionId),
            // The escalation child is a fresh open record: it inherits
            // no effects journal (its own terminal journals its own).
            null,
        );
    }

    /**
     * Bind the one active factor challenge of this demand. The
     * challenge expiry may never outlive the parent demand, and at most
     * one challenge is live per demand at a time: a second generation
     * while one is active refuses (null).
     */
    public function admitFactorChallenge(string $challengeId, int $challengeExpiresAt, int $now): ?self
    {
        if ($this->state !== StepUpDemandState::Open || $this->superseded() || $this->expired($now)) {
            return null;
        }
        if ($challengeExpiresAt > $this->expiresAt) {
            return null;
        }
        if ($this->activeChallengeId !== null
            && $this->activeChallengeExpiresAt !== null
            && $this->activeChallengeExpiresAt > $now) {
            return null;
        }

        return new self(
            $this->id,
            $this->scope,
            $this->sessionHash,
            $this->chainId,
            $this->decisionId,
            $this->createdAt,
            $this->expiresAt,
            $this->sends,
            $this->lastSentAt,
            $this->state,
            $this->stateAt,
            $this->operationBindingKind,
            $this->operationDigest,
            $this->operationIdentityDigest,
            $this->operationContentDigest,
            $this->quarantine,
            $this->factor,
            $this->authorizedAt,
            $this->parentDemandId,
            $this->supersededByDemandId,
            $this->leaseUntilMs,
            self::id($challengeId),
            $challengeExpiresAt,
            $this->requiredFactor,
            $this->generation,
            $this->raisedByDecisionId,
            $this->effects,
        );
    }

    /**
     * Whether the presented operation binding reproduces this
     * authorization: the same logical operation (identity digest) and
     * the same contents (content digest). An unbound demand carries
     * neither digest and matches only the unbound presentation.
     */
    public function matchesOperation(?string $operationIdentityDigest, ?string $operationContentDigest): bool
    {
        if ($this->operationIdentityDigest === null && $this->operationContentDigest === null) {
            return $operationIdentityDigest === null && $operationContentDigest === null;
        }
        if ($this->operationIdentityDigest === null || $this->operationContentDigest === null) {
            return false;
        }
        if ($operationIdentityDigest === null || $operationContentDigest === null) {
            return false;
        }

        return hash_equals($this->operationIdentityDigest, $operationIdentityDigest)
            && hash_equals($this->operationContentDigest, $operationContentDigest);
    }

    /** Whether the demand still funds a delivery. */
    public function canSend(): bool
    {
        return $this->sends < self::MAX_SENDS;
    }

    /** Whether the next delivery is the bounded resend (one initial send already used). */
    public function nextSendIsResend(): bool
    {
        return $this->sends === 1;
    }

    public function expired(int $now): bool
    {
        return $now >= $this->expiresAt;
    }

    /**
     * The canonical wire form: the exact JSON the stores persist. Only
     * pseudonyms, hashes and opaque ids, never a raw identifier. The
     * optional keys match the Redis Lua's spellings (`superseded_by`,
     * `lease_until`) so the atomic scripts and the PHP decoder agree.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $record = [
            'v' => self::SCHEMA_VERSION,
            'id' => $this->id,
            'scope' => $this->scope,
            'session_hash' => $this->sessionHash,
            'chain_id' => $this->chainId,
            'decision_id' => $this->decisionId,
            'created_at' => $this->createdAt,
            'expires_at' => $this->expiresAt,
            'sends' => $this->sends,
            'last_sent_at' => $this->lastSentAt,
            'state' => $this->state->value,
            'state_at' => $this->stateAt,
            'op_kind' => $this->operationBindingKind->value,
            'op_digest' => $this->operationDigest,
            'op_identity_digest' => $this->operationIdentityDigest,
            'op_content_digest' => $this->operationContentDigest,
            'quarantine' => $this->quarantine ? 1 : 0,
            'factor' => $this->factor,
            'authorized_at' => $this->authorizedAt,
            'parent_demand_id' => $this->parentDemandId,
            'superseded_by' => $this->supersededByDemandId,
            'lease_until' => $this->leaseUntilMs,
            'active_challenge_id' => $this->activeChallengeId,
            'active_challenge_expires_at' => $this->activeChallengeExpiresAt,
            'required_factor' => $this->requiredFactor?->family,
            'required_factor_id' => $this->requiredFactor?->factorId,
            'required_rank' => $this->requiredFactor?->assuranceRank,
            'generation' => $this->generation,
            'raised_by_decision_id' => $this->raisedByDecisionId,
            'fx' => $this->effects?->toArray(),
        ];

        return $record;
    }

    /**
     * The strict decode, all-or-nothing: a missing field, a wrong type
     * or a shape violation answers null (the caller treats the demand
     * as absent), never a defaulted record. A record of an earlier wire
     * shape carries no operation identity and no lifecycle state, so it
     * decodes as absent too: such a demand can never fund a delivery or
     * a finalization.
     *
     * @param array<string, mixed> $record
     */
    public static function fromArray(array $record): ?self
    {
        if (($record['v'] ?? null) !== self::SCHEMA_VERSION) {
            return null;
        }
        foreach (['id', 'scope', 'created_at', 'expires_at', 'sends'] as $field) {
            if (!isset($record[$field]) || !\is_scalar($record[$field])) {
                return null;
            }
        }
        if (!\is_string($record['id']) || preg_match('/^[A-Za-z0-9_-]{16,43}$/D', $record['id']) !== 1) {
            return null;
        }
        if (!\is_string($record['scope']) || preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $record['scope']) !== 1) {
            return null;
        }
        foreach (['created_at', 'expires_at', 'sends'] as $field) {
            if (!\is_int($record[$field])) {
                return null;
            }
        }
        if ($record['sends'] < 0 || $record['sends'] > self::MAX_SENDS) {
            return null;
        }
        if ($record['expires_at'] <= $record['created_at']) {
            return null;
        }
        $sessionHash = $record['session_hash'] ?? null;
        if ($sessionHash !== null && (!\is_string($sessionHash) || preg_match('/^[0-9a-f]{64}$/D', $sessionHash) !== 1)) {
            return null;
        }
        $chainId = $record['chain_id'] ?? null;
        if ($chainId !== null && (!\is_string($chainId) || !ChainId::isValid($chainId))) {
            return null;
        }
        $decisionId = $record['decision_id'] ?? null;
        if ($decisionId !== null && (!\is_string($decisionId) || preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $decisionId) !== 1)) {
            return null;
        }
        $lastSentAt = $record['last_sent_at'] ?? null;
        if ($lastSentAt !== null && !\is_int($lastSentAt)) {
            return null;
        }
        // The lifecycle state and the operation identity are load-bearing
        // on this wire shape: a record without them is not a demand.
        $state = \is_string($record['state'] ?? null) ? StepUpDemandState::of($record['state']) : null;
        if ($state === null) {
            return null;
        }
        $stateAt = $record['state_at'] ?? null;
        if ($stateAt !== null && !\is_int($stateAt)) {
            return null;
        }
        $kind = \is_string($record['op_kind'] ?? null) ? StepUpOperationBindingKind::of($record['op_kind']) : null;
        if ($kind === null) {
            return null;
        }
        $digest = $record['op_digest'] ?? null;
        if (!\is_string($digest) || !StepUpOperationDigest::isDigestShape($digest)) {
            return null;
        }
        $identityDigest = $record['op_identity_digest'] ?? null;
        if ($identityDigest !== null && (!\is_string($identityDigest) || !StepUpOperationDigest::isDigestShape($identityDigest))) {
            return null;
        }
        $contentDigest = $record['op_content_digest'] ?? null;
        if ($contentDigest !== null && (!\is_string($contentDigest) || !StepUpOperationDigest::isDigestShape($contentDigest))) {
            return null;
        }
        if (($identityDigest === null) !== ($contentDigest === null)) {
            return null;
        }
        $quarantineRaw = $record['quarantine'] ?? 0;
        if (!\is_int($quarantineRaw) || ($quarantineRaw !== 0 && $quarantineRaw !== 1)) {
            return null;
        }
        $factor = $record['factor'] ?? null;
        if ($factor !== null && (!\is_string($factor) || preg_match('/^[a-z0-9_]{1,64}$/D', $factor) !== 1)) {
            return null;
        }
        $authorizedAt = $record['authorized_at'] ?? null;
        if ($authorizedAt !== null && !\is_int($authorizedAt)) {
            return null;
        }
        $parentDemandId = $record['parent_demand_id'] ?? null;
        if ($parentDemandId !== null && (!\is_string($parentDemandId) || preg_match('/^[A-Za-z0-9_-]{16,43}$/D', $parentDemandId) !== 1)) {
            return null;
        }
        $supersededBy = $record['superseded_by'] ?? null;
        if ($supersededBy !== null && (!\is_string($supersededBy) || preg_match('/^[A-Za-z0-9_-]{16,43}$/D', $supersededBy) !== 1)) {
            return null;
        }
        $leaseUntilMs = $record['lease_until'] ?? null;
        if ($leaseUntilMs !== null && !\is_int($leaseUntilMs)) {
            return null;
        }
        $activeChallengeId = $record['active_challenge_id'] ?? null;
        if ($activeChallengeId !== null && (!\is_string($activeChallengeId) || preg_match('/^[A-Za-z0-9_-]{16,43}$/D', $activeChallengeId) !== 1)) {
            return null;
        }
        $activeChallengeExpiresAt = $record['active_challenge_expires_at'] ?? null;
        if ($activeChallengeExpiresAt !== null && !\is_int($activeChallengeExpiresAt)) {
            return null;
        }
        if (($activeChallengeId === null) !== ($activeChallengeExpiresAt === null)) {
            return null;
        }
        // The factor requirement snapshot is a coherent triple when it
        // rides at all: a half snapshot is not a decodable record.
        $requiredFamily = $record['required_factor'] ?? null;
        $requiredFactorId = $record['required_factor_id'] ?? null;
        $requiredRank = $record['required_rank'] ?? null;
        $requiredFactor = null;
        if ($requiredFamily !== null || $requiredFactorId !== null || $requiredRank !== null) {
            if (!\is_string($requiredFamily) || !\is_string($requiredFactorId) || !\is_int($requiredRank)) {
                return null;
            }
            try {
                $requiredFactor = new FactorRequirement($requiredFamily, $requiredFactorId, $requiredRank);
            } catch (\InvalidArgumentException) {
                return null;
            }
        }
        $generation = $record['generation'] ?? 0;
        if (!\is_int($generation) || $generation < 0 || $generation > self::MAX_GENERATION) {
            return null;
        }
        $raisedBy = $record['raised_by_decision_id'] ?? null;
        if ($raisedBy !== null && (!\is_string($raisedBy) || preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $raisedBy) !== 1)) {
            return null;
        }
        // The effects journal: absent on records predating it, present
        // (and strictly shaped) on any record that carries one. A wrong
        // shape refuses the whole record, fail closed: a corrupt
        // journal can never impersonate completed effects.
        $rawFx = \array_key_exists('fx', $record) ? $record['fx'] : null;
        $effects = StepUpEffectsJournal::fromArray($rawFx);
        if ($rawFx !== null && $effects === null) {
            return null;
        }

        return new self(
            $record['id'],
            $record['scope'],
            $sessionHash,
            $chainId,
            $decisionId,
            $record['created_at'],
            $record['expires_at'],
            $record['sends'],
            $lastSentAt,
            $state,
            $stateAt,
            $kind,
            $digest,
            $identityDigest,
            $contentDigest,
            $quarantineRaw === 1,
            $factor,
            $authorizedAt,
            $parentDemandId,
            $supersededBy,
            $leaseUntilMs,
            $activeChallengeId,
            $activeChallengeExpiresAt,
            $requiredFactor,
            $generation,
            $raisedBy,
            $effects,
        );
    }

    /** The demand after one effect of its journal landed. */
    public function withEffects(StepUpEffectsJournal $effects): self
    {
        return new self(
            $this->id,
            $this->scope,
            $this->sessionHash,
            $this->chainId,
            $this->decisionId,
            $this->createdAt,
            $this->expiresAt,
            $this->sends,
            $this->lastSentAt,
            $this->state,
            $this->stateAt,
            $this->operationBindingKind,
            $this->operationDigest,
            $this->operationIdentityDigest,
            $this->operationContentDigest,
            $this->quarantine,
            $this->factor,
            $this->authorizedAt,
            $this->parentDemandId,
            $this->supersededByDemandId,
            $this->leaseUntilMs,
            $this->activeChallengeId,
            $this->activeChallengeExpiresAt,
            $this->requiredFactor,
            $this->generation,
            $this->raisedByDecisionId,
            $effects,
        );
    }

    /** @return ?self null when the JSON is not a decodable demand record */
    public static function fromJson(string $json): ?self
    {
        $decoded = json_decode($json, true, 16);
        if (!\is_array($decoded)) {
            return null;
        }

        return self::fromArray($decoded);
    }

    /**
     * The split operation binding: both digests or neither. A half
     * bound demand could authorize a different operation through the
     * unbound half, so the split is refused at mint.
     *
     * @return array{0: ?string, 1: ?string}
     */
    private static function operationBinding(?string $identityDigest, ?string $contentDigest): array
    {
        if (($identityDigest === null) !== ($contentDigest === null)) {
            throw new \InvalidArgumentException('A step-up demand operation binding is both the identity digest and the content digest, never one alone');
        }
        if ($identityDigest === null) {
            return [null, null];
        }

        return [
            self::digest($identityDigest, 'operation identity'),
            self::digest($contentDigest, 'operation content'),
        ];
    }

    private static function digest(string $value, string $label): string
    {
        if (!StepUpOperationDigest::isDigestShape($value)) {
            throw new \InvalidArgumentException(sprintf('The %s digest of a step-up demand must be a 64-char lowercase hex digest', $label));
        }

        return $value;
    }

    private static function id(string $value): string
    {
        if (preg_match('/^[A-Za-z0-9_-]{16,43}$/D', $value) !== 1) {
            throw new \InvalidArgumentException('The step-up demand id must be the base64url id shape');
        }

        return $value;
    }

    private static function scope(string $value): string
    {
        if (preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $value) !== 1) {
            throw new \InvalidArgumentException('The scope of a step-up demand must be 1-128 chars of [A-Za-z0-9._:-]');
        }

        return $value;
    }

    private static function sessionHash(?string $value): ?string
    {
        if ($value === null || $value === '') {
            return null;
        }
        if (preg_match('/^[0-9a-f]{64}$/D', $value) !== 1) {
            throw new \InvalidArgumentException('The session hash of a step-up demand must be a 64-char lowercase hex digest');
        }

        return $value;
    }

    private static function chainId(string $value): string
    {
        if (!ChainId::isValid($value)) {
            throw new \InvalidArgumentException('The chain id of a step-up demand must be the canonical chain id shape');
        }

        return $value;
    }

    private static function decisionId(string $value): string
    {
        if (preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $value) !== 1) {
            throw new \InvalidArgumentException('The decision id of a step-up demand must be 1-128 chars of [A-Za-z0-9._:-]');
        }

        return $value;
    }

    private static function operationDigest(string $value): string
    {
        if ($value !== '' && !StepUpOperationDigest::isDigestShape($value)) {
            throw new \InvalidArgumentException('The operation digest of a step-up demand must be a 64-char lowercase hex digest');
        }

        return $value;
    }
}
