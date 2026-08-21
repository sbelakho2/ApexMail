<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Result of the storage one-shot consume transition.
 *
 * consume() no longer deletes the record: it atomically flips the stored
 * record's `state` from "pending" to "consumed" and keeps the record
 * until its TTL. Replay protection is the consumed marker, not absence.
 * This wrapper carries the record plus the transition outcome:
 *
 * - `consumedNow`: this call won the transition (state went pending ->
 *   consumed).
 * - `consumedBefore`: the record was already consumed by an earlier call.
 * - `consumedResult`: the deterministic verification result stored by
 *   {@see StorageInterface::commitResult()}, or null when absent (a
 *   crash between consume and commit).
 * - `operationIdentity`: the logical-operation identity recorded with
 *   the pending→consumed transition by
 *   {@see OperationIdentityAwareStorageInterface::consumeWithOperationIdentity()}.
 *   Null when the record carries none: a plain consume, an
 *   identity-less storage, or a malformed identity, which is rejected
 *   by {@see OperationIdentity} before the transition and so never
 *   lands.
 *
 * A verifier retrying an already-consumed record with a stored result
 * returns that stored outcome directly (Valid/InsufficientWork) without
 * re-deriving the proof; without a stored result the retry is ambiguous
 * ({@see VerifyError::ConsumeIndeterminate}).
 */
final class ConsumedRecord
{
    public function __construct(
        public readonly ChallengeRecord $record,
        public readonly bool $consumedNow,
        public readonly bool $consumedBefore,
        public readonly ?ConsumedResult $consumedResult,
        public readonly ?string $operationIdentity = null,
    ) {
    }
}
