<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Read-only recovery of the retained consumed outcome of a token,
 * identity-gated.
 *
 * This is not a verification retry API. It performs no signature,
 * expiry, scope, IP, region, issuer or policy checks and no fresh
 * derivation. It only reads the retained consumed record and its
 * committed deterministic result. The stored valid outcome is an
 * authorization grant: it is returned only when the caller proves the
 * exact logical operation, with $operationIdentity equal in constant
 * time to the identity the pending-to-consumed transition recorded
 * atomically with the state flip. A mismatched or absent identity —
 * including a record consumed by a plain consume that recorded none —
 * yields the {@see VerifyError::AlreadyConsumed} error outcome
 * instead. Possession of the raw token alone is never a sufficient
 * proof, so the API is not a replay oracle. A stored invalid outcome
 * replays deterministically to any caller exactly like the core's
 * replay path; it grants nothing.
 *
 * Null (nothing recoverable, retryable through the ordinary paths) is
 * returned for a non-capable storage, an undecodable token, a missing
 * or still-pending record, or a consumed record without a committed
 * result (crash between consume and commit: intrinsically ambiguous).
 * An ordinary replay without an identity proof must go through
 * {@see Verifier::verify()}, which maps a consumed token to the
 * duplicate vocabulary.
 *
 * The identity-proven acceptance of a stored success holds the same
 * failed-barrier replay guard as the verify and resume paths. When the
 * storage implements {@see \KiwiCaptcha\ReplicationBarrierInterface},
 * the replication fence is re-established before the stored outcome is
 * returned, and a barrier or shortfall failure answers the retryable
 * {@see VerifyError::StorageUnavailable} instead of an unproven
 * success. A retained envelope whose stored nonce does not match the
 * token's nonce is an impossible key-value pair and answers the
 * deterministic MalformedRecord, never the stored result.
 *
 * The retained evidence is readable even after the signed challenge has
 * expired (the storage's retention horizon covers the recovery window),
 * so a late-lifetime crash can still reproduce the original outcome.
 *
 * A stored success is released only when its server-state MAC verifies
 * see {@see Verifier::storedSuccessAuthentic()}. A storage writer who
 * forges `valid=true` under the recorded identity gets MalformedRecord,
 * never a grant. Checking the MAC needs the verifier and the secret: on
 * a storage that carries authenticated results
 * see {@see AuthenticatedResultCommitInterface}, a recovery constructed
 * without them fails every stored success closed.
 */
final class ConsumedOutcomeRecovery
{
    public function __construct(
        private readonly StorageInterface $storage,
        private readonly ?Verifier $verifier = null,
        #[\SensitiveParameter]
        private readonly ?string $secretKey = null,
    ) {
    }

    /**
     * Recover the retained committed outcome of a consumed token for the
     * logical operation named by $operationIdentity.
     *
     * @param string $rawToken          the base64 solution token whose
     *                                  consumed record holds the outcome
     * @param string $operationIdentity the expected logical-operation
     *                                  identity. It must match the stored
     *                                  one in constant time before a
     *                                  stored valid outcome is returned.
     *
     * @return VerifyOutcome|null the stored outcome when the identity is
     *                            proven ({@see VerifyError::AlreadyConsumed}
     *                            when it is not), or null when nothing is
     *                            recoverable (non-capable storage,
     *                            undecodable token, missing/pending
     *                            record, no committed result)
     */
    public function recover(string $rawToken, string $operationIdentity): ?VerifyOutcome
    {
        if (!$this->storage instanceof ConsumedStateReadableInterface) {
            return null;
        }
        try {
            $decoded = SolutionToken::decode($rawToken);
        } catch (DecodeError) {
            return null;
        }
        $consumed = $this->storage->consumedState($decoded->nonce);
        if ($consumed === null) {
            return null;
        }
        if ($consumed->record->nonce !== $decoded->nonce) {
            // The retained envelope was loaded by the token's nonce (the
            // storage key); a stored nonce field that differs is an
            // impossible key-value pair and never replays the retained
            // result — the deterministic MalformedRecord, mirroring the
            // verifier's consumed-envelope resolution.
            return VerifyOutcome::invalid(VerifyError::MalformedRecord);
        }
        if ($consumed->consumedResult === null) {
            // Crash between consume and commit: intrinsically ambiguous.
            return null;
        }

        // The stored invalid outcome is deterministic and grants nothing:
        // it replays to any caller exactly like the core's replay path.
        if (!$consumed->consumedResult->valid) {
            return VerifyOutcome::invalid(VerifyError::InsufficientWork);
        }

        // The identity gate: the stored valid outcome is an authorization
        // grant, released only to the logical operation that consumed the
        // record. A null stored identity (a plain consume) is unprovable
        // by construction; anything not exactly equal is refused.
        if (
            $consumed->operationIdentity === null
            || !hash_equals($consumed->operationIdentity, $operationIdentity)
        ) {
            return VerifyOutcome::invalid(VerifyError::AlreadyConsumed);
        }

        // The authenticity gate: a stored success must carry a
        // server-state MAC that verifies for this record, binding and
        // recorded identity. Forged or corrupt persisted state otherwise.
        $authentic = $this->verifier !== null && $this->secretKey !== null
            ? $this->verifier->storedSuccessAuthentic($consumed, $this->secretKey, $this->storage)
            : !$this->storage instanceof AuthenticatedResultCommitInterface;
        if (!$authentic) {
            return VerifyOutcome::invalid(VerifyError::MalformedRecord);
        }

        // Failed-barrier replay guard, the same fence the verify and
        // resume paths hold before accepting a stored success: the
        // consume/commit mutations that produced it may have landed on
        // the primary with their WAIT failing, and accepting the stored
        // result read-only would return a success a promotion could
        // lose. The barrier is re-established before the acceptance, and
        // a barrier or shortfall failure maps to the retryable
        // StorageUnavailable.
        try {
            if ($this->storage instanceof \KiwiCaptcha\ReplicationBarrierInterface) {
                $this->storage->establishReplicationFence('the recovered stored-result acceptance');
            }
        } catch (\Throwable) {
            return VerifyOutcome::invalid(VerifyError::StorageUnavailable);
        }

        // The stored valid outcome is an authorization grant, released
        // only to the logical operation that consumed the record. It is a
        // stored-result replay: no solve duration (the retry's receipt is
        // not the solve's endpoint, the shared PHP/Rust spec), the
        // authenticated decoy name from the replayed record.
        return VerifyOutcome::valid($consumed->record->nonce, $consumed->consumedResult->binding, true, null, $consumed->record->decoyField);
    }
}
