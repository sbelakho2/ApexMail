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
 * committed deterministic result — and the stored VALID outcome is an
 * authorization grant, so it is returned only when the caller proves
 * the exact logical operation: the $operationIdentity parameter must
 * equal (constant-time) the operation identity the pending→consumed
 * transition recorded atomically with the state flip. A mismatched or
 * absent identity (including a record consumed by a plain consume that
 * recorded none) yields the {@see VerifyError::AlreadyConsumed} error
 * outcome instead — possession of the raw token alone is never a
 * sufficient proof, so the API is not a replay oracle. A stored INVALID
 * outcome replays deterministically to any caller exactly like the
 * core's replay path (it grants nothing).
 *
 * Null (nothing recoverable, retryable through the ordinary paths) is
 * returned for a non-capable storage, an undecodable token, a missing
 * or still-pending record, or a consumed record without a committed
 * result (crash between consume and commit: intrinsically ambiguous).
 * An ordinary replay without an identity proof must go through
 * {@see Verifier::verify()}, which maps a consumed token to the
 * duplicate vocabulary.
 *
 * The retained evidence is readable even after the signed challenge has
 * expired (the storage's retention horizon covers the recovery window),
 * so a late-lifetime crash can still reproduce the original outcome.
 */
final class ConsumedOutcomeRecovery
{
    public function __construct(
        private readonly StorageInterface $storage,
    ) {
    }

    /**
     * Recover the retained committed outcome of a consumed token for the
     * logical operation named by $operationIdentity.
     *
     * @param string $rawToken          the base64 solution token whose
     *                                  consumed record holds the outcome
     * @param string $operationIdentity the expected logical-operation
     *                                  identity; must match the stored one
     *                                  (constant-time) before a stored
     *                                  valid outcome is returned
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
        if ($consumed->consumedResult === null) {
            // Crash between consume and commit: intrinsically ambiguous.
            return null;
        }

        // The stored INVALID outcome is deterministic and grants nothing:
        // it replays to any caller exactly like the core's replay path.
        if (!$consumed->consumedResult->valid) {
            return VerifyOutcome::invalid(VerifyError::InsufficientWork);
        }

        // The identity gate: the stored VALID outcome is an authorization
        // grant, released only to the logical operation that consumed the
        // record. A null stored identity (a plain consume) is unprovable
        // by construction; anything not exactly equal is refused.
        if (
            $consumed->operationIdentity === null
            || !hash_equals($consumed->operationIdentity, $operationIdentity)
        ) {
            return VerifyOutcome::invalid(VerifyError::AlreadyConsumed);
        }

        return VerifyOutcome::valid($consumed->record->nonce, $consumed->consumedResult->binding, true);
    }
}
