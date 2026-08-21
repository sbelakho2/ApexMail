<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Read-only recovery of the retained consumed outcome of a token.
 *
 * This is not a verification retry API. It performs no signature,
 * expiry, scope, IP, region, issuer or policy checks and no fresh
 * derivation. It only reads the retained consumed record and its
 * committed deterministic result. It is therefore usable only by a
 * caller that has independently proven the exact idempotency identity
 * (same backend plus idempotency key plus response hash plus remote-IP
 * fingerprint) against the pre-existing entry; the Siteverify takeover
 * path is the only intended caller. An ordinary replay without that
 * proof must go through {@see Verifier::verify()}, which maps a
 * consumed token to the duplicate vocabulary.
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

    public function recover(string $rawToken): ?VerifyOutcome
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

        return $consumed->consumedResult->valid
            ? VerifyOutcome::valid($consumed->record->nonce, $consumed->consumedResult->binding, true)
            : VerifyOutcome::invalid(VerifyError::InsufficientWork);
    }
}
