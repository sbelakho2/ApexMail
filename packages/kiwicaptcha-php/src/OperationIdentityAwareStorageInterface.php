<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Optional storage capability: the pending→consumed TRANSITION can record
 * the LOGICAL-OPERATION IDENTITY that performs it, in the SAME atomic
 * write as the state flip.
 *
 * The identity is a bounded (<= 128 bytes) caller-supplied token that
 * names the logical operation redeeming the nonce — e.g. a Siteverify
 * backend + idempotency-key + response fingerprint. It lands in the
 * retained consumed record atomically with `state` = "consumed", so the
 * stored identity is PROVABLY the identity of the ACTUAL atomic consume
 * winner — read it back via
 * {@see ConsumedStateReadableInterface::consumedState()}.
 *
 * The ordinary {@see StorageInterface::consume()} keeps byte-identical
 * behavior (no identity is recorded — the runtime `operation_identity`
 * field stays null); {@see self::consumeWithOperationIdentity()} is the
 * identity-bearing variant. A storage WITHOUT this interface verifies
 * normally but can never record an identity, so consumed-outcome
 * recovery that requires identity proof must refuse such storages at
 * configuration time.
 */
interface OperationIdentityAwareStorageInterface extends ConsumedStateReadableInterface
{
    /**
     * The one-shot consume transition WITH the logical-operation identity:
     * same semantics as {@see StorageInterface::consume()} — the record is
     * marked consumed and KEPT until its TTL — and, when `$operationIdentity`
     * is non-null (and <= 128 bytes), the identity is stored in the SAME
     * atomic write as the pending→consumed flip. A null identity (or an
     * over-long one, which is ignored) records no identity.
     */
    public function consumeWithOperationIdentity(string $nonce, ?string $operationIdentity): ?ConsumedRecord;
}
