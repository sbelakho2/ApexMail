<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Optional storage capability: the pending→consumed transition can record
 * the logical-operation identity that performs it, in the same atomic
 * write as the state flip.
 *
 * The identity is a caller-supplied token that names the logical
 * operation redeeming the nonce, e.g. a Siteverify backend plus
 * idempotency key plus response fingerprint. It lands in the retained
 * consumed record atomically with `state` = "consumed", so the stored
 * identity is provably the identity of the actual atomic consume winner.
 * Read it back via {@see ConsumedStateReadableInterface::consumedState()}.
 *
 * The identity is validated against a narrow alphabet: a non-empty
 * string of `[A-Za-z0-9_-]`, 1..128 bytes, see {@see OperationIdentity}.
 * Every storage shares that single validation seam, so Redis, PSR-6 and
 * the array backend reject a malformed identity identically with
 * \InvalidArgumentException, before the transition; it is never silently
 * dropped. The alphabet is narrow because the identity is JSON-encoded
 * and spliced into the Redis consume Lua's `string.gsub` replacement
 * string, where `%` is interpreted as a replacement-template escape.
 * The validated alphabet excludes `%` and every other gsub-special
 * character by construction, making the splice safe without a
 * replacement function. Hex fingerprints, base64url, UUIDs and HMAC
 * digests all fit.
 *
 * The ordinary {@see StorageInterface::consume()} keeps byte-identical
 * behavior: no identity is recorded, and the runtime
 * `operation_identity` field stays null.
 * {@see self::consumeWithOperationIdentity()} is the identity-bearing
 * variant. A storage without this interface verifies normally but can
 * never record an identity, so consumed-outcome recovery that requires
 * identity proof must refuse such storages at configuration time.
 */
interface OperationIdentityAwareStorageInterface extends ConsumedStateReadableInterface
{
    /**
     * The one-shot consume transition with the logical-operation identity:
     * same semantics as {@see StorageInterface::consume()}; the record is
     * marked consumed and kept until its TTL. When `$operationIdentity`
     * is non-null, the identity is stored in the same atomic write as the
     * pending→consumed flip. A null identity records no identity.
     *
     * A non-null identity is validated against the narrow shared alphabet
     * via {@see OperationIdentity::validate()}: `[A-Za-z0-9_-]`, 1..128
     * bytes. A malformed identity (empty, over-long, or containing `%`
     * or any other non-alphabet character) throws \InvalidArgumentException.
     * The record is left untouched; the identity is rejected, never
     * silently dropped, so a caller can never believe a recovery identity
     * was recorded while the consume stored null.
     *
     * @throws \InvalidArgumentException when a non-null identity is
     *                                   malformed
     */
    public function consumeWithOperationIdentity(string $nonce, ?string $operationIdentity): ?ConsumedRecord;
}
