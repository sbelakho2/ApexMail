<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

/**
 * The operation-bound stored-result lookup. The store classifies the
 * record under the caller's full operation identity in one atomic read:
 * response hash, remoteip fingerprint and binding digest. An acceptance
 * can therefore never cross between two logical operations that reused
 * the same idempotency key (an ABA after expiry, or any other key
 * reuse).
 *
 * The result payload is present only for {@see StoredLookupKind::CompleteSame}
 * and has already passed the canonical result validator on the store
 * side; callers re-validate defensively before serving it.
 */
final class StoredLookup
{
    private function __construct(
        public readonly StoredLookupKind $kind,
        public readonly ?array $result = null,
    ) {
    }

    public static function missing(): self
    {
        return new self(StoredLookupKind::Missing);
    }

    public static function pendingSame(): self
    {
        return new self(StoredLookupKind::PendingSame);
    }

    public static function completeSame(array $result): self
    {
        return new self(StoredLookupKind::CompleteSame, $result);
    }

    public static function changed(): self
    {
        return new self(StoredLookupKind::Changed);
    }

    public static function corrupt(): self
    {
        return new self(StoredLookupKind::Corrupt);
    }
}
