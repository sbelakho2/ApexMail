<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

use BelConsulting\KiwiCaptchaBundle\SiteVerify\StoredLookup;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\StoredLookupKind;

/**
 * Test-side helpers for the operation-bound stored-result lookup: the
 * completed result of a lookup (or null for every other state) and the
 * controller-identical remoteip/binding derivations, so store-level
 * assertions stay terse while remaining bound to the exact operation
 * identity they seeded.
 */
final class SiteVerifyStoreAssert
{
    /**
     * A placeholder identity whose hash can never equal a real
     * operation's response hash. It is used where a test only asserts
     * "this key stores no completed result", the exact translation of
     * the previous unbound read, which could not prove a specific
     * operation either.
     *
     * @return array{0: string, 1: string, 2: string}
     */
    public static function probe(): array
    {
        return [str_repeat('0', 64), 'no-ip', ''];
    }

    /** The completed result of an operation-bound lookup, or null for any other state. */
    public static function completed(StoredLookup $lookup): ?array
    {
        return $lookup->kind === StoredLookupKind::CompleteSame ? $lookup->result : null;
    }

    /** The controller-identical remoteip fingerprint for a canonical address. */
    public static function fingerprint(string $canonicalRemoteip, string $secretKey): string
    {
        if ($canonicalRemoteip === '') {
            return 'no-ip';
        }

        return hash_hmac('sha256', 'siteverify-idem-ip-v1|'.$canonicalRemoteip, $secretKey);
    }

    /** The controller-identical binding digest (the empty string when unbound). */
    public static function binding(?string $canonicalBinding, string $secretKey): string
    {
        if ($canonicalBinding === null || $canonicalBinding === '') {
            return '';
        }

        return hash_hmac('sha256', 'siteverify-idem-binding-v1|'.$canonicalBinding, $secretKey);
    }
}
