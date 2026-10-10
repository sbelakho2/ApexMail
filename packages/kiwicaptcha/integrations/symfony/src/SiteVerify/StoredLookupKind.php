<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

/**
 * The operation-bound lookup outcome (see
 * {@see SiteVerifyIdempotencyStore::storedForOperation()}): what the
 * store currently holds for the exact operation identity the caller
 * presents.
 */
enum StoredLookupKind: string
{
    /** No live record for the key. */
    case Missing = 'missing';

    /** The exact operation is still pending (another owner may hold it). */
    case PendingSame = 'pending_same';

    /** The exact operation completed; the cached result is authoritative. */
    case CompleteSame = 'complete_same';

    /** The key now holds a different operation (an ABA/reused key). */
    case Changed = 'changed';

    /** The record is present but structurally corrupt or lifetime-stripped. */
    case Corrupt = 'corrupt';
}
