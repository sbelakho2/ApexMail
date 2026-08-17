<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

/**
 * Round 30 (P1): the outcome of claiming an idempotency key for a
 * verification attempt.
 *
 * - CLAIMED: no prior key exists — this request OWNS verification.
 * - PENDING_SAME: the same key + same response hash is being processed by
 *   another request — wait/poll for completion instead of consuming the
 *   token independently.
 * - COMPLETE_SAME: the same key + same response hash already finished —
 *   return the exact stored canonical response WITHOUT invoking the
 *   verifier again.
 * - CONFLICT: the same key is being reused for a DIFFERENT response —
 *   reject.
 */
enum IdempotencyClaim: string
{
    case Claimed = 'claimed';
    case PendingSame = 'pending_same';
    case CompleteSame = 'complete_same';
    case Conflict = 'conflict';
}
