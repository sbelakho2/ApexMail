<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

/**
 * The outcome of claiming an idempotency key for a verification attempt.
 *
 * - `CLAIMED`: no prior key exists, so this request owns verification.
 * - `PENDING_SAME`: the same key + same response hash is being processed by
 *   another request; wait/poll for completion instead of consuming the
 *   token independently.
 * - `COMPLETE_SAME`: the same key + same response hash already finished;
 *   return the exact stored canonical response without invoking the
 *   verifier again.
 * - `CONFLICT`: the same key is being reused for a different response;
 *   reject.
 *
 * A `PENDING_SAME` waiter whose owner's lease has expired attempts an atomic
 * takeover:
 * - `TOOK_OVER`: this request atomically replaced the owner and now owns
 *   verification (it must finalize with the returned owner token).
 * - `STILL_PENDING`: the takeover attempt lost (entry complete, different
 *   hash, or the lease is still held); keep waiting.
 */
enum IdempotencyClaim: string
{
    case Claimed = 'claimed';
    case PendingSame = 'pending_same';
    case CompleteSame = 'complete_same';
    case Conflict = 'conflict';
    case TookOver = 'took_over';
    case StillPending = 'still_pending';
}
