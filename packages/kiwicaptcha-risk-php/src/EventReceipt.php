<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * Receipt of one feedback event applied to the risk state.
 *
 * eventId is the dedupe key actually used (the caller's idempotency key,
 * verbatim, when provided); isDuplicate reports whether that event_id had
 * already been applied (state untouched, current signals returned);
 * signals are the current signal vector.
 */
final class EventReceipt
{
    public function __construct(
        public readonly string $eventId,
        public readonly bool $isDuplicate,
        public readonly SignalVector $signals,
    ) {
    }
}
