<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * The runtime state kind of a challenge record: the retained Redis state
 * distinguishes a cancelled challenge from a merely-not-yet-consumed one
 * (both `find()` and `consumedState()` alone cannot — a cancelled record
 * is retained and still found, while its consumed state is null).
 */
enum ChallengeRuntimeStateKind: string
{
    case Missing = 'missing';
    case Pending = 'pending';
    case Consumed = 'consumed';
    case Cancelled = 'cancelled';
}
