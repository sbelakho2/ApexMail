<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Evidence;

/**
 * The reader seam of the engine wiring (the marks-reader precedent):
 * answers whether the session's decoy escalation is live. An unreadable
 * surface degrades to not-live: the stage is a temporary price raise,
 * so a backend miss must never escalate anyone.
 */
interface DecoyEscalationReaderInterface
{
    /** True when the session carries a live escalation record. */
    public function escalationLive(?string $session): bool;
}
