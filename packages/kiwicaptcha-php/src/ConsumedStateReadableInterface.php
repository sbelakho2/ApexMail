<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Optional capability for storages that can READ the retained consumed
 * state of a record WITHOUT any state transition. Not part of
 * {@see StorageInterface}: third-party adapters are not required to
 * implement it (PSR-6 pools, for example, cannot offer it).
 *
 * Used by the idempotent consumed-outcome recovery: after the signed
 * challenge has expired, the retained consumed record + its committed
 * deterministic result must still be readable to reproduce the original
 * outcome.
 */
interface ConsumedStateReadableInterface
{
    /**
     * Returns the retained ConsumedRecord for an already-consumed record
     * (consumedBefore=true) without any state transition, or null when
     * the record is missing, not yet consumed, or the backend cannot
     * inspect the state read-only.
     */
    public function consumedState(string $nonce): ?ConsumedRecord;
}
