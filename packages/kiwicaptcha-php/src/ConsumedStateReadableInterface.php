<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Optional capability for storages that can read the retained consumed
 * state of a record without any state transition. Not part of
 * {@see StorageInterface}: third-party adapters are not required to
 * implement it. PSR-6 pools intentionally do without it:
 * {@see \KiwiCaptcha\Storage\Psr6Storage} implements neither this
 * interface nor the identity-aware consume that extends it, because a
 * PSR-6 pool cannot make its retained state authoritative recovery
 * evidence (no fused read-and-transition). Its envelope stays readable
 * through a clearly-named off-interface diagnostic instead.
 *
 * Used by the idempotent consumed-outcome recovery: after the signed
 * challenge has expired, the retained consumed record and its committed
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
