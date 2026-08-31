<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

/**
 * The minimal store surface the model-checking walk needs, implemented by
 * the in-memory store driver (controllable clock) and the real-Redis
 * driver (Lua transitions), so the same randomized transition sequences
 * and the same invariant checks run against both backends.
 */
interface ChainStoreDriver
{
    /** The current backend time in unix seconds. */
    public function now(): int;

    public function obligationChainId(string $obligationId): ?string;

    /** @return string the chain id the obligation resolved to (the passed id on a fresh creation) */
    public function createOrGet(string $chainId, string $obligationId, int $rank, int $expiresAt): string;

    /** @return array<string, mixed>|null the strictly-decoded record or null when absent */
    public function read(string $chainId): ?array;

    public function reserve(string $chainId, string $ownerToken): string;

    public function release(string $chainId, string $ownerToken): void;

    public function markIssued(string $chainId, string $ownerToken, string $stage2Nonce): string;

    public function markVerified(string $chainId, string $stage2Nonce): string;

    public function markStepUpRequired(string $chainId, string $stage2Nonce): string;

    public function markDenied(string $chainId, string $stage2Nonce): string;

    public function markTransactionDenied(string $chainId, string $obligationId): string;

    public function markTransactionStepUpRequired(string $chainId, string $obligationId): string;

    public function rearmIssued(string $chainId, string $stage2Nonce): bool;

    public function deleteObligation(string $chainId, string $obligationId): void;

    /** @return string|null the completed record or null on a refusal */
    public function complete(string $chainId, string $ownerToken, string $stage2Nonce): ?array;

    /**
     * Let the short reservation lease run out (only when the record is
     * reserved with a live lease that can expire before the chain).
     *
     * @return bool whether the lease was actually advanced
     */
    public function advanceLease(string $chainId): bool;

    /**
     * Let the chain TTL run out: the record and the obligation mapping
     * vanish.
     *
     * @return bool whether the chain was actually expired
     */
    public function expireChain(string $chainId, string $obligationId): bool;
}
