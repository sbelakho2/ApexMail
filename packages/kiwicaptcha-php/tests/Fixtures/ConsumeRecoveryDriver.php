<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Fixtures;

use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;

/**
 * The concrete-driver surface of the consume/commit/recovery walk: every
 * transition the model executes against the real storages. The drivers
 * run the real implementations (the RedisStorage Lua scripts and the
 * ArrayStorage in-process mirror) and resolve the already-consumed
 * replay through the real Verifier, so the lockstep asserts the real
 * machine against the clean-room model.
 */
interface ConsumeRecoveryDriver
{
    /** Issue a fresh pending challenge and return its nonce. */
    public function issue(): string;

    /**
     * The consume transition.
     *
     * @return array{win: bool, lose: bool, resultValid: bool|null, identity: string|null}|null
     */
    public function consume(string $nonce, ?string $identity): ?array;

    /**
     * The result commit, with an optional claim-bearing owner token.
     */
    public function commit(string $nonce, bool $valid, ?string $owner): bool;

    /** The recovery-claim transition; the minted owner token or null. */
    public function claim(string $nonce, int $ttlSecs): ?string;

    /** Rewrite the claim lease deadline into the past; false when no lease exists. */
    public function expireClaim(string $nonce): bool;

    /** The compare-and-delete lease release. */
    public function release(string $nonce, string $owner): bool;

    /**
     * The verifier-level resolution of an already-consumed record, one
     * of granted|already_consumed|insufficient|indeterminate|
     * not_consumed.
     */
    public function replay(string $nonce, ?string $operationIdentity): string;

    /** The TTL sweep: the record vanishes. */
    public function vanish(string $nonce): void;

    /** The cancel transition; one of the cancel statuses or null. */
    public function cancel(string $nonce): ?string;

    /**
     * The observable stored shape of the record.
     *
     * @return array{state: string, identity: string|null, resultValid: bool|null, claimOwner: string|null, claimLive: bool}|null
     */
    public function readState(string $nonce): ?array;
}

/**
 * The in-memory driver over ArrayStorage: the same transitions through
 * the Array mirror, with the claim lease and the TTL sweep driven
 * through the storage's own fields. The storage clock is pinned into
 * the record's validity window, so no transition ever races the record
 * expiry.
 */
