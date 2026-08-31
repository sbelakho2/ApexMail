<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Fixtures;

use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;

final class ArrayConsumeRecoveryDriver implements ConsumeRecoveryDriver
{
    private const ISSUED_AT = 1_800_000_000;

    private readonly ArrayStorage $storage;

    private readonly Issuer $issuer;

    private readonly Verifier $verifier;

    public function __construct()
    {
        $this->storage = new ArrayStorage(now: static fn (): int => self::ISSUED_AT + 100);
        $this->issuer = new Issuer(
            new Config(secretKey: ConsumeRecoveryWalk::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0),
            $this->storage,
            now: static fn (): int => self::ISSUED_AT,
        );
        $this->verifier = new Verifier($this->storage, now: static fn (): int => self::ISSUED_AT + 100);
    }

    public function issue(): string
    {
        return $this->issuer->issue('login', '198.51.100.7')->nonce;
    }

    public function consume(string $nonce, ?string $identity): ?array
    {
        $consumed = $identity !== null
            ? $this->storage->consumeWithOperationIdentity($nonce, $identity)
            : $this->storage->consume($nonce);
        if ($consumed === null) {
            return null;
        }

        return [
            'win' => $consumed->consumedNow,
            'lose' => $consumed->consumedBefore,
            'resultValid' => $consumed->consumedResult?->valid,
            'identity' => $consumed->operationIdentity,
        ];
    }

    public function commit(string $nonce, bool $valid, ?string $owner): bool
    {
        return $owner !== null
            ? $this->storage->commitResultResume($nonce, $valid, null, $owner)
            : $this->storage->commitResult($nonce, $valid, null);
    }

    public function claim(string $nonce, int $ttlSecs): ?string
    {
        return $this->storage->claimResumeDerivation($nonce, $ttlSecs);
    }

    public function expireClaim(string $nonce): bool
    {
        $records = $this->entries();
        $entry = $records[$nonce] ?? null;
        if ($entry === null || ($entry['claim'] ?? null) === null || ($entry['claimUntil'] ?? 0) <= self::ISSUED_AT + 100) {
            return false;
        }
        $entry['claimUntil'] = 1;
        $records[$nonce] = $entry;
        $this->setEntries($records);

        return true;
    }

    public function release(string $nonce, string $owner): bool
    {
        return $this->storage->releaseResumeDerivation($nonce, $owner);
    }

    public function replay(string $nonce, ?string $operationIdentity): string
    {
        $token = SolutionToken::create($nonce, 0, 0, [])->encode();
        $outcome = $this->verifier->verify(
            $token,
            ConsumeRecoveryWalk::SECRET,
            'login',
            '198.51.100.7',
            (self::ISSUED_AT + 100) * 1_000_000,
            operationIdentity: $operationIdentity,
        );
        if ($outcome->isOk()) {
            return $outcome->fromStoredResult ? 'granted' : 'not_consumed';
        }
        if ($outcome->error === VerifyError::ConsumeIndeterminate) {
            return 'indeterminate';
        }
        if ($outcome->error === VerifyError::InsufficientWork) {
            return 'insufficient';
        }
        if ($outcome->error === VerifyError::AlreadyConsumed) {
            return 'already_consumed';
        }

        return 'not_consumed';
    }

    public function vanish(string $nonce): void
    {
        $records = $this->entries();
        unset($records[$nonce]);
        $this->setEntries($records);
    }

    public function cancel(string $nonce): ?string
    {
        return $this->storage->cancel($nonce)?->state;
    }

    public function readState(string $nonce): ?array
    {
        $records = $this->entries();
        $entry = $records[$nonce] ?? null;
        if ($entry === null) {
            return null;
        }
        $runtime = $this->storage->runtimeState($nonce);
        $state = match ($runtime->kind->name) {
            'Pending' => ConsumeRecoveryModel::PENDING,
            'Cancelled' => ConsumeRecoveryModel::CANCELLED,
            'Missing' => ConsumeRecoveryModel::MISSING,
            default => $runtime->consumed?->consumedResult !== null
                ? ($runtime->consumed->consumedResult->valid ? ConsumeRecoveryModel::COMMITTED_VALID : ConsumeRecoveryModel::COMMITTED_INVALID)
                : ConsumeRecoveryModel::CONSUMED_RESULTLESS,
        };

        return [
            'state' => $state,
            'identity' => $runtime->consumed?->operationIdentity,
            'resultValid' => $runtime->consumed?->consumedResult?->valid,
            'claimOwner' => $entry['claim'] ?? null,
            'claimLive' => ($entry['claimUntil'] ?? 0) > self::ISSUED_AT + 100,
        ];
    }

    /** @return array<string, array<string, mixed>> */
    private function entries(): array
    {
        $property = new \ReflectionProperty(ArrayStorage::class, 'records');

        return $property->getValue($this->storage);
    }

    /** @param array<string, array<string, mixed>> $records */
    private function setEntries(array $records): void
    {
        $property = new \ReflectionProperty(ArrayStorage::class, 'records');
        $property->setValue($this->storage, $records);
    }
}

/**
 * The real-Redis driver over RedisStorage: every transition is the
 * atomic Lua script, and the claim lease expiry is driven by rewriting
 * the embedded resume_until deadline into the past (the real-Redis
 * equivalent of the in-memory clock advance), preserving the key TTL.
 * The record TTL stays far beyond the walk horizon, so the record
 * expiry never races a step.
 */
