<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Fixtures;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\ConsumedRecord;
use KiwiCaptcha\ConsumedStateReadableInterface;
use KiwiCaptcha\OperationIdentityAwareStorageInterface;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\StorageInterface;

/**
 * An ArrayStorage whose retained consumed-state read can be told to
 * fail: everything delegates to the inner array backend (the real
 * transition, commit and identity-aware consume), and
 * `throwOnConsumedState` makes {@see consumedState()} throw — the wire
 * failure that models a storage whose retained-state READ is unavailable
 * while the record itself is intact. Used to prove the verifier's
 * evidence preservation: an unreadable consumed marker never deletes the
 * record and surfaces the retryable StorageUnavailable instead.
 */
final class FlakyConsumedStateStorage implements StorageInterface, ConsumedStateReadableInterface, OperationIdentityAwareStorageInterface
{
    public bool $throwOnConsumedState = false;

    public function __construct(private readonly ArrayStorage $inner = new ArrayStorage())
    {
    }

    public function store(ChallengeRecord $record): void
    {
        $this->inner->store($record);
    }

    public function find(string $nonce): ?ChallengeRecord
    {
        return $this->inner->find($nonce);
    }

    public function consumedState(string $nonce): ?ConsumedRecord
    {
        if ($this->throwOnConsumedState) {
            throw new \RuntimeException('simulated consumed-state read failure');
        }

        return $this->inner->consumedState($nonce);
    }

    public function consume(string $nonce): ?ConsumedRecord
    {
        return $this->inner->consume($nonce);
    }

    public function consumeWithOperationIdentity(string $nonce, ?string $operationIdentity): ?ConsumedRecord
    {
        return $this->inner->consumeWithOperationIdentity($nonce, $operationIdentity);
    }

    public function commitResult(string $nonce, bool $valid, ?string $binding): bool
    {
        return $this->inner->commitResult($nonce, $valid, $binding);
    }

    public function delete(string $nonce): void
    {
        $this->inner->delete($nonce);
    }
}
