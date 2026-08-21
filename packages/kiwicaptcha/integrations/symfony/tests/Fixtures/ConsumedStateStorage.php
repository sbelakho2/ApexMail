<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\ConsumedRecord;
use KiwiCaptcha\ConsumedStateReadableInterface;
use KiwiCaptcha\OperationIdentityAwareStorageInterface;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\StorageInterface;

/**
 * Emulates the consumed-state storage contract on top of an
 * ArrayStorage: consume() is a state transition (pending -> consumed)
 * rather than a delete, commitResult() records the derivation outcome,
 * and consumedState() is the read-only retained-state read the core and
 * the validator's ambiguous-consume normalization use. The identity-
 * aware consume records the logical-operation identity atomically with
 * the state flip, exactly like the Redis/array backends.
 * `throwOnConsume` simulates a lost consume response (the wire failure
 * that produces ConsumeIndeterminate). Every transition is counted
 * (`consumes`, `deletes`, `commits`) so tests can assert "no second
 * derive / no re-consume" via the storage counters.
 */
final class ConsumedStateStorage implements StorageInterface, ConsumedStateReadableInterface, OperationIdentityAwareStorageInterface
{
    public int $consumes = 0;
    public int $deletes = 0;
    public int $commits = 0;

    /** When true, consume() throws — simulating a lost response. */
    public bool $throwOnConsume = false;

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
        return $this->inner->consumedState($nonce);
    }

    public function consume(string $nonce): ?ConsumedRecord
    {
        if ($this->throwOnConsume) {
            throw new \RuntimeException('simulated lost consume response');
        }
        $this->consumes++;

        return $this->inner->consume($nonce);
    }

    public function consumeWithOperationIdentity(string $nonce, ?string $operationIdentity): ?ConsumedRecord
    {
        if ($this->throwOnConsume) {
            throw new \RuntimeException('simulated lost consume response');
        }
        $this->consumes++;

        return $this->inner->consumeWithOperationIdentity($nonce, $operationIdentity);
    }

    public function delete(string $nonce): void
    {
        $this->deletes++;
        $this->inner->delete($nonce);
    }

    public function commitResult(string $nonce, bool $valid, ?string $binding): bool
    {
        $this->commits++;

        return $this->inner->commitResult($nonce, $valid, $binding);
    }

    /** @internal test hook: transition a record to consumed without a result. */
    public function transitionConsumed(string $nonce): void
    {
        $this->inner->consume($nonce);
    }
}
