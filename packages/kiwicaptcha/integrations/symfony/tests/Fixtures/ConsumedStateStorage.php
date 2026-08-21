<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\StorageInterface;

/**
 * Emulates the consumed-state storage contract on top of an
 * ArrayStorage: consume() is a state transition (pending -> consumed)
 * rather than a delete, commitResult() records the derivation outcome,
 * and find() attaches the consumed state when the core's
 * ChallengeRecord supports it. `throwOnConsume` simulates a lost consume
 * response (the wire failure that produces ConsumeIndeterminate). Every
 * transition is counted (`consumes`, `deletes`, `commits`) so tests can
 * assert "no second derive / no re-consume" via the storage counters.
 */
final class ConsumedStateStorage implements StorageInterface
{
    public int $consumes = 0;
    public int $deletes = 0;
    public int $commits = 0;

    /** When true, consume() throws — simulating a lost response. */
    public bool $throwOnConsume = false;

    /** @var array<string, true> nonces in the consumed state */
    public array $consumed = [];

    /** @var array<string, array{0: bool, 1: ?string}> nonce => [valid, binding] */
    public array $committed = [];

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

                public function consumedState(string $nonce): ?\KiwiCaptcha\ConsumedRecord
            {
                return null;
            }

public function consume(string $nonce): ?\KiwiCaptcha\ConsumedRecord
    {
        if ($this->throwOnConsume) {
            throw new \RuntimeException('simulated lost consume response');
        }
        $this->consumes++;
        $record = $this->inner->find($nonce);
        if ($record === null) {
            return null;
        }
        // The consumed-state transition: the record persists, the state flips.
        $this->consumed[$nonce] = true;

        return new \KiwiCaptcha\ConsumedRecord($record, true, false, null);
    }

    public function delete(string $nonce): void
    {
        $this->deletes++;
        $this->inner->delete($nonce);
    }

    /** @internal test hook: commit the outcome of a derivation (new-core API). */
    public function commitResult(string $nonce, bool $valid, ?string $binding): bool
    {
        $this->commits++;
        $this->committed[$nonce] = [$valid, $binding];

        return true;
    }

    /** @internal test hook: transition a record to consumed without a result. */
    public function transitionConsumed(string $nonce): void
    {
        $this->consumed[$nonce] = true;
    }

    /**
     * Attach the consumed-state fields to the record when the core's
     * ChallengeRecord supports them (the current wire_keys); on cores that
     * predate the transition the plain record is returned (consumed records
     * were deleted there anyway).
     */
    private function withConsumedState(ChallengeRecord $record): ChallengeRecord
    {
        try {
            $data = $record->toArray();
            $data['consumed'] = isset($this->consumed[$record->nonce]);
            $data['consumed_result'] = $this->committed[$record->nonce][0] ?? null;
            $data['consumed_binding'] = $this->committed[$record->nonce][1] ?? null;

            return ChallengeRecord::fromArray($data);
        } catch (\Throwable) {
            return $record;
        }
    }
}
