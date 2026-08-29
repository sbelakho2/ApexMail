<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Fixtures;

use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;

/**
 * PSR-6 pool stand-in whose save() reports failure, exercising
 * Psr6Storage's fail-closed contract. PSR-6 permits save() === false
 * without raising, and the storage must treat that as a failed write
 * ({@see \KiwiCaptcha\Storage\StorageWriteException}) instead of
 * proceeding as if the write had landed.
 *
 * A minimal local re-creation of the Symfony bundle's
 * FailingSaveCachePool fixture (this package's test suite deliberately
 * has zero Symfony dependencies); everything delegates to the in-memory
 * {@see ArrayPool} so reads and successful saves behave exactly like
 * the other core tests.
 */
final class FailingSavePool implements CacheItemPoolInterface
{
    /** Number of save() calls since construction. */
    public int $saveCalls = 0;

    private readonly ArrayPool $inner;

    /**
     * @param int|null $failFromAttempt the 1-based save() call number
     *                                  from which on saves may report
     *                                  failure. Null, the default, fails
     *                                  every save
     * @param int|null $failUntilAttempt when set together with
     *                                  $failFromAttempt, the inclusive
     *                                  last failing attempt (a bounded
     *                                  outage window that recovers);
     *                                  null (the default) never recovers
     */
    public function __construct(
        private readonly ?int $failFromAttempt = null,
        private readonly ?int $failUntilAttempt = null,
    ) {
        $this->inner = new ArrayPool();
    }

    public function getItem(string $key): CacheItemInterface
    {
        return $this->inner->getItem($key);
    }

    public function getItems(array $keys = []): iterable
    {
        return $this->inner->getItems($keys);
    }

    public function hasItem(string $key): bool
    {
        return $this->inner->hasItem($key);
    }

    public function clear(): bool
    {
        return $this->inner->clear();
    }

    public function deleteItem(string $key): bool
    {
        return $this->inner->deleteItem($key);
    }

    public function deleteItems(array $keys): bool
    {
        return $this->inner->deleteItems($keys);
    }

    public function save(CacheItemInterface $item): bool
    {
        $this->saveCalls++;
        if ($this->failsNow()) {
            return false;
        }

        return $this->inner->save($item);
    }

    private function failsNow(): bool
    {
        if ($this->failFromAttempt === null) {
            return true; // fail every save
        }
        if ($this->saveCalls < $this->failFromAttempt) {
            return false;
        }

        return $this->failUntilAttempt === null || $this->saveCalls <= $this->failUntilAttempt;
    }

    public function saveDeferred(CacheItemInterface $item): bool
    {
        return $this->save($item);
    }

    public function commit(): bool
    {
        return true;
    }
}
