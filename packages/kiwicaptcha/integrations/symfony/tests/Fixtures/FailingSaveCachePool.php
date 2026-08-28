<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * PSR-6 pool stand-in whose save() reports failure for chosen keys,
 * exercising the fail-closed contract. PSR-6 permits save() === false
 * without raising, and the rate limiter must treat that as a backend
 * failure (RateLimitStorageException) instead of returning allow with the
 * accounting silently missing.
 *
 * Delegates everything else to an in-memory ArrayAdapter so reads and
 * non-failing saves behave exactly like the existing limiter tests.
 */
final class FailingSaveCachePool implements CacheItemPoolInterface
{
    /** Number of save() calls since construction (or the last reset). */
    public int $saveCalls = 0;

    private readonly ArrayAdapter $inner;

    /** @var list<string> keys whose save() must report failure (empty = every save fails) */
    private readonly array $failKeys;

    /**
     * @param list<string> $failKeys cache keys whose save() returns false;
     *                               the empty list (the default) fails
     *                               every save
     */
    public function __construct(array $failKeys = [])
    {
        $this->inner = new ArrayAdapter();
        $this->failKeys = $failKeys;
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
        if ($this->failKeys === [] || \in_array($item->getKey(), $this->failKeys, true)) {
            return false;
        }

        return $this->inner->save($item);
    }

    public function saveDeferred(CacheItemInterface $item): bool
    {
        return $this->inner->saveDeferred($item);
    }

    public function commit(): bool
    {
        return $this->inner->commit();
    }
}
