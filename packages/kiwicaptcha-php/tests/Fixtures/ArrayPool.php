<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Fixtures;

use DateInterval;
use DateTimeImmutable;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;

/**
 * Minimal in-memory PSR-6 pool used by the core tests so the library's own
 * test-suite has zero Symfony dependencies (the library is framework-neutral).
 *
 * Implements only the semantics Psr6Storage relies on: getItem, save,
 * deleteItem, and expiry via expiresAfter().
 */
final class ArrayPool implements CacheItemPoolInterface
{
    /** @var array<string, array{value: mixed, expiresAt: float|null}> */
    private array $items = [];

    public function getItem(string $key): CacheItemInterface
    {
        $item = new ArrayPoolItem($key);
        $entry = $this->items[$key] ?? null;
        if ($entry === null) {
            return $item;
        }
        if ($entry['expiresAt'] !== null && microtime(true) >= $entry['expiresAt']) {
            unset($this->items[$key]);

            return $item;
        }
        $item->hit = true;
        $item->value = $entry['value'];

        return $item;
    }

    public function getItems(array $keys = []): iterable
    {
        foreach ($keys as $key) {
            yield $key => $this->getItem($key);
        }
    }

    public function hasItem(string $key): bool
    {
        return $this->getItem($key)->isHit();
    }

    public function clear(): bool
    {
        $this->items = [];

        return true;
    }

    public function deleteItem(string $key): bool
    {
        unset($this->items[$key]);

        return true;
    }

    public function deleteItems(array $keys): bool
    {
        foreach ($keys as $key) {
            $this->deleteItem($key);
        }

        return true;
    }

    public function save(CacheItemInterface $item): bool
    {
        \assert($item instanceof ArrayPoolItem);
        $this->items[$item->getKey()] = [
            'value' => $item->value,
            'expiresAt' => $item->getExpiry(),
        ];

        return true;
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

/**
 * @internal
 */
final class ArrayPoolItem implements CacheItemInterface
{
    public bool $hit = false;

    public mixed $value = null;

    /** @var float|null absolute epoch-seconds expiry (microtime domain) */
    private ?float $expiry = null;

    private ?\DateTimeInterface $expiration = null;

    public function __construct(private readonly string $key)
    {
    }

    public function getKey(): string
    {
        return $this->key;
    }

    public function get(): mixed
    {
        return $this->hit ? $this->value : null;
    }

    public function isHit(): bool
    {
        return $this->hit;
    }

    public function set(mixed $value): static
    {
        $this->value = $value;

        return $this;
    }

    public function expiresAt(?\DateTimeInterface $expiration): static
    {
        $this->expiration = $expiration;
        $this->expiry = $expiration !== null ? (float) $expiration->format('U.u') : null;

        return $this;
    }

    public function expiresAfter(int|DateInterval|null $time): static
    {
        if ($time === null) {
            return $this->expiresAt(null);
        }
        $interval = $time instanceof DateInterval ? $time : new DateInterval(sprintf('PT%dS', $time));

        return $this->expiresAt((new DateTimeImmutable())->add($interval));
    }

    public function getExpiry(): ?float
    {
        return $this->expiry;
    }
}
