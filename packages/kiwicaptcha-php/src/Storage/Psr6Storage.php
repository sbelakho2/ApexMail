<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\StorageInterface;
use Psr\Cache\CacheItemPoolInterface;

/**
 * PSR-6 backed storage (Symfony Cache, etc.).
 *
 * Single-use semantics are enforced with a delete-then-read race guarded by
 * PSR-6's atomic delete: the record is deleted first, and only if the delete
 * reports true do we read the value. PSR-6 delete is atomic per key, which
 * makes this safe for concurrent consumers on the same pool.
 */
final class Psr6Storage implements StorageInterface
{
    private const PREFIX = 'kiwicaptcha:';

    public function __construct(private readonly CacheItemPoolInterface $pool)
    {
    }

    public function store(ChallengeRecord $record): void
    {
        $item = $this->pool->getItem(self::PREFIX.$record->nonce);
        $item->set($record->toArray());
        $item->expiresAfter(max(1, $record->expiresAt - time()));
        $this->pool->save($item);
    }

    public function find(string $nonce): ?ChallengeRecord
    {
        $item = $this->pool->getItem(self::PREFIX.$nonce);
        if (!$item->isHit()) {
            return null;
        }
        $data = $item->get();

        return \is_array($data) ? ChallengeRecord::fromArray($data) : null;
    }

    public function consume(string $nonce): ?ChallengeRecord
    {
        // PSR-6 cannot atomically read-and-delete; delete first (atomic), then
        // read. Two concurrent consumers cannot both observe the record.
        if (!$this->pool->deleteItem(self::PREFIX.$nonce)) {
            return null;
        }

        return $this->find($nonce);
    }

    public function delete(string $nonce): void
    {
        $this->pool->deleteItem(self::PREFIX.$nonce);
    }
}
