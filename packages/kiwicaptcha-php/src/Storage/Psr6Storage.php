<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\StorageInterface;
use Psr\Cache\CacheItemPoolInterface;

/**
 * PSR-6 backed storage (Symfony Cache, etc.).
 *
 * IMPORTANT LIMITATION: PSR-6 cannot express an atomic get-and-delete, so
 * `consume()` is NOT atomic under concurrency — two racing requests can both
 * read the same record before either deletes it, and both verifications may
 * pass. The pool's delete is atomic, but the read cannot be fused with it.
 * This is best-effort single-use; implementers of
 * {@see \KiwiCaptcha\AtomicStorageInterface} (e.g. {@see RedisStorage}, Redis
 * GETDEL) guarantee that two concurrent consumers can never both win.
 */
final class Psr6Storage implements StorageInterface
{
    /**
     * PSR-6 reserves the characters `{}()/\@:` in cache keys, so the prefix
     * deliberately avoids the colon used by the Redis backend (Symfony Cache
     * rejects keys such as "kiwicaptcha:nonce").
     */
    private const PREFIX = 'kiwicaptcha_';

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
        // Read first, delete second. PSR-6 offers no atomic get-and-delete, so
        // this is read-then-delete: the record is returned exactly once per
        // stored item, but under concurrency two readers may both observe it
        // (see the class docblock — RedisStorage is the atomic backend).
        $item = $this->pool->getItem(self::PREFIX.$nonce);
        if (!$item->isHit()) {
            return null;
        }
        $data = $item->get();

        // Delete unconditionally: if the item was a hit the delete must
        // succeed (PSR-6 pools must not fail deletes for existing items), so
        // there is no need to branch on its result.
        $this->pool->deleteItem(self::PREFIX.$nonce);

        return \is_array($data) ? ChallengeRecord::fromArray($data) : null;
    }

    public function delete(string $nonce): void
    {
        $this->pool->deleteItem(self::PREFIX.$nonce);
    }
}
