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

    /**
     * PSR-6 cache key for a challenge nonce.
     *
     * The wire nonce is standard Base64 and may legitimately contain the
     * reserved PSR-6 characters `/` and `+` (and is 44 chars). Conforming
     * pools are allowed to reject such keys, so the nonce is never used
     * directly as a cache key — it is hashed to a PSR-6-safe hex digest
     * (3 + 60 = 63 chars).
     */
    private static function key(string $nonce): string
    {
        return self::PREFIX.substr(hash('sha256', $nonce), 0, 60);
    }

    public function __construct(private readonly CacheItemPoolInterface $pool)
    {
    }

    public function store(ChallengeRecord $record): void
    {
        $item = $this->pool->getItem(self::key($record->nonce));
        $item->set($record->toArray());
        $item->expiresAfter(max(1, $record->expiresAt - time()));
        $this->pool->save($item);
    }

    public function find(string $nonce): ?ChallengeRecord
    {
        $item = $this->pool->getItem(self::key($nonce));
        if (!$item->isHit()) {
            return null;
        }
        $data = $item->get();
        if (!\is_array($data)) {
            return null;
        }

        try {
            return ChallengeRecord::fromArray($data);
        } catch (\Throwable) {
            // Corrupt/foreign stored data (e.g. an unknown algorithm value)
            // must never surface as an exception — treat it as absent and
            // clean up the poisoned key.
            $this->pool->deleteItem(self::key($nonce));

            return null;
        }
    }

    public function consume(string $nonce): ?ChallengeRecord
    {
        // Read first, delete second. PSR-6 offers no atomic get-and-delete, so
        // this is read-then-delete: the record is returned exactly once per
        // stored item, but under concurrency two readers may both observe it
        // (see the class docblock — RedisStorage is the atomic backend).
        $item = $this->pool->getItem(self::key($nonce));
        if (!$item->isHit()) {
            return null;
        }
        $data = $item->get();

        // Delete unconditionally: if the item was a hit the delete must
        // succeed (PSR-6 pools must not fail deletes for existing items), so
        // there is no need to branch on its result.
        $this->pool->deleteItem(self::key($nonce));

        if (!\is_array($data)) {
            return null;
        }

        try {
            return ChallengeRecord::fromArray($data);
        } catch (\Throwable) {
            // Corrupt data: already deleted above; never propagate.
            return null;
        }
    }

    public function delete(string $nonce): void
    {
        $this->pool->deleteItem(self::key($nonce));
    }
}
