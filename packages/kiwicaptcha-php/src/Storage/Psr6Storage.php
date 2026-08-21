<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\ConsumedRecord;
use KiwiCaptcha\ConsumedResult;
use KiwiCaptcha\NonAtomicStorageInterface;
use KiwiCaptcha\OperationIdentity;
use KiwiCaptcha\OperationIdentityAwareStorageInterface;
use KiwiCaptcha\StorageInterface;
use Psr\Cache\CacheItemPoolInterface;

/**
 * PSR-6 backed storage (Symfony Cache, etc.).
 *
 * consume() is the one-shot transition: the record is marked consumed
 * and kept until its own expiration; replay protection is the consumed
 * marker, not absence. The runtime envelope carries the
 * `operation_identity` marker (null | a bounded <= 128-byte
 * logical-operation identity) exactly like the Redis backend; the
 * identity-aware consume writes the identity in the same array write as
 * the state flip. consumedState() is the read-only retained-state read:
 * it decodes the stored envelope (the same array consume() wrote) and
 * reports the consumed record, its committed result and its recorded
 * operation identity without any transition.
 *
 * Important limitation: PSR-6 cannot express an atomic get-and-transition,
 * so `consume()` is not atomic under concurrency. Two racing requests can
 * both observe the pending state before either marks it consumed, and
 * both may win `consumedNow`. This is best-effort single-use; the class
 * therefore carries the {@see NonAtomicStorageInterface} capability
 * marker (implementers of {@see \KiwiCaptcha\AtomicStorageInterface},
 * e.g. {@see RedisStorage} with its fused Lua transition, guarantee that
 * exactly one concurrent consumer wins). The Verifier emits a one-time
 * deprecation warning when constructed with a non-atomic backend;
 * consumers that need strict single-use must refuse it outright.
 */
final class Psr6Storage implements StorageInterface, OperationIdentityAwareStorageInterface, NonAtomicStorageInterface
{
    /**
     * PSR-6 reserves the characters `{}()/\@:` in cache keys, so the
     * prefix deliberately avoids the colon used by the Redis backend
     * (Symfony Cache rejects keys such as "kiwicaptcha:nonce").
     */
    private const PREFIX = 'kc_';

    /**
     * PSR-6 cache key for a challenge nonce.
     *
     * The wire nonce is standard base64 and may legitimately contain the
     * reserved PSR-6 characters `/` and `+` (it is 44 chars). Conforming
     * pools are allowed to reject such keys, so the nonce is never used
     * directly as a cache key; it is hashed to a PSR-6-safe hex digest.
     *
     * Key length: 3 (prefix) + 60 (hex digest) = 63 characters, within
     * the 64-character maximum that PSR-6 requires implementations to
     * support, so every conforming pool accepts it.
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
        $item->set($record->toArray() + ['state' => 'pending', 'consumed_result' => null, 'operation_identity' => null]);
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
            return ChallengeRecord::fromArray(self::stripRuntimeFields($data));
        } catch (\Throwable) {
            // Corrupt/foreign stored data (e.g. an unknown algorithm
            // value) must not surface as an exception; treat it as
            // absent and clean up the poisoned key.
            $this->pool->deleteItem(self::key($nonce));

            return null;
        }
    }

    public function consumedState(string $nonce): ?ConsumedRecord
    {
        // Read-only inspection of the stored envelope (the same array
        // consume()/commitResult() write): no transition, no save. A
        // pool item that is absent, unhit, non-array, still pending or
        // undecodable reports null — nothing retained to read.
        $item = $this->pool->getItem(self::key($nonce));
        if (!$item->isHit()) {
            return null;
        }
        $data = $item->get();
        if (!\is_array($data) || ($data['state'] ?? 'pending') !== 'consumed') {
            return null;
        }
        try {
            $record = ChallengeRecord::fromArray(self::stripRuntimeFields($data));
        } catch (\Throwable) {
            return null;
        }

        return new ConsumedRecord(
            $record,
            false,
            true,
            self::parseResult($data['consumed_result'] ?? null),
            self::parseIdentity($data['operation_identity'] ?? null),
        );
    }

    public function consume(string $nonce): ?ConsumedRecord
    {
        // Read first, transition second. PSR-6 offers no atomic
        // get-and-set, so this is best-effort single-use: under
        // concurrency two readers may both observe the pending state
        // (see the class docblock; the Redis backend is the atomic one).
        $item = $this->pool->getItem(self::key($nonce));
        if (!$item->isHit()) {
            return null;
        }
        $data = $item->get();
        if (!\is_array($data)) {
            // Corrupt data: already-read above; delete and never propagate.
            $this->pool->deleteItem(self::key($nonce));

            return null;
        }

        $consumed = ($data['state'] ?? 'pending') === 'consumed';
        if (!$consumed) {
            $data['state'] = 'consumed';
            $item->set($data);
            $this->pool->save($item);
        }
        $result = self::parseResult($data['consumed_result'] ?? null);

        try {
            $record = ChallengeRecord::fromArray(self::stripRuntimeFields($data));
        } catch (\Throwable) {
            // Corrupt data: delete and never propagate.
            $this->pool->deleteItem(self::key($nonce));

            return null;
        }

        return new ConsumedRecord($record, !$consumed, $consumed, $result, self::parseIdentity($data['operation_identity'] ?? null));
    }

    public function consumeWithOperationIdentity(string $nonce, ?string $operationIdentity): ?ConsumedRecord
    {
        // Same read-then-transition as consume(); the identity, validated
        // against the narrow shared alphabet via {@see
        // OperationIdentity::validate()} (1..128 bytes of
        // [A-Za-z0-9_-]), lands in the same array write as the state
        // flip. A malformed identity is rejected with
        // InvalidArgumentException, never silently dropped.
        $validated = OperationIdentity::validate($operationIdentity);
        $item = $this->pool->getItem(self::key($nonce));
        if (!$item->isHit()) {
            return null;
        }
        $data = $item->get();
        if (!\is_array($data)) {
            $this->pool->deleteItem(self::key($nonce));

            return null;
        }

        $consumed = ($data['state'] ?? 'pending') === 'consumed';
        if (!$consumed) {
            $data['state'] = 'consumed';
            if ($validated !== null) {
                $data['operation_identity'] = $validated;
            }
            $item->set($data);
            $this->pool->save($item);
        }
        $result = self::parseResult($data['consumed_result'] ?? null);

        try {
            $record = ChallengeRecord::fromArray(self::stripRuntimeFields($data));
        } catch (\Throwable) {
            $this->pool->deleteItem(self::key($nonce));

            return null;
        }

        return new ConsumedRecord($record, !$consumed, $consumed, $result, self::parseIdentity($data['operation_identity'] ?? null));
    }

    public function commitResult(string $nonce, bool $valid, ?string $binding): bool
    {
        $item = $this->pool->getItem(self::key($nonce));
        if (!$item->isHit()) {
            return false;
        }
        $data = $item->get();
        if (!\is_array($data)) {
            return false;
        }
        if (($data['state'] ?? 'pending') !== 'consumed') {
            return false;
        }
        if (isset($data['consumed_result']) && $data['consumed_result'] !== null) {
            return false;
        }
        $data['consumed_result'] = ['valid' => $valid, 'binding' => $binding];
        $item->set($data);

        return $this->pool->save($item);
    }

    public function delete(string $nonce): void
    {
        $this->pool->deleteItem(self::key($nonce));
    }

    /**
     * @param array<string, mixed> $data
     *
     * @return array<string, mixed>
     */
    private static function stripRuntimeFields(array $data): array
    {
        unset($data['state'], $data['consumed_result'], $data['operation_identity']);

        return $data;
    }

    /** @param mixed $raw */
    private static function parseIdentity(mixed $raw): ?string
    {
        return \is_string($raw) ? $raw : null;
    }

    /** @param mixed $raw */
    private static function parseResult(mixed $raw): ?ConsumedResult
    {
        if (!\is_array($raw)) {
            return null;
        }

        try {
            return ConsumedResult::fromArray($raw);
        } catch (\Throwable) {
            return null;
        }
    }
}
