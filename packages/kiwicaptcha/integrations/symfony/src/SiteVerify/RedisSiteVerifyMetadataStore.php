<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

use KiwiCaptcha\Storage\StorageInterface;
use BelConsulting\KiwiCaptchaBundle\RedisNamespace;

/**
 * Redis-backed metadata sidecar. Namespace:
 * `{kiwi:<namespace>}:siteverify-meta:<nonce>` — the nonce is random and
 * bounded, so the key space is safe. TTL equals the challenge lifetime
 * plus a small replay/response margin (the caller passes it).
 */
final class RedisSiteVerifyMetadataStore implements SiteVerifyMetadataStore
{
    private const PREFIX = 'siteverify-meta:';

    /**
     * The encoded deployment namespace inside the `{kiwi:<ns>}` hash
     * tag, derived from the raw configured discriminator.
     */
    private readonly string $namespace;

    public function __construct(
        private readonly \Predis\Client|\Redis $redis,
        string $namespace = 'kiwicaptcha',
        private readonly int $waitReplicas = 0,
        private readonly int $waitTimeoutMs = 100,
        int $namespaceKeyVersion = RedisNamespace::VERSION_LEGACY,
    ) {
        // The RAW discriminator is derived here, so the metadata lives
        // under the deployment namespace exactly like the idempotency
        // entries.
        $this->namespace = RedisNamespace::deriveOr($namespace, 'kiwicaptcha', $namespaceKeyVersion);
        $this->refuseVerifiedWaitOnUnsupportedPredisClients();
    }

    public function store(string $nonce, SiteVerifyMetadata $metadata, int $ttlSeconds): void
    {
        $this->redis->setex(
            $this->key($nonce),
            max(1, $ttlSeconds),
            (string) json_encode($metadata->toArray(), JSON_THROW_ON_ERROR),
        );
        // The metadata write is part of the pre-handoff contract (action /
        // cData / chain identity): the verified-WAIT barrier makes it
        // survive a promotion like the challenge state it accompanies.
        if ($this->waitReplicas > 0) {
            $this->waitAndVerify('the siteverify metadata store');
        }
    }

    public function find(string $nonce): ?SiteVerifyMetadata
    {
        $raw = $this->redis->get($this->key($nonce));
        if (!\is_string($raw) || $raw === '') {
            return null;
        }
        // The strict persisted-JSON authority: a malformed, oversized or
        // semantically duplicated document is corrupt security metadata,
        // never "missing" — the typed fail-closed exception (the
        // controller answers the 503).
        $data = \KiwiCaptcha\Storage\StrictJson::decodeObject($raw, 8192);
        if ($data === null) {
            throw new SiteVerifyMetadataCorruptException('the siteverify metadata record is not a clean JSON object (malformed, oversized or carrying a semantic duplicate key)');
        }
        if (!\is_array($data)) {
            throw new SiteVerifyMetadataCorruptException('the siteverify metadata record is not an object');
        }

        return SiteVerifyMetadata::fromArray($data);
    }

    private function key(string $nonce): string
    {
        return sprintf('{kiwi:%s}:%s%s', $this->namespace, self::PREFIX, $nonce);
    }

    private function waitAndVerify(string $what): void
    {
        if ($this->redis instanceof \Redis) {
            $acked = $this->redis->rawCommand('WAIT', $this->waitReplicas, $this->waitTimeoutMs);
        } else {
            $acked = $this->redis->executeRaw(['WAIT', $this->waitReplicas, $this->waitTimeoutMs]);
        }
        if ($acked === false || $acked === null || (int) $acked < $this->waitReplicas) {
            throw new \KiwiCaptcha\Storage\ReplicaWaitException(sprintf(
                'Redis WAIT acknowledged %s of %d requested replicas after %s',
                (string) $acked,
                $this->waitReplicas,
                $what,
            ));
        }
    }

    private function refuseVerifiedWaitOnUnsupportedPredisClients(): void
    {
        \KiwiCaptcha\VerifiedWaitGuard::refuseUnsupported($this->redis, $this->waitReplicas, 'RedisSiteVerifyMetadataStore');
    }

}
