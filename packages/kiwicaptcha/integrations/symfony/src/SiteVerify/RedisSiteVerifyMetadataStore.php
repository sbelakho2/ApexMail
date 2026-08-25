<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

use KiwiCaptcha\Storage\StorageInterface;

/**
 * Redis-backed metadata sidecar. Namespace:
 * `{kiwi:<namespace>}:siteverify-meta:<nonce>` — the nonce is random and
 * bounded, so the key space is safe. TTL equals the challenge lifetime
 * plus a small replay/response margin (the caller passes it).
 */
final class RedisSiteVerifyMetadataStore implements SiteVerifyMetadataStore
{
    private const PREFIX = 'siteverify-meta:';

    public function __construct(
        private readonly \Predis\Client|\Redis $redis,
        private readonly string $namespace = 'kiwicaptcha',
        private readonly int $waitReplicas = 0,
        private readonly int $waitTimeoutMs = 100,
    ) {
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
        try {
            $data = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            // Corrupt security metadata is never "missing": the typed
            // fail-closed exception (the controller answers the 503).
            throw new SiteVerifyMetadataCorruptException('the siteverify metadata record is malformed', 0, $e);
        }
        if (!\is_array($data)) {
            throw new SiteVerifyMetadataCorruptException('the siteverify metadata record is not an object');
        }

        return SiteVerifyMetadata::fromArray($data);
    }

    private function key(string $nonce): string
    {
        return sprintf('{%s}:%s%s', $this->namespace, self::PREFIX, $nonce);
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
        if ($this->waitReplicas <= 0 || !($this->redis instanceof \Predis\Client)) {
            return;
        }
        $connection = $this->redis->getConnection();
        if ($connection instanceof \Predis\Connection\Replication\ReplicationInterface
            || $connection instanceof \Predis\Connection\Cluster\ClusterInterface
        ) {
            throw new \InvalidArgumentException(
                'RedisSiteVerifyMetadataStore: verified-WAIT durability (waitReplicas > 0) is not supported on a Predis replication aggregate or cluster client — the verified barrier supports standalone Redis connections only; use a standalone connection with waitReplicas > 0, or keep waitReplicas = 0.'
            );
        }
        if ($connection === null || $connection instanceof \Predis\Connection\RelayConnection) {
            return;
        }
        if (!$connection->getParameters()->isDisabledRetry()) {
            throw new \InvalidArgumentException(
                'RedisSiteVerifyMetadataStore: verified-WAIT durability (waitReplicas > 0) is not supported on a retry-enabled standalone Predis client — retries must be disabled on the connection, or keep waitReplicas = 0.'
            );
        }
    }
}
