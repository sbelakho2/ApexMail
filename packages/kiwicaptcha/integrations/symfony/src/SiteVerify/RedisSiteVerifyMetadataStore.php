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
    ) {
    }

    public function store(string $nonce, SiteVerifyMetadata $metadata, int $ttlSeconds): void
    {
        $this->redis->setex(
            $this->key($nonce),
            max(1, $ttlSeconds),
            (string) json_encode($metadata->toArray(), JSON_THROW_ON_ERROR),
        );
    }

    public function find(string $nonce): ?SiteVerifyMetadata
    {
        $raw = $this->redis->get($this->key($nonce));
        if (!\is_string($raw) || $raw === '') {
            return null;
        }
        try {
            $data = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }

        return \is_array($data) ? SiteVerifyMetadata::fromArray($data) : null;
    }

    private function key(string $nonce): string
    {
        return sprintf('{%s}:%s%s', $this->namespace, self::PREFIX, $nonce);
    }
}
