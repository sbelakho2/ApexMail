<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

/**
 * In-memory metadata sidecar for tests/dev (single-process semantics, like
 * ArrayStorage). NOT for production: metadata must survive across requests.
 */
final class ArraySiteVerifyMetadataStore implements SiteVerifyMetadataStore
{
    /** @var array<string, array{0: SiteVerifyMetadata, 1: float}> nonce => [metadata, expiresAt] */
    private array $records = [];

    public function store(string $nonce, SiteVerifyMetadata $metadata, int $ttlSeconds): void
    {
        $this->records[$nonce] = [$metadata, microtime(true) + max(1, $ttlSeconds)];
    }

    public function find(string $nonce): ?SiteVerifyMetadata
    {
        $entry = $this->records[$nonce] ?? null;
        if ($entry === null) {
            return null;
        }
        if ($entry[1] < microtime(true)) {
            unset($this->records[$nonce]);

            return null;
        }

        return $entry[0];
    }
}
