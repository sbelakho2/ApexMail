<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

/**
 * Server-side storage for provider-compatible challenge metadata, keyed by
 * the challenge nonce. Implementations must be failure-visible: if metadata
 * was explicitly supplied at issuance and the store cannot persist it, the
 * challenge endpoint MUST fail closed (the 503 + discard behavior) rather
 * than silently issuing a token whose verification would return no
 * action/cData.
 */
interface SiteVerifyMetadataStore
{
    public function store(string $nonce, SiteVerifyMetadata $metadata, int $ttlSeconds): void;

    public function find(string $nonce): ?SiteVerifyMetadata;
}
