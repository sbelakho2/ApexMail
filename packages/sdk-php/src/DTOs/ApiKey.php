<?php

declare(strict_types=1);

namespace ApexMail\DTOs;

/**
 * An API key for the authenticated account.
 *
 * @immutable
 *
 * @property-read string      $id
 * @property-read string      $name
 * @property-read string|null $key          The actual key (only in create response)
 * @property-read string|null $expires_at
 * @property-read string|null $created_at
 */
class ApiKey extends DTO
{
    public function getId(): string
    {
        return $this->data['id'] ?? '';
    }

    public function getName(): string
    {
        return $this->data['name'] ?? '';
    }

    /** The actual key value — only present in the create response. */
    public function getKey(): ?string
    {
        return $this->string('key');
    }

    public function getExpiresAt(): ?string
    {
        return $this->string('expires_at') ?? $this->string('expiresAt');
    }

    public function getCreatedAt(): ?string
    {
        return $this->string('created_at') ?? $this->string('createdAt');
    }
}
