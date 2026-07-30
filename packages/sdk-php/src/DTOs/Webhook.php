<?php

declare(strict_types=1);

namespace ApexMail\DTOs;

/**
 * A registered webhook endpoint.
 *
 * @immutable
 *
 * @property-read string      $id
 * @property-read string      $url
 * @property-read string[]    $events
 * @property-read bool        $active
 * @property-read string|null $secret
 * @property-read string|null $created_at
 * @property-read string|null $updated_at
 */
class Webhook extends DTO
{
    public function getId(): string
    {
        return $this->data['id'] ?? '';
    }

    public function getUrl(): string
    {
        return $this->data['url'] ?? '';
    }

    /** @return string[] */
    public function getEvents(): array
    {
        $events = $this->data['events'] ?? [];
        return is_array($events) ? $events : [];
    }

    public function isActive(): bool
    {
        return $this->bool('active') ?? true;
    }

    public function getSecret(): ?string
    {
        return $this->string('secret');
    }

    public function getCreatedAt(): ?string
    {
        return $this->string('created_at') ?? $this->string('createdAt');
    }

    public function getUpdatedAt(): ?string
    {
        return $this->string('updated_at') ?? $this->string('updatedAt');
    }
}
