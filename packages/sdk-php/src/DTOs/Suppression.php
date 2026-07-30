<?php

declare(strict_types=1);

namespace ApexMail\DTOs;

/**
 * A suppressed email address entry.
 *
 * @immutable
 *
 * @property-read string      $id
 * @property-read string      $email
 * @property-read string      $reason   bounce | complaint | unsubscribe | manual
 * @property-read string|null $created_at
 */
class Suppression extends DTO
{
    public function getId(): string
    {
        return $this->data['id'] ?? '';
    }

    public function getEmail(): string
    {
        return $this->data['email'] ?? '';
    }

    public function getReason(): string
    {
        return $this->string('reason') ?? 'manual';
    }

    public function getCreatedAt(): ?string
    {
        return $this->string('created_at') ?? $this->string('createdAt');
    }
}
