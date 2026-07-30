<?php

declare(strict_types=1);

namespace ApexMail\DTOs;

/**
 * An email address with optional display name.
 *
 * @immutable
 *
 * @property-read string      $email
 * @property-read string|null $name
 */
class Address extends DTO
{
    public function getEmail(): string
    {
        return $this->data['email'] ?? '';
    }

    public function getName(): ?string
    {
        return $this->string('name');
    }

    /** Build an Address from a raw API value (string or array). */
    public static function from(mixed $value): self
    {
        if ($value instanceof self) {
            return $value;
        }
        if (is_string($value)) {
            return new self(['email' => $value]);
        }
        if (is_array($value)) {
            return new self($value);
        }
        return new self(['email' => '']);
    }
}
