<?php

declare(strict_types=1);

namespace ApexMail\DTOs;

/**
 * Rate-limit state returned in API response headers.
 *
 * @immutable
 *
 * @property-read int|null    $limit
 * @property-read int|null    $remaining
 * @property-read int|null    $reset      Unix timestamp
 * @property-read string|null $retry_after
 */
class RateLimit extends DTO
{
    public function getLimit(): ?int
    {
        return $this->int('limit');
    }

    public function getRemaining(): ?int
    {
        return $this->int('remaining');
    }

    public function getReset(): ?int
    {
        return $this->int('reset');
    }

    public function getRetryAfter(): ?string
    {
        return $this->string('retry_after') ?? $this->string('retryAfter');
    }
}
