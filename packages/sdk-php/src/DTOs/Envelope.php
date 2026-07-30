<?php

declare(strict_types=1);

namespace ApexMail\DTOs;

/**
 * Authentication and routing info attached to delivery events.
 *
 * @immutable
 *
 * @property-read string|null   $from
 * @property-read string[]|null $to
 * @property-read string|null   $dkim
 * @property-read string|null   $spf
 * @property-read string|null   $dmarc
 * @property-read string|null   $timestamp
 */
class Envelope extends DTO
{
    public function getFrom(): ?string
    {
        return $this->string('from');
    }

    /** @return string[]|null */
    public function getTo(): ?array
    {
        return $this->list('to');
    }

    public function getDkim(): ?string
    {
        return $this->string('dkim');
    }

    public function getSpf(): ?string
    {
        return $this->string('spf');
    }

    public function getDmarc(): ?string
    {
        return $this->string('dmarc');
    }

    public function getTimestamp(): ?string
    {
        return $this->string('timestamp');
    }
}
