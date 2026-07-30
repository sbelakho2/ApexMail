<?php

declare(strict_types=1);

namespace ApexMail\DTOs;

/**
 * Aggregate analytics data.
 *
 * @immutable
 *
 * @property-read int         $sent
 * @property-read int         $delivered
 * @property-read int         $opened
 * @property-read int         $clicked
 * @property-read int         $bounced
 * @property-read int         $complained
 * @property-read int         $unsubscribed
 * @property-read float|null  $open_rate
 * @property-read float|null  $click_rate
 * @property-read float|null  $bounce_rate
 * @property-read string|null $from
 * @property-read string|null $to
 * @property-read string|null $group_by
 */
class Analytics extends DTO
{
    public function getSent(): int
    {
        return $this->int('sent') ?? 0;
    }

    public function getDelivered(): int
    {
        return $this->int('delivered') ?? 0;
    }

    public function getOpened(): int
    {
        return $this->int('opened') ?? 0;
    }

    public function getClicked(): int
    {
        return $this->int('clicked') ?? 0;
    }

    public function getBounced(): int
    {
        return $this->int('bounced') ?? 0;
    }

    public function getComplained(): int
    {
        return $this->int('complained') ?? 0;
    }

    public function getUnsubscribed(): int
    {
        return $this->int('unsubscribed') ?? 0;
    }

    public function getOpenRate(): ?float
    {
        return $this->float('open_rate') ?? $this->float('openRate');
    }

    public function getClickRate(): ?float
    {
        return $this->float('click_rate') ?? $this->float('clickRate');
    }

    public function getBounceRate(): ?float
    {
        return $this->float('bounce_rate') ?? $this->float('bounceRate');
    }

    public function getFrom(): ?string
    {
        return $this->string('from');
    }

    public function getTo(): ?string
    {
        return $this->string('to');
    }

    public function getGroupBy(): ?string
    {
        return $this->string('group_by') ?? $this->string('groupBy');
    }
}
