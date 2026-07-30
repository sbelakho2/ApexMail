<?php

declare(strict_types=1);

namespace ApexMail\DTOs;

/**
 * A sending domain with DNS verification status.
 *
 * @immutable
 *
 * @property-read string      $id
 * @property-read string      $domain
 * @property-read string      $status          verified | pending | failed
 * @property-read array[]|null $dns_records    SPF / DKIM / DMARC records
 * @property-read string|null $region
 * @property-read bool|null   $click_tracking
 * @property-read bool|null   $open_tracking
 * @property-read string|null $created_at
 * @property-read string|null $updated_at
 */
class Domain extends DTO
{
    use DTOFactory;

    public function getId(): string
    {
        return $this->data['id'] ?? '';
    }

    public function getDomain(): string
    {
        return $this->data['domain'] ?? '';
    }

    public function getStatus(): string
    {
        return $this->string('status') ?? 'pending';
    }

    /** @return array[]|null */
    public function getDnsRecords(): ?array
    {
        $records = $this->data['dns_records'] ?? $this->data['dnsRecords'] ?? null;
        return is_array($records) ? $records : null;
    }

    public function getRegion(): ?string
    {
        return $this->string('region');
    }

    public function getClickTracking(): ?bool
    {
        return $this->bool('click_tracking') ?? $this->bool('clickTracking');
    }

    public function getOpenTracking(): ?bool
    {
        return $this->bool('open_tracking') ?? $this->bool('openTracking');
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
