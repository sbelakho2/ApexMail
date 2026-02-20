<?php

declare(strict_types=1);

namespace ApexMail\Resources;

use ApexMail\Client;

/**
 * Manage sending domains (SPF / DKIM / DMARC).
 */
class Domains
{
    public function __construct(private readonly Client $client) {}

    /**
     * Add a new sending domain.
     *
     * @param string $domain   e.g. "mail.example.com"
     * @param array  $options  { region, click_tracking, open_tracking }
     */
    public function create(string $domain, array $options = []): array
    {
        return $this->client->request('POST', '/v1/domains', array_filter([
            'domain'         => $domain,
            'region'         => $options['region']          ?? null,
            'clickTracking'  => $options['click_tracking']  ?? $options['clickTracking']  ?? null,
            'openTracking'   => $options['open_tracking']   ?? $options['openTracking']   ?? null,
        ], static fn ($v) => $v !== null));
    }

    /** List all domains on the account. */
    public function list(): array
    {
        return $this->client->request('GET', '/v1/domains');
    }

    /** Get a domain by ID. */
    public function get(string $id): array
    {
        return $this->client->request('GET', '/v1/domains/' . urlencode($id));
    }

    /** Trigger DNS record verification for a domain. */
    public function verify(string $id): array
    {
        return $this->client->request('POST', '/v1/domains/' . urlencode($id) . '/verify');
    }

    /** Delete a domain (irreversible). */
    public function delete(string $id): array
    {
        return $this->client->request('DELETE', '/v1/domains/' . urlencode($id));
    }

    /**
     * Check the deliverability health of a domain.
     * Returns SPF / DKIM / DMARC / blacklist status.
     */
    public function health(string $id): array
    {
        return $this->client->request('GET', '/v1/domains/' . urlencode($id) . '/health');
    }
}
