<?php

declare(strict_types=1);

namespace ApexMail\Resources;

use ApexMail\Client;

/**
 * Manage sending domains (SPF / DKIM / DMARC).
 *
 * The server's CreateDomainRequest accepts exactly {name} and the domain
 * response carries the verification state
 * {id, name, status, ses_verified, spf_verified, dkim_verified,
 *  dmarc_verified, return_path_verified, created_at}.
 */
class Domains
{
    public function __construct(private readonly Client $client) {}

    /**
     * Add a new sending domain.
     *
     * @param string $domain   e.g. "mail.example.com" (sent as {name})
     * @param array  $options  Unused legacy options (region, click_tracking,
     *                         open_tracking) — accepted for backwards
     *                         compatibility but not sent: the API has no
     *                         such fields.
     */
    public function create(string $domain, array $options = []): array
    {
        return $this->client->request('POST', '/v1/domains', [
            'name' => $domain,
        ]);
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
     *
     * The API has no GET /:id/health endpoint — GET /:id itself returns the
     * health information (spf_verified, dkim_verified, dmarc_verified,
     * return_path_verified, status), so this is a thin alias of get().
     */
    public function health(string $id): array
    {
        return $this->get($id);
    }
}
