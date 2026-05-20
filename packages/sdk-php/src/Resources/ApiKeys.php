<?php

declare(strict_types=1);

namespace ApexMail\Resources;

use ApexMail\Client;

/**
 * Manage API keys for the authenticated account.
 */
class ApiKeys
{
    public function __construct(private readonly Client $client) {}

    /**
     * Create a new API key.
     *
     * @param array $params { name, expiresAt, expires_at }
     */
    public function create(array $params): array
    {
        $body = array_filter([
            'name'      => $params['name'] ?? null,
            'expiresAt' => $params['expires_at'] ?? $params['expiresAt'] ?? null,
        ], static fn ($value) => $value !== null && $value !== '');

        return $this->client->request('POST', '/v1/auth/api-keys', $body);
    }

    /**
     * List API keys.
     *
     * @param array $options { limit, offset }
     */
    public function list(array $options = []): array
    {
        $query = http_build_query(array_filter([
            'limit'  => $options['limit']  ?? 50,
            'offset' => $options['offset'] ?? 0,
            'cursor' => $options['cursor'] ?? null,
        ], static fn ($value) => $value !== null && $value !== ''));

        return $this->client->request('GET', '/v1/auth/api-keys' . ($query ? '?' . $query : ''));
    }

    /**
     * Revoke an API key.
     */
    public function revoke(string $id): array
    {
        return $this->client->request('DELETE', '/v1/auth/api-keys/' . urlencode($id));
    }
}