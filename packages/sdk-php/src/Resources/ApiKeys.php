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
     * The server's CreateApiKeyRequest accepts exactly
     * {name, scopes: string[], expires_in_days?} (deny_unknown_fields).
     * `scopes` is required by the API and defaults to [] (a key with no
     * scopes); the legacy expiresAt input is accepted but not sent — use
     * expires_in_days (1..365).
     *
     * @param array $params { name, scopes?, expires_in_days?, expires_at? (unused) }
     */
    public function create(array $params): array
    {
        $scopes = $params['scopes'] ?? [];
        $body = array_filter([
            'name'             => $params['name'] ?? null,
            'scopes'           => array_values(array_map('strval', (array) $scopes)),
            'expires_in_days'  => $params['expires_in_days'] ?? $params['expiresInDays'] ?? null,
        ], static fn ($value) => $value !== null && $value !== '');

        // scopes must always be present (even empty) for the server DTO.
        if (!isset($body['scopes'])) {
            $body['scopes'] = [];
        }

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