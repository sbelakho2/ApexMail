<?php

declare(strict_types=1);

namespace ApexMail\Resources;

use ApexMail\Client;

/**
 * Manage outbound webhooks.
 */
class Webhooks
{
    public function __construct(private readonly Client $client) {}

    /**
     * Register a new webhook endpoint.
     *
     * @param array $params {
     *   @type string   $url     HTTPS endpoint URL
     *   @type string[] $events  e.g. ["message.delivered", "message.bounced"]
     *   @type string   $secret  Optional HMAC signing secret
     * }
     */
    public function create(array $params): array
    {
        return $this->client->request('POST', '/v1/webhooks', $params);
    }

    /** List all registered webhook endpoints. */
    public function list(): array
    {
        return $this->client->request('GET', '/v1/webhooks');
    }

    /** Get a single webhook by ID. */
    public function get(string $id): array
    {
        return $this->client->request('GET', '/v1/webhooks/' . urlencode($id));
    }

    /**
     * Update a webhook's URL or event subscriptions.
     *
     * @param array $params { url, events, secret, active }
     */
    public function update(string $id, array $params): array
    {
        return $this->client->request('PUT', '/v1/webhooks/' . urlencode($id), $params);
    }

    /** Delete a webhook. */
    public function delete(string $id): array
    {
        return $this->client->request('DELETE', '/v1/webhooks/' . urlencode($id));
    }

    /** Send a signed test event to a registered webhook endpoint. */
    public function test(string $id): array
    {
        return $this->client->request('POST', '/v1/webhooks/' . urlencode($id) . '/test');
    }
}
