<?php

declare(strict_types=1);

namespace ApexMail\Resources;

use ApexMail\Client;

/**
 * Manage outbound webhooks.
 */
class Webhooks
{
    /**
     * Event types the server accepts (webhooks.rs KNOWN_WEBHOOK_EVENTS,
     * canonicalized 2026-09-08). Anything else is rejected with 422 by
     * the API.
     */
    public const EVENTS = [
        'message.accepted',
        'message.queued',
        'message.attempted',
        'message.deferred',
        'message.delivered',
        'message.bounced',
        'message.complained',
        'message.suppressed',
        'message.opened',
        'message.clicked',
        'message.cancelled',
        'recipient.unsubscribed',
        'campaign.started',
        'campaign.ab_winner_selected',
        'campaign.completed',
        'placement_test.completed',
        'inbound',
        '*',
    ];

    public function __construct(private readonly Client $client) {}

    /**
     * Register a new webhook endpoint.
     *
     * The server's CreateWebhookRequest accepts exactly {url, events} and
     * uses deny_unknown_fields — anything else in the body is a 422. The
     * signing secret is generated server-side and returned in the response
     * (secret is only present on creation and secret rotation).
     *
     * @param array $params {
     *   @type string   $url     HTTPS endpoint URL
     *   @type string[] $events  e.g. ["message.delivered", "message.bounced", "*"]
     * }
     */
    public function create(array $params): array
    {
        $body = [
            'url'    => (string) ($params['url'] ?? ''),
            'events' => array_values(array_map('strval', (array) ($params['events'] ?? []))),
        ];

        return $this->client->request('POST', '/v1/webhooks', $body);
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
     * Update a webhook's URL, event subscriptions, or status.
     *
     * The server's UpdateWebhookRequest accepts {url, events, status} with
     * status one of "active" | "paused" | "disabled". For backwards
     * compatibility a boolean `active` input is mapped to
     * status=active/paused; unknown keys (secret, name, enabled) are NOT
     * sent.
     *
     * @param array $params { url?, events?, status?: "active"|"paused"|"disabled", active?: bool }
     */
    public function update(string $id, array $params): array
    {
        $status = $params['status'] ?? null;
        if ($status === null && array_key_exists('active', $params)) {
            $status = $params['active'] ? 'active' : 'paused';
        }

        $body = array_filter([
            'url'    => $params['url'] ?? null,
            'events' => isset($params['events'])
                ? array_values(array_map('strval', (array) $params['events']))
                : null,
            'status' => $status,
        ], static fn ($v) => $v !== null);

        return $this->client->request('PUT', '/v1/webhooks/' . urlencode($id), $body);
    }

    /** Delete a webhook. */
    public function delete(string $id): array
    {
        return $this->client->request('DELETE', '/v1/webhooks/' . urlencode($id));
    }

    /**
     * Send a signed test event to a registered webhook endpoint.
     * The server takes no body for this endpoint.
     */
    public function test(string $id): array
    {
        return $this->client->request('POST', '/v1/webhooks/' . urlencode($id) . '/test');
    }

    /**
     * Rotate the webhook's signing secret (`POST /:id/rotate-secret`).
     *
     * The new secret is returned in this response only — the previous secret
     * stops verifying deliveries immediately, so update the receiver before
     * rotating. The secret is used verbatim (the full `whsec_…` string) when
     * verifying signatures with {@see Client::verifyWebhookSignature()}.
     */
    public function rotateSecret(string $id): array
    {
        return $this->client->request('POST', '/v1/webhooks/' . urlencode($id) . '/rotate-secret');
    }
}
