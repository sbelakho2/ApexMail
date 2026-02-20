<?php

declare(strict_types=1);

namespace ApexMail\Resources;

use ApexMail\Client;

/**
 * Query the email event log (delivery, opens, clicks, bounces, …).
 */
class Events
{
    public function __construct(private readonly Client $client) {}

    /**
     * List events with optional filters.
     *
     * @param array $options {
     *   @type string   $type       Event type, e.g. "email.delivered"
     *   @type string   $message_id Filter by specific message (email) ID
     *   @type string   $domain_id  Filter by sending domain
     *   @type string   $start      ISO 8601 start date
     *   @type string   $end        ISO 8601 end date
     *   @type int      $limit      Max results per page (default 50)
     *   @type int      $offset     Pagination offset
     * }
     */
    public function list(array $options = []): array
    {
        $query = http_build_query(array_filter([
            'type'      => $options['type']                                ?? null,
            'messageId' => $options['message_id'] ?? $options['messageId'] ?? null,
            'domainId'  => $options['domain_id']  ?? $options['domainId']  ?? null,
            'start'     => $options['start']                               ?? null,
            'end'       => $options['end']                                 ?? null,
            'limit'     => $options['limit']                               ?? 50,
            'offset'    => $options['offset']                              ?? 0,
        ], static fn ($v) => $v !== null && $v !== ''));

        return $this->client->request('GET', '/v1/events' . ($query ? '?' . $query : ''));
    }

    /**
     * Retrieve all events for a specific sent message.
     *
     * @param string $messageId  The email ID returned by emails.send()
     */
    public function getByMessage(string $messageId): array
    {
        return $this->client->request(
            'GET',
            '/v1/events?messageId=' . urlencode($messageId) . '&limit=100'
        );
    }

    /**
     * Get a single event by its ID.
     */
    public function get(string $eventId): array
    {
        return $this->client->request('GET', '/v1/events/' . urlencode($eventId));
    }
}
