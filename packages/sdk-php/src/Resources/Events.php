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
     * Each event in the response may include an `envelope` key with:
     *   - from:      (string|null) Envelope MAIL FROM address
     *   - to:        (string[])    Envelope RCPT TO addresses
     *   - dkim:      (string)      Authentication result: pass|fail|neutral|none
     *   - spf:       (string)      Authentication result: pass|fail|neutral|none
     *   - dmarc:     (string)      Authentication result: pass|fail|neutral|none
     *   - timestamp: (string)      ISO 8601 delivery event timestamp
     *
     * @param array $options {
     *   @type string   $type       Event type, e.g. "message.delivered"
     *   @type string   $message_id Filter by specific message (email) ID
     *   @type string   $domain_id  Filter by sending domain
     *   @type string   $start      ISO 8601 start date
     *   @type string   $end        ISO 8601 end date
     *   @type int      $limit      Max results per page (default 50)
     *   @type int      $offset     Pagination offset
     *   @type string   $cursor     Cursor for cursor-based pagination
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
            'cursor'    => $options['cursor']                              ?? null,
        ], static fn ($v) => $v !== null && $v !== ''));

        return $this->client->request('GET', '/v1/events' . ($query ? '?' . $query : ''));
    }

    /**
     * Retrieve all events for a specific sent message.
     *
     * @param string $messageId  The email ID returned by emails.send()
     */
    /**
     * Events for one message. The limit is exposed (default 100, server
     * cap) and the client's getNextCursor()/getLastResponseMeta() carry the
     * continuation when a retry storm produced more events than one page.
     */
    public function getByMessage(string $messageId, int $limit = 100): array
    {
        $limit = max(1, min(100, $limit));
        return $this->client->request(
            'GET',
            '/v1/events?messageId=' . urlencode($messageId) . '&limit=' . $limit
        );
    }

    /**
     * Get a single event by its ID.
     */
    public function get(string $eventId): array
    {
        return $this->client->request('GET', '/v1/events/' . urlencode($eventId));
    }

    /** Return aggregate event counts with optional filters. */
    public function stats(array $options = []): array
    {
        $query = http_build_query(array_filter([
            'type'      => $options['type']                                ?? null,
            'messageId' => $options['message_id'] ?? $options['messageId'] ?? null,
            'domainId'  => $options['domain_id']  ?? $options['domainId']  ?? null,
            'start'     => $options['start']                               ?? null,
            'end'       => $options['end']                                 ?? null,
        ], static fn ($v) => $v !== null && $v !== ''));

        return $this->client->request('GET', '/v1/events/stats' . ($query ? '?' . $query : ''));
    }

    /** Return event counts over time with optional filters. */
    public function timeseries(array $options = []): array
    {
        $query = http_build_query(array_filter([
            'type'      => $options['type']                                ?? null,
            'messageId' => $options['message_id'] ?? $options['messageId'] ?? null,
            'domainId'  => $options['domain_id']  ?? $options['domainId']  ?? null,
            'start'     => $options['start']                               ?? null,
            'end'       => $options['end']                                 ?? null,
            'interval'  => $options['interval']                            ?? null,
        ], static fn ($v) => $v !== null && $v !== ''));

        return $this->client->request('GET', '/v1/events/timeseries' . ($query ? '?' . $query : ''));
    }
}
