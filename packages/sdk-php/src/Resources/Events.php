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
     * The server's ListEventsQuery (events.rs, deny_unknown_fields) accepts
     * exactly {limit, offset, event_type, message_id}. There is no
     * cursor/keyset pagination and no start/end/domain filter: those keys
     * were sent historically and rejected with HTTP 400 ("unknown field"),
     * so they now fail fast client-side instead.
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
     *   @type string   $event_type Event type, e.g. "message.delivered" (legacy alias: type)
     *   @type string   $message_id Filter by specific message (email) ID (legacy alias: messageId)
     *   @type int      $limit      Max results per page (default 50)
     *   @type int      $offset     Pagination offset
     * }
     */
    public function list(array $options = []): array
    {
        $this->rejectUnsupportedFilters($options);
        $query = http_build_query(array_filter([
            'event_type' => $options['event_type'] ?? $options['type'] ?? null,
            'message_id' => $options['message_id'] ?? $options['messageId'] ?? null,
            'limit'      => $options['limit'] ?? 50,
            'offset'     => $options['offset'] ?? 0,
        ], static fn ($v) => $v !== null && $v !== ''));

        return $this->client->request('GET', '/v1/events' . ($query ? '?' . $query : ''));
    }

    /**
     * Retrieve all events for a specific sent message.
     *
     * @param string $messageId  The email ID returned by emails.send()
     * @param int    $limit      Max results (default 100, server window)
     */
    public function getByMessage(string $messageId, int $limit = 100): array
    {
        $limit = max(1, min(100, $limit));
        return $this->client->request(
            'GET',
            '/v1/events?message_id=' . urlencode($messageId) . '&limit=' . $limit
        );
    }

    /**
     * Reject filters the server does not accept with a precise client-side
     * error instead of letting the server 400 on an unknown query field.
     */
    private function rejectUnsupportedFilters(array $options): void
    {
        $unsupported = array_values(array_intersect(
            array_keys($options),
            ['cursor', 'start', 'end', 'domain_id', 'domainId', 'status']
        ));
        if ($unsupported !== []) {
            throw new \InvalidArgumentException(
                'GET /v1/events does not support: ' . implode(', ', $unsupported)
                . ' (server ListEventsQuery accepts limit, offset, event_type, message_id only)'
            );
        }
    }

    /**
     * Get a single event by its ID.
     */
    public function get(string $eventId): array
    {
        return $this->client->request('GET', '/v1/events/' . urlencode($eventId));
    }

    /**
     * Return aggregate event counts with optional filters.
     *
     * The server's StatsQuery (events.rs, deny_unknown_fields) accepts
     * {from, to} only; legacy `start`/`end` inputs are mapped to them. Any
     * other filter (type/messageId/domainId/interval) is a 400 server-side
     * and therefore rejected client-side.
     *
     * @param array $options { from?, to?, start? (legacy from), end? (legacy to) }
     */
    public function stats(array $options = []): array
    {
        return $this->client->request('GET', '/v1/events/stats' . $this->statsQuery($options));
    }

    /**
     * Return event counts over time with optional filters.
     *
     * @param array $options { from?, to?, start? (legacy from), end? (legacy to) }
     */
    public function timeseries(array $options = []): array
    {
        return $this->client->request('GET', '/v1/events/timeseries' . $this->statsQuery($options));
    }

    private function statsQuery(array $options): string
    {
        $unsupported = array_values(array_intersect(
            array_keys($options),
            ['type', 'event_type', 'message_id', 'messageId', 'domain_id', 'domainId', 'interval', 'cursor', 'status']
        ));
        if ($unsupported !== []) {
            throw new \InvalidArgumentException(
                'GET /v1/events/stats and /timeseries do not support: ' . implode(', ', $unsupported)
                . ' (server StatsQuery accepts from, to only)'
            );
        }

        $query = http_build_query(array_filter([
            'from' => $options['from'] ?? $options['start'] ?? null,
            'to'   => $options['to']   ?? $options['end']   ?? null,
        ], static fn ($v) => $v !== null && $v !== ''));

        return $query ? '?' . $query : '';
    }
}
