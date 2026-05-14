<?php

declare(strict_types=1);

namespace ApexMail\Resources;

use ApexMail\Client;

/**
 * Query aggregate analytics for sent mail.
 */
class Analytics
{
    public function __construct(private readonly Client $client) {}

    /**
     * Fetch analytics with required from/to dates and optional filters.
     *
     * @param array $options {
     *   @type string $from     Required. ISO 8601 start date
     *   @type string $to       Required. ISO 8601 end date
     *   @type string $groupBy  Grouping dimension
     *   @type string $tag      Filter by tag name
     *   @type string $domain   Filter by sending domain
     * }
     */
    public function get(array $options = []): array
    {
        $query = http_build_query(array_filter([
            'from'    => $options['from']                      ?? null,
            'to'      => $options['to']                        ?? null,
            'groupBy' => $options['group_by'] ?? $options['groupBy'] ?? null,
            'tag'     => $options['tag']                       ?? null,
            'domain'  => $options['domain']                    ?? null,
        ], static fn ($value) => $value !== null && $value !== ''));

        return $this->client->request('GET', '/v1/analytics' . ($query ? '?' . $query : ''));
    }
}