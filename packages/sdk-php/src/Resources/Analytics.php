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
     * Fetch analytics with optional date and grouping filters.
     *
     * @param array $options { from, to, groupBy, group_by, tag }
     */
    public function get(array $options = []): array
    {
        $query = http_build_query(array_filter([
            'from'    => $options['from']                      ?? null,
            'to'      => $options['to']                        ?? null,
            'groupBy' => $options['group_by'] ?? $options['groupBy'] ?? null,
            'tag'     => $options['tag']                       ?? null,
        ], static fn ($value) => $value !== null && $value !== ''));

        return $this->client->request('GET', '/v1/analytics' . ($query ? '?' . $query : ''));
    }
}