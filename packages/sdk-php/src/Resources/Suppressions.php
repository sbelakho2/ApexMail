<?php

declare(strict_types=1);

namespace ApexMail\Resources;

use ApexMail\Client;

/**
 * Manage the suppression list (bounces, unsubscribes, spam complaints).
 */
class Suppressions
{
    public function __construct(private readonly Client $client) {}

    /**
     * Add an email address (or list of addresses) to the suppression list.
     *
     * The server's CreateSuppressionRequest accepts exactly
     * {email: string, reason: string, source?: string} for ONE address
     * (deny_unknown_fields — the historical emails[] body was a 400/422).
     * A single address POSTs once; a list POSTs one request per address and
     * returns the array of responses in input order.
     *
     * @param string|string[] $emails
     * @param string          $reason  "unsubscribe" | "bounce" | "complaint" | "manual"
     * @return array Single response {id, email, reason, source, created_at},
     *               or a list of such responses when an array of emails is given.
     */
    public function add(string|array $emails, string $reason = 'manual', array $options = []): array
    {
        $source = $options['source'] ?? null;
        $list = array_values((array) $emails);

        $results = [];
        foreach ($list as $email) {
            $results[] = $this->client->request('POST', '/v1/suppressions', array_filter([
                'email'  => (string) $email,
                'reason' => $reason,
                'source' => $source,
            ], static fn ($v) => $v !== null));
        }

        return count($results) === 1 ? $results[0] : $results;
    }

    /**
     * List suppressed addresses.
     *
     * The server's ListSuppressionsQuery accepts {limit, offset, cursor,
     * reason} only — unknown query parameters are rejected.
     *
     * @param array $options { reason, limit, offset, cursor }
     */
    public function list(array $options = []): array
    {
        $query = http_build_query(array_filter([
            'reason' => $options['reason'] ?? null,
            'limit'  => $options['limit']  ?? 50,
            'offset' => $options['offset'] ?? 0,
            'cursor' => $options['cursor'] ?? null,
        ], static fn ($v) => $v !== null && $v !== ''));

        return $this->client->request('GET', '/v1/suppressions' . ($query ? '?' . $query : ''));
    }

    /**
     * Check whether a specific email address is suppressed.
     *
     * @return array { suppressed: bool, reason?: string, created_at?: string }
     */
    public function check(string $email): array
    {
        return $this->client->request(
            'GET',
            '/v1/suppressions/check/' . urlencode($email)
        );
    }

    /**
     * Remove a suppression entry by its ID.
     * Note: does NOT re-subscribe — only removes internal suppression.
     *
     * @param string $id  The suppression entry ID (UUID)
     */
    public function delete(string $id): array
    {
        return $this->client->request(
            'DELETE',
            '/v1/suppressions/' . urlencode($id)
        );
    }

    /** Add suppression entries through the API bulk endpoint. */
    public function bulk(array $entries): array
    {
        return $this->client->request('POST', '/v1/suppressions/bulk', ['entries' => $entries]);
    }
}
