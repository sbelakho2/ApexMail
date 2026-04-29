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
     * @param string|string[] $emails
     * @param string          $reason  "unsubscribe" | "bounce" | "complaint" | "manual"
     */
    public function add(string|array $emails, string $reason = 'manual', array $options = []): array
    {
        return $this->client->request('POST', '/v1/suppressions', array_filter([
            'emails'  => (array) $emails,
            'reason'  => $reason,
            'domainId' => $options['domain_id'] ?? $options['domainId'] ?? null,
        ], static fn ($v) => $v !== null));
    }

    /**
     * List suppressed addresses.
     *
     * @param array $options { reason, limit, offset }
     */
    public function list(array $options = []): array
    {
        $query = http_build_query(array_filter([
            'reason' => $options['reason'] ?? null,
            'limit'  => $options['limit']  ?? 50,
            'offset' => $options['offset'] ?? 0,
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
     * Remove an address from the suppression list.
     * Note: does NOT re-subscribe — only removes internal suppression.
     */
    public function delete(string $email): array
    {
        return $this->client->request(
            'DELETE',
            '/v1/suppressions/' . urlencode($email)
        );
    }
}
