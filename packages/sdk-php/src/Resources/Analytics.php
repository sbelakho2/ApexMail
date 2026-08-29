<?php

declare(strict_types=1);

namespace ApexMail\Resources;

use ApexMail\Client;

/**
 * Query aggregate analytics for sent mail.
 *
 * The analytics API has no GET /v1/analytics endpoint — it exposes typed
 * subpaths only (analytics.rs): /dashboard, /volume, /engagement,
 * /deliverability, /subject-line (POST) and /export. Every GET subpath
 * accepts exactly the query parameters {from, to, interval} (interval one
 * of hour | day | week | month; anything else falls back to day
 * server-side).
 */
class Analytics
{
    public function __construct(private readonly Client $client) {}

    /**
     * Dashboard counters for a date range:
     * {total_sent, total_delivered, total_bounced, total_opened,
     *  total_clicked, delivery_rate, open_rate, click_rate}.
     */
    public function dashboard(?string $from = null, ?string $to = null, ?string $interval = null): array
    {
        return $this->client->request('GET', '/v1/analytics/dashboard' . $this->buildQuery($from, $to, $interval));
    }

    /**
     * Volume timeseries: [{date, sent, delivered, bounced}, ...].
     */
    public function volume(?string $from = null, ?string $to = null, ?string $interval = null): array
    {
        return $this->client->request('GET', '/v1/analytics/volume' . $this->buildQuery($from, $to, $interval));
    }

    /**
     * Engagement rates plus a per-day timeseries:
     * {open_rate, click_rate, unsubscribe_rate, timeseries}.
     */
    public function engagement(?string $from = null, ?string $to = null, ?string $interval = null): array
    {
        return $this->client->request('GET', '/v1/analytics/engagement' . $this->buildQuery($from, $to, $interval));
    }

    /**
     * Deliverability rates: {delivery_rate, bounce_rate, complaint_rate,
     * inbox_rate}.
     */
    public function deliverability(?string $from = null, ?string $to = null, ?string $interval = null): array
    {
        return $this->client->request('GET', '/v1/analytics/deliverability' . $this->buildQuery($from, $to, $interval));
    }

    /**
     * Analyze a subject line (POST /subject-line, body {subject}).
     */
    public function analyzeSubjectLine(string $subject): array
    {
        return $this->client->request('POST', '/v1/analytics/subject-line', ['subject' => $subject]);
    }

    /**
     * Start an analytics export job (GET /export with {from, to, format}).
     */
    public function export(?string $from = null, ?string $to = null, string $format = 'json'): array
    {
        $query = http_build_query(array_filter([
            'from'   => $from,
            'to'     => $to,
            'format' => $format,
        ], static fn ($v) => $v !== null && $v !== ''));

        return $this->client->request('GET', '/v1/analytics/export' . ($query ? '?' . $query : ''));
    }

    /**
     * @deprecated The API has no GET /v1/analytics endpoint; use the typed
     *   subpath methods (dashboard(), volume(), engagement(),
     *   deliverability()). Kept as a thin alias of dashboard() for
     *   backwards compatibility.
     */
    public function get(array $options = []): array
    {
        @trigger_error('Analytics::get() is deprecated; use dashboard()/volume()/engagement()/deliverability()', E_USER_DEPRECATED);

        return $this->dashboard(
            $options['from'] ?? null,
            $options['to'] ?? null,
            $options['interval'] ?? $options['group_by'] ?? $options['groupBy'] ?? null,
        );
    }

    /** @var string|null $interval */
    private function buildQuery(?string $from, ?string $to, ?string $interval): string
    {
        $query = http_build_query(array_filter([
            'from'     => $from,
            'to'       => $to,
            'interval' => $interval,
        ], static fn ($v) => $v !== null && $v !== ''));

        return $query ? '?' . $query : '';
    }
}
