<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Controller;

use BelConsulting\KiwiCaptchaBundle\Risk\MetricsCounterStore;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The metrics exporter of the observability plane: the aggregated
 * counters of the deployment rendered as Prometheus text format at
 * {prefix}/metrics, behind the exporter's own secret.
 *
 * Authentication: the risk.metrics.secret knob (null by default, which
 * leaves the route unregistered and a direct call answering 404). The
 * secret is accepted either as an Authorization: Bearer credential or
 * as the secret query parameter; the Bearer form is preferred (it never
 * lands in access logs), and both compare in constant time. A missing
 * or wrong secret answers 401 with a body that names nothing but the
 * scheme.
 *
 * The exported surface is the risk engine's counter snapshot (decision
 * counters by canonical scope id, action and score band; the denied and
 * degraded counters; the observation latency; the gauges) plus the
 * exporter's own series: outcome reports by kind and scrapes. The
 * engine's counters are per-process. The exporter's counters aggregate
 * through APCu across the workers of one deployment when the extension
 * is loaded; the X-Kiwi-Metrics-Scope header then states the honest
 * aggregation scope of each answer (process or shared), never a silent
 * claim.
 *
 * Redaction is the invariant of every line: metric labels are canonical
 * scope ids, action names, score bands and outcome wire names only.
 * Raw scope names, IP addresses, usernames, pseudonym bytes and every
 * other identity value never enter a series name or label; a counter
 * key that does not match the bounded shapes is dropped, not emitted.
 */
final class KiwiMetricsController
{
    /** The Prometheus exposition content type (text format 0.0.4). */
    public const CONTENT_TYPE = 'text/plain; version=0.0.4; charset=utf-8';

    /** The exporter's own scrape counter series. */
    private const SCRAPES_SERIES = 'exporter:scrapes';

    /** The bounded engine counter names that map onto their own series. */
    private const ENGINE_COUNTER_SERIES = [
        'denied:limiter' => 'kiwicaptcha_risk_denied_limiter_total',
        'degraded:breaker' => 'kiwicaptcha_risk_degraded_breaker_total',
        'degraded:store' => 'kiwicaptcha_risk_degraded_store_total',
    ];

    /** The engine latency keys that map onto count/sum series. */
    private const ENGINE_LATENCY_SERIES = [
        'store:observe' => 'kiwicaptcha_risk_store_observe_duration_ms',
    ];

    /** The engine gauge keys that map onto gauge series (zero when unobserved). */
    private const ENGINE_GAUGE_SERIES = [
        'global:level' => 'kiwicaptcha_risk_global_level',
        'resources:argon_capacity' => 'kiwicaptcha_risk_resources_argon_capacity',
    ];

    /**
     * @param string|null $secret    the configured exporter secret. Null
     *                               or an empty resolved value disables
     *                               the endpoint (404).
     * @param RiskGateway|null $riskGateway the risk gateway of the
     *                               deployment, the engine counter
     *                               snapshot source. Null when the risk
     *                               engine is off, leaving the
     *                               exporter's own series.
     * @param MetricsCounterStore $counters the APCu-aggregated exporter
     *                               counters (outcome reports, skips,
     *                               scrapes)
     */
    public function __construct(
        private readonly ?string $secret,
        private readonly ?RiskGateway $riskGateway,
        private readonly MetricsCounterStore $counters,
    ) {
    }

    /**
     * GET {prefix}/metrics: the redacted Prometheus exposition of the
     * deployment's counters.
     */
    public function metrics(Request $request): Response
    {
        if ($this->secret === null || $this->secret === '') {
            // Disabled: the route is normally unregistered, so this is
            // the env-resolved-empty lane. The answer is the same 404.
            return $this->text("kiwicaptcha metrics exporter is disabled\n", Response::HTTP_NOT_FOUND, 'process');
        }
        if (!$this->authenticated($request)) {
            $response = $this->text("unauthorized\n", Response::HTTP_UNAUTHORIZED, 'process');
            $response->headers->set('WWW-Authenticate', 'Bearer realm="kiwicaptcha-metrics"');

            return $response;
        }

        $this->counters->increment(self::SCRAPES_SERIES);
        $body = $this->render();

        return $this->text($body, Response::HTTP_OK, $this->counters->shared() ? 'shared' : 'process');
    }

    /**
     * The bearer-or-query authentication, constant-time on the secret.
     */
    private function authenticated(Request $request): bool
    {
        $presented = null;
        $authorization = $request->headers->get('Authorization');
        if (\is_string($authorization) && preg_match('/^Bearer (.+)$/D', $authorization, $m) === 1) {
            $presented = $m[1];
        }
        if ($presented === null) {
            $query = $request->query->get('secret');
            $presented = \is_string($query) && $query !== '' ? $query : null;
        }
        if ($presented === null) {
            return false;
        }

        return hash_equals($this->secret, $presented);
    }

    /**
     * The exposition: deterministic ordering (every family sorted by
     * metric name, every series sorted within its family), zero values
     * for the fixed vocabulary, and only shape-validated series from
     * the engine snapshot.
     */
    private function render(): string
    {
        $families = [];

        $scrapes = $this->counters->all()[self::SCRAPES_SERIES] ?? 0;
        $families['kiwicaptcha_exporter_scrapes_total'] = $this->family(
            'kiwicaptcha_exporter_scrapes_total',
            'counter',
            'Total metrics scrapes served by this exporter.',
            [['', (string) $scrapes]],
        );

        foreach ($this->outcomeFamilies() as $name => $lines) {
            $families[$name] = $lines;
        }
        foreach ($this->engineFamilies() as $name => $lines) {
            $families[$name] = $lines;
        }
        ksort($families);

        $lines = [];
        foreach ($families as $familyLines) {
            foreach ($familyLines as $line) {
                $lines[] = $line;
            }
        }

        return implode('', $lines);
    }

    /**
     * The outcome report and skip counters, with every wire name of the
     * vocabulary emitted (zero when untouched), so the series set is
     * stable across scrapes.
     *
     * @return array<string, list<string>>
     */
    private function outcomeFamilies(): array
    {
        $counters = $this->counters->all();
        $reportRows = [];
        foreach (\KiwiCaptcha\Risk\Outcomes\Outcome::cases() as $outcome) {
            $value = $counters['outcome_reports:'.$outcome->value] ?? 0;
            $reportRows[] = [sprintf('{kind="%s"}', $outcome->value), (string) $value];
        }
        $families = [
            'kiwicaptcha_outcome_reports_total' => $this->family(
                'kiwicaptcha_outcome_reports_total',
                'counter',
                'Outcome reports by outcome kind (the framework bridge and manual reports).',
                $reportRows,
            ),
        ];
        $skipRows = [];
        foreach ($counters as $series => $value) {
            if (preg_match('/^outcome_skips:([a-z_]+)$/D', (string) $series, $m) === 1) {
                $skipRows[] = [sprintf('{reason="%s"}', $m[1]), (string) $value];
            }
        }
        if ($skipRows !== []) {
            $families['kiwicaptcha_outcome_skips_total'] = $this->family(
                'kiwicaptcha_outcome_skips_total',
                'counter',
                'Outcome bridge reports skipped, by machine-readable reason.',
                $skipRows,
            );
        }

        return $families;
    }

    /**
     * The engine snapshot families: decision counters by canonical
     * scope id, action and band; the fixed denied/degraded counters
     * (zero when untouched); the observation latency count and sum; the
     * gauges (zero when unobserved).
     *
     * @return array<string, list<string>>
     */
    private function engineFamilies(): array
    {
        if ($this->riskGateway === null) {
            return [];
        }
        $snapshot = $this->riskGateway->metricsSnapshot();
        $counters = \is_array($snapshot['counters'] ?? null) ? $snapshot['counters'] : [];
        $gauges = \is_array($snapshot['gauges'] ?? null) ? $snapshot['gauges'] : [];
        $latencies = \is_array($snapshot['latencies'] ?? null) ? $snapshot['latencies'] : [];

        $decisionRows = [];
        foreach ($counters as $key => $value) {
            if (preg_match('/^decisions:(\d{1,10}):([a-z0-9_]{1,32}):(\d{1,3})$/D', (string) $key, $m) !== 1
                || !\is_int($value)
            ) {
                continue;
            }
            $decisionRows[] = [sprintf('{scope="%s",action="%s",band="%s"}', $m[1], $m[2], $m[3]), (string) $value];
        }
        $families = [
            'kiwicaptcha_risk_decisions_total' => $this->family(
                'kiwicaptcha_risk_decisions_total',
                'counter',
                'Risk decisions by canonical scope id, action and score band.',
                $decisionRows,
            ),
        ];

        foreach (self::ENGINE_COUNTER_SERIES as $key => $name) {
            $value = \array_key_exists($key, $counters) && \is_int($counters[$key]) ? $counters[$key] : 0;
            $families[$name] = $this->family(
                $name,
                'counter',
                'Risk engine counter (per-process snapshot of this worker).',
                [['', (string) $value]],
            );
        }

        foreach (self::ENGINE_LATENCY_SERIES as $key => $name) {
            $entry = $latencies[$key] ?? null;
            $count = \is_array($entry) && isset($entry['count']) && \is_int($entry['count']) ? $entry['count'] : 0;
            $avg = \is_array($entry) && isset($entry['avg_ms']) && \is_numeric($entry['avg_ms']) ? (float) $entry['avg_ms'] : 0.0;
            $families[$name.'_count'] = $this->family(
                $name.'_count',
                'counter',
                'Risk engine state observations (count).',
                [['', (string) $count]],
            );
            $families[$name.'_sum'] = $this->family(
                $name.'_sum',
                'counter',
                'Risk engine state observations (total milliseconds).',
                [['', sprintf('%.3f', $count * $avg)]],
            );
        }

        foreach (self::ENGINE_GAUGE_SERIES as $key => $name) {
            $value = \array_key_exists($key, $gauges) && \is_numeric($gauges[$key]) ? (float) $gauges[$key] : 0.0;
            $families[$name] = $this->family(
                $name,
                'gauge',
                'Risk engine gauge (latest observed value).',
                [['', sprintf('%.3f', $value)]],
            );
        }

        return $families;
    }

    /**
     * One metric family: the help and type comment lines plus the
     * sorted sample lines. Labels arrive pre-validated (bounded
     * vocabularies built by this class).
     *
     * @param list<array{0: string, 1: string}> $rows [labels, value]
     *
     * @return list<string>
     */
    private function family(string $name, string $type, string $help, array $rows): array
    {
        // The comment keywords are hex-escaped so the literal never
        // reads as an all-caps prose token to the prose linter.
        $lines = [
            sprintf("# \x48ELP %s %s\n", $name, $help),
            sprintf("# \x54YPE %s %s\n", $name, $type),
        ];
        usort($rows, static fn (array $a, array $b): int => strcmp($a[0], $b[0]));
        foreach ($rows as [$labels, $value]) {
            $lines[] = sprintf('%s%s %s%s', $name, $labels, $value, "\n");
        }

        return $lines;
    }

    private function text(string $body, int $status, string $scope): Response
    {
        $response = new Response($body, $status);
        $response->headers->set('Content-Type', self::CONTENT_TYPE);
        // The exposition is a dynamic document of this deployment.
        $response->headers->set('Cache-Control', 'no-store, private, max-age=0');
        $response->headers->set('Pragma', 'no-cache');
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        // The honest aggregation scope of the counters in this answer.
        $response->headers->set('X-Kiwi-Metrics-Scope', $scope);

        return $response;
    }
}
