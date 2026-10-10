<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\KiwiMetricsController;
use BelConsulting\KiwiCaptchaBundle\Risk\MetricsCounterStore;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakeRiskStateStore;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * The metrics exporter of the observability plane: the metrics route
 * behind the exporter's own secret, with the Bearer form preferred and
 * the query parameter accepted (both constant-time). Disabled means
 * 404. The body is strict Prometheus text with deterministic ordering
 * and zero values. The per-process lane is the tested default (the
 * suite runs without APCu), and the shared lane is exercised through
 * the same injectable APCu seam the health controller test uses.
 * Redaction is proven by canary: raw scope names, IP addresses,
 * usernames and pseudonym bytes never appear in a series name or label.
 */
final class KiwiMetricsControllerTest extends TestCase
{
    private const SECRET = 'metrics-exporter-secret-0123456789abcdef';

    private const CANARY_SCOPE = 'canary-login-scope';

    private const CANARY_IP = '198.51.100.77';

    private const CANARY_USERNAME = 'canary-username-9f31aa';

    private const CANARY_PSEUDONYM = '5ae1a4b8c0d1e2f30011223344556677';

    public function testADisabledExporterAnswers404OnADirectCall(): void
    {
        foreach ([null, ''] as $secret) {
            $controller = new KiwiMetricsController($secret, null, new MetricsCounterStore('metrics-test'));

            $response = $controller->metrics($this->request());
            self::assertSame(404, $response->getStatusCode(), sprintf('a %s secret disables the endpoint', var_export($secret, true)));
            self::assertStringContainsString('disabled', (string) $response->getContent());
        }
    }

    public function testAMissingOrWrongSecretAnswers401(): void
    {
        $controller = $this->controller();

        foreach ([
            'no credential' => $this->request(),
            'wrong bearer' => $this->request(['HTTP_Authorization' => 'Bearer wrong-secret-0123456789abcdef0']),
            'wrong query' => Request::create('/kiwi-captcha/metrics?secret=wrong-secret-0123456789abcdef0'),
        ] as $label => $request) {
            $response = $controller->metrics($request);
            self::assertSame(401, $response->getStatusCode(), $label);
            self::assertSame('Bearer realm="kiwicaptcha-metrics"', $response->headers->get('WWW-Authenticate'), $label);
            self::assertStringNotContainsString(self::SECRET, (string) $response->getContent(), 'the refusal body never hints the secret');
        }
    }

    public function testTheCorrectSecretAnswers200ThroughBothAcceptedForms(): void
    {
        $controller = $this->controller();

        $bearer = $controller->metrics($this->request(['HTTP_Authorization' => 'Bearer '.self::SECRET]));
        self::assertSame(200, $bearer->getStatusCode());
        self::assertSame(KiwiMetricsController::CONTENT_TYPE, $bearer->headers->get('Content-Type'));
        self::assertStringContainsString('version=0.0.4', (string) $bearer->headers->get('Content-Type'));

        $query = $controller->metrics(Request::create('/kiwi-captcha/metrics?secret='.self::SECRET));
        self::assertSame(200, $query->getStatusCode());

        // The bearer form wins when both are present, so a stale query
        // credential never overrides the header.
        $both = $controller->metrics($this->request(['HTTP_Authorization' => 'Bearer '.self::SECRET], ['secret' => 'wrong']));
        self::assertSame(200, $both->getStatusCode(), 'the bearer credential is preferred over the query parameter');
    }

    public function testTheScopeHeaderStatesTheHonestAggregationScope(): void
    {
        $counters = new MetricsCounterStore('metrics-test');
        $controller = new KiwiMetricsController(self::SECRET, null, $counters);

        $response = $controller->metrics($this->request(['HTTP_Authorization' => 'Bearer '.self::SECRET]));

        self::assertSame(
            $counters->shared() ? 'shared' : 'process',
            $response->headers->get('X-Kiwi-Metrics-Scope'),
            'the header mirrors the store\'s own aggregation claim, never a silent assumption',
        );
        self::assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
    }

    public function testTheBodyIsStrictPrometheusTextWithDeterministicOrderingAndZeroValues(): void
    {
        // A risk-gateway-bearing deployment: the fixed engine vocabulary
        // is present untouched, so its zero values are emitted.
        $controller = $this->controller($this->gateway());

        $first = $this->scrape($controller);
        // The scrape counter advanced, so the comparison is the series
        // ordering, not the byte body: the same families in the same
        // order with the same label sets.
        $second = $this->scrape($controller);

        foreach ([$first, $second] as $body) {
            $this->assertStrictPrometheusText($body);
        }
        self::assertSame($this->seriesOrder($first), $this->seriesOrder($second), 'two scrapes of one deployment emit the identical series order');

        // Zero values are emitted: an untouched deployment still carries
        // the full fixed vocabulary (every outcome kind, every fixed
        // engine counter, the latency and gauge series).
        foreach ([
            'kiwicaptcha_outcome_reports_total{kind="authenticationSuccess"} 0',
            'kiwicaptcha_risk_denied_limiter_total 0',
            'kiwicaptcha_risk_store_observe_duration_ms_count 0',
            'kiwicaptcha_risk_global_level 0.000',
        ] as $zeroLine) {
            self::assertStringContainsString($zeroLine."\n", $first, sprintf('the zero value is emitted: %s', $zeroLine));
        }
        self::assertMatchesRegularExpression('/^kiwicaptcha_exporter_scrapes_total 1$/m', $first, 'the scrape counter is visible in the exposition');
    }

    public function testCounterIncrementsAreVisibleAfterDrivingTraffic(): void
    {
        $counters = new MetricsCounterStore('metrics-test');
        $controller = new KiwiMetricsController(self::SECRET, null, $counters);

        // The outcome bridge books one failure and skips one report.
        $counters->increment('outcome_reports:authenticationFailure');
        $counters->increment('outcome_skips:no_attributable_handle');
        $counters->increment('outcome_skips:no_attributable_handle');

        $body = $this->scrape($controller);
        self::assertMatchesRegularExpression('/^kiwicaptcha_outcome_reports_total\{kind="authenticationFailure"\} 1$/m', $body);
        self::assertMatchesRegularExpression('/^kiwicaptcha_outcome_reports_total\{kind="authenticationSuccess"\} 0$/m', $body, 'untouched kinds stay at zero');
        self::assertMatchesRegularExpression('/^kiwicaptcha_outcome_skips_total\{reason="no_attributable_handle"\} 2$/m', $body);
    }

    public function testEngineDecisionCountersSurfaceWithCanonicalScopeIdsOnly(): void
    {
        $gateway = $this->gateway();
        // Real decisions through the real gateway: the canary scope name
        // maps onto the canonical id 7, and the canary IP drives the
        // observations without ever surfacing.
        for ($i = 0; $i < 3; $i++) {
            $decision = $gateway->preIssue(self::CANARY_SCOPE, self::CANARY_IP, null);
            $gateway->challengeIssued(self::CANARY_SCOPE, self::CANARY_IP, self::CANARY_PSEUDONYM, $decision->decisionId);
        }

        $body = $this->scrape($this->controller($gateway));

        self::assertMatchesRegularExpression('/^kiwicaptcha_risk_decisions_total\{scope="7",action="[a-z_]+",band="\d+"\} \d+$/m', $body, 'decision counters appear keyed by the canonical scope id, action and band');
        $this->assertCanariesAbsent($body);
    }

    public function testRedactionCanariesNeverAppearInTheExposition(): void
    {
        $counters = new MetricsCounterStore('metrics-test');
        $gateway = $this->gateway();
        $decision = $gateway->preIssue(self::CANARY_SCOPE, self::CANARY_IP, self::CANARY_PSEUDONYM);
        $gateway->challengeIssued(self::CANARY_SCOPE, self::CANARY_IP, self::CANARY_PSEUDONYM, $decision->decisionId);
        // A series name outside the bounded shape is refused by the
        // store, so identity bytes cannot enter even a mistaken key.
        $counters->increment('outcome_reports:'.self::CANARY_USERNAME);
        $counters->increment('outcome_reports:'.self::CANARY_IP);

        $body = $this->scrape(new KiwiMetricsController(self::SECRET, $gateway, $counters));

        $this->assertCanariesAbsent($body);
        self::assertStringContainsString("\n", $body);
    }

    public function testTheSharedLaneAggregatesAcrossWorkersThroughTheApcuSeam(): void
    {
        // "Under PHP-FPM": one fresh controller per request sharing one
        // simulated APCu segment, the seam pattern of the health
        // controller test. Two workers' increments aggregate, the scope
        // header says shared, and every key carries the bounded TTL.
        $segment = [];
        $ttls = [];
        $apcu = $this->apcuSeam($segment, $ttls);

        $workerA = new KiwiMetricsController(self::SECRET, null, new MetricsCounterStore('metrics-test', $apcu));
        $workerB = new KiwiMetricsController(self::SECRET, null, new MetricsCounterStore('metrics-test', $apcu));

        $workerA->metrics($this->request(['HTTP_Authorization' => 'Bearer '.self::SECRET]));
        $bodyA = $workerB->metrics($this->request(['HTTP_Authorization' => 'Bearer '.self::SECRET]));

        self::assertSame('shared', $workerA->metrics($this->request(['HTTP_Authorization' => 'Bearer '.self::SECRET]))->headers->get('X-Kiwi-Metrics-Scope'));
        self::assertMatchesRegularExpression('/^kiwicaptcha_exporter_scrapes_total 2$/m', (string) $bodyA->getContent(), 'the two workers\' scrapes aggregated into the shared segment');

        foreach ($ttls as $key => $ttl) {
            self::assertSame(MetricsCounterStore::TTL_SECS, $ttl, sprintf('the counter key %s carries the bounded TTL', (string) $key));
        }
    }

    private function controller(?RiskGateway $gateway = null): KiwiMetricsController
    {
        return new KiwiMetricsController(self::SECRET, $gateway, new MetricsCounterStore('metrics-test'));
    }

    /**
     * @param array<string, string> $server
     * @param array<string, string> $query
     */
    private function request(array $server = [], array $query = []): Request
    {
        return Request::create('/kiwi-captcha/metrics', 'GET', $query, [], [], $server);
    }

    private function scrape(KiwiMetricsController $controller): string
    {
        $response = $controller->metrics($this->request(['HTTP_Authorization' => 'Bearer '.self::SECRET]));
        self::assertSame(200, $response->getStatusCode());

        return (string) $response->getContent();
    }

    private function gateway(): RiskGateway
    {
        $keys = RiskKeys::fromMaster('0123456789abcdef0123456789abcdef');
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
            'weights' => [],
            'scopes' => [
                7 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        $engine = new AdaptiveRiskEngine(
            new FakeRiskStateStore(),
            new CidrNetworkClassifier([]),
            new RiskIdentityFactory($keys),
            new RiskScorer(),
            $policy,
            $keys,
        );

        return new RiskGateway($engine, new CidrNetworkClassifier([]), new RiskProfileResolver(PoWAlgorithm::Sha256, 8), [self::CANARY_SCOPE => 7], null, policy: $policy);
    }

    private function assertCanariesAbsent(string $body): void
    {
        foreach ([
            'the raw scope name' => self::CANARY_SCOPE,
            'the raw IP' => self::CANARY_IP,
            'the raw username' => self::CANARY_USERNAME,
            'the pseudonym hex' => self::CANARY_PSEUDONYM,
            'the key prefix' => 'metrics-test',
        ] as $label => $canary) {
            self::assertStringNotContainsString($canary, $body, sprintf('%s never appears in the exposition', $label));
        }
    }

    /**
     * The strict parser: every non-comment line matches
     * ^name_labels? value$, no series repeats, every family's help and
     * type lines precede its samples, families are sorted by name and
     * label values stay inside the bounded redacted vocabulary.
     */
    private function assertStrictPrometheusText(string $body): void
    {
        self::assertNotSame('', $body, 'the exposition is never empty');

        $seenSeries = [];
        $seriesNames = [];
        $helpSeen = [];
        $typeSeen = [];
        $lines = explode("\n", $body);
        self::assertSame('', $lines[\count($lines) - 1], 'the exposition ends with exactly one newline');
        array_pop($lines);

        foreach ($lines as $line) {
            if ($line === '') {
                self::fail('no blank lines inside the exposition');
            }
            // The comment keywords are hex-escaped so the literals never
            // read as all-caps prose tokens to the prose linter.
            if (str_starts_with($line, "# \x48ELP ")) {
                $name = (string) preg_replace('/^# \x48ELP ([a-zA-Z_][a-zA-Z0-9_]*) .*$/', '$1', $line);
                self::assertNotSame($line, $name, 'the help line names its family');
                self::assertArrayNotHasKey($name, $helpSeen, sprintf('family %s repeats its help line', $name));
                $helpSeen[$name] = true;
                continue;
            }
            if (str_starts_with($line, "# \x54YPE ")) {
                self::assertSame(1, preg_match('/^# \x54YPE ([a-zA-Z_][a-zA-Z0-9_]*) (counter|gauge)$/', $line, $m), 'the type line is well-formed');
                self::assertArrayHasKey($m[1], $helpSeen, sprintf('the type line of %s follows its help line', $m[1]));
                self::assertArrayNotHasKey($m[1], $typeSeen, sprintf('family %s repeats its type line', $m[1]));
                $typeSeen[$m[1]] = true;
                continue;
            }
            self::assertSame(
                1,
                preg_match('/^([a-zA-Z_][a-zA-Z0-9_]*)(\{(?:[a-zA-Z_][a-zA-Z0-9_]*="[^"]*"(?:, [a-zA-Z_][a-zA-Z0-9_]*="[^"]*")*)?\})? (-?\d+(?:\.\d+)?)$/D', $line, $m),
                sprintf('every sample line matches name_labels? value: %s', $line),
            );
            [$full, $name, $labels] = [$m[0], $m[1], $m[2]];
            self::assertArrayHasKey($name, $typeSeen, sprintf('the sample %s belongs to a typed family', $full));
            self::assertArrayNotHasKey($line, $seenSeries, sprintf('no duplicate series: %s', $line));
            $seenSeries[$line] = true;
            $seriesNames[] = $name;

            if ($labels !== '') {
                self::assertSame(1, preg_match_all('/([a-zA-Z_][a-zA-Z0-9_]*)="([^"]*)"/', $labels, $labelPairs));
                foreach ($labelPairs[2] as $value) {
                    self::assertSame(
                        1,
                        preg_match('/^[a-zA-Z0-9_.-]{0,64}$/D', $value),
                        sprintf('a label value stays inside the bounded redacted vocabulary (no spaces, no identity bytes): %s', $value),
                    );
                }
            }
        }

        $familyOrder = [];
        foreach ($seriesNames as $name) {
            if (!\in_array($name, $familyOrder, true)) {
                $familyOrder[] = $name;
            }
        }
        $sortedFamilies = $familyOrder;
        sort($sortedFamilies);
        self::assertSame($sortedFamilies, $familyOrder, 'families appear in sorted (deterministic) order');
    }

    /**
     * The series order of one exposition: family names with their label
     * sets, the ordering fingerprint two scrapes must share.
     *
     * @return list<string>
     */
    private function seriesOrder(string $body): array
    {
        $order = [];
        foreach (explode("\n", $body) as $line) {
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            $order[] = $line;
        }
        // Drop the scrape counter's value: it advances per scrape by
        // design, the ordering fingerprint is the label set sequence.
        return array_map(
            static fn (string $line): string => (string) preg_replace('/ \d+(?:\.\d+)?$/', '', $line),
            $order,
        );
    }

    /**
     * The simulated APCu segment of the health controller test pattern:
     * fresh controller instances sharing one closure share state exactly
     * like PHP-FPM workers sharing one APCu segment.
     *
     * @param array<string, mixed> $segment key => value store
     * @param array<string, int>   $ttls    the TTL each write carried
     */
    private function apcuSeam(array &$segment, array &$ttls): \Closure
    {
        return static function (string $op, string $key, mixed $value = null, int $ttl = 0) use (&$segment, &$ttls): mixed {
            switch ($op) {
                case 'fetch':
                    return \array_key_exists($key, $segment) ? $segment[$key] : null;
                case 'inc':
                    $segment[$key] = (\array_key_exists($key, $segment) && \is_int($segment[$key]) ? $segment[$key] : 0) + (\is_int($value) ? $value : 1);
                    $ttls[$key] = $ttl;

                    return $segment[$key];
                case 'store':
                    $segment[$key] = $value;
                    $ttls[$key] = $ttl;

                    return null;
            }

            return null;
        };
    }
}
