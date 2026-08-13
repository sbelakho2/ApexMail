<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

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
use Psr\Log\LoggerInterface;

/**
 * Audit #35/#36: the risk metrics keys and decision logs must never carry
 * identity or bearer material. Metric keys are bounded to the tuple
 * "decisions:<scope>:<action>:<band>" plus the fixed counter/gauge/latency
 * names — NO challenge id, nonce, decision id, IP, user agent, session or
 * principal label. Decision logs (RiskGateway::logDecision) carry score /
 * action / band / reasons only — the decision id is deliberately excluded
 * (it would let log analysis correlate decisions across requests).
 */
final class MetricsRedactionTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    /** @var list<string> identity/bearer material that must never appear */
    private const FORBIDDEN_LABELS = ['challenge', 'nonce', 'ip', 'user_agent', 'session', 'principal', 'token', 'cookie'];

    /**
     * @return array{0: AdaptiveRiskEngine, 1: RiskGateway}
     */
    private function stack(?LoggerInterface $logger = null): array
    {
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        $engine = new AdaptiveRiskEngine(new FakeRiskStateStore(), $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1], $logger, policy: $policy);

        return [$engine, $gateway];
    }

    public function testMetricKeysAreBoundedAndNeverCarryDecisionIdsOrIdentity(): void
    {
        [, $gateway] = $this->stack();

        // Drive real decisions + post-issue signals so counters exist.
        for ($i = 0; $i < 5; $i++) {
            $decision = $gateway->preIssue('login', '198.51.100.7', null);
            $gateway->challengeIssued('login', '198.51.100.7', null, $decision->decisionId);
            $gateway->rateLimitHit('login', '198.51.100.7', null);
        }

        $snapshot = $gateway->metricsSnapshot();
        $keys = array_merge(
            array_keys($snapshot['counters'] ?? []),
            array_keys($snapshot['gauges'] ?? []),
            array_keys($snapshot['latencies'] ?? []),
        );
        self::assertNotEmpty($keys, 'the engine must have produced metrics');

        $bounded = '/^decisions:\d+:[a-z0-9_]+:\d+$/';
        $fixed = ['denied:limiter', 'degraded:breaker', 'degraded:store', 'store:observe', 'global:level', 'resources:argon_capacity'];
        foreach ($keys as $key) {
            self::assertTrue(
                \in_array($key, $fixed, true) || (bool) preg_match($bounded, (string) $key),
                sprintf('metric key "%s" must be a bounded tuple or a fixed name (low cardinality)', (string) $key)
            );
            self::assertDoesNotMatchRegularExpression('/[0-9a-f]{32}/', (string) $key, 'no decision id / nonce hex may leak into a metric key');
            foreach (self::FORBIDDEN_LABELS as $label) {
                self::assertStringNotContainsString($label, (string) $key, sprintf('metric key must not carry the "%s" label', $label));
            }
        }
    }

    public function testDecisionLogsNeverCarryDecisionIdsOrBearerMaterial(): void
    {
        $logger = new class implements LoggerInterface {
            /** @var list<array<string, mixed>> */
            public array $contexts = [];

            public function emergency($message, array $context = []): void { $this->contexts[] = $context; }
            public function alert($message, array $context = []): void { $this->contexts[] = $context; }
            public function critical($message, array $context = []): void { $this->contexts[] = $context; }
            public function error($message, array $context = []): void { $this->contexts[] = $context; }
            public function warning($message, array $context = []): void { $this->contexts[] = $context; }
            public function notice($message, array $context = []): void { $this->contexts[] = $context; }
            public function info($message, array $context = []): void { $this->contexts[] = $context; }
            public function debug($message, array $context = []): void { $this->contexts[] = $context; }
            public function log($level, $message, array $context = []): void { $this->contexts[] = $context; }
        };

        [, $gateway] = $this->stack($logger);
        $decision = $gateway->preIssue('login', '198.51.100.7', 'session-cookie-value');
        $gateway->challengeIssued('login', '198.51.100.7', 'session-cookie-value', $decision->decisionId);

        self::assertNotEmpty($logger->contexts, 'the gateway must have logged decisions');
        foreach ($logger->contexts as $context) {
            self::assertArrayNotHasKey('decision_id', $context, 'the decision id must never be logged (correlation handle only)');
            foreach ($context as $value) {
                if (\is_string($value)) {
                    self::assertDoesNotMatchRegularExpression('/[0-9a-f]{32}/', $value, 'no hex bearer material (nonce/decision id) may reach log context values');
                }
                if (\is_array($value)) {
                    foreach ($value as $inner) {
                        if (\is_string($inner)) {
                            self::assertDoesNotMatchRegularExpression('/[0-9a-f]{32}/', $inner, 'no hex bearer material may reach nested log context values');
                        }
                    }
                }
            }
        }
    }
}
