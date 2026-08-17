<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\Network\NetworkFlags;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskContext;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\RiskWeights;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use PHPUnit\Framework\TestCase;

/**
 * TRUST-BOUNDARY PROPERTY.
 *
 * The SignalVector carries NO client-visible fields: every one of its 13
 * fields is server-derived (the risk-v1.lua state channels and the
 * classifier's network-risk side channel). "Perturbing client-controlled
 * inputs of a vector" is therefore impossible — the vector-level property
 * risk_final >= risk_server_only holds trivially (a vector is a pure
 * function of server state; the scorer is a pure function of the vector,
 * and monotonicity of every field is already covered by ScoringPropertyTest).
 *
 * The REAL trust boundary is the engine: the RiskContext fields (scope,
 * sourceIp, sessionId, principalId, idempotencyKey, event) are
 * client-visible. The invariant under test: for IDENTICAL server state,
 * assess() with client-supplied session/principal/idempotency fields NEVER
 * yields a score lower than the same assessment without them.
 *
 * Subtlety: different IPs produce different pseudonyms with different
 * state, so the property is constrained to IDENTICAL server state — fresh
 * keys per iteration (two FRESH namespaces, one for the baseline context,
 * one for the varied context: the empty state is bit-identical). With
 * empty state the Lua's aggregation (risk-v1.lua: source/session/principal
 * dimensions MAX into the signal channels — they never subtract) leaves
 * every signal unchanged when a fresh session/principal is added, so the
 * invariant must hold; the 500 randomized iterations below pin it.
 */
final class RiskPropertyTest extends TestCase
{
    private const ITERATIONS = 500;

    private function policy(): RiskPolicy
    {
        return RiskPolicy::fromConfig([
            'version' => 3,
            'weights' => (new RiskWeights())->toArray(),
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20'],
                2 => ['base_risk' => 200, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20'],
                3 => ['base_risk' => 300, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20'],
            ],
            'global_floors' => [1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
        ]);
    }

    private function engine(RedisRiskStateStore $store): AdaptiveRiskEngine
    {
        $keys = RiskKeys::fromMaster(str_repeat(chr(0x42), 32));
        return new AdaptiveRiskEngine(
            store: $store,
            classifier: new CidrNetworkClassifier([['cidr' => '203.0.113.0/24', 'flags' => ['hosting']]]),
            identityFactory: new RiskIdentityFactory($keys),
            scorer: new RiskScorer(),
            policy: $this->policy(),
            keys: $keys,
        );
    }

    private function context(int $scope, string $ip, ?string $sessionId, ?string $principalId, NetworkFlags $flags): RiskContext
    {
        return new RiskContext(
            scope: $scope,
            sourceIp: $ip,
            sessionId: $sessionId,
            principalId: $principalId,
            event: RiskEventKind::PreIssue,
            networkFlags: $flags,
            resources: new ResourcePressure(1000, 1000),
        );
    }

    private function randomIp(SeededVector $prng): string
    {
        // Valid, non-reserved dotted-quad (1..255 per octet).
        return sprintf(
            '%d.%d.%d.%d',
            1 + $prng->next() % 254,
            $prng->next() % 256,
            $prng->next() % 256,
            1 + $prng->next() % 254,
        );
    }

    private function randomId(SeededVector $prng, string $prefix): ?string
    {
        if ($prng->next() % 4 === 0) {
            return null;
        }
        return sprintf('%s-%d-%d-%d', $prefix, $prng->next(), $prng->next(), $prng->next());
    }

    /**
     * Vector-level property (documented, holds trivially): the SignalVector
     * is a pure function of server state — there are no client-visible
     * fields to perturb. Re-assert the scorer is a pure function of the
     * vector (identical vectors score identically) and that the vector
     * field set is exactly the server-derived contract set.
     */
    public function testSignalVectorHasNoClientControlledFields(): void
    {
        $scorer = new RiskScorer();
        $weights = new RiskWeights();
        $prng = new SeededVector();

        self::assertSame(
            [
                'source_fast', 'source_slow', 'subnet_fast', 'issue_debt', 'bad_proof',
                'malformed', 'replay', 'action_failure', 'scope_switch', 'global_pressure',
                'network_risk', 'trust_credit', 'principal_credit',
            ],
            array_keys(SignalVector::zero()->toArray()),
            'the 13 signal fields are exactly the server-derived contract set'
        );

        for ($i = 0; $i < 100; $i++) {
            $vector = SignalVector::fromArray($prng->vector());
            self::assertSame(
                $scorer->score(100, $vector, $weights),
                $scorer->score(100, $vector, $weights),
                'the scorer must be a pure function of the server-derived vector'
            );
        }
    }

    /**
     * The engine-level trust-boundary invariant, 500 randomized iterations
     * against real Redis (skipped without RISK_REDIS_URL): with IDENTICAL
     * (fresh, empty) server state, client-supplied session/principal/
     * idempotency-key fields never lower the RiskDecision score.
     */
    public function testClientSuppliedIdentityFieldsNeverLowerTheScore(): void
    {
        $url = getenv('RISK_REDIS_URL');
        if (!is_string($url) || $url === '') {
            self::markTestSkipped('RISK_REDIS_URL not set; start redis with: docker run -d -p 6399:6379 redis:7-alpine');
        }
        $client = RedisRiskStateStore::createClient($url);
        $classifier = new CidrNetworkClassifier([['cidr' => '203.0.113.0/24', 'flags' => ['hosting']]]);
        $prng = new SeededVector();

        for ($i = 0; $i < self::ITERATIONS; $i++) {
            $scope = 1 + $prng->next() % 3;
            $ip = $this->randomIp($prng);
            $sessionId = $this->randomId($prng, 'sess');
            $principalId = $this->randomId($prng, 'prin');
            $key = $this->randomId($prng, 'idem');
            $flags = $classifier->classify($ip);

            // Two FRESH namespaces = bit-identical EMPTY server state: the
            // score is a pure function of the state, and the varied context
            // differs from the baseline ONLY in the client-supplied fields.
            $baselineStore = new RedisRiskStateStore($client, namespace: 'propb' . bin2hex(random_bytes(4)));
            $variedStore = new RedisRiskStateStore($client, namespace: 'propv' . bin2hex(random_bytes(4)));
            $baseline = $this->engine($baselineStore)->assess($this->context($scope, $ip, null, null, $flags));
            $varied = $this->engine($variedStore)->assess(
                $this->context($scope, $ip, $sessionId, $principalId, $flags),
                $key,
            );

            self::assertGreaterThanOrEqual(
                $baseline->score,
                $varied->score,
                sprintf(
                    'iteration %d: client-supplied identity fields lowered the score from %d to %d ' .
                    '(scope=%d ip=%s session=%s principal=%s idempotency=%s)',
                    $i,
                    $baseline->score,
                    $varied->score,
                    $scope,
                    $ip,
                    var_export($sessionId, true),
                    var_export($principalId, true),
                    var_export($key, true),
                ),
            );
        }
    }
}
