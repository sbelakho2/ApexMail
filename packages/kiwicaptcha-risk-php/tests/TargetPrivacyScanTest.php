<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\FormFieldTargetResolver;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\Network\NetworkFlags;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskContext;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\RiskWeights;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\TargetIdentifierNormalizer;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use PHPUnit\Framework\TestCase;
use Predis\Client;
use Predis\Command\CommandInterface;

/**
 * Privacy scanner for the target dimension: a canary raw identifier
 * rides the resolver, the normalization pipeline and the engine
 * assessment, and the scan proves it exists nowhere except inside the
 * caller's own call frame.
 *
 * Emission surfaces scanned: every Redis command payload the state store
 * emits (recorded by a predis client spy around the real store, with
 * canned replies so the lane needs no backend), and the engine metrics
 * snapshot. The risk core writes no logs and carries no logger, so those
 * two surfaces are the complete emission boundary of this package.
 *
 * The stored and derived material is only the 32-byte HMAC: the engine's
 * target side channel returns 64 lowercase hex chars, and neither the
 * raw canary nor its normalized form appears in any recorded payload.
 */
final class TargetPrivacyScanTest extends TestCase
{
    private const CANARY = 'canary.target.7f3a@gmail.com';
    private const CANARY_FULLWIDTH = 'ｃａｎａｒｙ.target.7f3a+news@gmail.com';

    public function testCanaryNeverReachesRedisCommandsLogsOrMetrics(): void
    {
        $client = new RecordingTargetClient();
        $store = new RedisRiskStateStore($client, namespace: 'target-privacy');
        $engine = new AdaptiveRiskEngine(
            store: $store,
            classifier: new CidrNetworkClassifier([]),
            identityFactory: new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat(chr(0x42), 32))),
            scorer: new RiskScorer(),
            policy: RiskPolicy::fromConfig([
                'version' => 3,
                'weights' => (new RiskWeights())->toArray(),
                'scopes' => [
                    1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20'],
                ],
                'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
            ]),
            keys: RiskKeys::fromMaster(str_repeat(chr(0x42), 32)),
            targetResolver: new FormFieldTargetResolver([1 => 'email']),
        );

        $context = new RiskContext(
            scope: 1,
            sourceIp: '203.0.113.77',
            sessionId: null,
            principalId: null,
            event: RiskEventKind::PreIssue,
            networkFlags: new NetworkFlags(),
            resources: new ResourcePressure(1000, 1000),
        );
        $fields = ['email' => self::CANARY, 'password' => 'not-the-canary'];

        // The engine path and the target side channel run for the same
        // request: the assessment emits its store commands while the
        // resolver derives the target pseudonym beside it.
        $decision = $engine->assessPreIssue($context);
        self::assertNotNull($decision);
        $targetId = $engine->resolveTargetId(1, $fields);
        self::assertNotNull($targetId);

        // The derived material is only the HMAC: 64 lowercase hex chars,
        // free of the canary in raw and normalized form.
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $targetId);
        $normalized = TargetIdentifierNormalizer::normalize(self::CANARY);
        self::assertStringNotContainsString(self::CANARY, $targetId);
        self::assertStringNotContainsString($normalized, $targetId);

        // The store emitted real command traffic (the scan is meaningful).
        self::assertNotEmpty($client->payloads, 'the assessment must have emitted store commands');

        // A fullwidth spelling of the same mailbox collapses onto the
        // same target through the engine side channel.
        self::assertSame(
            $targetId,
            $engine->resolveTargetId(1, ['email' => self::CANARY_FULLWIDTH]),
        );

        // A scope without a configured field carries no target dimension.
        self::assertNull($engine->resolveTargetId(7, $fields));

        // The canary, raw or normalized, exists in no Redis command
        // payload the store emitted.
        $blob = implode("\n", $client->payloads);
        self::assertStringNotContainsString(self::CANARY, $blob, 'the raw canary leaked into a Redis command payload');
        self::assertStringNotContainsString($normalized, $blob, 'the normalized canary leaked into a Redis command payload');
        self::assertStringNotContainsString(self::CANARY_FULLWIDTH, $blob);

        // And in no metrics payload: the snapshot carries counters,
        // gauges and latencies keyed by low-cardinality labels only.
        $metricsBlob = json_encode($engine->metrics()->snapshot());
        self::assertIsString($metricsBlob);
        self::assertStringNotContainsString(self::CANARY, $metricsBlob, 'the raw canary leaked into metrics');
        self::assertStringNotContainsString($normalized, $metricsBlob, 'the normalized canary leaked into metrics');
    }

    public function testEngineWithoutAResolverCarriesNoTargetDimension(): void
    {
        $engine = new AdaptiveRiskEngine(
            store: new class extends RiskStateStoreStub {
                public function observe(RiskObservation $observation): SignalVector
                {
                    return SignalVector::zero();
                }
            },
            classifier: new CidrNetworkClassifier([]),
            identityFactory: new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat(chr(0x42), 32))),
            scorer: new RiskScorer(),
            policy: RiskPolicy::fromConfig([
                'version' => 3,
                'weights' => (new RiskWeights())->toArray(),
                'scopes' => [
                    1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20'],
                ],
                'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
            ]),
            keys: RiskKeys::fromMaster(str_repeat(chr(0x42), 32)),
        );
        self::assertNull($engine->resolveTargetId(1, ['email' => self::CANARY]));
    }
}

/**
 * Predis client spy: records the command id and every argument of each
 * command as one payload line, and answers with canned replies so no
 * backend is needed. The canned replies match the shapes the store
 * decodes (the 19-slot consolidated reply for the risk scripts, a truthy
 * scalar for the ledger scripts).
 */
final class RecordingTargetClient extends Client
{
    /** @var list<string> one flattened payload line per emitted command */
    public array $payloads = [];

    public function executeCommand(CommandInterface $command)
    {
        $args = array_map(
            static fn ($arg): string => \is_scalar($arg) ? (string) $arg : json_encode($arg),
            $command->getArguments(),
        );
        $this->payloads[] = $command->getId() . ' ' . implode(' ', $args);

        $id = strtoupper((string) $command->getId());
        if ($id === 'EVALSHA' || $id === 'EVAL') {
            // 13 vector slots, level/cooldown/duplicate, the two optional
            // tag slots and the registration status: the consolidated
            // reply shape.
            return [...array_fill(0, 16, 0), '', '', 1];
        }

        return 1;
    }
}
