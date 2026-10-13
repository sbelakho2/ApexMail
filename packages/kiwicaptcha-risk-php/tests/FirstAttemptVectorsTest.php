<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Asn\AsnDataset;
use KiwiCaptcha\Risk\Marks\MarksReaderInterface;
use KiwiCaptcha\Risk\Marks\MarksRequest;
use KiwiCaptcha\Risk\Marks\MarksView;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\Network\NetworkFlags;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskContext;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskReason;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\RiskV2Context;
use KiwiCaptcha\Risk\RiskWeights;
use KiwiCaptcha\Risk\Storage\PrincipalNetworkTagStoreInterface;
use PHPUnit\Framework\TestCase;

/**
 * The shared first-attempt prevention corpus (protocol/risk-v1/
 * first-attempt-vectors.json): every row pins the trusted-history state
 * around one AuthenticationSuccess and the per-mode verdict. The Rust
 * mirror (packages/kiwicaptcha-risk/tests/first_attempt_vectors.rs)
 * derives the identical outputs over the same file. The session tag is
 * the only seeded tag, so the post-call device trust reads as the
 * binding detector; trust is sticky, so a record without the flag
 * never revokes a minted mirror.
 */
final class FirstAttemptVectorsTest extends TestCase
{
    private const RAW_USER = 'alice@example.com';
    private const SESSION = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    private const DEVICE = 'dddddddddddddddddddddddddddddddd';
    private const HOME_IP = '198.51.100.42';
    private const OTHER_ASN_IP = '203.0.113.42';
    private const OLD_HOME_IP = '192.0.2.7';

    private RiskIdentityFactory $identity;
    private string $principalHex;
    private string $sessionTag;
    private string $deviceTag;
    private FirstAttemptVectorsNetworks $networks;

    public static function vectorsPath(): string
    {
        $override = getenv('RISK_FIRST_ATTEMPT_VECTORS_PATH');
        if (is_string($override) && $override !== '') {
            return $override;
        }

        return __DIR__.'/../../../protocol/risk-v1/first-attempt-vectors.json';
    }

    protected function setUp(): void
    {
        $this->identity = new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat("\x42", 32)));
        $this->principalHex = $this->identity->principalId(self::RAW_USER);
        $this->sessionTag = 'session:'.$this->identity->sessionId(self::SESSION);
        $this->deviceTag = 'device:'.$this->identity->deviceId(self::DEVICE);
    }

    private function buildEngine(
        string $noveltyEnforcement,
        bool $withDataset,
        bool $probeFailure,
        int $globalLevel = 0,
    ): AdaptiveRiskEngine {
        // The sample dataset from the corpus: the same fixture the Rust
        // side reads, so both cores resolve the same ASN numbers.
        $datasetPath = self::vectorsPath();
        $root = dirname($datasetPath, 3);
        $datasetRelative = null;
        $doc = json_decode((string) file_get_contents($datasetPath), true);
        $datasetRelative = $doc['dataset_path'] ?? null;
        $networks = new FirstAttemptVectorsNetworks($probeFailure);
        $this->networks = $networks;
        $store = new class ($globalLevel) extends RiskStateStoreStub {
            public function __construct(private readonly int $fixedGlobalLevel = 0)
            {
            }

            public function observe(\KiwiCaptcha\Risk\RiskObservation $observation): \KiwiCaptcha\Risk\SignalVector
            {
                return \KiwiCaptcha\Risk\SignalVector::fromArray([]);
            }

            public function lastGlobalLevel(): int
            {
                return $this->fixedGlobalLevel;
            }
        };
        $marksReader = new class implements MarksReaderInterface {
            public function requestMarks(MarksRequest $request): MarksView
            {
                return MarksView::read(new EmptyMarksStore(), [], null);
            }

            public function markTtlMs(): int
            {
                return 600000;
            }
        };

        return new AdaptiveRiskEngine(
            store: $store,
            classifier: new CidrNetworkClassifier([]),
            identityFactory: new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat("\x42", 32))),
            scorer: new RiskScorer(),
            policy: RiskPolicy::fromConfig([
                'version' => 3,
                'weights' => (new RiskWeights())->toArray(),
                'scopes' => [1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20']],
                'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
            ]),
            keys: RiskKeys::fromMaster(str_repeat("\x42", 32)),
            enableGlobalPressure: true,
            noveltyEnforcement: $noveltyEnforcement,
            principalNetworks: $networks,
            marksReader: $marksReader,
            asnDataset: $withDataset && is_string($datasetRelative)
                ? AsnDataset::open($root.'/'.$datasetRelative)
                : null,
        );
    }

    private function loginContext(string $ip, RiskEventKind $event = RiskEventKind::AuthenticationSuccess): RiskContext
    {
        return new RiskContext(
            scope: 1,
            sourceIp: $ip,
            sessionId: self::SESSION,
            principalId: self::RAW_USER,
            event: $event,
            networkFlags: new NetworkFlags(),
            resources: new ResourcePressure(1000, 1000),
            deviceId: self::DEVICE,
        );
    }

    public function testSharedFirstAttemptVectorsMatchRust(): void
    {
        $doc = json_decode((string) file_get_contents(self::vectorsPath()), true);
        self::assertSame('risk-v1', $doc['protocol']);
        self::assertSame('first-attempt-vectors', $doc['kind']);
        self::assertGreaterThanOrEqual(16, count($doc['vectors']), 'the F16 cross product must stay rich');
        foreach ($doc['vectors'] as $vector) {
            $asn = $vector['asn'];
            $prefixSeen = $vector['prefix'] === 'seen';
            $accountTrusted = $vector['account_trusted'];
            $ip = $asn === 'unseen' ? self::OTHER_ASN_IP : self::HOME_IP;
            $probeFailure = $vector['probe_failure'] ?? false;
            $globalLevel = ($vector['expected']['learn']['global_attack'] ?? false) ? 1 : 0;
            $event = ($vector['event'] ?? 'authentication_success') === 'solve_success'
                ? RiskEventKind::SolveSuccess
                : RiskEventKind::AuthenticationSuccess;
            $breached = $vector['breached'] ?? false;

            foreach (['learn' => 'learn', 'enforce' => 'enforce'] as $mode => $enforcement) {
                $expected = $vector['expected'][$mode];
                $engine = $this->buildEngine($enforcement, $asn !== 'absent', $probeFailure, $globalLevel);

                if ($prefixSeen) {
                    $this->networks->seedPrincipalTag($this->principalHex, AdaptiveRiskEngine::networkBucket($ip), $accountTrusted);
                } elseif ($accountTrusted) {
                    $this->networks->seedPrincipalTag($this->principalHex, AdaptiveRiskEngine::networkBucket(self::OLD_HOME_IP), true);
                }
                if ($asn === 'seen') {
                    $this->networks->seedPrincipalTag($this->principalHex, 'asn:64498', true);
                }
                if (($vector['continuity']) === 'bound') {
                    $this->networks->seedPrincipalTag($this->principalHex, $this->sessionTag, true);
                } elseif (($vector['continuity']) === 'seen-untrusted') {
                    $this->networks->seedPrincipalTag($this->principalHex, $this->sessionTag, false);
                }

                $context = $this->loginContext($ip, $event);
                $decision = $breached
                    ? $engine->reassessV2($context, new RiskV2Context(breachedCredential: true))
                    : $engine->reassess($context);

                $label = sprintf('%s (%s)', $vector['note'], $mode);
                self::assertSame($expected['action'], $decision->action->value, "vector {$label} action");
                self::assertSame(
                    $expected['novel_network'],
                    $decision->hasReason(RiskReason::NovelNetwork),
                    "vector {$label} novel-network reason",
                );
                self::assertSame(
                    $expected['evidence_unavailable'],
                    $decision->hasReason(RiskReason::EvidenceUnavailable),
                    "vector {$label} evidence-unavailable reason",
                );
                self::assertSame(
                    $expected['global_attack'],
                    $decision->hasReason(RiskReason::GlobalAttack),
                    "vector {$label} global-attack reason",
                );
                self::assertSame(
                    $expected['breached_credential'],
                    $decision->hasReason(RiskReason::BreachedCredential),
                    "vector {$label} breached-credential reason",
                );
                $this->assertTrustState($expected['session_trust'], $this->sessionTag, $label, 'session_trust');
                $this->assertTrustState($expected['device_trust'], $this->deviceTag, $label, 'device_trust');
            }
        }
    }

    /** minted = live mirror, unminted = recorded without one, absent or unbound = never recorded. */
    private function assertTrustState(string $state, string $tag, string $label, string $column): void
    {
        if ($state === 'minted') {
            self::assertSame(
                true,
                $this->networks->recordedTrust($this->principalHex, $tag),
                "vector {$label} {$column} must be minted",
            );

            return;
        }
        if ($state === 'unminted') {
            self::assertTrue(
                $this->networks->isRecorded($this->principalHex, $tag),
                "vector {$label} {$column} must be recorded",
            );
            self::assertNotTrue(
                $this->networks->recordedTrust($this->principalHex, $tag),
                "vector {$label} {$column} must stay unminted",
            );

            return;
        }
        self::assertTrue(
            in_array($state, ['absent', 'unbound'], true),
            "vector {$label} unknown {$column} state {$state}",
        );
        self::assertFalse(
            $this->networks->isRecorded($this->principalHex, $tag),
            "vector {$label} {$column} must never be recorded",
        );
    }
}

/**
 * The in-memory trusted-history twin of the canonical Lua semantics:
 * the bare tag carries seen-ness, the `t:` mirror carries trust, a
 * record only ever mints the mirror (never revokes), and the
 * any-trusted probe counts network-class mirrors only. Seed state is
 * injected by the test through seedPrincipalTag.
 */
final class FirstAttemptVectorsNetworks implements PrincipalNetworkTagStoreInterface
{
    /** @var array<string, array<string, true>> */
    private array $tags = [];

    /** @var array<string, array<string, true>> */
    private array $trusted = [];

    public function __construct(private readonly bool $failingReads = false)
    {
    }

    public function seedPrincipalTag(string $principalId, string $tag, bool $trusted): void
    {
        $this->tags[$principalId][$tag] = true;
        if ($trusted) {
            $this->trusted[$principalId][$tag] = true;
        }
    }

    public function principalNetworkSeen(string $principalId, string $network): ?bool
    {
        if ($this->failingReads) {
            throw new \KiwiCaptcha\Risk\Storage\RiskStoreException('tag backend unavailable');
        }

        return isset($this->tags[$principalId][$network]);
    }

    public function recordPrincipalNetworkTag(string $principalId, string $network, bool $trusted = false): bool
    {
        $isNew = !isset($this->tags[$principalId][$network]);
        $this->tags[$principalId][$network] = true;
        if ($trusted) {
            $this->trusted[$principalId][$network] = true;
        }

        return $isNew;
    }

    private static function isNetworkClass(string $tag): bool
    {
        if (str_starts_with($tag, 'session:') || str_starts_with($tag, 'device:') || str_starts_with($tag, 't:')) {
            return false;
        }
        if (str_starts_with($tag, 'net:') || str_starts_with($tag, 'asn:')) {
            return true;
        }

        return $tag !== '' && preg_match('/^[0-9a-f]+$/', $tag) === 1;
    }

    public function principalHasTrustedNetwork(string $principalId): ?bool
    {
        if ($this->failingReads) {
            throw new \KiwiCaptcha\Risk\Storage\RiskStoreException('tag backend unavailable');
        }
        foreach ($this->tags[$principalId] ?? [] as $tag => $_) {
            if (self::isNetworkClass($tag) && isset($this->trusted[$principalId][$tag])) {
                return true;
            }
        }

        return false;
    }

    public function tagIsTrusted(string $principalId, string $network): ?bool
    {
        if ($this->failingReads) {
            throw new \KiwiCaptcha\Risk\Storage\RiskStoreException('tag backend unavailable');
        }

        return isset($this->tags[$principalId][$network])
            && isset($this->trusted[$principalId][$network]);
    }

    public function forgetDevices(string $principalId): void
    {
        foreach (array_keys($this->tags[$principalId] ?? []) as $tag) {
            if (str_starts_with($tag, 'session:') || str_starts_with($tag, 'device:')) {
                unset($this->tags[$principalId][$tag]);
            }
        }
    }

    /** Assertion-side state reads: they never simulate the outage. */
    public function isRecorded(string $principalId, string $tag): bool
    {
        return isset($this->tags[$principalId][$tag]);
    }

    public function recordedTrust(string $principalId, string $tag): ?bool
    {
        return $this->isRecorded($principalId, $tag)
            ? isset($this->trusted[$principalId][$tag])
            : null;
    }
}
