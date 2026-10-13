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
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\RiskWeights;
use KiwiCaptcha\Risk\Storage\PrincipalNetworkTagStoreInterface;
use PHPUnit\Framework\TestCase;

/**
 * The first-attempt novelty gate against ISP-matched residential
 * proxies (D3.5 P0-2). A known ASN is NOT an automatic pass: a stuffer
 * who buys proxies on the victim's own ISP rides the same ASN on a
 * fresh /64. The same-ASN new-prefix shape is a weaker novelty signal
 * that fires unless device continuity (the first-party session
 * pseudonym) vouches for the browser.
 */
final class FirstAttemptNoveltyTest extends TestCase
{
    private const RAW_USER = 'alice@example.com';
    private const SESSION = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    private const DEVICE = 'dddddddddddddddddddddddddddddddd';
    private const HOME_IP = '10.1.2.3';
    private const ATTACKER_SAME_ASN = '10.9.9.9';
    private const ATTACKER_OTHER_ASN = '45.1.2.3';
    private const HOME_ASN_TAG = 'asn:64496';

    private RiskIdentityFactory $identity;
    private string $principalHex;
    private string $asnFixture;
    private PrincipalNetworkTagStoreInterface $networks;

    protected function setUp(): void
    {
        $keys = RiskKeys::fromMaster(str_repeat("\x11", 32));
        $this->identity = new RiskIdentityFactory($keys);
        $this->principalHex = $this->identity->principalId(self::RAW_USER);
        $this->asnFixture = sys_get_temp_dir().'/kiwi-novelty-asn-'.getmypid().'.tsv';
        file_put_contents(
            $this->asnFixture,
            "# test dataset\n10.0.0.0\t10.255.255.255\t64496\n45.0.0.0\t45.255.255.255\t64500\n",
        );
    }

    protected function tearDown(): void
    {
        @unlink($this->asnFixture);
    }

    /** @param array<string, true> $tags */
    private function buildEngine(
        array $tags,
        string $noveltyEnforcement = 'enforce',
        bool $failingReads = false,
        bool $failingTargetReads = false,
        string $failureClass = \KiwiCaptcha\Risk\Storage\RiskStoreException::class,
        bool $withMarksReader = true,
    ): AdaptiveRiskEngine {
        // The same identity factory as setUp: the tag store is keyed by
        // the hashed principal, so the engine and the seed must agree.
        $keys = RiskKeys::fromMaster(str_repeat("\x11", 32));
        $identity = new RiskIdentityFactory($keys);
        $store = new class extends RiskStateStoreStub {
            public bool $failingTargetReads = false;

            public function observe(\KiwiCaptcha\Risk\RiskObservation $observation): \KiwiCaptcha\Risk\SignalVector
            {
                return \KiwiCaptcha\Risk\SignalVector::fromArray([]);
            }

            public function readTargetState(string $targetId): array
            {
                if ($this->failingTargetReads) {
                    throw new \KiwiCaptcha\Risk\Storage\RiskStoreException('target backend unavailable');
                }

                return parent::readTargetState($targetId);
            }
        };
        $store->failingTargetReads = $failingTargetReads;
        $networks = new class ($tags, $failingReads, $failureClass) implements PrincipalNetworkTagStoreInterface {
            /**
             * @param array<string, array<string, true>> $tags
             * @param array<string, array<string, true>> $trusted
             */
            public function __construct(
                private array $tags,
                private bool $failingReads = false,
                private string $failureClass = \KiwiCaptcha\Risk\Storage\RiskStoreException::class,
                private array $trusted = [],
            ) {
                // Seeded history stands for the learned trusted state:
                // it was minted by Allow logins before the test window.
                foreach (array_keys($this->tags) as $principal) {
                    foreach (array_keys($this->tags[$principal]) as $tag) {
                        $this->trusted[$principal][$tag] = true;
                    }
                }
            }

            public function principalNetworkSeen(string $principalId, string $network): ?bool
            {
                if ($this->failingReads) {
                    throw new $this->failureClass('tag backend unavailable');
                }

                return isset($this->tags[$principalId][$network]);
            }

            public function recordPrincipalNetworkTag(string $principalId, string $network, bool $trusted = false): bool
            {
                // The canonical record.lua contract: the tag upserts on
                // every record, a trusted record mints the trust mirror
                // even over an existing untrusted tag, and the answer is
                // whether the record was newly created.
                $isNew = !isset($this->tags[$principalId][$network]);
                $this->tags[$principalId][$network] = true;
                if ($trusted) {
                    $this->trusted[$principalId][$network] = true;
                }

                return $isNew;
            }

            public function principalHasTrustedNetwork(string $principalId): ?bool
            {
                if ($this->failingReads) {
                    throw new $this->failureClass('tag backend unavailable');
                }

                return isset($this->tags[$principalId]) && $this->tags[$principalId] !== [];
            }

            public function tagIsTrusted(string $principalId, string $network): ?bool
            {
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
        };
        $this->networks = $networks;
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
            identityFactory: $identity,
            scorer: new RiskScorer(),
            policy: RiskPolicy::fromConfig([
                'version' => 3,
                'weights' => (new RiskWeights())->toArray(),
                'scopes' => [1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20']],
                'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
            ]),
            keys: $keys,
            enableGlobalPressure: true,
            noveltyEnforcement: $noveltyEnforcement,
            principalNetworks: $networks,
            marksReader: $withMarksReader ? $marksReader : null,
            asnDataset: AsnDataset::open($this->asnFixture),
            targetResolver: new \KiwiCaptcha\Risk\FormFieldTargetResolver([1 => 'username']),
        );
    }

    private function loginContext(string $ip, ?string $sessionId, ?string $deviceId = null, array $targetFields = []): RiskContext
    {
        return new RiskContext(
            scope: 1,
            sourceIp: $ip,
            sessionId: $sessionId,
            principalId: self::RAW_USER,
            event: RiskEventKind::AuthenticationSuccess,
            networkFlags: new NetworkFlags(),
            resources: new ResourcePressure(1000, 1000),
            deviceId: $deviceId,
            targetFields: $targetFields,
        );
    }

    /**
     * The learned history: the home /32, the home ASN, and the owner's
     * continuity session bound to the principal at a prior login.
     */
    private function homeTags(): array
    {
        return [
            $this->principalHex => [
                self::HOME_ASN_TAG => true,
                AdaptiveRiskEngine::networkBucket(self::HOME_IP) => true,
                'session:'.$this->identity->sessionId(self::SESSION) => true,
            ],
        ];
    }

    /** Home history without a bound session (the attacker's shape). */
    private function homeTagsUnbound(): array
    {
        return [
            $this->principalHex => [
                self::HOME_ASN_TAG => true,
                AdaptiveRiskEngine::networkBucket(self::HOME_IP) => true,
            ],
        ];
    }

    public function testAnUnknownAsnIsNovel(): void
    {
        $engine = $this->buildEngine($this->homeTags());
        $decision = $engine->reassess($this->loginContext(self::ATTACKER_OTHER_ASN, self::SESSION));
        self::assertNotSame(
            \KiwiCaptcha\Risk\RiskAction::Allow,
            $decision->action,
            'an unknown ASN is novel and must not land on the Allow path',
        );
    }

    public function testAKnownAsnAndKnownPrefixIsNotNovel(): void
    {
        $engine = $this->buildEngine($this->homeTags());
        $decision = $engine->reassess($this->loginContext(self::HOME_IP, self::SESSION));
        self::assertSame(
            \KiwiCaptcha\Risk\RiskAction::Allow,
            $decision->action,
            'the home network on the home ASN is not novel',
        );
    }

    /**
     * The residential-proxy bypass: a stuffer on the victim's own ISP
     * ASN, fresh /64, no device continuity. Before this change the known
     * ASN was an automatic pass. It must now escalate.
     */
    public function testAKnownAsnWithANewPrefixAndNoDeviceContinuityIsNovel(): void
    {
        $engine = $this->buildEngine($this->homeTags());
        $decision = $engine->reassess($this->loginContext(self::ATTACKER_SAME_ASN, null));
        self::assertNotSame(
            \KiwiCaptcha\Risk\RiskAction::Allow,
            $decision->action,
            'same-ASN new-prefix without device continuity is the residential-proxy shape and must escalate',
        );
    }

    /** A returning browser on a new /64 of its home ISP is normal. */
    public function testAKnownAsnWithANewPrefixAndDeviceContinuityIsNotNovel(): void
    {
        $engine = $this->buildEngine($this->homeTags());
        $decision = $engine->reassess($this->loginContext(self::ATTACKER_SAME_ASN, self::SESSION));
        self::assertSame(
            \KiwiCaptcha\Risk\RiskAction::Allow,
            $decision->action,
            'a returning browser on a new /64 of its home ISP passes on device continuity',
        );
    }

    /**
     * The ISP-matched bypass with a cookie: the attacker mints a fresh
     * 32-hex value (they loaded the login page). Unbound sessions are
     * never continuity, so the known-ASN new-prefix shape must still
     * escalate.
     */
    public function testAFreshUnboundCookieIsNotDeviceContinuity(): void
    {
        $engine = $this->buildEngine($this->homeTagsUnbound());
        $decision = $engine->reassess($this->loginContext(self::ATTACKER_SAME_ASN, self::SESSION));
        self::assertNotSame(
            \KiwiCaptcha\Risk\RiskAction::Allow,
            $decision->action,
            'a fresh unbound cookie is not device continuity: the residential-proxy shape must escalate',
        );
    }

    public function testLearnModeRecordsButDoesNotEscalate(): void
    {
        $engine = $this->buildEngine($this->homeTags(), 'learn');
        $decision = $engine->reassess($this->loginContext(self::ATTACKER_SAME_ASN, null));
        self::assertSame(
            \KiwiCaptcha\Risk\RiskAction::Allow,
            $decision->action,
            'learn mode is the rollout window: novel networks are recorded, never escalated',
        );
    }

    /**
     * Learn mode is the seeding window: a successful (Allow) login
     * binds the session and accrues the trusted network and ASN
     * history, so the second login from the same /64 is no longer
     * novel and carries no novelty signal.
     */
    public function testLearnModeAccruesTrustedHistoryOnAllow(): void
    {
        $engine = $this->buildEngine([], 'learn');
        $networkBucket = AdaptiveRiskEngine::networkBucket(self::HOME_IP);

        $first = $engine->reassess($this->loginContext(self::HOME_IP, self::SESSION));
        self::assertSame(
            \KiwiCaptcha\Risk\RiskAction::Allow,
            $first->action,
            'learn mode never escalates a first login',
        );

        // The post-Allow binding recorded the network bucket and the
        // ASN bucket with the trust flag minted (the session binding
        // stays alongside them).
        self::assertTrue(
            $this->networks->principalNetworkSeen($this->principalHex, $networkBucket),
            'the Allow binding must record the network bucket',
        );
        self::assertTrue(
            $this->networks->principalNetworkSeen($this->principalHex, self::HOME_ASN_TAG),
            'the Allow binding must record the ASN bucket',
        );
        self::assertTrue(
            $this->networks->tagIsTrusted($this->principalHex, $networkBucket),
            'the recorded network tag must carry trust',
        );
        self::assertTrue(
            $this->networks->tagIsTrusted($this->principalHex, self::HOME_ASN_TAG),
            'the recorded ASN tag must carry trust',
        );

        $second = $engine->reassess($this->loginContext(self::HOME_IP, self::SESSION));
        self::assertSame(
            \KiwiCaptcha\Risk\RiskAction::Allow,
            $second->action,
            'the second login from the same /64 rides the accrued history',
        );
        self::assertFalse(
            $second->hasReason(\KiwiCaptcha\Risk\RiskReason::NovelNetwork),
            'the second login from the same /64 is not novel',
        );
    }

    /**
     * Enforce mode never lets a repeated attempt earn its own trust:
     * the post-Allow binding is the only writer, so a stepped-up login
     * records nothing and every retry from the same IP stays novel.
     */
    public function testRetryFromSameNetworkStaysSteppedUp(): void
    {
        $engine = $this->buildEngine([], 'enforce');
        $networkBucket = AdaptiveRiskEngine::networkBucket(self::HOME_IP);

        for ($attempt = 1; $attempt <= 10; $attempt++) {
            $decision = $engine->reassess($this->loginContext(self::HOME_IP, self::SESSION));
            self::assertSame(
                \KiwiCaptcha\Risk\RiskAction::StepUp,
                $decision->action,
                sprintf('retry %d from the same network must stay stepped up', $attempt),
            );
        }

        // Zero network tags written across all ten attempts: neither
        // the network bucket, nor the ASN bucket, nor the session.
        self::assertFalse($this->networks->principalNetworkSeen($this->principalHex, $networkBucket));
        self::assertFalse($this->networks->principalNetworkSeen($this->principalHex, self::HOME_ASN_TAG));
        self::assertFalse($this->networks->principalNetworkSeen(
            $this->principalHex,
            'session:'.$this->identity->sessionId(self::SESSION),
        ));
    }

    /**
     * Fail closed on an unreadable history: a store error on any probe
     * means no read can vouch for the login. Enforce mode treats the
     * request as novel and steps it up carrying the evidence-
     * unavailable reason, with the degraded:evidence metric recorded.
     */
    public function testAStoreFailureStepsUpWithTheEvidenceUnavailableReason(): void
    {
        $engine = $this->buildEngine([], 'enforce', failingReads: true);
        $decision = $engine->reassess($this->loginContext(self::HOME_IP, self::SESSION));
        self::assertSame(
            \KiwiCaptcha\Risk\RiskAction::StepUp,
            $decision->action,
            'unreadable trusted history cannot vouch for the login: fail closed',
        );
        self::assertTrue($decision->hasReason(\KiwiCaptcha\Risk\RiskReason::EvidenceUnavailable));
        self::assertSame(
            1,
            $engine->metrics()->snapshot()['counters']['degraded:evidence'] ?? 0,
            'the degraded:evidence metric records the store failure',
        );
    }

    /** Learn mode never escalates on a store failure: Allow carrying the reason. */
    public function testAStoreFailureInLearnModeStaysAllowCarryingTheReason(): void
    {
        $engine = $this->buildEngine([], 'learn', failingReads: true);
        $decision = $engine->reassess($this->loginContext(self::HOME_IP, self::SESSION));
        self::assertSame(
            \KiwiCaptcha\Risk\RiskAction::Allow,
            $decision->action,
            'learn mode records the evidence failure without escalating',
        );
        self::assertTrue($decision->hasReason(\KiwiCaptcha\Risk\RiskReason::EvidenceUnavailable));
        self::assertFalse(
            $decision->hasReason(\KiwiCaptcha\Risk\RiskReason::NovelNetwork),
            'learn mode never reports the novelty signal as enforcing',
        );
    }

    /**
     * Any probe error class fails closed: an InvalidArgumentException
     * (a rejected tag on the record surface, for example) means no
     * readable history vouches for the login, exactly like a store
     * outage. Enforce mode steps it up with the evidence-unavailable
     * reason; nothing reads as neutral.
     */
    public function testAnUnexpectedProbeFailureStillFailsClosed(): void
    {
        $engine = $this->buildEngine(
            $this->homeTags(),
            'enforce',
            failingReads: true,
            failureClass: \InvalidArgumentException::class,
        );
        $decision = $engine->reassess($this->loginContext(self::HOME_IP, self::SESSION));
        self::assertSame(
            \KiwiCaptcha\Risk\RiskAction::StepUp,
            $decision->action,
            'a type violation from the tag surface cannot vouch for the login: fail closed',
        );
        self::assertTrue($decision->hasReason(\KiwiCaptcha\Risk\RiskReason::EvidenceUnavailable));
    }

    /**
     * Learn mode's deferred step-up must not mint device trust. A
     * novel login is allowed (the rollout window's leniency), but its
     * session and device bindings are recorded without the trust
     * flag: a stolen-credential login from a novel network leaves
     * nothing trusted behind. The second, non-novel Allow from the
     * same network is what earns the trust (the repeat visit is the
     * trust signal), and a credential change revokes the trust
     * mirrors so the gate re-arms.
     */
    public function testLearnModeNovelAllowDoesNotMintDeviceTrust(): void
    {
        $engine = $this->buildEngine([], 'learn');
        $deviceTag = 'device:'.$this->identity->deviceId(self::DEVICE);
        $sessionTag = 'session:'.$this->identity->sessionId(self::SESSION);
        $networkBucket = AdaptiveRiskEngine::networkBucket(self::HOME_IP);

        $first = $engine->reassess($this->loginContext(self::HOME_IP, self::SESSION, self::DEVICE));
        self::assertSame(
            \KiwiCaptcha\Risk\RiskAction::Allow,
            $first->action,
            'learn mode never escalates a first (novel) login',
        );
        self::assertTrue(
            $this->networks->principalNetworkSeen($this->principalHex, $deviceTag),
            'the binding records the device pseudonym',
        );
        self::assertFalse(
            $this->networks->tagIsTrusted($this->principalHex, $deviceTag),
            'a novel Allow must not mint device trust',
        );
        self::assertFalse(
            $this->networks->tagIsTrusted($this->principalHex, $sessionTag),
            'a novel Allow must not mint session trust either (both continuity probes read the trust flag)',
        );
        self::assertTrue(
            $this->networks->tagIsTrusted($this->principalHex, $networkBucket),
            'the network bucket keeps the learn-history record with trust',
        );
        self::assertTrue(
            $this->networks->tagIsTrusted($this->principalHex, self::HOME_ASN_TAG),
            'the ASN bucket keeps the learn-history record with trust',
        );

        $second = $engine->reassess($this->loginContext(self::HOME_IP, self::SESSION, self::DEVICE));
        self::assertSame(
            \KiwiCaptcha\Risk\RiskAction::Allow,
            $second->action,
            'the second login from the same network rides the accrued history',
        );
        self::assertTrue(
            $this->networks->tagIsTrusted($this->principalHex, $deviceTag),
            'a non-novel Allow is a trust-minting event',
        );
    }

    /**
     * A failed live target read never reads as clean: the fallback
     * path returns the saturated attack picture (the threshold failure
     * count, the spread saturated on both axes), the decision carries
     * the evidence-unavailable reason, and enforce mode steps the
     * login up. The step-up is the completable rung: the real owner
     * can always finish the login.
     */
    public function testAStoreFailureOnTheTargetReadReadsSaturatedAndStepsUp(): void
    {
        $engine = $this->buildEngine($this->homeTags(), 'enforce', failingTargetReads: true);
        $control = $this->buildEngine($this->homeTags(), 'enforce');
        $context = $this->loginContext(self::HOME_IP, self::SESSION, targetFields: ['username' => 'victim@example.com']);

        $decision = $engine->reassessV2($context, new \KiwiCaptcha\Risk\RiskV2Context());
        self::assertSame(
            \KiwiCaptcha\Risk\RiskAction::StepUp,
            $decision->action,
            'an unreadable target picture cannot read as clean: fail closed to the completable rung',
        );
        self::assertTrue($decision->hasReason(\KiwiCaptcha\Risk\RiskReason::EvidenceUnavailable));
        self::assertSame(
            360,
            $decision->score,
            'the saturated counts land as the full target pressure and spread signals',
        );

        $controlDecision = $control->reassessV2($context, new \KiwiCaptcha\Risk\RiskV2Context());
        self::assertSame(
            \KiwiCaptcha\Risk\RiskAction::Allow,
            $controlDecision->action,
            'the same login on a readable store is the plain allow',
        );
        self::assertSame(100, $controlDecision->score, 'the healthy read stays clean');
    }

    /**
     * Learn mode records the failed target read without escalating:
     * the fail-closed score stays (the saturated target picture is
     * mode-independent pricing), but the enforcing novelty verdict
     * stays off and the reason is carried.
     */
    public function testAStoreFailureOnTheTargetReadInLearnModeStaysAllowCarryingTheReason(): void
    {
        $engine = $this->buildEngine($this->homeTags(), 'learn', failingTargetReads: true);
        $context = $this->loginContext(self::HOME_IP, self::SESSION, targetFields: ['username' => 'victim@example.com']);
        $decision = $engine->reassessV2($context, new \KiwiCaptcha\Risk\RiskV2Context());
        self::assertSame(
            360,
            $decision->score,
            'the saturated target picture prices the login the same in both modes',
        );
        self::assertSame(
            \KiwiCaptcha\Risk\RiskAction::Sha18,
            $decision->action,
            'learn mode records the target-read failure without the enforcing step-up',
        );
        self::assertTrue($decision->hasReason(\KiwiCaptcha\Risk\RiskReason::EvidenceUnavailable));
        self::assertFalse(
            $decision->hasReason(\KiwiCaptcha\Risk\RiskReason::NovelNetwork),
            'learn mode never reports the novelty signal as enforcing',
        );
    }

    /**
     * The gate exists without the marks reader: a deployment that never
     * wired the marks stage (or turned it off) still escalates a
     * genuinely novel login in enforce mode. The pipeline derives the
     * first-attempt evidence for every assessment and enforces it on
     * its own when no reader composes it.
     */
    public function testEnforceWithoutMarksReaderStillStepsUpNovelLogins(): void
    {
        $engine = $this->buildEngine($this->homeTags(), 'enforce', withMarksReader: false);
        $decision = $engine->reassess($this->loginContext(self::ATTACKER_OTHER_ASN, null));
        self::assertSame(
            \KiwiCaptcha\Risk\RiskAction::StepUp,
            $decision->action,
            'enforce mode steps a novel login up even with no marks reader wired',
        );
        self::assertTrue(
            $decision->hasReason(\KiwiCaptcha\Risk\RiskReason::NovelNetwork),
            'the escalation carries the novelty reason',
        );

        // The same engine stays silent for the owner's known network:
        // the fallback enforces the verdict, it does not widen it.
        $control = $this->buildEngine($this->homeTags(), 'enforce', withMarksReader: false);
        $known = $control->reassess($this->loginContext(self::HOME_IP, self::SESSION));
        self::assertSame(
            \KiwiCaptcha\Risk\RiskAction::Allow,
            $known->action,
            'a known network on a bound session stays an Allow without a marks reader',
        );
    }

    /**
     * Trust is never minted from a novel Allow when no marks reader is
     * wired: learn mode defers the step-up demand, so the post-Allow
     * binding records the session and the device without the trust
     * flag, exactly like the wired-reader path. An attacker riding the
     * rollout window leaves no trusted device behind.
     */
    public function testNoMarksReaderNovelAllowMintsNoTrust(): void
    {
        $engine = $this->buildEngine([], 'learn', withMarksReader: false);
        $sessionTag = 'session:'.$this->identity->sessionId(self::SESSION);
        $deviceTag = 'device:'.$this->identity->deviceId(self::DEVICE);
        $networkBucket = AdaptiveRiskEngine::networkBucket(self::HOME_IP);

        $decision = $engine->reassess($this->loginContext(self::HOME_IP, self::SESSION, self::DEVICE));
        self::assertSame(
            \KiwiCaptcha\Risk\RiskAction::Allow,
            $decision->action,
            'learn mode stays on Allow for a novel first login',
        );
        self::assertTrue(
            $this->networks->principalNetworkSeen($this->principalHex, $deviceTag),
            'the binding still records the device pseudonym',
        );
        self::assertFalse(
            $this->networks->tagIsTrusted($this->principalHex, $deviceTag),
            'a novel Allow with no marks reader mints no device trust',
        );
        self::assertFalse(
            $this->networks->tagIsTrusted($this->principalHex, $sessionTag),
            'a novel Allow with no marks reader mints no session trust either',
        );
        self::assertTrue(
            $this->networks->tagIsTrusted($this->principalHex, $networkBucket),
            'the learn history accrues as it does with a reader',
        );
    }
}

/** Empty marks store: the novelty tests exercise first-attempt evidence, not marks. */
final class EmptyMarksStore implements \KiwiCaptcha\Risk\Storage\OutcomeMarksStoreInterface
{
    public function markKey(string $dimension, string $id): string
    {
        return 'mark:'.$dimension.':'.$id;
    }

    public function writeMark(string $dimension, string $id, string $kind, int $nowMs, string $eventId = ''): int
    {
        return 1;
    }

    public function readMark(string $dimension, string $id): ?array
    {
        return null;
    }

    public function forgetMarks(string $dimension, string $id): int
    {
        return 0;
    }
}
