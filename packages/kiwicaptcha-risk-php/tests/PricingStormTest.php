<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\Pricing\PriceContextSourceInterface;
use KiwiCaptcha\Risk\Pricing\PriceInputs;
use KiwiCaptcha\Risk\Pricing\PriceModel;
use KiwiCaptcha\Risk\Pricing\PriceRequest;
use KiwiCaptcha\Risk\Pricing\ValueClass;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskContext;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskReason;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\Storage\ObservationReply;
use PHPUnit\Framework\TestCase;

/**
 * The change.md 3.3.2 done-when simulator: a level-4 global-pressure
 * storm composed through the real engine with the pricing stage wired.
 *
 * The storm drives the global-pressure plumbing exactly the way the
 * state script does (risk-v1.lua): 32 back-to-back PreIssue events each
 * add 2000 raw pressure (rf 1000 + rs 1000). The raw total 64000
 * normalizes against the 70000 saturation to 914, and 914 clears the
 * level-4 enter threshold of the script's ratchet. The scenario is
 * deterministic and policy-layer only: a store stub replays the
 * storm-normalized vector and the ratcheted level, no sleeps and no
 * real backend.
 *
 * Done-when (the solve-time proxy at rung granularity): the trusted
 * session's priced rung moves at most one rung versus its calm
 * baseline, while the unproven storm sessions land at the full
 * escalation (an argon rung or stronger). The plain policy's global
 * floor keeps composing underneath: the trusted session's final action
 * at level 4 stays at the operator's floor because the price may only
 * raise, never lower.
 */
final class PricingStormTest extends TestCase
{
    private const STORM_EVENTS = 32;
    private const RAW_PER_EVENT = 2000;
    private const GLOBAL_SATURATION = 70000;
    private const ENTER = [300, 550, 750, 900];

    /** The state script's normalize(gp, saturation) in pure integer math. */
    private static function normalizeGlobal(int $raw): int
    {
        return min(1000, intdiv($raw * 1000, self::GLOBAL_SATURATION));
    }

    /** The state script's ratchet: the highest level whose enter threshold clears. */
    private static function targetLevel(int $gnorm): int
    {
        for ($level = 4; $level >= 1; $level--) {
            if ($gnorm >= self::ENTER[$level - 1]) {
                return $level;
            }
        }
        return 0;
    }

    private static function policy(): RiskPolicy
    {
        return RiskPolicy::fromConfig([
            'version' => 3,
            'weights' => [
                'source_fast' => 190, 'source_slow' => 110, 'subnet_fast' => 80,
                'issue_debt' => 150, 'bad_proof' => 220, 'malformed' => 260,
                'replay' => 320, 'action_failure' => 120, 'scope_switch' => 60,
                'global_pressure' => 170, 'network_risk' => 100,
                'trust_credit' => 130, 'principal_credit' => 100,
            ],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20'],
            ],
            'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
        ]);
    }

    /**
     * A price-context source answering fixed inputs, recording the
     * requests it saw (the marks-reader wiring-test pattern).
     */
    private static function fixedSource(ValueClass $class, int $trust): PriceContextSourceInterface
    {
        return new class ($class, $trust) implements PriceContextSourceInterface {
            /** @var list<PriceRequest> the requests the engine handed over */
            public array $seen = [];

            public function __construct(
                private readonly ValueClass $class,
                private readonly int $trust,
            ) {
            }

            public function priceInputs(PriceRequest $request): PriceInputs
            {
                $this->seen[] = $request;
                return new PriceInputs($this->class, $this->trust);
            }
        };
    }

    /** A source whose backend always fails: the engine must price fail-closed. */
    private static function unreadableSource(): PriceContextSourceInterface
    {
        return new class implements PriceContextSourceInterface {
            public function priceInputs(PriceRequest $request): PriceInputs
            {
                throw new \RuntimeException('pricing surface unreadable');
            }
        };
    }

    private static function engine(SignalVector $vector, int $level, ?PriceContextSourceInterface $source): AdaptiveRiskEngine
    {
        $store = new class ($vector, $level) extends RiskStateStoreStub {
            public function __construct(private readonly SignalVector $vector, private readonly int $level)
            {
            }

            public function observeWithReply(RiskObservation $observation): ObservationReply
            {
                return new ObservationReply($this->vector, $this->level, 0, false);
            }

            public function observe(RiskObservation $observation): SignalVector
            {
                return $this->vector;
            }
        };
        $keys = RiskKeys::fromMaster(str_repeat(chr(0x42), 32));
        $args = [
            'store' => $store,
            'classifier' => new CidrNetworkClassifier([]),
            'identityFactory' => new RiskIdentityFactory($keys),
            'scorer' => new RiskScorer(),
            'policy' => self::policy(),
            'keys' => $keys,
        ];
        if ($source !== null) {
            $args['priceContext'] = $source;
        }
        return new AdaptiveRiskEngine(...$args);
    }

    private static function ctx(string $sessionId): RiskContext
    {
        return new RiskContext(
            scope: 1,
            sourceIp: '203.0.113.27',
            sessionId: $sessionId,
            principalId: null,
            event: RiskEventKind::PreIssue,
            networkFlags: new \KiwiCaptcha\Risk\Network\NetworkFlags(),
            resources: new ResourcePressure(1000, 1000),
        );
    }

    public function testStormDrivesTheGlobalLevelTo4ThroughThePlumbing(): void
    {
        $raw = self::STORM_EVENTS * self::RAW_PER_EVENT;
        self::assertSame(64000, $raw);
        $gnorm = self::normalizeGlobal($raw);
        self::assertSame(914, $gnorm);
        self::assertSame(4, self::targetLevel($gnorm));
        // every lower enter threshold clears on the way up, calm does not
        self::assertSame(0, self::targetLevel(299));
        self::assertSame(1, self::targetLevel(300));
        self::assertSame(2, self::targetLevel(550));
        self::assertSame(3, self::targetLevel(750));
        self::assertSame(4, self::targetLevel(900));
    }

    public function testL4StormPricesTrustedWithinOneRungAndEscalatesUntrusted(): void
    {
        $trustedSession = str_repeat('4', 32);
        $stormBot = str_repeat('7', 32);

        // The trusted session's own signals: full bucket credit (raw 10000
        // normalizes to the 1000 trust signal) and nothing else.
        $calmTrustedVector = SignalVector::fromArray(['trust_credit' => 1000]);
        // The storm bot's own signals: invalid proofs plus its own
        // velocity, on top of the storm's global pressure.
        $stormBotVector = SignalVector::fromArray([
            'bad_proof' => 900, 'source_fast' => 800, 'global_pressure' => 914,
        ]);
        $trustedStormVector = SignalVector::fromArray([
            'trust_credit' => 1000, 'global_pressure' => 914,
        ]);

        // Calm baseline: level 0, clean signals.
        $calm = self::engine($calmTrustedVector, 0, self::fixedSource(ValueClass::Standard, 10000));
        $calmDecision = $calm->assessPreIssue(self::ctx($trustedSession));
        self::assertSame(RiskAction::Allow, $calmDecision->action);
        self::assertSame(0, $calmDecision->score, 'the trust credit repays the base risk');
        $calmPriced = PriceModel::price($calmDecision->score, ValueClass::Standard, 10000, $calmTrustedVector->globalPressure);
        self::assertSame(RiskAction::Allow, $calmPriced);

        // Storm: level 4 through the plumbing, the same trusted session.
        $storm = self::engine(
            $trustedStormVector,
            self::targetLevel(self::normalizeGlobal(self::STORM_EVENTS * self::RAW_PER_EVENT)),
            self::fixedSource(ValueClass::Standard, 10000),
        );
        $stormDecision = $storm->assessPreIssue(self::ctx($trustedSession));
        self::assertSame(4, $stormDecision->globalLevel);
        // base 100 + weighted(914, 170) - weighted(1000, 130) = 125
        self::assertSame(125, $stormDecision->score);
        $stormPriced = PriceModel::price($stormDecision->score, ValueClass::Standard, 10000, $trustedStormVector->globalPressure);
        self::assertSame(RiskAction::Sha16, $stormPriced);
        self::assertLessThanOrEqual(
            1,
            $stormPriced->rank() - $calmPriced->rank(),
            'the trusted session priced rung moved too many rungs under the storm'
        );
        // The composed action keeps the operator level-4 floor (sha20):
        // the priced rung sha16 stays below it, and the price never lowers.
        self::assertSame(RiskAction::Sha20, $stormDecision->action);

        // The unproven storm session: full escalation through the engine.
        $botEngine = self::engine($stormBotVector, 4, self::fixedSource(ValueClass::Standard, 0));
        $botDecision = $botEngine->assessPreIssue(self::ctx($stormBot));
        self::assertSame(4, $botDecision->globalLevel);
        // base 100 + 198 + 152 + 155 = 605 through the real scorer
        self::assertSame(605, $botDecision->score);
        self::assertGreaterThanOrEqual(
            RiskAction::Argon16->rank(),
            $botDecision->action->rank(),
            'the unproven storm session must land at the full escalation'
        );
        // 605 + the full 914-pressure ramp = 902 work: the priced rung is
        // the interactive step-up, past the whole argon regime.
        self::assertSame(RiskAction::StepUp, $botDecision->action);
        self::assertTrue($botDecision->hasReason(RiskReason::PricedEscalation));
    }

    public function testPriceContextWiringIsOptInAndFailClosed(): void
    {
        // A transient pressure signal without the ratcheted level proves
        // the stage reads the observed global-pressure signal as its
        // pressure.
        $pressured = SignalVector::fromArray(['global_pressure' => 914]);
        $session = str_repeat('9', 32);

        $unwired = self::engine($pressured, 0, null);
        $plain = $unwired->assessPreIssue(self::ctx($session));
        // base 100 + weighted(914, 170) = 255 -> sha16 band
        self::assertSame(255, $plain->score);
        self::assertSame(RiskAction::Sha16, $plain->action);
        self::assertFalse($plain->hasReason(RiskReason::PricedEscalation));

        $requests = [];
        $source = self::fixedSource(ValueClass::Standard, 0);
        $wired = self::engine($pressured, 0, $source);
        $priced = $wired->assessPreIssue(self::ctx($session));
        // 255 + the full 914-pressure ramp = 552 -> sha20
        self::assertSame(RiskAction::Sha20, $priced->action);
        self::assertTrue($priced->hasReason(RiskReason::PricedEscalation));

        // The engine handed the source the derived session pseudonym (32
        // hex chars), never the raw cookie value.
        $seen = $source->seen;
        self::assertCount(1, $seen);
        self::assertNotNull($seen[0]->session);
        self::assertSame(32, strlen($seen[0]->session));
        self::assertTrue(ctype_xdigit($seen[0]->session));
        self::assertNotSame($session, $seen[0]->session);

        // An unreadable source prices the same request fail-closed: zero
        // credit, full ramp (identical action to the wired leg above).
        $failClosed = self::engine($pressured, 0, self::unreadableSource());
        $closed = $failClosed->assessPreIssue(self::ctx($session));
        self::assertSame(RiskAction::Sha20, $closed->action);
        self::assertTrue($closed->hasReason(RiskReason::PricedEscalation));
    }
}
