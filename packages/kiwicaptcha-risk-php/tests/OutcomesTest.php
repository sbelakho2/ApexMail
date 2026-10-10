<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\Outcomes\KiwiOutcomes;
use KiwiCaptcha\Risk\Outcomes\Outcome;
use KiwiCaptcha\Risk\Outcomes\OutcomeHandle;
use KiwiCaptcha\Risk\Outcomes\OutcomeHandleDimension;
use KiwiCaptcha\Risk\Outcomes\OutcomeMap;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskContext;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\Storage\OutcomeMarksStoreInterface;
use PHPUnit\Framework\TestCase;

/**
 * The typed outcomes API against the mapping table and the stubbed
 * store: the table's completeness and polarity properties, the sealed
 * handle validation, and the report()/forget() resolution onto the
 * ledger, feedback and mark surfaces.
 */
final class OutcomesTest extends TestCase
{
    private const PRINCIPAL = '9f1c4a7e2b8d63f05a1e9c4d7b2e6f18';
    private const SESSION = 'c7b3e1f9a5d24708b6e0c8a2f4d69123';
    private const TARGET = '5e2a9b4c1d7f38e6a0b5c9d2e4f6a813';
    private const DECISION = 'd4e5f60718293a4b5c6d7e8f90a1b2c3';

    /** The trust trio: the only outcomes whose paths may lower risk. */
    private const TRUST_OUTCOMES = [
        Outcome::ConfirmedLegitimate,
        Outcome::StepUpCompleted,
        Outcome::AuthenticationSuccess,
    ];

    /** The abuse quartet: the only outcomes that write long-memory marks. */
    private const MARK_OUTCOMES = [
        Outcome::SpamReported,
        Outcome::Chargeback,
        Outcome::AccountBanned,
        Outcome::FraudConfirmed,
    ];

    public function testMappingTableIsCompleteAndTotal(): void
    {
        $rows = OutcomeMap::all();
        self::assertCount(count(Outcome::cases()), $rows);
        self::assertSame(
            array_map(static fn (Outcome $o): string => $o->value, Outcome::cases()),
            array_map(static fn ($row): string => $row->outcome->value, $rows),
            'one row per outcome, in vocabulary order',
        );
        foreach (Outcome::cases() as $outcome) {
            self::assertSame($outcome, OutcomeMap::for($outcome)->outcome);
            self::assertNotSame([], OutcomeMap::for($outcome)->acceptedHandles);
        }
        self::assertSame(1, OutcomeMap::VERSION);
    }

    public function testEveryOutcomeMapsToExactlyOneChannelAndMarkBehavior(): void
    {
        $seenChannels = [];
        foreach (OutcomeMap::all() as $row) {
            self::assertContains($row->channel, RiskEventKind::cases());
            $seenChannels[] = $row->channel;
            self::assertSame($row->writesAbuseMark ? $row->outcome->value : null, $row->markKind());
            // Ledger handles are accepted exactly when a ledger action exists.
            foreach (OutcomeMap::ledgerDimensions() as $dimension) {
                self::assertSame(
                    $row->hasLedgerAction(),
                    $row->accepts($dimension),
                    sprintf('%s must accept a ledger handle exactly when it carries a ledger action', $row->outcome->value),
                );
            }
            foreach ([OutcomeHandleDimension::Principal, OutcomeHandleDimension::Target, OutcomeHandleDimension::Session, OutcomeHandleDimension::Agent] as $dimension) {
                self::assertTrue($row->accepts($dimension), sprintf('%s must accept every identity handle', $row->outcome->value));
            }
        }
        // The vocabulary maps onto the existing channels only: 8, 9, 10,
        // 11, 12 and 13, each at least once.
        $channelValues = array_map(static fn ($k): int => $k->value, $seenChannels);
        sort($channelValues);
        self::assertSame(
            [8, 9, 10, 11, 12, 13],
            array_values(array_unique($channelValues)),
            'the mapping must reuse the existing risk-v1 channels',
        );
    }

    public function testPolarityProperties(): void
    {
        foreach (OutcomeMap::all() as $row) {
            $name = $row->outcome->value;
            // Only server-confirmed outcomes subtract risk or write marks.
            if ($row->maySubtractRisk || $row->writesAbuseMark) {
                self::assertTrue($row->serverConfirmed, "{$name} must be server-confirmed");
            }
            // The attacker-influenceable outcome adds risk only.
            if (!$row->serverConfirmed) {
                self::assertFalse($row->maySubtractRisk, "{$name} may never subtract risk");
                self::assertFalse($row->writesAbuseMark, "{$name} may never write a mark");
            }
            // Trust and abuse are disjoint: no outcome both subtracts and marks.
            self::assertFalse(
                $row->maySubtractRisk && $row->writesAbuseMark,
                "{$name} may not both subtract risk and write an abuse mark",
            );
            if (\in_array($row->outcome, self::TRUST_OUTCOMES, true)) {
                self::assertTrue($row->maySubtractRisk, "{$name} is a trust outcome");
            } else {
                self::assertFalse($row->maySubtractRisk, "{$name} must never subtract risk");
            }
            if (\in_array($row->outcome, self::MARK_OUTCOMES, true)) {
                self::assertTrue($row->writesAbuseMark, "{$name} writes a long-memory mark");
            } else {
                self::assertFalse($row->writesAbuseMark, "{$name} must never write an abuse mark");
            }
        }
        // The attacker-influenceable set is exactly authenticationFailure.
        $notConfirmed = array_values(array_map(
            static fn ($row): string => $row->outcome->value,
            array_filter(OutcomeMap::all(), static fn ($row): bool => !$row->serverConfirmed),
        ));
        self::assertSame(['authenticationFailure'], $notConfirmed);
        // The authentication outcomes ride the auth channels only: the
        // auth pair maps to events 10 and 11 and writes no marks.
        self::assertSame(RiskEventKind::AuthenticationSuccess, OutcomeMap::for(Outcome::AuthenticationSuccess)->channel);
        self::assertSame(RiskEventKind::AuthenticationFailure, OutcomeMap::for(Outcome::AuthenticationFailure)->channel);
    }

    public function testChannelPolarityMatchesTheRiskV1Contract(): void
    {
        // The add-only outcomes map only onto channels the state script
        // uses to add pressure (9, 11, 13); the trust outcomes map only
        // onto the trust channels (8, 10, 12). This is the table-side
        // half of the invariant; the Redis-marked test proves the Lua
        // half against the real state script.
        foreach (OutcomeMap::all() as $row) {
            $value = $row->channel->value;
            if ($row->maySubtractRisk) {
                self::assertContains($value, [8, 10, 12], "{$row->outcome->value} trust channel");
            } else {
                self::assertContains($value, [9, 11, 13], "{$row->outcome->value} add-only channel");
            }
        }
    }

    public function testRawIdentityHandlesAreRejected(): void
    {
        try {
            OutcomeHandle::principal('user@example.com');
            self::fail('a raw email must be rejected as a principal handle');
        } catch (\InvalidArgumentException) {
            self::addToAssertionCount(1);
        }
        try {
            OutcomeHandle::target('acct-2024-11');
            self::fail('a raw account id must be rejected as a target handle');
        } catch (\InvalidArgumentException) {
            self::addToAssertionCount(1);
        }
        try {
            OutcomeHandle::session('short');
            self::fail('a non-hex session handle must be rejected');
        } catch (\InvalidArgumentException) {
            self::addToAssertionCount(1);
        }
        try {
            OutcomeHandle::session(strtoupper(self::SESSION));
            self::fail('an uppercase-hex session handle must be rejected');
        } catch (\InvalidArgumentException) {
            self::addToAssertionCount(1);
        }
        try {
            OutcomeHandle::agent('agent:two');
            self::fail('a colon-carrying agent id must be rejected');
        } catch (\InvalidArgumentException) {
            self::addToAssertionCount(1);
        }
        try {
            OutcomeHandle::nonce('');
            self::fail('an empty nonce must be rejected');
        } catch (\InvalidArgumentException) {
            self::addToAssertionCount(1);
        }
    }

    public function testValidHandlesCarryTheirDimensions(): void
    {
        self::assertSame(OutcomeHandleDimension::Principal, OutcomeHandle::principal(self::PRINCIPAL)->dimension);
        self::assertTrue(OutcomeHandle::decisionId(self::DECISION)->dimension->isLedger());
        self::assertSame('principal', OutcomeHandle::principal(self::PRINCIPAL)->dimension->markDimension());
        self::assertNull(OutcomeHandle::decisionId(self::DECISION)->dimension->markDimension());
        self::assertSame('confirmedLegitimate', Outcome::fromWireName('confirmedLegitimate')->value);
        self::assertNull(Outcome::fromWireName('unknownOutcome'));
    }

    public function testReportLedgerHandleConfirmsTheLedger(): void
    {
        $store = new class extends RiskStateStoreStub {
            public ?RiskObservation $observed = null;

            public function observe(RiskObservation $observation): SignalVector
            {
                $this->observed = $observation;

                return SignalVector::zero();
            }
        };
        $outcomes = new KiwiOutcomes($this->engine($store), $store);

        $receipt = $outcomes->report(Outcome::Chargeback, OutcomeHandle::decisionId(self::DECISION));
        self::assertSame(1, $receipt->status);
        self::assertFalse($receipt->channelBooked);
        self::assertSame(0, $receipt->marksWritten);
        self::assertSame(['confirm', self::DECISION, false], $store->ledgerCalls[0]);
        self::assertNull($store->observed, 'a contextless ledger report books no feedback event');

        $receipt = $outcomes->report(Outcome::ConfirmedLegitimate, OutcomeHandle::nonce('0f1e2d3c4b5a69788796a5b4c3d2e1f0'));
        self::assertSame(1, $receipt->status);
        self::assertSame(['confirm', '0f1e2d3c4b5a69788796a5b4c3d2e1f0', true], $store->ledgerCalls[1]);
    }

    public function testReportLedgerHandleWithContextBooksTheChannelOnlyWhenAuthorized(): void
    {
        $store = new class extends RiskStateStoreStub {
            public ?RiskObservation $observed = null;

            public function observe(RiskObservation $observation): SignalVector
            {
                $this->observed = $observation;

                return SignalVector::zero();
            }
        };
        $outcomes = new KiwiOutcomes($this->engine($store), $store);

        $receipt = $outcomes->report(
            Outcome::ConfirmedLegitimate,
            OutcomeHandle::decisionId(self::DECISION),
            'retry-1',
            $this->context(),
        );
        self::assertSame(1, $receipt->status);
        self::assertTrue($receipt->channelBooked);
        self::assertSame(RiskEventKind::ConfirmedLegitimate, $store->observed->event);

        // Status 0 (already confirmed): the ledger refuses and no
        // feedback event is booked, exactly like the confirmed* wrappers.
        $store->confirmOutcomeStatus = 0;
        $store->observed = null;
        $receipt = $outcomes->report(
            Outcome::Chargeback,
            OutcomeHandle::decisionId(self::DECISION),
            null,
            $this->context(),
        );
        self::assertSame(0, $receipt->status);
        self::assertFalse($receipt->channelBooked);
        self::assertNull($store->observed);
    }

    public function testReportIdentityHandleWritesTheMarkAndBooksTheChannel(): void
    {
        $store = new class extends RiskStateStoreStub {
            public ?RiskObservation $observed = null;

            public function observe(RiskObservation $observation): SignalVector
            {
                $this->observed = $observation;

                return SignalVector::zero();
            }
        };
        $outcomes = new KiwiOutcomes($this->engine($store), $store);

        $receipt = $outcomes->report(
            Outcome::SpamReported,
            OutcomeHandle::principal(self::PRINCIPAL),
            'idem-1',
            $this->context(),
        );
        self::assertSame(0, $receipt->status);
        self::assertTrue($receipt->channelBooked);
        self::assertSame(1, $receipt->marksWritten);
        self::assertSame(1, $receipt->markCount);
        $mark = $store->readMark('principal', self::PRINCIPAL);
        self::assertSame('spamReported', $mark['kind']);
        self::assertSame(RiskEventKind::ProtectedActionFailure, $store->observed->event);
        // The handle's pseudonym rides the observation verbatim.
        self::assertSame(self::PRINCIPAL, $store->observed->principalId);
        self::assertNotSame(self::SESSION, $store->observed->sessionId, 'the context session stays its own derivation');

        // A contextless deferred report writes the mark only.
        $store->observed = null;
        $receipt = $outcomes->report(Outcome::AccountBanned, OutcomeHandle::principal(self::PRINCIPAL));
        self::assertFalse($receipt->channelBooked);
        self::assertSame(2, $receipt->markCount);
        self::assertNull($store->observed);
        $mark = $store->readMark('principal', self::PRINCIPAL);
        self::assertSame('accountBanned', $mark['kind'], 'the kind carries the most recent outcome');
        self::assertSame(2, $mark['count'], 'the count accumulates');
    }

    public function testSessionHandleRidesTheSessionSlot(): void
    {
        $store = new class extends RiskStateStoreStub {
            public ?RiskObservation $observed = null;

            public function observe(RiskObservation $observation): SignalVector
            {
                $this->observed = $observation;

                return SignalVector::zero();
            }
        };
        $outcomes = new KiwiOutcomes($this->engine($store), $store);

        $outcomes->report(Outcome::AuthenticationFailure, OutcomeHandle::session(self::SESSION), null, $this->context());
        self::assertSame(RiskEventKind::AuthenticationFailure, $store->observed->event);
        self::assertSame(self::SESSION, $store->observed->sessionId);
        self::assertNotNull($store->observed->principalId, 'the context principal keeps its own derivation');
        self::assertNotSame(self::SESSION, $store->observed->principalId);
        self::assertNull($store->readMark('session', self::SESSION), 'authenticationFailure writes no mark');
    }

    public function testTargetHandleStoresFailuresInTheEngineState(): void
    {
        $store = new class extends RiskStateStoreStub {
            public ?RiskObservation $observed = null;

            public function observe(RiskObservation $observation): SignalVector
            {
                $this->observed = $observation;

                return SignalVector::zero();
            }
        };
        $outcomes = new KiwiOutcomes($this->engine($store), $store);
        $target = '5e2a9b4c1d7f38e6a0b5c9d2e4f6a813';

        // The engine stores each authentication failure against the
        // target — the test injects no record.
        for ($i = 0; $i < 5; $i++) {
            $outcomes->report(Outcome::AuthenticationFailure, OutcomeHandle::target($target), "fail-$i", $this->context());
        }
        self::assertSame(5, $store->readTargetState($target)['fails']);
        // MarksView compiles the attacked-target record from the engine
        // state once the count reaches the threshold.
        $view = \KiwiCaptcha\Risk\Marks\MarksView::read($store, [], $target);
        $now = (int) floor(microtime(true) * 1000);
        self::assertNotNull($view->targetInTtl($now, \KiwiCaptcha\Risk\Marks\MarksEscalation::DEFAULT_MARK_TTL_MS));
        // The step-up completion clears the counter (change.md 3.4.2).
        $outcomes->report(Outcome::StepUpCompleted, OutcomeHandle::target($target), 'cleared', $this->context());
        self::assertSame(0, $store->readTargetState($target)['fails']);
    }

    public function testTargetFailuresFromDistinctAsnsSpread(): void
    {
        $store = new class extends RiskStateStoreStub {
            public function observe(RiskObservation $observation): SignalVector
            {
                return SignalVector::zero();
            }
        };
        $dataset = \KiwiCaptcha\Risk\Asn\AsnDataset::open(dirname(__DIR__) . '/../../protocol/asn/sample-asn.tsv');
        $outcomes = new KiwiOutcomes($this->engine($store, $dataset), $store);
        $target = self::TARGET;

        // 192.0.2.0/24 is AS64496 and 203.0.113.0/27 is AS64500 in the
        // shared sample dataset: two failures from those origins must
        // contribute two distinct asn spread elements.
        foreach (['192.0.2.7', '203.0.113.9'] as $ip) {
            $outcomes->report(
                Outcome::AuthenticationFailure,
                OutcomeHandle::target($target),
                null,
                new RiskContext(
                    scope: 1,
                    sourceIp: $ip,
                    sessionId: null,
                    principalId: null,
                    event: RiskEventKind::PreIssue,
                    networkFlags: (new CidrNetworkClassifier([]))->classify($ip),
                    resources: new ResourcePressure(1000, 1000),
                ),
            );
        }

        $state = $store->readTargetState($target);
        self::assertGreaterThanOrEqual(2, $state['spread_asns'], 'two distinct ASNs must spread at least 2');
        self::assertCount(2, array_filter(array_keys($store->targetSpread[$target]), static fn (string $k): bool => str_starts_with($k, 'asn:')));
    }

    public function testReportRejectsUnmappedHandleDimensions(): void
    {
        $store = new class extends RiskStateStoreStub {
            public function observe(RiskObservation $observation): SignalVector
            {
                return SignalVector::zero();
            }
        };
        $outcomes = new KiwiOutcomes($this->engine($store), $store);

        foreach (
            [
                [Outcome::StepUpCompleted, OutcomeHandle::decisionId(self::DECISION)],
                [Outcome::AuthenticationSuccess, OutcomeHandle::nonce('0f1e2d3c4b5a69788796a5b4c3d2e1f0')],
                [Outcome::SpamReported, OutcomeHandle::decisionId(self::DECISION)],
                [Outcome::AuthenticationFailure, OutcomeHandle::nonce('0f1e2d3c4b5a69788796a5b4c3d2e1f0')],
            ] as [$outcome, $handle]
        ) {
            try {
                $outcomes->report($outcome, $handle);
                self::fail(sprintf('%s must reject a %s handle', $outcome->value, $handle->dimension->value));
            } catch (\InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }
    }

    public function testForgetRemovesMarksAndCounts(): void
    {
        $store = new class extends RiskStateStoreStub {
            public function observe(RiskObservation $observation): SignalVector
            {
                return SignalVector::zero();
            }
        };
        $outcomes = new KiwiOutcomes($this->engine($store), $store);

        $outcomes->report(Outcome::FraudConfirmed, OutcomeHandle::target(self::TARGET));
        $outcomes->report(Outcome::Chargeback, OutcomeHandle::principal(self::PRINCIPAL));

        self::assertSame(1, $outcomes->forget(OutcomeHandle::target(self::TARGET)));
        self::assertNull($store->readMark('target', self::TARGET));
        self::assertNotNull($store->readMark('principal', self::PRINCIPAL), 'other dimensions stay');
        self::assertSame(0, $outcomes->forget(OutcomeHandle::target(self::TARGET)), 'a second forget is a no-op');
        self::assertSame(0, $outcomes->forget(OutcomeHandle::decisionId(self::DECISION)), 'a ledger handle names no mark');
    }

    public function testOutcomeFeedbackRidesHandlePseudonymsThroughTheEngine(): void
    {
        $store = new class extends RiskStateStoreStub {
            public ?RiskObservation $observed = null;

            public function observe(RiskObservation $observation): SignalVector
            {
                $this->observed = $observation;

                return SignalVector::zero();
            }
        };
        $engine = $this->engine($store);
        $receipt = $engine->recordOutcomeFeedback(
            RiskEventKind::ConfirmedAbuse,
            $this->context(),
            'key-1',
            self::SESSION,
            self::PRINCIPAL,
        );
        self::assertFalse($receipt->isDuplicate);
        self::assertSame(self::SESSION, $store->observed->sessionId);
        self::assertSame(self::PRINCIPAL, $store->observed->principalId);
        self::assertSame(RiskEventKind::ConfirmedAbuse, $store->observed->event);
    }

    private function context(): RiskContext
    {
        return new RiskContext(
            scope: 1,
            sourceIp: '198.51.100.7',
            sessionId: '00112233445566778899aabbccddeeff',
            principalId: 'raw-principal-42',
            event: RiskEventKind::PreIssue,
            networkFlags: (new CidrNetworkClassifier([]))->classify('198.51.100.7'),
            resources: new ResourcePressure(1000, 1000),
        );
    }

    private function engine(OutcomeMarksStoreInterface $store, ?\KiwiCaptcha\Risk\Asn\AsnDataset $asnDataset = null): AdaptiveRiskEngine
    {
        $keys = RiskKeys::fromMaster(str_repeat(chr(0x42), 32));

        return new AdaptiveRiskEngine(
            store: $store,
            classifier: new CidrNetworkClassifier([]),
            identityFactory: new RiskIdentityFactory($keys),
            scorer: new RiskScorer(),
            policy: RiskPolicy::fromConfig([
                'version' => 3,
                'weights' => (new \KiwiCaptcha\Risk\RiskWeights())->toArray(),
                'scopes' => [
                    1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20'],
                ],
                'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
            ]),
            keys: $keys,
            asnDataset: $asnDataset,
        );
    }
}
