<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Evidence\AutofillQualificationGate;
use KiwiCaptcha\Risk\Evidence\DecoyEscalation;
use KiwiCaptcha\Risk\Evidence\DecoyEscalationStore;
use KiwiCaptcha\Risk\Evidence\RedisScriptRunnerInterface;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskDecision;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskReason;
use KiwiCaptcha\Risk\SignalVector;
use PHPUnit\Framework\TestCase;

/**
 * The decoy escalation of change.md 3.2.2: the one-rung raise (an
 * escalation, never a block) and the runtime autofill-qualification
 * gate. The gate is closed on the committed fail-closed matrix and
 * open only when every required surface qualifies. The suite also pins
 * the canonical Lua record and read behavior through a scripted
 * runner.
 */
final class DecoyEscalationTest extends TestCase
{
    private const T0 = 1_700_000_000_000;

    private function policy(): RiskPolicy
    {
        return RiskPolicy::fromConfig([
            'version' => 3,
            'weights' => (new \KiwiCaptcha\Risk\RiskWeights())->toArray(),
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20'],
            ],
            'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
        ]);
    }

    private function plain(int $score): RiskDecision
    {
        return $this->policy()->decide(1, $score, SignalVector::zero(), new ResourcePressure(1000, 1000), 0, self::T0);
    }

    public function testNotLivePassesThrough(): void
    {
        $base = $this->plain(500);
        $out = DecoyEscalation::apply($base, false);
        self::assertSame($base->action, $out->action);
        self::assertSame($base->reasons, $out->reasons);
    }

    public function testLiveRaisesExactlyOneRung(): void
    {
        self::assertSame(RiskAction::Sha16, DecoyEscalation::apply($this->plain(100), true)->action);
        self::assertSame(RiskAction::Argon16, DecoyEscalation::apply($this->plain(500), true)->action);
        self::assertSame(RiskAction::StepUp, DecoyEscalation::apply($this->plain(900), true)->action);
        $out = DecoyEscalation::apply($this->plain(500), true);
        self::assertTrue($out->hasReason(RiskReason::DecoyEscalation));
    }

    public function testEscalationNeverBlocks(): void
    {
        self::assertSame(RiskAction::StepUp, DecoyEscalation::apply($this->plain(950), true)->action);
        $deny = $this->plain(990);
        $out = DecoyEscalation::apply($deny, true);
        self::assertSame(RiskAction::Deny, $out->action);
        self::assertSame($deny->reasons, $out->reasons);
    }

    public function testTtlConstantIsTheTenMinuteWindow(): void
    {
        self::assertSame(600000, DecoyEscalation::ESCALATION_TTL_MS);
    }

    public function testTheCanonicalScriptIsByteIdenticalAcrossTheThreeCopies(): void
    {
        $root = dirname(__DIR__, 3);
        $copies = [
            $root . '/protocol/risk-v1/decoy_escalation.lua',
            $root . '/packages/kiwicaptcha-risk/resources/decoy_escalation.lua',
            $root . '/packages/kiwicaptcha-risk-php/resources/decoy_escalation.lua',
        ];
        $first = file_get_contents($copies[0]);
        self::assertNotFalse($first);
        foreach (array_slice($copies, 1) as $copy) {
            $raw = file_get_contents($copy);
            self::assertNotFalse($raw, "$copy readable");
            self::assertSame($first, $raw, "$copy must stay byte-identical");
        }
    }

    public function testTheCommittedMatrixClosesTheGate(): void
    {
        // The committed matrix stands fail-closed on purpose: no real
        // qualification has happened, so the gate must refuse.
        self::assertFalse(AutofillQualificationGate::committed()->isOpen());
    }

    public function testAMissingMatrixClosesTheGate(): void
    {
        $gate = new AutofillQualificationGate('/nonexistent/matrix.json', '/nonexistent/registry.json');
        self::assertFalse($gate->isOpen());
    }

    public function testAFullyQualifiedMatrixOpensTheGate(): void
    {
        $gate = new AutofillQualificationGate(
            $this->writeMatrix('pass'),
            $this->registryPath(),
            90,
        );
        self::assertTrue($gate->isOpen());
    }

    public function testOneUnqualifiedSurfaceClosesTheGate(): void
    {
        $gate = new AutofillQualificationGate(
            $this->writeMatrix('mixed'),
            $this->registryPath(),
            90,
        );
        self::assertFalse($gate->isOpen());
    }

    public function testAStalePassRowClosesTheGate(): void
    {
        $gate = new AutofillQualificationGate(
            $this->writeMatrix('stale'),
            $this->registryPath(),
            90,
        );
        self::assertFalse($gate->isOpen());
    }

    public function testAPlaceholderVersionClosesTheGate(): void
    {
        $gate = new AutofillQualificationGate(
            $this->writeMatrix('placeholder'),
            $this->registryPath(),
            90,
        );
        self::assertFalse($gate->isOpen());
    }

    /**
     * The explicit configuration value: a runtime security decision
     * must not depend solely on tests/ QA data, so the gate opens as a
     * deliberate operator decision with no matrix consulted.
     */
    public function testAnExplicitConfigurationValueOpensTheGateWithoutAnyMatrix(): void
    {
        $gate = AutofillQualificationGate::fromConfiguration(true);
        self::assertTrue($gate->isExplicitlyArmed());
        self::assertTrue($gate->isOpen());
    }

    public function testAnExplicitArmIgnoresAMissingMatrix(): void
    {
        $gate = AutofillQualificationGate::fromConfiguration(true, '/nonexistent/matrix.json', '/nonexistent/registry.json');
        self::assertTrue($gate->isOpen(), 'the explicit operator decision must not fall back to a matrix');
    }

    public function testFromConfigurationWithoutAnArmStaysFailClosedOnTheCommittedMatrix(): void
    {
        $gate = AutofillQualificationGate::fromConfiguration(false);
        self::assertFalse($gate->isExplicitlyArmed());
        self::assertFalse($gate->isOpen(), 'the committed matrix carries no passing rows, so the gate stays closed');
    }

    public function testFromConfigurationRoutesACustomVersionedAssetPair(): void
    {
        $gate = AutofillQualificationGate::fromConfiguration(
            false,
            $this->writeMatrix('pass'),
            $this->registryPath(),
        );
        self::assertFalse($gate->isExplicitlyArmed());
        self::assertTrue($gate->isOpen(), 'a versioned asset outside tests/ can open the gate');
    }

    public function testTheRecordOpArmsUnderAnExplicitConfigurationValue(): void
    {
        $runner = new ScriptedRunner();
        $store = new DecoyEscalationStore(
            $runner,
            AutofillQualificationGate::fromConfiguration(true),
            'ns1',
            600000,
        );
        self::assertSame(1, $store->recordConfirmedHit(str_repeat('a', 32), self::T0));
        self::assertSame('1', $runner->lastArgs[2], 'the explicitly armed gate must ride as "1"');
    }

    /**
     * The scripted store: the gate rides into the script as an argument
     * and a closed gate leaves the record unwritten.
     */
    public function testTheRecordOpRefusesWhenTheGateIsClosed(): void
    {
        $runner = new ScriptedRunner();
        $store = new DecoyEscalationStore($runner, $this->openGate(), 'ns1', 600000);
        $count = $store->recordConfirmedHit(str_repeat('a', 32), self::T0);
        self::assertSame(1, $count);
        self::assertSame('record', $runner->lastArgs[0]);
        self::assertSame('1', $runner->lastArgs[2], 'the open gate must ride as "1"');

        $closed = new DecoyEscalationStore(new ScriptedRunner(), new AutofillQualificationGate('/missing/a.json', '/missing/b.json'), 'ns1');
        self::assertSame(0, $closed->recordConfirmedHit(str_repeat('a', 32), self::T0));
    }

    public function testTheReaderDegradesToNotLiveOnFailure(): void
    {
        $runner = new ScriptedRunner();
        $runner->throwOnRead = true;
        $store = new DecoyEscalationStore($runner, $this->openGate(), 'ns1');
        self::assertFalse($store->escalationLive(str_repeat('a', 32)));
        self::assertFalse($store->escalationLive(null));
        $live = new DecoyEscalationStore(new ScriptedRunner(reply: 1), $this->openGate(), 'ns1');
        self::assertTrue($live->escalationLive(str_repeat('a', 32)));
    }

    public function testTheReadOpCarriesTheWindowAndNeverWrites(): void
    {
        $runner = new ScriptedRunner();
        $store = new DecoyEscalationStore($runner, $this->openGate(), 'ns1', 600000);
        $store->escalationLive(str_repeat('a', 32));
        self::assertSame('read', $runner->lastArgs[0]);
        self::assertSame('600000', $runner->lastArgs[4]);
        self::assertCount(1, $runner->keys);
    }

    private function openGate(): AutofillQualificationGate
    {
        return new AutofillQualificationGate($this->writeMatrix('pass'), $this->registryPath(), 90);
    }

    private function registryPath(): string
    {
        return dirname(__DIR__, 3) . '/tests/browser/qualification/surfaces.json';
    }

    /** Writes a synthetic matrix fixture with the given scenario. */
    private function writeMatrix(string $scenario): string
    {
        $registry = json_decode((string) file_get_contents($this->registryPath()), true, 16, JSON_THROW_ON_ERROR);
        $rows = [];
        $fresh = gmdate('Y-m-d\TH:i:s.v\Z');
        $stale = gmdate('Y-m-d\TH:i:s.v\Z', time() - 91 * 86400);
        foreach ($registry['surfaces'] as $i => $surface) {
            $status = 'manual_pending';
            $version = 'CURRENT';
            $testedAt = null;
            if ($scenario === 'pass' || ($scenario === 'mixed' && $i === 0)) {
                $status = 'pass';
                $version = '1.2.3';
                $testedAt = $fresh;
            } elseif ($scenario === 'stale') {
                $status = 'pass';
                $version = '1.2.3';
                $testedAt = $stale;
            } elseif ($scenario === 'placeholder') {
                $status = 'pass';
                $version = 'CURRENT';
                $testedAt = $fresh;
            }
            $row = [
                'surface' => $surface['id'],
                'product' => $surface['product'],
                'version' => $version,
                'platform' => $surface['platform'],
                'status' => $status,
                'tested_at' => $testedAt,
            ];
            if ($status === 'pass') {
                $row['controls'] = [
                    'negative' => ['result' => 'pass', 'note' => 'decoy stayed empty, honeypot_hit false'],
                    'positive' => ['result' => 'pass', 'note' => 'deliberate fill reported the hit'],
                ];
            }
            $rows[] = $row;
        }
        $path = tempnam(sys_get_temp_dir(), 'kiwi-matrix-');
        self::assertIsString($path);
        file_put_contents($path, json_encode([
            'schema' => 'kiwicaptcha.autofill-qualification/1',
            'rows' => $rows,
        ], JSON_THROW_ON_ERROR));

        return $path;
    }
}

/**
 * The scripted runner: records the last call and answers a fixed reply.
 */
final class ScriptedRunner implements RedisScriptRunnerInterface
{
    /** @var list<string> */
    public array $lastArgs = [];

    /** @var list<string> */
    public array $keys = [];

    public bool $throwOnRead = false;

    public function __construct(private readonly int|string|null $reply = 1)
    {
    }

    public function evalScript(string $script, array $keys, array $args): int|string|null
    {
        if (str_contains($script, 'error_reply') && ($args[0] ?? '') === 'boom') {
            throw new \RuntimeException('script error');
        }
        $this->lastArgs = $args;
        $this->keys = $keys;
        if ($this->throwOnRead && $args[0] === 'read') {
            throw new \RuntimeException('backend down');
        }
        // The script's own refusal contract, mirrored by the double: a
        // closed gate or an unconfirmed hit never writes.
        if ($args[0] === 'record' && ($args[2] !== '1' || $args[1] !== '1')) {
            return 0;
        }

        return $this->reply;
    }
}
