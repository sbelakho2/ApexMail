<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Calibration\AggregateCalibrator;
use KiwiCaptcha\Risk\RiskAction;
use Predis\Client;
use Predis\Command\CommandInterface;
use PHPUnit\Framework\TestCase;

/**
 * Slow-script guard (a guard, not a benchmark): the verification-path
 * scripts (risk-v1.lua + the calibration read) must run well under a
 * generous bound when the state is at its maximum allowed size. Every
 * key carries its full bounded field set: 12 flat fields per risk
 * state hash, 6 fields per calibration bucket, and all 24 buckets plus
 * state present. The asserted bound is a generous 50 ms average over
 * 100 runs so CI noise cannot flake it; typical means are
 * sub-millisecond. Skipped unless a Redis URL is configured.
 */
final class ScriptBoundPerfTest extends TestCase
{
    private const RUNS = 100;
    private const AVG_BUDGET_MS = 50.0; // generous CI-safe guard, not a spec

    private ?Client $client = null;

    protected function setUp(): void
    {
        $url = getenv('RISK_REDIS_URL');
        if (is_string($url) && $url !== '') {
            $this->client = AggregateCalibrator::createClient($url);
        }
    }

    private function requireClient(): Client
    {
        if ($this->client === null) {
            self::markTestSkipped('RISK_REDIS_URL not set; start redis with: docker run -d -p 6399:6379 redis:7-alpine');
        }
        return $this->client;
    }

    private function loadScript(string $file): string
    {
        $path = dirname(__DIR__) . '/resources/' . $file;
        $script = @file_get_contents($path);
        if ($script === false) {
            self::fail("cannot read bundled script at resources/{$file}");
        }
        return $script;
    }

    /**
     * The calibrator ships script bytes only on the first use per script
     * and on a NOSCRIPT repair (SCRIPT LOAD). Every steady-state call is
     * an EVALSHA of the cached 40-char sha, never a full-body EVAL of the
     * multi-kilobyte script — the same cached-sha pattern the state store
     * applies.
     */
    public function testCalibratorShipsScriptBytesOnlyOnNoscriptRepair(): void
    {
        $url = getenv('RISK_REDIS_URL');
        if (!is_string($url) || $url === '') {
            self::markTestSkipped('RISK_REDIS_URL not set');
        }
        $spy = new CommandSpyClient($url);
        $c = new AggregateCalibrator($spy, namespace: $this->namespace(), samplingMode: 'complete');
        $hour = intdiv($this->nowMs(), 3_600_000);

        // First use of register_decision.lua and confirm.lua: one SCRIPT
        // LOAD each; every following call is a bare EVALSHA.
        $c->recordReceipt('sbp-1', 1, 1, RiskAction::Sha20, 100, 1, $hour);
        $c->recordReceipt('sbp-2', 1, 1, RiskAction::Sha20, 100, 1, $hour);
        $c->confirmOutcome('sbp-1', false);
        $c->confirmOutcome('sbp-2', false);

        $tally = static function (CommandSpyClient $spy): array {
            $out = ['SCRIPT' => 0, 'EVAL' => 0, 'EVALSHA' => 0];
            foreach ($spy->commands as $id) {
                if (isset($out[$id])) {
                    $out[$id]++;
                }
            }
            return $out;
        };
        $before = $tally($spy);
        self::assertSame(0, $before['EVAL'], 'the calibrator must never ship the full script body via EVAL');
        self::assertSame(2, $before['SCRIPT'], 'exactly one SCRIPT LOAD per script on first use');
        self::assertSame(4, $before['EVALSHA'], 'every script invocation is a cached-sha EVALSHA');

        // A server-side script-cache flush forces one NOSCRIPT repair:
        // exactly one more SCRIPT LOAD, still no full-body EVAL.
        AggregateCalibrator::createClient($url)->script('FLUSH');
        $c->recordReceipt('sbp-3', 1, 1, RiskAction::Sha20, 100, 1, $hour);
        $after = $tally($spy);
        self::assertSame(0, $after['EVAL'], 'the repair path must reload the sha, never EVAL the body');
        self::assertSame(3, $after['SCRIPT'], 'the NOSCRIPT repair ships the script bytes exactly once more');
        self::assertSame(6, $after['EVALSHA'], 'the repair call issues the failed EVALSHA plus the retried EVALSHA');
    }

    private function namespace(): string
    {
        return 'sb' . bin2hex(random_bytes(4));
    }

    private function nowMs(): int
    {
        return (int) floor(microtime(true) * 1000);
    }

    /** The 12 state fields of the risk state hashes at their maximum. */
    private function seedRiskState(string $key, Client $client, int $now): void
    {
        $client->hset($key, 'ts', (string) $now);
        foreach (['rf', 'rs', 'iss', 'bad', 'mal', 'rep', 'af', 'sw', 'trust'] as $field) {
            $client->hset($key, $field, '999999999');
        }
        $client->hset($key, 'scope', '1');
        $client->hset($key, 'cool', '0');
    }

    /** All 6 flat bucket fields on a calibration bucket. */
    private function seedBucket(string $key, Client $client): void
    {
        $client->hset($key, 'legit_count', '1000000');
        $client->hset($key, 'legit_score_sum', '1000000000');
        $client->hset($key, 'abuse_count', '1000000');
        $client->hset($key, 'abuse_score_sum', '1000000000');
        $client->hset($key, 'sample_total', '1000000');
        $client->hset($key, 'sample_resolved', '900000');
    }

    /**
     * risk-v1.lua under maximum state (all 10 keys present with all 12
     * fields and the full event path, session and principal present,
     * dedupe miss): 100 runs must average under the generous 50 ms
     * guard.
     */
    public function testRiskV1AverageStaysUnderBudgetAtMaximumState(): void
    {
        $client = $this->requireClient();
        $script = $this->loadScript('risk-v1.lua');
        $ns = $this->namespace();
        $now = $this->nowMs();

        $keys = [];
        for ($i = 0; $i < 9; $i++) {
            $key = "{kiwi:{$ns}}:risk:perf:{$i}";
            $keys[] = $key;
            $this->seedRiskState($key, $client, $now);
        }
        $this->seedRiskState($keys[8], $client, $now); // global key re-seed (same shape)

        $sat = [8000, 100000, 6000, 4000, 3000, 2000, 6000, 10000, 70000, 10000, 10000];
        $times = [];
        for ($i = 0; $i < self::RUNS; $i++) {
            $dedupeKey = "{kiwi:{$ns}}:risk:dedupe:evt{$i}";
            $args = [
                1, // PreIssue
                1, // scope
                $now,
                str_pad(dechex($i), 32, '0', STR_PAD_LEFT), // fresh event_id: dedupe miss
                60,
                1800,
                60000,
                ...$sat,
                1, // has_session
                1, // has_principal
                1800,
                86400,
            ];
            $start = hrtime(true);
            $result = $client->eval($script, 10, ...array_merge($keys, [$dedupeKey], $args));
            $times[] = (hrtime(true) - $start) / 1000; // µs
            self::assertIsArray($result);
            self::assertCount(16, $result, 'the script must return the full 16-element vector');
        }

        $meanUs = array_sum($times) / self::RUNS;
        fwrite(STDERR, sprintf(
            "\nScriptBoundPerf: risk-v1.lua %d runs at max state, mean %.2f µs (guard: avg < %.0f ms)\n",
            self::RUNS,
            $meanUs,
            self::AVG_BUDGET_MS
        ));
        self::assertLessThan(
            self::AVG_BUDGET_MS * 1000,
            $meanUs,
            sprintf('risk-v1.lua average %.2f µs exceeds the %.0f ms guard', $meanUs, self::AVG_BUDGET_MS)
        );
    }

    /**
     * calibration.lua under maximum state (24 buckets × 6 fields plus
     * rate state): 100 runs must average under the generous 50 ms guard.
     */
    public function testCalibrationAverageStaysUnderBudgetAtMaximumState(): void
    {
        $client = $this->requireClient();
        $script = $this->loadScript('calibration.lua');
        $ns = $this->namespace();
        $now = $this->nowMs();
        $hour = intdiv($now, 3_600_000);

        $keys = [];
        for ($i = 0; $i < 24; $i++) {
            $key = "{kiwi:{$ns}}:cal:1:" . ($hour - $i);
            $keys[] = $key;
            $this->seedBucket($key, $client);
        }
        $keys[] = "{kiwi:{$ns}}:cal:state:1";

        $times = [];
        for ($i = 0; $i < self::RUNS; $i++) {
            $start = hrtime(true);
            $bias = $client->eval(
                $script,
                count($keys),
                ...array_merge($keys, [
                    $now,
                    1000,     // min_samples
                    150,      // max_adjustment
                    10,       // max_change_per_minute
                    0.80,     // minimum_resolution_ratio
                    1,        // random_sample
                    1.0,      // false_positive_cost
                    2.0,      // false_negative_cost
                ]),
            );
            $times[] = (hrtime(true) - $start) / 1000; // µs
            self::assertIsInt((int) $bias, 'the calibration read must return a bounded integer bias');
        }

        $meanUs = array_sum($times) / self::RUNS;
        fwrite(STDERR, sprintf(
            "\nScriptBoundPerf: calibration.lua %d runs at max state, mean %.2f µs (guard: avg < %.0f ms)\n",
            self::RUNS,
            $meanUs,
            self::AVG_BUDGET_MS
        ));
        self::assertLessThan(
            self::AVG_BUDGET_MS * 1000,
            $meanUs,
            sprintf('calibration.lua average %.2f µs exceeds the %.0f ms guard', $meanUs, self::AVG_BUDGET_MS)
        );
    }
}

/** Predis client recording every command id executed (no body). */
final class CommandSpyClient extends Client
{
    /** @var list<string> */
    public array $commands = [];

    public function executeCommand(CommandInterface $command)
    {
        $this->commands[] = $command->getId();
        return parent::executeCommand($command);
    }
}
