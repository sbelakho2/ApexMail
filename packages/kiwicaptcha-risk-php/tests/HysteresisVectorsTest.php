<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\ScopeActionHysteresis;
use PHPUnit\Framework\TestCase;

/**
 * Shared hysteresis edge-fallback vectors (protocol/risk-v1/
 * hysteresis-vectors.json): the Rust ScopeActionHysteresis and this
 * implementation must select the identical action for every step. Each
 * step is independent — the client's last action in the scope is seeded
 * from the recorded previous, then select(score) runs with the plain
 * mapping and must return the recorded expected.
 */
final class HysteresisVectorsTest extends TestCase
{
    private const T0 = 1_700_000_000_000;

    private function vectorsPath(): string
    {
        $env = getenv('RISK_HYSTERESIS_VECTORS_PATH');
        if (is_string($env) && $env !== '') {
            return $env;
        }
        return dirname(__DIR__) . '/../../protocol/risk-v1/hysteresis-vectors.json';
    }

    /** Case names are the enum case names (StepUp carries the wire value 'step_up'). */
    private function action(string $name): RiskAction
    {
        return match ($name) {
            'StepUp' => RiskAction::StepUp,
            default => RiskAction::from(strtolower($name)),
        };
    }

    /** A score whose plain mapping is the action — seeds the entry the way a real request would. */
    private function seedScore(RiskAction $action): int
    {
        for ($score = 0; $score <= 1000; $score++) {
            if (RiskAction::actionForScore($score) === $action) {
                return $score;
            }
        }
        throw new \RuntimeException('no score maps to ' . $action->name);
    }

    public function testEveryVectorMatchesExactly(): void
    {
        $path = $this->vectorsPath();
        self::assertFileExists($path, sprintf('Hysteresis vectors file not found at %s (set RISK_HYSTERESIS_VECTORS_PATH)', $path));
        $vectors = json_decode((string) file_get_contents($path), true);
        self::assertIsArray($vectors);
        self::assertNotEmpty($vectors['vectors'], 'hysteresis vectors must not be empty');

        $steps = 0;
        foreach ($vectors['vectors'] as $vector) {
            $client = $vector['client'];
            foreach ($vector['steps'] as $step) {
                $scope = (int) $step['scope'];
                $score = (int) $step['score'];
                $previous = $this->action($step['previous']);
                $expected = $this->action($step['expected']);

                // Each step is independent: seed the previous action, then
                // select at the recorded score one tick later.
                $h = new ScopeActionHysteresis();
                $seed = $this->seedScore($previous);
                self::assertSame(
                    $previous,
                    $h->select($scope, $client, $seed, RiskAction::actionForScore($seed), self::T0),
                    'the seed step must store the recorded previous action'
                );
                self::assertSame(
                    $expected,
                    $h->select($scope, $client, $score, RiskAction::actionForScore($score), self::T0 + 1),
                    sprintf('client %s scope %d score %d previous %s', $client, $scope, $score, $previous->name)
                );
                $steps++;
            }
        }
        // Both done-when pins and the coverage families must be present.
        self::assertGreaterThanOrEqual(15, $steps, 'the vector families must stay comprehensive');
    }
}
