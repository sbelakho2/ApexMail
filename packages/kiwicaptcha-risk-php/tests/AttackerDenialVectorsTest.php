<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Marks\MarksEscalation;
use KiwiCaptcha\Risk\Marks\MarksView;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\SignalVector;
use PHPUnit\Framework\TestCase;

/**
 * Shared attacker-denial vectors (protocol/risk-v1/
 * attacker-denial-vectors.json): the Rust mirror and this implementation
 * must resolve every vector to the identical action, retry hint and
 * ordered reason list. The vectors pin the decisive stage of the marks
 * plane, so a divergent core fails one of these assertions in whichever
 * core drifted.
 */
final class AttackerDenialVectorsTest extends TestCase
{
    private function vectorsPath(): string
    {
        $env = getenv('RISK_ATTACKER_VECTORS_PATH');
        if (is_string($env) && $env !== '') {
            return $env;
        }

        return dirname(__DIR__) . '/../../protocol/risk-v1/attacker-denial-vectors.json';
    }

    public function testEveryVectorMatchesExactly(): void
    {
        $path = $this->vectorsPath();
        self::assertFileExists($path, sprintf('Attacker-denial vectors file not found at %s (set RISK_ATTACKER_VECTORS_PATH)', $path));
        $vectors = json_decode((string) file_get_contents($path), true);
        self::assertIsArray($vectors);
        self::assertSame(1, $vectors['version'], 'the vectors pin the stage version');
        $policy = RiskPolicy::fromConfig(self::intScopeKeys($vectors['policy']));
        $ttl = (int) $vectors['mark_ttl_ms'];

        $rows = $vectors['vectors'];
        self::assertNotEmpty($rows);
        foreach ($rows as $vector) {
            $why = $vector['why'] ?? 'vector';
            $signals = SignalVector::fromArray($vector['signals']);
            $resources = new ResourcePressure((int) $vector['argon_capacity'], (int) $vector['issuance_capacity']);
            $now = (int) $vector['now_ms'];
            $plain = $policy->decide(
                scope: (int) $vector['scope'],
                score: (int) $vector['score'],
                s: $signals,
                r: $resources,
                globalLevel: (int) $vector['global_level'],
                nowMs: $now,
            );
            $view = MarksView::fromParts($vector['own_marks'], $vector['target_mark']);
            $out = MarksEscalation::apply(
                $plain,
                $view,
                (bool) $vector['corroborated'],
                $now,
                $ttl,
                $resources,
            );
            self::assertSame($vector['expected_action'], $out->action->value, "action mismatch: {$why}");
            $expectedRetry = $vector['expected_retry_after_ms'];
            self::assertSame($expectedRetry, $out->retryAfterMs, "retry mismatch: {$why}");
            $expectedReasons = array_map(
                static fn (string $reason): string => $reason,
                $vector['expected_reasons'],
            );
            $actualReasons = array_map(
                static fn ($reason): string => $reason->value,
                $out->reasons,
            );
            self::assertSame($expectedReasons, $actualReasons, "reasons mismatch: {$why}");
        }
    }

    /**
     * JSON decodes the scope keys as strings; the parser requires the
     * canonical integer keys, so the reader casts them back.
     *
     * @param array<string, mixed> $config
     * @return array<string, mixed>
     */
    private static function intScopeKeys(array $config): array
    {
        $scopes = [];
        foreach ($config['scopes'] as $scope => $row) {
            $scopes[(int) $scope] = $row;
        }
        $config['scopes'] = $scopes;

        return $config;
    }
}
