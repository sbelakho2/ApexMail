<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Outcomes\Outcome;
use KiwiCaptcha\Risk\Outcomes\OutcomeHandle;
use KiwiCaptcha\Risk\Outcomes\OutcomeMap;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use PHPUnit\Framework\TestCase;

/**
 * Shared typed-outcome vectors (protocol/risk-v1/outcomes-vectors.json):
 * the Rust mirror and this implementation must resolve every vector to
 * the identical event channel, ledger action, mark behavior, polarity
 * decision and mark key. The vectors are the cross-language pin of the
 * versioned mapping table, so a divergent row fails one of these
 * assertions in whichever core drifted.
 */
final class OutcomesVectorsTest extends TestCase
{
    private function vectorsPath(): string
    {
        $env = getenv('RISK_OUTCOMES_VECTORS_PATH');
        if (is_string($env) && $env !== '') {
            return $env;
        }

        return dirname(__DIR__) . '/../../protocol/risk-v1/outcomes-vectors.json';
    }

    public function testEveryVectorMatchesExactly(): void
    {
        $path = $this->vectorsPath();
        self::assertFileExists($path, sprintf('Outcome vectors file not found at %s (set RISK_OUTCOMES_VECTORS_PATH)', $path));
        $vectors = json_decode((string) file_get_contents($path), true);
        self::assertIsArray($vectors);
        self::assertSame(OutcomeMap::VERSION, $vectors['version'], 'the vectors pin the mapping table version');

        // Key-building surface: the store never connects for key building,
        // so a client pointed at a dead port is enough.
        $store = new RedisRiskStateStore(
            RedisRiskStateStore::createClient('redis://127.0.0.1:1/'),
            namespace: (string) $vectors['namespace'],
        );

        $seen = [];
        foreach ($vectors['vectors'] as $vector) {
            $outcome = Outcome::fromWireName((string) $vector['outcome']);
            self::assertNotNull($outcome, "unknown outcome wire name {$vector['outcome']}");
            $seen[] = $vector['outcome'];
            $dimension = $vector['handle']['dimension'];
            $id = (string) $vector['handle']['id'];

            if ($vector['accepted'] === false) {
                if (($vector['reject'] ?? null) === 'identifier') {
                    try {
                        self::buildHandle($dimension, $id);
                        self::fail(sprintf('%s on %s must reject the identifier', $vector['outcome'], $dimension));
                    } catch (\InvalidArgumentException) {
                        self::addToAssertionCount(1);
                    }
                } else {
                    $handle = self::buildHandle($dimension, $id);
                    self::assertFalse(
                        OutcomeMap::for($outcome)->accepts($handle->dimension),
                        sprintf('%s must reject a %s handle', $vector['outcome'], $dimension),
                    );
                }
                continue;
            }

            $handle = self::buildHandle($dimension, $id);
            $mapping = OutcomeMap::for($outcome);
            self::assertTrue($mapping->accepts($handle->dimension), "{$vector['outcome']} accepts a {$dimension} handle");
            self::assertSame($vector['channel_value'], $mapping->channel->value, "{$vector['outcome']} channel");
            self::assertSame($vector['writes_abuse_mark'], $mapping->writesAbuseMark, "{$vector['outcome']} mark behavior");
            self::assertSame($vector['server_confirmed'], $mapping->serverConfirmed, "{$vector['outcome']} confirmation class");
            self::assertSame($vector['may_subtract_risk'], $mapping->maySubtractRisk, "{$vector['outcome']} polarity");
            self::assertSame($vector['mark_kind'], $mapping->markKind(), "{$vector['outcome']} mark kind");
            $expectedLedger = $vector['ledger_action'];
            self::assertSame($expectedLedger, $mapping->ledgerLegitimate === null ? null : ($mapping->ledgerLegitimate ? 'L' : 'A'));

            if ($vector['mark_key'] !== null) {
                self::assertSame($vector['mark_key'], $store->markKey($handle->dimension->markDimension() ?? '', $handle->id));
            }
        }

        // Every outcome of the vocabulary is covered.
        self::assertSame(
            array_map(static fn (Outcome $o): string => $o->value, Outcome::cases()),
            array_values(array_unique($seen)),
            'the vectors must cover the whole vocabulary',
        );

        // The store-level mark keys (the asn surface and an identity one).
        foreach ($vectors['store_marks'] as $row) {
            self::assertSame($row['key'], $store->markKey((string) $row['dimension'], (string) $row['id']));
        }
    }

    private static function buildHandle(string $dimension, string $id): OutcomeHandle
    {
        return match ($dimension) {
            'nonce' => OutcomeHandle::nonce($id),
            'decisionId' => OutcomeHandle::decisionId($id),
            'principal' => OutcomeHandle::principal($id),
            'target' => OutcomeHandle::target($id),
            'session' => OutcomeHandle::session($id),
            'agent' => OutcomeHandle::agent($id),
            default => throw new \InvalidArgumentException("unknown dimension {$dimension}"),
        };
    }
}
