<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Pricing\PriceModel;
use KiwiCaptcha\Risk\Pricing\ValueClass;
use PHPUnit\Framework\TestCase;

/**
 * Shared pricing vectors (protocol/risk-v1/pricing-vectors.json): both
 * cores must resolve every vector to the identical work score and rung.
 * The corpus header records the consts table; the reader asserts it
 * equals the compiled table, so a constant change without a corpus
 * regeneration fails loudly. `RISK_PRICING_VECTORS_PATH` overrides the
 * corpus location.
 */
final class PricingVectorsTest extends TestCase
{
    private function vectorsPath(): string
    {
        $env = getenv('RISK_PRICING_VECTORS_PATH');
        if (is_string($env) && $env !== '') {
            return $env;
        }
        return dirname(__DIR__) . '/../../protocol/risk-v1/pricing-vectors.json';
    }

    public function testEveryVectorMatchesExactly(): void
    {
        $path = $this->vectorsPath();
        self::assertFileExists($path, sprintf('Pricing vectors file not found at %s (set RISK_PRICING_VECTORS_PATH)', $path));
        $doc = json_decode((string) file_get_contents($path), true);
        self::assertIsArray($doc);
        self::assertSame('risk-v1', $doc['protocol']);
        self::assertSame('pricing-vectors', $doc['kind']);
        self::assertSame(2, $doc['version']);
        self::assertSame(
            PriceModel::version(),
            $doc['price_model_version'],
            'the corpus was generated under a different price model version'
        );
        $consts = $doc['constants'];
        unset($consts['class_order'], $consts['rung_order']);
        self::assertSame(
            PriceModel::CONSTS,
            $consts,
            'the corpus consts table must equal the compiled table byte for byte'
        );
        self::assertSame(
            ['allow', 'sha16', 'sha18', 'sha20', 'argon16', 'argon32', 'argon64', 'rsw', 'step_up', 'deny'],
            $doc['constants']['rung_order'],
            'the rung order the integer codes index into'
        );
        self::assertSame(
            ['low', 'standard', 'high', 'critical'],
            $doc['constants']['class_order'],
            'the class order the integer codes index into'
        );
        self::assertSame(['risk', 'class', 'trust', 'pressure', 'work_score', 'rung'], $doc['columns']);

        $vectors = $doc['vectors'];
        self::assertIsArray($vectors);
        self::assertNotEmpty($vectors);
        self::assertCount((int) $doc['generator']['count'], $vectors, 'the recorded count must match the array length');
        self::assertCount(100000, $vectors, 'the corpus must ship its documented size');

        $classOrder = $doc['constants']['class_order'];
        $rungOrder = $doc['constants']['rung_order'];
        foreach ($vectors as $i => $vector) {
            [$risk, $classCode, $trust, $pressure, $expectedScore, $expectedRung] = $vector;
            $class = ValueClass::from($classOrder[$classCode]);

            self::assertSame(
                $expectedScore,
                PriceModel::workScore($risk, $class, $trust, $pressure),
                "work score mismatch at vector {$i}: risk {$risk} {$class->value} trust {$trust} pressure {$pressure}"
            );
            self::assertSame(
                $rungOrder[$expectedRung],
                PriceModel::price($risk, $class, $trust, $pressure)->value,
                "rung mismatch at vector {$i}: risk {$risk} {$class->value} trust {$trust} pressure {$pressure}"
            );
        }
    }
}
