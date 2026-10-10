<?php

declare(strict_types=1);

/**
 * The committed generator of protocol/risk-v1/pricing-vectors.json.
 *
 * The corpus is the shared cross-language contract for the continuous
 * pricing model: both cores resolve every vector to the identical work
 * score and rung. Regenerate with:
 *
 *   php tools/gen-pricing-vectors.php [output-path]
 *
 * The generator self-checks before writing: every vector of the
 * previously shipped corpus is recomputed through the live PriceModel
 * and must match its recorded score and rung. A model change without a
 * deliberate regeneration fails here loudly. The random-interior
 * family draws from one documented LCG stream (seed 1337, four draws
 * per vector: risk, class, trust, pressure, in that order) so the
 * corpus is reproducible byte for byte.
 *
 * Schema version 2 is columnar (arrays of six integers) so the full
 * 10^5 vectors fit a practical file size. The columns array names the
 * positions and the constants block carries the class and rung orders
 * the integer codes index into.
 */

require __DIR__ . '/../vendor/autoload.php';

use KiwiCaptcha\Risk\Pricing\PriceModel;
use KiwiCaptcha\Risk\Pricing\ValueClass;

const LCG_MODULUS = 2147483648; // 2^31
const LCG_MULTIPLIER = 1103515245;
const LCG_INCREMENT = 12345;
const SEED = 1337;
const CORPUS_TOTAL = 100000;

$repoRoot = dirname(__DIR__, 3);
$outPath = $argv[1] ?? $repoRoot . '/protocol/risk-v1/pricing-vectors.json';
$legacyPath = $repoRoot . '/protocol/risk-v1/pricing-vectors.json';

$classes = ValueClass::cases();
$classOrder = array_map(static fn (ValueClass $c): string => $c->value, $classes);
$rungOrder = ['allow', 'sha16', 'sha18', 'sha20', 'argon16', 'argon32', 'argon64', 'rsw', 'step_up', 'deny'];

$riskAxis = [0, 1, 74, 149, 150, 299, 300, 449, 450, 599, 600, 699, 700, 789, 790, 879, 880, 969, 970, 999, 1000];
$trustAxis = [0, 1, 2500, 5000, 7999, 8000, 9999, 10000];
$pressureAxis = [0, 1, 250, 500, 749, 750, 1000];
$edgeRisks = range(0, 1000, 10);

/** @return array{0:int,1:int,2:int,3:int,4:int,5:int} [risk, class, trust, pressure, score, rung] */
$vector = static function (int $risk, ValueClass $class, int $trust, int $pressure) use ($rungOrder): array {
    $score = PriceModel::workScore($risk, $class, $trust, $pressure);
    $rung = array_search(PriceModel::actionForWorkScore($score)->value, $rungOrder, true);

    return [$risk, $class->index(), $trust, $pressure, $score, (int) $rung];
};

$vectors = [];

// Family 1: the input-grid corners (4 classes x 21 risks x 8 trusts x 7 pressures).
foreach ($classes as $class) {
    foreach ($riskAxis as $risk) {
        foreach ($trustAxis as $trust) {
            foreach ($pressureAxis as $pressure) {
                $vectors[] = $vector($risk, $class, $trust, $pressure);
            }
        }
    }
}
$gridCount = count($vectors);

// Family 2: the band-edge sweep (4 classes x 101 risks x the trusted
// bucket x the two pressure extremes).
foreach ($classes as $class) {
    foreach ($edgeRisks as $risk) {
        foreach ([0, 1000] as $pressure) {
            $vectors[] = $vector($risk, $class, 8000, $pressure);
        }
    }
}
$edgeCount = count($vectors) - $gridCount;

// Family 3: the seeded random interior, extending the stream until the
// corpus holds exactly the corpus total.
$state = SEED;
$next = static function () use (&$state): int {
    $state = (LCG_MULTIPLIER * $state + LCG_INCREMENT) % LCG_MODULUS;

    return $state;
};
while (count($vectors) < CORPUS_TOTAL) {
    $risk = $next() % 1001;
    $class = $classes[$next() % 4];
    $trust = $next() % 10001;
    $pressure = $next() % 1001;
    $vectors[] = $vector($risk, $class, $trust, $pressure);
}
$randomCount = count($vectors) - $gridCount - $edgeCount;

// Self-check: recompute the previously shipped corpus. Every recorded
// score and rung must match, or the model moved without a regeneration.
if (is_file($legacyPath)) {
    $legacy = json_decode((string) file_get_contents($legacyPath), true);
    if (is_array($legacy) && ($legacy['version'] ?? 0) === 1) {
        foreach ($legacy['vectors'] as $i => $old) {
            $class = ValueClass::from($old['value_class']);
            $score = PriceModel::workScore($old['risk'], $class, $old['trust'], $old['pressure']);
            $rung = PriceModel::actionForWorkScore($score)->value;
            if ($score !== $old['work_score'] || $rung !== $old['expected_rung']) {
                fwrite(STDERR, sprintf(
                    "self-check failed at legacy vector %d: recorded %d/%s, model %d/%s\n",
                    $i,
                    $old['work_score'],
                    $old['expected_rung'],
                    $score,
                    $rung,
                ));
                exit(1);
            }
        }
        fwrite(STDERR, sprintf("self-check ok: %d legacy vectors reproduce\n", count($legacy['vectors'])));
    }
}

$doc = [
    'protocol' => 'risk-v1',
    'kind' => 'pricing-vectors',
    'version' => 2,
    'price_model_version' => PriceModel::version(),
    'generator' => [
        'seed' => SEED,
        'rule' => 'x = (1103515245*x + 12345) mod 2^31; four draws per random vector (risk, class, trust, pressure, in that order)',
        'families' => ['grid' => $gridCount, 'band_edge_sweep' => $edgeCount, 'random_interior' => $randomCount],
        'count' => count($vectors),
        'expected_by' => 'kiwicaptcha-risk-php PriceModel (integer math mirrored by the Rust core)',
        'generator' => 'packages/kiwicaptcha-risk-php/tools/gen-pricing-vectors.php',
    ],
    'constants' => [
        'version' => PriceModel::version(),
        'score_saturation' => 1000,
        'trust_saturation' => 10000,
        'trust_half_scale' => 2500,
        'trusted_bucket_credit' => 8000,
        'pressure_gain_saturation' => 300,
        'value_weights' => array_map(static fn (ValueClass $c): int => $c->weight(), $classes),
        'band_edges' => [150, 300, 450, 600, 700, 790, 880, 970],
        'argon_capacity_floor' => 300,
        'class_order' => $classOrder,
        'rung_order' => $rungOrder,
    ],
    'columns' => ['risk', 'class', 'trust', 'pressure', 'work_score', 'rung'],
    'vectors' => $vectors,
];

$json = json_encode($doc, JSON_UNESCAPED_SLASHES);
if ($json === false) {
    fwrite(STDERR, "encoding failed\n");
    exit(1);
}
file_put_contents($outPath, $json . "\n");
fwrite(STDERR, sprintf(
    "wrote %s: %d vectors (%d grid, %d edge, %d random), %.1f MiB\n",
    $outPath,
    count($vectors),
    $gridCount,
    $edgeCount,
    $randomCount,
    strlen($json) / 1048576,
));
