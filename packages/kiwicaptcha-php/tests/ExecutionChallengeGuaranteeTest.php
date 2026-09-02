<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ExecutionChallengeGenerator;
use PHPUnit\Framework\TestCase;

/**
 * ExecutionChallengeV1 guaranteed-structure corpus.
 *
 * Every armed program must carry a mandatory DOM construction block
 * (createElement with a drawn id, a mutate op on that node, an
 * append) followed by a mandatory real-probe block. The probe id
 * operands reference the constructed id bytes, drawn once and reused.
 * The corpus asserts the structure on decoded programs and that the
 * browser-equivalent executed trace verifies end to end.
 *
 * The adversarial cases frame the boundary: a solver that skips the
 * DOM construction cannot forge the probe entries. A naive trace
 * whose probes read 'none' (as if the constructed node never existed),
 * a trace without the probe block, and geometry entries that break
 * the layout invariants are all rejected by the anchored trace walk.
 * The genuine executed trace verifies.
 */
final class ExecutionChallengeGuaranteeTest extends TestCase
{
    private const KEY = '0123456789abcdef0123456789abcdef';
    private const SCOPE = 'login';
    private const ACTION = 'login-action';
    private const VERSION = 1;

    public function testCausalObserveForgeriesAreRejected(): void
    {
        // The V2 adversarial framing: the observed height is written
        // through into the replay state, so a trace that reports a
        // value but does not carry it coherently through the later
        // checksum/read entries is rejected by the anchored walk.
        $label = 'obsforge';
        $nonce = $this->nonceFor($label);
        $programB64 = $this->blobFor($label);
        $decoded = ExecutionChallengeGenerator::decode($programB64);
        self::assertNotNull($decoded);
        $trace = ExecutionChallengeGenerator::executedTraceFor($decoded);
        self::assertNotNull(ExecutionChallengeGenerator::verifyExecutedTrace($programB64, $nonce, $trace));

        $obsEntry = null;
        foreach (explode(';', $trace) as $entry) {
            if (str_starts_with($entry, 'obs(')) {
                $obsEntry = $entry;
                break;
            }
        }
        self::assertNotNull($obsEntry, 'the executed trace carries the observe entry');

        // Bounds: heights 0 and 256 are rejected.
        self::assertNull(
            ExecutionChallengeGenerator::verifyExecutedTrace($programB64, $nonce, str_replace($obsEntry, 'obs(0,0)', $trace)),
            'an observe height of 0 must be rejected',
        );
        self::assertNull(
            ExecutionChallengeGenerator::verifyExecutedTrace($programB64, $nonce, str_replace($obsEntry, 'obs(0,256)', $trace)),
            'an observe height of 256 must be rejected',
        );

        // A destination index that differs from the program operand is
        // rejected.
        self::assertNull(
            ExecutionChallengeGenerator::verifyExecutedTrace($programB64, $nonce, str_replace($obsEntry, 'obs(63,10)', $trace)),
            'an observe destination that differs from the operand must be rejected',
        );

        // The write-through contradiction: report the observed value
        // but read the observed index back as if the write never
        // happened.
        $readEntry = null;
        foreach (explode(';', $trace) as $entry) {
            if (str_starts_with($entry, 'u8r(')) {
                $readEntry = $entry;
                break;
            }
        }
        self::assertNotNull($readEntry, 'the executed trace reads the observed byte back');
        self::assertNull(
            ExecutionChallengeGenerator::verifyExecutedTrace($programB64, $nonce, str_replace($readEntry, 'u8r(0)', $trace)),
            'a trace that reports the observe but drops the write-through is rejected',
        );

        // Removing the observe entry breaks the anchored walk.
        $obsRemoved = implode(';', array_values(array_filter(explode(';', $trace), static fn (string $e): bool => !str_starts_with($e, 'obs('))));
        self::assertNull(
            ExecutionChallengeGenerator::verifyExecutedTrace($programB64, $nonce, $obsRemoved),
            'a trace without the observe entry must be rejected',
        );
    }

    private function nonceFor(string $label): string
    {
        return base64_encode(hash('sha256', $label, true));
    }

    /**
     * The decoded program ops of a fixed-seed challenge.
     *
     * @return array{ops: list<array{op: int, operands: array<string, mixed>}>}
     */
    private function programFor(string $label): array
    {
        $nonce = $this->nonceFor($label);
        $program = ExecutionChallengeGenerator::generate(self::KEY, $nonce, self::SCOPE, self::ACTION, self::VERSION);
        $decoded = ExecutionChallengeGenerator::decode($program);
        self::assertNotNull($decoded, 'every generated program must parse');

        return $decoded;
    }

    /**
     * The drawn id bytes of the mandatory construction create (op 0).
     */
    private function constructedId(array $decoded): string
    {
        $create = $decoded['ops'][0];
        self::assertSame(ExecutionChallengeGenerator::OP_DOM_CREATE, $create['op']);
        $id = $create['operands']['id'] ?? null;
        self::assertIsString($id);

        return $id;
    }

    /**
     * The canonical base64 program blob of a fixed-seed challenge.
     */
    private function blobFor(string $label): string
    {
        $nonce = $this->nonceFor($label);

        return ExecutionChallengeGenerator::generate(self::KEY, $nonce, self::SCOPE, self::ACTION, self::VERSION);
    }

    /**
     * The blob with the op-0 create id rewritten to a foreign id of
     * the same length (every id byte becomes 'z'). The probes then
     * reference a node that was never constructed.
     */
    private function blobWithForeignCreateId(string $programB64): string
    {
        $bytes = base64_decode($programB64, true);
        self::assertNotFalse($bytes);
        $scopeLen = \ord($bytes[1]);
        $actionLen = \ord($bytes[2 + $scopeLen]);
        $op0 = 2 + $scopeLen + 1 + $actionLen + 2;
        self::assertSame(ExecutionChallengeGenerator::OP_DOM_CREATE, \ord($bytes[$op0]));
        $idLen = \ord($bytes[$op0 + 2]);
        self::assertGreaterThanOrEqual(4, $idLen);
        self::assertNotSame('zzzzzzzzzzzzzzzz', substr($bytes, $op0 + 3, $idLen), 'the drawn id must differ from the foreign id');
        for ($i = 0; $i < $idLen; $i++) {
            $bytes[$op0 + 3 + $i] = 'z';
        }
        $foreign = base64_encode($bytes);
        self::assertNotSame($programB64, $foreign);

        return $foreign;
    }

    public function testEveryGeneratedProgramCarriesTheGuaranteedStructure(): void
    {
        $qrealReadbacks = 0;
        $probeOpcodeCounts = [];
        for ($i = 0; $i < 200; $i++) {
            $label = sprintf('corpus-%03d', $i);
            $programB64 = $this->blobFor($label);
            $decoded = ExecutionChallengeGenerator::decode($programB64);
            self::assertNotNull($decoded);
            $ops = $decoded['ops'];
            $count = \count($ops);
            self::assertGreaterThanOrEqual(ExecutionChallengeGenerator::MIN_OPS, $count);
            self::assertLessThanOrEqual(ExecutionChallengeGenerator::MAX_OPS, $count);

            // The construction block: create with a drawn id, a mutate
            // op on that node, an append.
            $createdId = $this->constructedId($decoded);
            self::assertGreaterThanOrEqual(4, \strlen($createdId));
            self::assertLessThanOrEqual(16, \strlen($createdId));
            self::assertContains($ops[1]['op'], [
                ExecutionChallengeGenerator::OP_DOM_SET_ATTR,
                ExecutionChallengeGenerator::OP_DOM_DATASET_SET,
                ExecutionChallengeGenerator::OP_DOM_CLASS_ADD,
            ], 'op 1 is a mutate op on the created node');
            self::assertSame(ExecutionChallengeGenerator::OP_DOM_APPEND, $ops[2]['op'], 'op 2 is the construction append');

            // The causal u8 chain: create the array, observe the real
            // height of the constructed node into it, read the observed
            // byte back, checksum or rotate over it.
            self::assertSame(ExecutionChallengeGenerator::OP_U8_CREATE, $ops[3]['op'], 'op 3 creates the u8 array');
            $u8cLen = $ops[3]['operands']['len'];
            $obs = $ops[4];
            self::assertSame(ExecutionChallengeGenerator::OP_DOM_OBSERVE, $obs['op'], 'op 4 observes the constructed node');
            self::assertSame($createdId, $obs['operands']['id'], 'the observe op references the constructed id');
            self::assertLessThan($u8cLen, $obs['operands']['idx'], 'the observed byte lands inside the created array');
            self::assertSame(ExecutionChallengeGenerator::OP_U8_READ, $ops[5]['op'], 'op 5 reads the observed byte back');
            self::assertSame($obs['operands']['idx'], $ops[5]['operands']['idx'], 'the read targets the observed index');
            self::assertContains($ops[6]['op'], [
                ExecutionChallengeGenerator::OP_U8_WRITE,
                ExecutionChallengeGenerator::OP_U8_ROTATE,
            ], 'op 6 checksums or rotates over the observed byte');

            // The real-probe block: every probe op references the
            // constructed id bytes; the filler after it never draws
            // the browser-observed probes.
            self::assertContains($ops[7]['op'], [
                ExecutionChallengeGenerator::OP_DOM_QUERY_REAL,
                ExecutionChallengeGenerator::OP_DOM_GEOMETRY,
                ExecutionChallengeGenerator::OP_DOM_EVENT_REAL,
            ], 'the link probe is one of the id-carrying real probes');
            $probeEnd = 7;
            $seenConstructedProbe = false;
            while ($probeEnd < $count && $ops[$probeEnd]['op'] >= ExecutionChallengeGenerator::OP_DOM_QUERY_REAL) {
                $probe = $ops[$probeEnd];
                $probeOpcodeCounts[$probe['op']] = ($probeOpcodeCounts[$probe['op']] ?? 0) + 1;
                if (\in_array($probe['op'], [
                    ExecutionChallengeGenerator::OP_DOM_QUERY_REAL,
                    ExecutionChallengeGenerator::OP_DOM_GEOMETRY,
                    ExecutionChallengeGenerator::OP_DOM_EVENT_REAL,
                ], true)) {
                    self::assertSame($createdId, $probe['operands']['id'], 'every id-carrying probe references the constructed id');
                    $seenConstructedProbe = true;
                }
                $probeEnd++;
            }
            self::assertTrue($seenConstructedProbe, 'at least one probe reads the constructed id');
            for ($k = $probeEnd; $k < $count; $k++) {
                self::assertLessThan(ExecutionChallengeGenerator::OP_DOM_QUERY_REAL, $ops[$k]['op'], 'the filler ops never draw the browser-observed probes');
            }

            // The browser-equivalent executed trace verifies against
            // the program, and the digest machinery accepts it.
            $trace = ExecutionChallengeGenerator::executedTraceFor($decoded);
            self::assertNotNull(
                ExecutionChallengeGenerator::verifyExecutedTrace($programB64, $this->nonceFor($label), $trace),
                'the executed trace of a generated program must verify',
            );
            self::assertNotNull(ExecutionChallengeGenerator::digestOverTrace($programB64, $this->nonceFor($label), $trace));
            self::assertNotNull(ExecutionChallengeGenerator::expectedDigest($programB64, $this->nonceFor($label)));
            if (str_contains($trace, 'qreal(div|')) {
                $qrealReadbacks++;
            }
        }
        self::assertGreaterThan(0, $qrealReadbacks, 'the corpus must exercise real qreal readbacks of constructed nodes');
        self::assertArrayHasKey(ExecutionChallengeGenerator::OP_DOM_QUERY_REAL, $probeOpcodeCounts);
        self::assertArrayHasKey(ExecutionChallengeGenerator::OP_DOM_GEOMETRY, $probeOpcodeCounts);
        self::assertArrayHasKey(ExecutionChallengeGenerator::OP_DOM_EVENT_REAL, $probeOpcodeCounts);
        self::assertArrayHasKey(ExecutionChallengeGenerator::OP_DOM_POINT, $probeOpcodeCounts);
        self::assertArrayHasKey(ExecutionChallengeGenerator::OP_DOM_SERIALIZE_REAL, $probeOpcodeCounts);
    }

    public function testTheRealProbeReadsTheConstructedNode(): void
    {
        // The browser-equivalent executed trace of a program whose
        // probe ids reference constructed nodes carries the real
        // readbacks: the qreal entry shows 'div|...' (the canonical
        // attribute pairs of the constructed node), never 'none'.
        $seenQreal = false;
        for ($i = 0; $i < 128; $i++) {
            $label = sprintf('readback-%03d', $i);
            $decoded = $this->programFor($label);
            if ($decoded['ops'][7]['op'] !== ExecutionChallengeGenerator::OP_DOM_QUERY_REAL) {
                continue;
            }
            $seenQreal = true;
            $trace = ExecutionChallengeGenerator::executedTraceFor($decoded);
            self::assertStringContainsString('qreal(div|', $trace, 'the qreal probe reads back the constructed node');
            self::assertStringNotContainsString('qreal(none)', $trace, 'a constructed probe never reads as absent');
            break;
        }
        self::assertTrue($seenQreal, 'the corpus must contain a qreal link probe');

        $seenEvent = false;
        for ($i = 0; $i < 128; $i++) {
            $label = sprintf('readback-event-%03d', $i);
            $decoded = $this->programFor($label);
            if ($decoded['ops'][7]['op'] !== ExecutionChallengeGenerator::OP_DOM_EVENT_REAL) {
                continue;
            }
            $seenEvent = true;
            $trace = ExecutionChallengeGenerator::executedTraceFor($decoded);
            self::assertStringContainsString('evreal(kiwi-ev:div)', $trace, 'the event probe reads back the constructed node');
            self::assertStringNotContainsString('evreal(none)', $trace, 'a constructed probe never reads as absent');
            break;
        }
        self::assertTrue($seenEvent, 'the corpus must contain an event link probe');
    }

    public function testAForgerWhoSkipsTheConstructionCannotForgeTheProbeEntries(): void
    {
        // The adversarial framing: a solver that skips the DOM
        // construction produces a trace whose real probes read 'none'
        // (the constructed node never existed in its simulation). The
        // verifier simulates the construction and demands the real
        // readback, so the naive trace is rejected while the genuine
        // executed trace verifies.
        $nonce = null;
        $programB64 = null;
        for ($i = 0; $i < 128; $i++) {
            $label = sprintf('forger-%03d', $i);
            $decoded = $this->programFor($label);
            if ($decoded['ops'][7]['op'] === ExecutionChallengeGenerator::OP_DOM_QUERY_REAL) {
                $nonce = $this->nonceFor($label);
                $programB64 = $this->blobFor($label);
                break;
            }
        }
        self::assertNotNull($programB64, 'the corpus must contain a qreal link probe');
        $program = ExecutionChallengeGenerator::decode($programB64);
        self::assertNotNull($program);
        $genuine = ExecutionChallengeGenerator::executedTraceFor($program);
        self::assertNotNull(ExecutionChallengeGenerator::verifyExecutedTrace($programB64, $nonce, $genuine));

        // The naive trace of the same program shape with a foreign
        // create id: every real probe reads 'none'.
        $naiveB64 = $this->blobWithForeignCreateId($programB64);
        $naiveProgram = ExecutionChallengeGenerator::decode($naiveB64);
        self::assertNotNull($naiveProgram, 'the foreign-id program must parse');
        $naiveTrace = ExecutionChallengeGenerator::executedTraceFor($naiveProgram);
        self::assertStringContainsString('qreal(none)', $naiveTrace, 'a solver skipping the construction reads the probe as absent');
        self::assertNull(
            ExecutionChallengeGenerator::verifyExecutedTrace($programB64, $nonce, $naiveTrace),
            'the naive none probe trace must be rejected against the real program',
        );

        // Removing the probe block: a trace cut after the construction
        // append is missing every probe entry and must be rejected.
        $cut = strpos($genuine, 'dappend(1);') + \strlen('dappend(1);');
        self::assertNotFalse($cut);
        $truncated = substr($genuine, 0, $cut);
        self::assertNull(
            ExecutionChallengeGenerator::verifyExecutedTrace($programB64, $nonce, $truncated),
            'a trace without the probe entries must be rejected',
        );
    }

    public function testLayoutProbeForgeriesAreRejected(): void
    {
        // The geometry forgeries: a height-0 entry and a
        // non-monotonic entry both fail the layout invariants, while
        // the genuine executed trace verifies.
        $seenHeight0 = false;
        for ($i = 0; $i < 256; $i++) {
            $label = sprintf('geom-height-%03d', $i);
            $programB64 = $this->blobFor($label);
            $program = ExecutionChallengeGenerator::decode($programB64);
            self::assertNotNull($program);
            $hasGeom = false;
            foreach ($program['ops'] as $op) {
                if ($op['op'] === ExecutionChallengeGenerator::OP_DOM_GEOMETRY) {
                    $hasGeom = true;
                    break;
                }
            }
            if (!$hasGeom) {
                continue;
            }
            $seenHeight0 = true;
            $genuine = ExecutionChallengeGenerator::executedTraceFor($program);
            self::assertNotNull(ExecutionChallengeGenerator::verifyExecutedTrace($programB64, $this->nonceFor($label), $genuine));
            $forged = preg_replace('/geom\(0,10\)/', 'geom(0,0)', $genuine, 1);
            self::assertIsString($forged);
            self::assertNotSame($genuine, $forged, 'the height-0 forge must change the trace');
            self::assertNull(
                ExecutionChallengeGenerator::verifyExecutedTrace($programB64, $this->nonceFor($label), $forged),
                'a geometry entry with height 0 must be rejected',
            );
            break;
        }
        self::assertTrue($seenHeight0, 'the corpus must contain a geometry probe');

        $seenNonMonotonic = false;
        for ($i = 0; $i < 256; $i++) {
            $label = sprintf('geom-top-%03d', $i);
            $programB64 = $this->blobFor($label);
            $program = ExecutionChallengeGenerator::decode($programB64);
            self::assertNotNull($program);
            $geomCount = 0;
            foreach ($program['ops'] as $op) {
                if ($op['op'] === ExecutionChallengeGenerator::OP_DOM_GEOMETRY) {
                    $geomCount++;
                }
            }
            if ($geomCount < 2) {
                continue;
            }
            $seenNonMonotonic = true;
            $genuine = ExecutionChallengeGenerator::executedTraceFor($program);
            self::assertNotNull(ExecutionChallengeGenerator::verifyExecutedTrace($programB64, $this->nonceFor($label), $genuine));
            $forged = preg_replace('/geom\(0,10\)/', 'geom(50,10)', $genuine, 1);
            self::assertIsString($forged);
            self::assertNull(
                ExecutionChallengeGenerator::verifyExecutedTrace($programB64, $this->nonceFor($label), $forged),
                'a non-monotonic geometry sequence must be rejected',
            );
            break;
        }
        self::assertTrue($seenNonMonotonic, 'the corpus must contain two geometry probes');
    }
}
