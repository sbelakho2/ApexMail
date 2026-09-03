<?php

declare(strict_types=1);

namespace KiwiCaptcha\TestSupport;

use KiwiCaptcha\ExecutionChallengeGenerator;

/**
 * Test-only execution-trace fixture builder.
 *
 * Synthesizes the browser-equivalent executed trace of an
 * ExecutionChallengeV1 program, the trace a genuine browser execution
 * submits, without a browser. The layout entries are fabricated with
 * the fixed reference height {@see self::OBSERVED_HEIGHT} (10), and
 * the observed byte is written through the u8 state exactly like the
 * verifier's replay, so the synthesized trace is accepted by
 * `ExecutionChallengeGenerator::verifyExecutedTrace`.
 *
 * Why this surface exists: no public production API may promise a
 * non-browser equivalent of a real execution. The former
 * `ExecutionChallengeGenerator::executedTraceFor` entry point is gone.
 * The fabrication lives here, behind the explicitly test-only
 * `KiwiCaptcha\TestSupport` namespace. Never call this class from a
 * production path. Test suites, cross-language fixtures and the
 * browser fixture router are its only callers. The verifier's own
 * machinery (`verifyExecutedTrace`, `digestOverTrace`,
 * `expectedDigest`) stays on the generator and operates over
 * submitted evidence, replaying whatever the trace reports.
 *
 * Implementation note: PHP has no cross-class private visibility, so
 * this fixture carries a private copy of the generator's
 * deterministic state machine (`simulateOp` and its helpers) plus the
 * trace-name table. The copy is behavior-exact by construction and
 * pinned by the full suites: every fixture trace is replayed
 * entry-by-entry by `verifyExecutedTrace` and cross-checked against
 * the Rust mirror, so any divergence from the generator's semantics
 * fails loudly. Keep this copy in lockstep with
 * `ExecutionChallengeGenerator` when the op semantics ever change.
 * The opcode numbers and the attribute-name list are read from the
 * generator's public constants, the single source of truth for the
 * wire contract.
 */
final class ExecutionTraceFixture
{
    /**
     * The fabricated reference height the browser-equivalent trace
     * synthesizes: the real observed value is the engine's own text
     * metrics (never predictable by the mirrors), so the synthesizer
     * uses this constant and the verifier replays whatever the trace
     * reports. A fabricated reference value, never a browser's
     * measurement.
     */
    public const OBSERVED_HEIGHT = 10;

    /** The trace entry names, one per opcode (index = opcode). */
    private const TRACE_NAMES = [
        'add', 'sub', 'mul', 'xor', 'and', 'or', 'shl', 'shr',
        'u8c', 'u8w', 'u8r', 'u8rot',
        'slen', 'schar', 'scode', 'sslice',
        'dcreate', 'dattr', 'dappend', 'dqsel', 'dget', 'dset', 'dgetd',
        'cadd', 'ccont', 'dparent', 'ddispatch', 'dserialize',
        'qreal', 'geom', 'point', 'evreal', 'sreal', 'obs',
    ];

    private function __construct()
    {
    }

    /**
     * Test-only. The browser-equivalent executed trace of a program:
     * the canonical trace with the layout-probe placeholders replaced
     * by valid browser-observed values (monotonic geometry offsets
     * with height {@see self::OBSERVED_HEIGHT}; the point probe names
     * the topmost constructed node). Lets a test simulate a genuine
     * browser execution.
     *
     * The entries are built per op from the same state machine the
     * canonical trace uses; only the layout entries are replaced, so
     * readback values that contain ';' or parentheses travel intact.
     *
     * @param array{format: int, scope: string, action: string, op_version: int, ops: list<array{op: int, operands: array<string, mixed>}>} $program
     */
    public static function executedTraceFor(array $program): string
    {
        $u8 = [];
        $cur = null; // ['id', 'attrs' map, 'dataset' map, 'classes' set, 'appended' bool]
        $docIds = [];
        $top = 0;
        // The verifier's `POINT` probe accepts 'div' exactly when the
        // program constructs any node (its construction check is
        // whole-program), so the browser-equivalent trace must use the
        // same predicate — 'point(none)' on a program with no DOM_APPEND
        // would otherwise mismatch deterministically.
        $hasAppend = false;
        foreach ($program['ops'] as $record) {
            if ($record['op'] === ExecutionChallengeGenerator::OP_DOM_APPEND) {
                $hasAppend = true;
                break;
            }
        }
        $entries = [];
        foreach ($program['ops'] as $record) {
            $op = $record['op'];
            if ($op === ExecutionChallengeGenerator::OP_DOM_GEOMETRY) {
                $entries[] = 'geom('.($top * 10).',10)';
                ++$top;
            } elseif ($op === ExecutionChallengeGenerator::OP_DOM_POINT) {
                $entries[] = 'point('.($hasAppend ? 'div' : 'none').')';
            } elseif ($op === ExecutionChallengeGenerator::OP_DOM_OBSERVE) {
                // The browser-equivalent observe: the fabricated reference
                // height (the real value is the engine's own text
                // metrics, never predictable here) is written through
                // into the replay state,
                // so the following checksum/read entries in this
                // synthesized trace are computed over the observed byte —
                // the full causal-graph semantics, never a placeholder.
                $idx = $record['operands']['idx'];
                $entries[] = self::TRACE_NAMES[$op].'('.$idx.','.self::OBSERVED_HEIGHT.')';
                if ($idx < \count($u8)) {
                    $u8[$idx] = self::OBSERVED_HEIGHT;
                }
            } else {
                $entries[] = self::TRACE_NAMES[$op].'('.self::simulateOp($op, $record['operands'], $u8, $cur, $docIds).')';
            }
        }

        return implode(';', $entries);
    }

    /**
     * The deterministic state-machine execution of one op; returns the
     * op's canonical trace value (decimal, "1"/"0", or standard base64).
     * Private copy of the generator's simulator (see the class
     * docblock): behavior-exact, pinned by the verification suites.
     *
     * @param array<string, mixed> $operands
     * @param list<int>            $u8    the u8 array state (by reference)
     * @param array|null           $cur   the current DOM node state
     * @param array<string, true>  $docIds appended ids
     */
    private static function simulateOp(int $op, array $operands, array &$u8, ?array &$cur, array &$docIds): string
    {
        $u32 = static fn (int $v): int => $v & 0xFFFFFFFF;
        $checksum = static function () use (&$u8): int {
            $sum = 0;
            foreach ($u8 as $b) {
                $sum = ($sum + $b) & 0xFF;
            }

            return $sum;
        };

        return match ($op) {
            ExecutionChallengeGenerator::OP_ADD => (string) $u32($operands['a'] + $operands['b']),
            ExecutionChallengeGenerator::OP_SUB => (string) $u32($operands['a'] - $operands['b']),
            ExecutionChallengeGenerator::OP_MUL => (string) self::mul32($operands['a'], $operands['b']),
            ExecutionChallengeGenerator::OP_XOR => (string) ($operands['a'] ^ $operands['b']),
            ExecutionChallengeGenerator::OP_AND => (string) ($operands['a'] & $operands['b']),
            ExecutionChallengeGenerator::OP_OR => (string) ($operands['a'] | $operands['b']),
            ExecutionChallengeGenerator::OP_SHL => (string) $u32($operands['a'] << ($operands['b'] & 31)),
            ExecutionChallengeGenerator::OP_SHR => (string) $u32($operands['a'] >> ($operands['b'] & 31)),
            ExecutionChallengeGenerator::OP_U8_CREATE => self::opU8Create($operands, $u8, $checksum),
            ExecutionChallengeGenerator::OP_U8_WRITE => self::opU8Write($operands, $u8, $checksum),
            ExecutionChallengeGenerator::OP_U8_READ => (string) ((($operands['idx'] < \count($u8)) ? $u8[$operands['idx']] : 0) & 0xFF),
            ExecutionChallengeGenerator::OP_U8_ROTATE => self::opU8Rotate($operands, $u8, $checksum),
            ExecutionChallengeGenerator::OP_STR_LEN => (string) \strlen($operands['s']),
            ExecutionChallengeGenerator::OP_STR_CHARCODE, ExecutionChallengeGenerator::OP_STR_CODEPOINT => (string) (($operands['idx'] < \strlen($operands['s']))
                ? \ord($operands['s'][$operands['idx']])
                : 0),
            ExecutionChallengeGenerator::OP_STR_SLICE => base64_encode(substr($operands['s'], $operands['start'], $operands['count'])),
            ExecutionChallengeGenerator::OP_DOM_CREATE => self::opDomCreate($operands, $cur),
            ExecutionChallengeGenerator::OP_DOM_SET_ATTR => self::opDomSetAttr($operands, $cur),
            ExecutionChallengeGenerator::OP_DOM_APPEND => self::opDomAppend($cur, $docIds),
            ExecutionChallengeGenerator::OP_DOM_QUERY => isset($docIds[$operands['s']]) ? '1' : '0',
            ExecutionChallengeGenerator::OP_DOM_GET_ATTR => self::opDomGetAttr($operands, $cur),
            ExecutionChallengeGenerator::OP_DOM_DATASET_SET => self::opDatasetSet($operands, $cur),
            ExecutionChallengeGenerator::OP_DOM_DATASET_GET => self::opDatasetGet($operands, $cur),
            ExecutionChallengeGenerator::OP_DOM_CLASS_ADD => self::opClassAdd($operands, $cur),
            ExecutionChallengeGenerator::OP_DOM_CLASS_CONTAINS => self::opClassContains($operands, $cur),
            ExecutionChallengeGenerator::OP_DOM_PARENT => $cur !== null && $cur['appended'] ? '1' : '0',
            ExecutionChallengeGenerator::OP_DOM_DISPATCH => '1',
            ExecutionChallengeGenerator::OP_DOM_SERIALIZE => self::opDomSerialize($cur, $docIds),
            // Browser-observed entries: the expected values are
            // construction-determined for `QUERY_REAL`/`EVENT_REAL`/
            // `SERIALIZE_REAL` (the interpreter must read the real DOM
            // back to these exact values), while the layout probes
            // (`GEOMETRY`/`POINT`) carry the literal placeholders 'geom'/
            // 'point' here — the verifier validates the `SUBMITTED` trace
            // entries against their invariants separately (see
            // ExecutionChallengeGenerator::verifyExecutedTrace), so a pure
            // non-browser solver cannot reproduce a valid trace without
            // emulating layout.
            ExecutionChallengeGenerator::OP_DOM_QUERY_REAL => self::opQueryRealExpected($operands, $cur, $docIds),
            ExecutionChallengeGenerator::OP_DOM_GEOMETRY => 'geom',
            ExecutionChallengeGenerator::OP_DOM_POINT => 'point',
            ExecutionChallengeGenerator::OP_DOM_EVENT_REAL => self::opEventRealExpected($operands, $cur, $docIds),
            ExecutionChallengeGenerator::OP_DOM_SERIALIZE_REAL => self::opSerializeRealExpected($docIds, $cur),
            // The observed height is browser-only: the pure sim emits the
            // placeholder; the verifier replays the value the submitted
            // trace reports (see ExecutionChallengeGenerator::verifyExecutedTrace).
            ExecutionChallengeGenerator::OP_DOM_OBSERVE => 'obs',
            default => '0',
        };
    }

    /**
     * Expected real querySelectorById readback: tag|sortedAttrPairs of
     * the appended node (the interpreter reads the real DOM and must
     * return exactly these values).
     *
     * @param array<string, mixed> $operands
     * @param array|null           $cur
     * @param array<string, true>  $docIds
     */
    private static function opQueryRealExpected(array $operands, ?array &$cur, array &$docIds): string
    {
        $id = $operands['id'];
        if (!isset($docIds[$id])) {
            return 'none';
        }

        return self::realReadback($cur !== null && $cur['id'] === $id ? $cur : null, $id);
    }

    /**
     * @param array<string, true> $docIds
     * @param array|null          $cur
     */
    private static function opEventRealExpected(array $operands, ?array &$cur, array &$docIds): string
    {
        $id = $operands['id'];

        return isset($docIds[$id]) ? 'kiwi-ev:'.self::nodeTag($cur, $id) : 'none';
    }

    /**
     * Canonical real-DOM readback digest: the shadow's current node's
     * sorted canonical attribute pairs hashed — the interpreter builds
     * the same canonical string from the real node's sorted attributes.
     *
     * @param array<string, true> $docIds
     * @param array|null          $cur
     */
    private static function opSerializeRealExpected(array $docIds, ?array &$cur): string
    {
        if ($cur === null || !$cur['appended']) {
            return hash('sha256', '');
        }
        $names = array_keys($cur['attrs']);
        sort($names);
        $parts = [];
        foreach ($names as $n) {
            $parts[] = $n.'='.$cur['attrs'][$n];
        }

        return hash('sha256', implode(';', $parts));
    }

    /** @param array|null $cur */
    private static function nodeTag(?array $cur, string $id): string
    {
        return $cur !== null && $cur['id'] === $id ? 'div' : 'span';
    }

    /**
     * @param array<string, mixed>|null $cur
     */
    private static function realReadback(?array $cur, string $id): string
    {
        if ($cur === null) {
            return 'none';
        }
        $names = array_keys($cur['attrs']);
        sort($names);
        $parts = [];
        foreach ($names as $n) {
            $parts[] = $n.'='.$cur['attrs'][$n];
        }

        return 'div|'.implode(';', $parts);
    }

    /** @param array<string, mixed> $operands */
    private static function mul32(int $a, int $b): int
    {
        // a*b mod 2^32 without any 64-bit overflow: split both factors
        // into 16-bit halves; the aH*bH term is a multiple of 2^32 and
        // vanishes modulo 2^32.
        $lo = ($a & 0xFFFF) * ($b & 0xFFFF);
        $cross = (($a >> 16) & 0xFFFF) * ($b & 0xFFFF) + ($a & 0xFFFF) * (($b >> 16) & 0xFFFF);

        return (($lo & 0xFFFFFFFF) + (($cross & 0xFFFF) << 16)) & 0xFFFFFFFF;
    }

    /**
     * @param array<string, mixed> $operands
     * @param list<int>            $u8
     */
    private static function opU8Create(array $operands, array &$u8, callable $checksum): string
    {
        $u8 = array_fill(0, $operands['len'], 0);

        return (string) $checksum();
    }

    /**
     * @param array<string, mixed> $operands
     * @param list<int>            $u8
     */
    private static function opU8Write(array $operands, array &$u8, callable $checksum): string
    {
        if ($operands['idx'] < \count($u8)) {
            $u8[$operands['idx']] = $operands['val'] & 0xFF;
        }

        return (string) $checksum();
    }

    /**
     * @param array<string, mixed> $operands
     * @param list<int>            $u8
     */
    private static function opU8Rotate(array $operands, array &$u8, callable $checksum): string
    {
        $n = \count($u8);
        $k = $operands['k'] % 8;
        if ($n > 0 && $k > 0) {
            $rotated = [];
            for ($i = 0; $i < $n; $i++) {
                $rotated[$i] = $u8[($i + $k) % $n];
            }
            $u8 = $rotated;
        }

        return (string) $checksum();
    }

    /**
     * @param array<string, mixed> $operands
     * @param array|null           $cur
     */
    private static function opDomCreate(array $operands, ?array &$cur): string
    {
        $id = $operands['id'];
        $cur = [
            'id' => $id,
            // The created element carries its id as the reflected id
            // attribute (the browser's `el.id = id`), so serialization
            // includes it.
            'attrs' => ['id' => $id],
            'dataset' => [],
            'classes' => [],
            'appended' => false,
        ];

        return base64_encode($id);
    }

    /**
     * @param array<string, mixed> $operands
     * @param array|null           $cur
     */
    private static function opDomSetAttr(array $operands, ?array &$cur): string
    {
        $name = ExecutionChallengeGenerator::ATTR_NAMES[$operands['name']];
        if ($cur !== null) {
            $cur['attrs'][$name] = $operands['val'];
        }

        return base64_encode($name);
    }

    /**
     * @param array|null          $cur
     * @param array<string, true> $docIds
     */
    private static function opDomAppend(?array &$cur, array &$docIds): string
    {
        if ($cur !== null) {
            $cur['appended'] = true;
            $docIds[$cur['id']] = true;
        }

        return '1';
    }

    /**
     * @param array<string, mixed> $operands
     * @param array|null           $cur
     */
    private static function opDomGetAttr(array $operands, ?array &$cur): string
    {
        $name = ExecutionChallengeGenerator::ATTR_NAMES[$operands['name']];

        return base64_encode($cur !== null ? ($cur['attrs'][$name] ?? '') : '');
    }

    /**
     * @param array<string, mixed> $operands
     * @param array|null           $cur
     */
    private static function opDatasetSet(array $operands, ?array &$cur): string
    {
        $key = $operands['s'];
        if ($cur !== null) {
            $cur['dataset'][$key] = $operands['val'] ?? '';
        }

        return base64_encode($key);
    }

    /**
     * @param array<string, mixed> $operands
     * @param array|null           $cur
     */
    private static function opDatasetGet(array $operands, ?array &$cur): string
    {
        $key = $operands['s'];

        return base64_encode($cur !== null ? ($cur['dataset'][$key] ?? '') : '');
    }

    /**
     * @param array<string, mixed> $operands
     * @param array|null           $cur
     */
    private static function opClassAdd(array $operands, ?array &$cur): string
    {
        $cls = $operands['s'];
        if ($cur !== null) {
            $cur['classes'][$cls] = true;
        }

        return base64_encode($cls);
    }

    /**
     * @param array<string, mixed> $operands
     * @param array|null           $cur
     */
    private static function opClassContains(array $operands, ?array &$cur): string
    {
        $cls = $operands['s'];

        return $cur !== null && isset($cur['classes'][$cls]) ? '1' : '0';
    }

    /**
     * The mutation/readback op: appends the current node to the document
     * AND traces the canonical serialization of its attributes (sorted
     * by name, `name=value` joined with ';').
     *
     * @param array|null          $cur
     * @param array<string, true> $docIds
     */
    private static function opDomSerialize(?array &$cur, array &$docIds): string
    {
        if ($cur !== null) {
            $cur['appended'] = true;
            $docIds[$cur['id']] = true;
        }
        $attrs = $cur !== null ? $cur['attrs'] : [];
        \ksort($attrs);
        $parts = [];
        foreach ($attrs as $name => $value) {
            $parts[] = $name.'='.$value;
        }

        return base64_encode(implode(';', $parts));
    }
}
