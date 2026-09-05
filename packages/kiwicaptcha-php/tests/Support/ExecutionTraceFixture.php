<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Support;

use KiwiCaptcha\ExecutionChallengeGenerator;

/**
 * Test-only execution-trace fixture builder.
 *
 * Synthesizes the browser-equivalent executed trace of an
 * ExecutionChallengeV1 program, the trace a genuine browser execution
 * submits, without a browser. The layout entries are fabricated with
 * the fixed reference height {@see self::OBSERVED_HEIGHT} (10), the
 * URL-canon entries with the fixed reference digest
 * {@see self::FABRICATED_URL_DIGEST}. The observed byte is written
 * through the u8 state exactly like the verifier's replay, so the
 * synthesized trace is accepted by
 * `ExecutionChallengeGenerator::verifyExecutedTrace`.
 *
 * Why this surface exists: no public production API may promise a
 * non-browser equivalent of a real execution. The former
 * `ExecutionChallengeGenerator::executedTraceFor` entry point is gone.
 * The fabrication lives here, behind the explicitly test-only
 * `KiwiCaptcha\Tests\Support` namespace (autoload-dev only: a
 * production Composer install never ships this class, matching the
 * Rust crate's default-off `test-fixtures` feature). Never call this
 * class from a production path. Test suites, cross-language fixtures
 * and the browser fixture router are its only callers. The verifier's
 * own machinery (`verifyExecutedTrace`, `digestOverTrace`,
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
 * `ExecutionChallengeGenerator` when the op semantics ever change
 * (the version-5 object-graph arms and the graph state included).
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
        'qreal', 'geom', 'point', 'evreal', 'sreal', 'obs', 'dsib', 'dchild', 'ddepth',
        'dfrag', 'dclone', 'drepar', 'dreflec', 'dphase', 'durlc', 'dmutate', 'dsdep',
    ];

    /**
     * The fabricated canonical-URL digest of the version-5 URL-canon
     * probe. The real entry is the SHA-256 of the canonicalized
     * sandboxed document URL, environment evidence the verifier
     * shape-validates and replays, never predicts. The synthesizer
     * uses this fixed hex reference value exactly like the fixed
     * observed height above, a fabricated reference value.
     */
    private const FABRICATED_URL_DIGEST = 'e76cac2dfcc313d58bb0f731c433badf0651978a1769007ff3c1ab62cf59fee7';

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
        return self::buildTrace($program, self::OBSERVED_HEIGHT);
    }

    /**
     * The browser-equivalent trace with an explicit fabricated observe
     * choice. Any legal observed height 1..255 is written through the
     * u8 state exactly as the verifier replays it, so the later
     * checksum and read entries stay coherent with that choice. This
     * entry exists for the adversarial shadow solver: see
     * BrowserlessForgerySolver. Test-only, never a production API.
     *
     * @param array{format: int, scope: string, action: string, op_version: int, ops: list<array{op: int, operands: array<string, mixed>}>} $program
     */
    public static function executedTraceForWithObservedHeight(array $program, int $observedHeight): string
    {
        if ($observedHeight < 1 || $observedHeight > 255) {
            throw new \InvalidArgumentException('the fabricated observed height must stay within 1..255');
        }

        return self::buildTrace($program, $observedHeight);
    }

    /**
     * The single state-machine trace builder: the observed height is a
     * parameter so the fixture's fixed reference choice and the
     * solver's explicit choice share one behavior-exact simulation.
     * A version-5 program replays over the object-graph state exactly
     * like the generator's canonical simulation.
     */
    private static function buildTrace(array $program, int $observedHeight): string
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
        $appendRank = [];
        $parent = [];
        $cur = null;
        $ctx = $program['op_version'] >= 5 ? self::newExecutionGraph() : null;
        foreach ($program['ops'] as $record) {
            $op = $record['op'];
            if ($op === ExecutionChallengeGenerator::OP_DOM_APPEND && $cur !== null && !isset($appendRank[$cur['id']])) {
                $appendRank[$cur['id']] = \count($appendRank);
            }
            if ($op === ExecutionChallengeGenerator::OP_DOM_CHILD && $cur !== null) {
                $parent[$record['operands']['id']] = $cur['id'];
            }
            if ($op === ExecutionChallengeGenerator::OP_DOM_GEOMETRY) {
                $entries[] = 'geom('.($top * 10).',10)';
                ++$top;
            } elseif ($op === ExecutionChallengeGenerator::OP_DOM_POINT) {
                $entries[] = 'point('.($hasAppend ? 'div' : 'none').')';
            } elseif ($op === ExecutionChallengeGenerator::OP_DOM_URL_CANON) {
                // The browser-equivalent URL-canon entry: the real
                // value is the SHA-256 digest of the canonicalized
                // sandboxed document URL (environment evidence the
                // verifier shape-validates and replays, never
                // predicts), so the synthesizer fabricates the fixed
                // reference digest above.
                $entries[] = self::TRACE_NAMES[$op].'('.self::FABRICATED_URL_DIGEST.')';
            } elseif ($op === ExecutionChallengeGenerator::OP_DOM_DEPTH) {
                // The browser-equivalent ancestor walk: the number of
                // ancestors up to (excluding) the body — the exact
                // value the verifier derives from the tree model.
                $depth = 0;
                $cursorId = $record['operands']['id'] ?? null;
                while ($cursorId !== null && isset($parent[$cursorId])) {
                    ++$depth;
                    $cursorId = $parent[$cursorId];
                }
                $entries[] = self::TRACE_NAMES[$op].'('.$depth.')';
            } elseif ($op === ExecutionChallengeGenerator::OP_DOM_SIBLING_INDEX) {
                // The browser-equivalent sibling traversal: the rank of
                // the probed node's append (its real index among the
                // body children the program built) — the exact value
                // the verifier computes from the append order.
                // The interpreter's own script element is the first
                // body child, so the real index is the append rank + 1.
                $entries[] = self::TRACE_NAMES[$op].'('.($appendRank[$record['operands']['id']] ?? -2) + 1 .')';
            } elseif ($op === ExecutionChallengeGenerator::OP_DOM_OBSERVE) {
                // The browser-equivalent observe: the fabricated height
                // (the caller's explicit choice, a value the engine's
                // own text metrics would measure) is written through
                // into the replay state,
                // so the following checksum/read entries in this
                // synthesized trace are computed over the observed byte —
                // the full causal-graph semantics, never a placeholder.
                $idx = $record['operands']['idx'];
                $entries[] = self::TRACE_NAMES[$op].'('.$idx.','.$observedHeight.')';
                if ($idx < \count($u8)) {
                    $u8[$idx] = $observedHeight;
                }
            } else {
                $entries[] = self::TRACE_NAMES[$op].'('.self::simulateOp($op, $record['operands'], $u8, $cur, $docIds, $ctx).')';
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
     * @param array|null           $ctx   the version-5 graph, null on versions 1-4
     */
    private static function simChild(array $operands, ?array &$cur, ?array &$ctx = null): string
    {
        // Behavior-exact copy of the generator's opDomChild: the child
        // id entry and cur moves onto the new node.
        $id = $operands['id'];
        $parentId = $cur['id'] ?? null;
        $cur = [
            'id' => $id,
            'attrs' => ['id' => $id],
            'dataset' => [],
            'classes' => [],
            'appended' => true,
        ];
        if ($parentId !== null && $parentId !== $id) {
            $cur['parent'] = $parentId;
        }
        if ($ctx !== null) {
            // The graph bookkeeping: the child is appended under the
            // current node, so the parent record's child list gains
            // the new id and the child record points back at the
            // parent.
            $ctx['nodes'][$id] = ['parent' => $parentId, 'children' => [], 'appended' => true];
            if ($parentId !== null && isset($ctx['nodes'][$parentId])) {
                $ctx['nodes'][$parentId]['children'][] = $id;
            }
        }

        return base64_encode($id);
    }

    private static function simulateOp(int $op, array $operands, array &$u8, ?array &$cur, array &$docIds, ?array &$ctx = null): string
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
            ExecutionChallengeGenerator::OP_DOM_CREATE => self::opDomCreate($operands, $cur, $ctx),
            ExecutionChallengeGenerator::OP_DOM_SET_ATTR => self::opDomSetAttr($operands, $cur),
            ExecutionChallengeGenerator::OP_DOM_APPEND => self::opDomAppend($cur, $docIds, $ctx),
            ExecutionChallengeGenerator::OP_DOM_QUERY => isset($docIds[$operands['s']]) ? '1' : '0',
            ExecutionChallengeGenerator::OP_DOM_GET_ATTR => self::opDomGetAttr($operands, $cur),
            ExecutionChallengeGenerator::OP_DOM_DATASET_SET => self::opDatasetSet($operands, $cur),
            ExecutionChallengeGenerator::OP_DOM_DATASET_GET => self::opDatasetGet($operands, $cur),
            ExecutionChallengeGenerator::OP_DOM_CLASS_ADD => self::opClassAdd($operands, $cur),
            ExecutionChallengeGenerator::OP_DOM_CLASS_CONTAINS => self::opClassContains($operands, $cur),
            ExecutionChallengeGenerator::OP_DOM_PARENT => $cur !== null && $cur['appended'] ? '1' : '0',
            ExecutionChallengeGenerator::OP_DOM_DISPATCH => '1',
            ExecutionChallengeGenerator::OP_DOM_SERIALIZE => self::opDomSerialize($cur, $docIds, $ctx),
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
            ExecutionChallengeGenerator::OP_DOM_SERIALIZE_REAL => self::opSerializeRealExpected($docIds, $cur, $ctx),
            // The observed height is browser-only: the pure sim emits the
            // placeholder; the verifier replays the value the submitted
            // trace reports (see ExecutionChallengeGenerator::verifyExecutedTrace).
            ExecutionChallengeGenerator::OP_DOM_OBSERVE => 'obs',
            ExecutionChallengeGenerator::OP_DOM_SIBLING_INDEX => 'dsib',
            ExecutionChallengeGenerator::OP_DOM_DEPTH => 'ddepth',
            ExecutionChallengeGenerator::OP_DOM_CHILD => self::simChild($operands, $cur, $ctx),
            // The version-5 object-graph ops, behavior-exact copies of
            // the generator's arms: the exact entries run over the
            // graph state, the integer entries write their u8 cells
            // like the observe replay, and the URL-canon entry is
            // browser-observed (the fixture's buildTrace fabricates
            // the hex digest above).
            ExecutionChallengeGenerator::OP_DOM_FRAGMENT_APPEND => self::opFragAppend($operands, $u8, $cur, $docIds, $ctx),
            ExecutionChallengeGenerator::OP_DOM_CLONE => self::opDomClone($operands, $u8, $cur, $docIds, $ctx),
            ExecutionChallengeGenerator::OP_DOM_REPARENT => self::opDomReparent($operands, $u8, $cur, $ctx),
            ExecutionChallengeGenerator::OP_DOM_ATTR_REFLECT => self::opAttrReflect($operands, $cur),
            ExecutionChallengeGenerator::OP_DOM_EVENT_PHASE => self::opEventPhase($operands, $u8, $cur, $ctx),
            ExecutionChallengeGenerator::OP_DOM_URL_CANON => 'durlc',
            ExecutionChallengeGenerator::OP_DOM_TEXT_MUTATE => self::opTextMutate($operands, $u8, $cur, $docIds, $ctx),
            ExecutionChallengeGenerator::OP_DOM_SELECT_DEP => self::opSelectDep($operands, $cur, $ctx),
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
     * canonical string hashed — the interpreter builds the same string
     * from the real node. The serialization grammar is rung-scoped:
     * versions 1-4 hash the sorted attribute pairs, and a version-5
     * program hashes the version-5 canonical node string (see
     * {@see self::canonicalNodeString()}).
     *
     * @param array<string, true> $docIds
     * @param array|null          $cur
     * @param array|null          $ctx   the version-5 graph, null on versions 1-4
     */
    private static function opSerializeRealExpected(array $docIds, ?array &$cur, ?array &$ctx = null): string
    {
        if ($cur === null || !$cur['appended']) {
            return hash('sha256', '');
        }

        return hash('sha256', self::canonicalNodeString($cur, $ctx));
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
     * @param array|null           $ctx   the version-5 graph, null on versions 1-4
     */
    private static function opDomCreate(array $operands, ?array &$cur, ?array &$ctx = null): string
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
        if ($ctx !== null) {
            // The graph record of the created element: no parent, no
            // children, not yet in the document.
            $ctx['nodes'][$id] = ['parent' => null, 'children' => [], 'appended' => false];
        }

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
     * @param array|null          $ctx   the version-5 graph, null on versions 1-4
     */
    private static function opDomAppend(?array &$cur, array &$docIds, ?array &$ctx = null): string
    {
        if ($cur !== null) {
            $cur['appended'] = true;
            $docIds[$cur['id']] = true;
            if ($ctx !== null) {
                // The graph bookkeeping: body.appendChild moves the
                // element to the end of the body child list, whatever
                // its previous parent, body position or fragment slot.
                self::graphAttachToBody($ctx, $cur['id']);
            }
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
     * AND traces the canonical serialization of the current node record.
     *
     * The serialization grammar is rung-scoped. Versions 1-4 keep the
     * attribute-only string, sorted by name with `name=value` entries
     * joined by ';'. A version-5 program hashes or base64s the
     * version-5 canonical node string of the same record, see
     * {@see self::canonicalNodeString()}. Older challenges stay
     * verifiable for their whole TTL.
     *
     * @param array|null          $cur
     * @param array<string, true> $docIds
     * @param array|null          $ctx   the version-5 graph, null on versions 1-4
     */
    private static function opDomSerialize(?array &$cur, array &$docIds, ?array &$ctx = null): string
    {
        if ($cur !== null) {
            // The real interpreter appends an un-appended current node
            // to the body and leaves an appended one in place.
            $cur['appended'] = true;
            $docIds[$cur['id']] = true;
            if ($ctx !== null && !self::graphIsAttached($ctx, $cur['id'])) {
                self::graphAttachToBody($ctx, $cur['id']);
            }
        }

        return base64_encode(self::canonicalNodeString($cur, $ctx));
    }

    /**
     * The fresh version-5 execution graph: the node records with
     * parent and ordered child-id lists per constructed element, the
     * body child list and the four fragment slots. The body list holds
     * the constructed nodes in append order; the interpreter's own
     * script element is the implicit first child, never in the list.
     *
     * @return array{nodes: array<string, array{parent: ?string, children: list<string>, appended: bool}>, body: list<string>, frags: array<int, list<string>>}
     */
    private static function newExecutionGraph(): array
    {
        return [
            'nodes' => [],
            'body' => [],
            'frags' => [[], [], [], []],
        ];
    }

    /**
     * The version-5 canonical node string of a record: the sorted
     * attribute pairs, then the sorted dataset pairs, then the sorted
     * class names, then the text segment when present, joined with ';'
     * in that fixed segment order. Versions 1-4 keep the attribute-only
     * string (the $ctx switch), so older challenges stay verifiable for
     * their whole TTL.
     *
     * @param array|null $cur
     * @param array|null $ctx   the version-5 graph, null on versions 1-4
     */
    private static function canonicalNodeString(?array $cur, ?array $ctx = null): string
    {
        if ($cur === null) {
            return '';
        }
        $parts = [];
        $attrs = $cur['attrs'];
        \ksort($attrs);
        foreach ($attrs as $name => $value) {
            $parts[] = $name.'='.$value;
        }
        if ($ctx !== null) {
            $dataset = $cur['dataset'] ?? [];
            \ksort($dataset);
            foreach ($dataset as $key => $value) {
                $parts[] = $key.'='.$value;
            }
            $classes = array_keys($cur['classes'] ?? []);
            sort($classes);
            foreach ($classes as $cls) {
                $parts[] = $cls;
            }
            if (array_key_exists('text', $cur) && $cur['text'] !== '') {
                $parts[] = $cur['text'];
            }
        }

        return implode(';', $parts);
    }

    /**
     * The fragment-append arm (v5): moves the current node (with its
     * whole subtree) into the detached fragment slot named by the
     * operand. The node leaves its parent, the body child list and the
     * appended-id set (real-document probes read a fragment-moved node
     * as absent, deterministically), and the entry is the slot's
     * child-element count after the move.
     *
     * @param array<string, mixed> $operands
     * @param list<int>            $u8
     * @param array|null           $cur
     * @param array<string, true>  $docIds
     * @param array{nodes: array<string, array{parent: ?string, children: list<string>, appended: bool}>, body: list<string>, frags: array<int, list<string>>} $ctx
     */
    private static function opFragAppend(array $operands, array &$u8, ?array &$cur, array &$docIds, array &$ctx): string
    {
        $slot = $operands['s'];
        $entry = \count($ctx['frags'][$slot]);
        if ($cur !== null && isset($ctx['nodes'][$cur['id']])) {
            $id = $cur['id'];
            self::graphDetach($ctx, $id);
            $ctx['frags'][$slot][] = $id;
            $entry = \count($ctx['frags'][$slot]);
            $cur['appended'] = false;
            unset($docIds[$id]);
        }
        self::writeV5Cell($u8, $operands['cell'], $entry);

        return (string) $entry;
    }

    /**
     * The clone arm (v5): deep-copies the current node's subtree
     * (cloneNode semantics), reassigns the copy's reflected id to the
     * operand id, inserts the copy directly after the original and
     * moves the current node onto the copy. The entry is the cloned
     * subtree's element count (the copy root plus every element
     * descendant, counted over the graph child lists).
     *
     * @param array<string, mixed> $operands
     * @param list<int>            $u8
     * @param array|null           $cur
     * @param array<string, true>  $docIds
     * @param array{nodes: array<string, array{parent: ?string, children: list<string>, appended: bool}>, body: list<string>, frags: array<int, list<string>>} $ctx
     */
    private static function opDomClone(array $operands, array &$u8, ?array &$cur, array &$docIds, array &$ctx): string
    {
        $entry = 0;
        if ($cur !== null && isset($ctx['nodes'][$cur['id']])) {
            $sourceId = $cur['id'];
            $cloneId = $operands['id'];
            $source = $ctx['nodes'][$sourceId];
            $entry = self::graphSubtreeElementCount($ctx, $sourceId);
            $copy = $cur;
            $copy['id'] = $cloneId;
            $copy['attrs'] = $cur['attrs'];
            $copy['attrs']['id'] = $cloneId;
            if (array_key_exists('children', $copy)) {
                unset($copy['children']);
            }
            $copy['parent'] = $source['parent'];
            $copy['appended'] = $source['appended'];
            $ctx['nodes'][$cloneId] = [
                'parent' => $source['parent'],
                'children' => $source['children'],
                'appended' => $source['appended'],
            ];
            if ($source['appended']) {
                // The copy is inserted directly after the original,
                // either inside the original's parent or, for a body
                // child, in the body child list.
                $docIds[$cloneId] = true;
                $parentId = $source['parent'];
                if ($parentId !== null && isset($ctx['nodes'][$parentId])) {
                    $siblings = $ctx['nodes'][$parentId]['children'];
                    $at = array_search($sourceId, $siblings, true);
                    $at = $at === false ? \count($siblings) : $at + 1;
                    array_splice($siblings, $at, 0, [$cloneId]);
                    $ctx['nodes'][$parentId]['children'] = $siblings;
                } else {
                    $at = array_search($sourceId, $ctx['body'], true);
                    $at = $at === false ? \count($ctx['body']) : $at + 1;
                    array_splice($ctx['body'], $at, 0, [$cloneId]);
                }
            }
            $cur = $copy;
        }
        self::writeV5Cell($u8, $operands['cell'], $entry);

        return (string) $entry;
    }

    /**
     * The reparent arm (v5): moves the current node's subtree under
     * the constructed node named by the id operand (real appendChild
     * semantics); the current node does not move. The entry is the
     * target's child-element count after the move. A move onto the
     * node itself or onto one of its own descendants is refused (the
     * real HierarchyRequestError), and an absent target is a no-op.
     *
     * @param array<string, mixed> $operands
     * @param list<int>            $u8
     * @param array|null           $cur
     * @param array{nodes: array<string, array{parent: ?string, children: list<string>, appended: bool}>, body: list<string>, frags: array<int, list<string>>} $ctx
     */
    private static function opDomReparent(array $operands, array &$u8, ?array &$cur, array &$ctx): string
    {
        $entry = 0;
        $targetId = $operands['id'];
        if ($cur !== null && isset($ctx['nodes'][$cur['id']]) && isset($ctx['nodes'][$targetId])) {
            $curId = $cur['id'];
            $entry = \count($ctx['nodes'][$targetId]['children']);
            $valid = $curId !== $targetId && !self::graphNodeIsAncestorOf($ctx, $curId, $targetId);
            if ($valid) {
                $targetAttached = self::graphIsAttached($ctx, $targetId);
                self::graphDetach($ctx, $curId);
                $ctx['nodes'][$curId]['parent'] = $targetId;
                $ctx['nodes'][$curId]['appended'] = $targetAttached;
                $ctx['nodes'][$targetId]['children'][] = $curId;
                $cur['parent'] = $targetId;
                $cur['appended'] = $targetAttached;
                if ($targetAttached) {
                    $docIds[$curId] = true;
                } else {
                    unset($docIds[$curId]);
                }
                $entry = \count($ctx['nodes'][$targetId]['children']);
            }
        }
        self::writeV5Cell($u8, $operands['cell'], $entry);

        return (string) $entry;
    }

    /**
     * The attribute-reflect arm (v5): reads the current node's
     * reflected property value for the indexed fixed attribute name.
     * The model reads the record's attr surface (the interpreter keeps
     * the real property surface in exact agreement: id, title and the
     * data-* attributes are written through the same canonical model),
     * so the entry is exact. The entry is the standard base64 of the
     * value, '' when the attribute is absent.
     *
     * @param array<string, mixed> $operands
     * @param array|null           $cur
     */
    private static function opAttrReflect(array $operands, ?array &$cur): string
    {
        $name = ExecutionChallengeGenerator::ATTR_NAMES[$operands['name']];

        return base64_encode($cur !== null ? ($cur['attrs'][$name] ?? '') : '');
    }

    /**
     * The event-phase arm (v5): dispatches a real bubbling event on
     * the current node with listeners on every constructed element.
     * The entry is the number of constructed elements that received
     * it: the target itself plus its constructed ancestors up to the
     * document body, excluding the body and the interpreter's script
     * element. The graph parent chain is the exact model of that walk.
     *
     * @param array<string, mixed> $operands
     * @param list<int>            $u8
     * @param array|null           $cur
     * @param array{nodes: array<string, array{parent: ?string, children: list<string>, appended: bool}>, body: list<string>, frags: array<int, list<string>>} $ctx
     */
    private static function opEventPhase(array $operands, array &$u8, ?array &$cur, array &$ctx): string
    {
        $count = 0;
        if ($cur !== null && isset($ctx['nodes'][$cur['id']])) {
            $count = 1;
            $guard = 0;
            $cursor = $ctx['nodes'][$cur['id']]['parent'];
            while ($cursor !== null && isset($ctx['nodes'][$cursor]) && $guard++ < 4096) {
                ++$count;
                $cursor = $ctx['nodes'][$cursor]['parent'];
            }
        }
        self::writeV5Cell($u8, $operands['cell'], $count);

        return (string) $count;
    }

    /**
     * The text-mutate arm (v5): sets the current node's real
     * textContent to the value operand, replacing any previous text
     * and removing every child element (the real textContent
     * semantics); the node record now carries the text segment. The
     * entry is the resulting text byte length.
     *
     * @param array<string, mixed> $operands
     * @param list<int>            $u8
     * @param array|null           $cur
     * @param array<string, true>  $docIds
     * @param array{nodes: array<string, array{parent: ?string, children: list<string>, appended: bool}>, body: list<string>, frags: array<int, list<string>>} $ctx
     */
    private static function opTextMutate(array $operands, array &$u8, ?array &$cur, array &$docIds, array &$ctx): string
    {
        $len = 0;
        if ($cur !== null) {
            $cur['text'] = $operands['val'];
            $len = \strlen($operands['val']);
            $id = $cur['id'];
            if (isset($ctx['nodes'][$id]) && $ctx['nodes'][$id]['children'] !== []) {
                $attached = self::graphIsAttached($ctx, $id);
                foreach ($ctx['nodes'][$id]['children'] as $childId) {
                    self::graphDetach($ctx, $childId);
                    if ($attached) {
                        unset($docIds[$childId]);
                    }
                }
            }
        }
        self::writeV5Cell($u8, $operands['cell'], $len);

        return (string) $len;
    }

    /**
     * The select-depth arm (v5): walks real child elements from the
     * current node down. Step j descends into the child at index
     * (byte j % child count) when the current level has children; the
     * entry is the number of descent levels completed, 0-3, an exact
     * traversal result over the graph child lists.
     *
     * @param array<string, mixed> $operands
     * @param array|null           $cur
     * @param array{nodes: array<string, array{parent: ?string, children: list<string>, appended: bool}>, body: list<string>, frags: array<int, list<string>>} $ctx
     */
    private static function opSelectDep(array $operands, ?array &$cur, array &$ctx): string
    {
        $completed = 0;
        if ($cur !== null && isset($ctx['nodes'][$cur['id']])) {
            $levelId = $cur['id'];
            foreach ([$operands['b0'], $operands['b1'], $operands['b2']] as $byte) {
                $children = $ctx['nodes'][$levelId]['children'];
                if ($children === []) {
                    break;
                }
                $levelId = $children[$byte % \count($children)];
                ++$completed;
                if (!isset($ctx['nodes'][$levelId])) {
                    break;
                }
            }
        }

        return (string) $completed;
    }

    /**
     * The v5 integer-entry ops write their entry into the u8 cell the
     * operand names, mirroring the observe replay rule. The write
     * happens when the array exists and the cell is in range; every
     * issued program draws its cell bytes modulo the live array
     * length, so the writes land in range.
     *
     * @param list<int> $u8
     */
    private static function writeV5Cell(array &$u8, int $cell, int $entry): void
    {
        if ($cell < \count($u8)) {
            $u8[$cell] = $entry & 0xFF;
        }
    }

    /**
     * The element count of a node's subtree: the node itself plus
     * every element descendant, walked over the graph child lists.
     *
     * @param array{nodes: array<string, array{parent: ?string, children: list<string>, appended: bool}>, body: list<string>, frags: array<int, list<string>>} $ctx
     */
    private static function graphSubtreeElementCount(array $ctx, string $id): int
    {
        $total = 1;
        $children = $ctx['nodes'][$id]['children'] ?? [];
        foreach ($children as $childId) {
            $total += isset($ctx['nodes'][$childId])
                ? self::graphSubtreeElementCount($ctx, $childId)
                : 1;
        }

        return $total;
    }

    /**
     * Whether a node is attached to the document: it is a body child
     * itself or its parent chain reaches a body child.
     *
     * @param array{nodes: array<string, array{parent: ?string, children: list<string>, appended: bool}>, body: list<string>, frags: array<int, list<string>>} $ctx
     */
    private static function graphIsAttached(array $ctx, string $id): bool
    {
        if (!isset($ctx['nodes'][$id])) {
            return false;
        }
        if (\in_array($id, $ctx['body'], true)) {
            return true;
        }
        $guard = 0;
        $cursor = $ctx['nodes'][$id]['parent'];
        while ($cursor !== null && isset($ctx['nodes'][$cursor]) && $guard++ < 4096) {
            if (\in_array($cursor, $ctx['body'], true)) {
                return true;
            }
            $cursor = $ctx['nodes'][$cursor]['parent'];
        }

        return false;
    }

    /**
     * Whether $ancestorId appears in the parent chain of $id (the
     * cycle guard bounds a pathological foreign chain).
     *
     * @param array{nodes: array<string, array{parent: ?string, children: list<string>, appended: bool}>, body: list<string>, frags: array<int, list<string>>} $ctx
     */
    private static function graphNodeIsAncestorOf(array $ctx, string $ancestorId, string $id): bool
    {
        $guard = 0;
        $cursor = $ctx['nodes'][$id]['parent'] ?? null;
        while ($cursor !== null && isset($ctx['nodes'][$cursor]) && $guard++ < 4096) {
            if ($cursor === $ancestorId) {
                return true;
            }
            $cursor = $ctx['nodes'][$cursor]['parent'];
        }

        return false;
    }

    /**
     * Detaches a node from the graph: it leaves its parent's child
     * list, the body child list and any fragment slot, and its parent
     * pointer and appended flag reset (the node stays registered).
     *
     * @param array{nodes: array<string, array{parent: ?string, children: list<string>, appended: bool}>, body: list<string>, frags: array<int, list<string>>} $ctx
     */
    private static function graphDetach(array &$ctx, string $id): void
    {
        if (!isset($ctx['nodes'][$id])) {
            return;
        }
        $parentId = $ctx['nodes'][$id]['parent'];
        if ($parentId !== null && isset($ctx['nodes'][$parentId])) {
            $ctx['nodes'][$parentId]['children'] = array_values(array_diff(
                $ctx['nodes'][$parentId]['children'],
                [$id]
            ));
        }
        $pos = array_search($id, $ctx['body'], true);
        if ($pos !== false) {
            array_splice($ctx['body'], $pos, 1);
        }
        foreach (array_keys($ctx['frags']) as $slot) {
            $slotPos = array_search($id, $ctx['frags'][$slot], true);
            if ($slotPos !== false) {
                array_splice($ctx['frags'][$slot], $slotPos, 1);
            }
        }
        $ctx['nodes'][$id]['parent'] = null;
        $ctx['nodes'][$id]['appended'] = false;
    }

    /**
     * Attaches a node to the end of the body child list (the real
     * body.appendChild move semantics): it first detaches from any
     * parent, body position or fragment slot.
     *
     * @param array{nodes: array<string, array{parent: ?string, children: list<string>, appended: bool}>, body: list<string>, frags: array<int, list<string>>} $ctx
     */
    private static function graphAttachToBody(array &$ctx, string $id): void
    {
        self::graphDetach($ctx, $id);
        $ctx['nodes'][$id]['parent'] = null;
        $ctx['nodes'][$id]['appended'] = true;
        $ctx['body'][] = $id;
    }
}
