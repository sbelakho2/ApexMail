<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * ExecutionChallengeV1: the deterministic browser-execution program
 * generator, the Cap-style dimension of the challenge stack.
 *
 * Given the secret `execution_key` and the challenge context
 * (nonce, scope, action, version) it produces an opaque bytecode program
 * whose op sequence and literals are drawn from a keyed PRF stream:
 *
 *     block_i = HMAC-SHA256(execution_key,
 *         "kiwi-execution-v1|" . nonce . "|" . scope . "|" . action . "|" . version
 *         . u32be(i))
 *
 * The same inputs always produce the same program, deterministic per
 * challenge, and a different context produces a different program.
 * There is no Math.random, no Date and no wall-clock input in the
 * generation or the op semantics: the program is a pure function of the
 * context.
 *
 * # The program blob (binary, base64 on the wire)
 *
 * The program is self-describing. It embeds the scope, the action and
 * the protocol version it was generated for, so the browser interpreter
 * can recompute the digest without any server-provided context beyond
 * the challenge nonce. The blob starts with the format version, the
 * length-prefixed scope and action, the op version and the op count,
 * then N op records, one opcode byte each plus the fixed-shape operand
 * bytes of that opcode.
 *
 * # The fixed opcode set
 *
 * Every opcode's operand bytes are read in a fixed canonical order, so
 * the generator, which draws the bytes from the PRF stream, and every
 * interpreter, which reads them from the blob, can never drift.
 * The opcode table is the OP_* constant block of this class. It covers
 * integer arithmetic, typed-array ops, string ops and DOM ops.
 * The list: add, sub, mul, xor, and, or, shl, shr, u8 create, u8
 * write, u8 read, u8 rotate, length, charcode, codepoint, slice,
 * create, set attribute, append, query, get attribute, dataset set,
 * dataset get, class add, class contains, parent, dispatch, serialize.
 *
 * String literals are printable ASCII (0x20..0x7E); ids and class
 * names come from fixed 64-char alphabets; u32 literals are raw
 * big-endian bytes, so charcode, codepoint, length and slice
 * semantics are byte-exact across JS, PHP and Rust. Dataset keys
 * always start with a digit, so a real-DOM dataset write can never
 * reflect onto a `data-*` attribute that collides with the fixed
 * attribute-name list.
 *
 * # The canonical op trace and the execution digest
 *
 * The canonical op trace is the deterministic execution trace of the
 * ops: one entry per op, `opname-result`, joined with ';'. Results are
 * canonical decimal integers, "1"/"0", or standard base64 of a string.
 * No result alphabet contains '(', ')' or ';', so the trace is
 * unambiguous. The server verifier and the browser interpreter
 * simulate the same deterministic state machine, a u8 array, a current
 * DOM node and an appended-id set. The trace is a pure function of the
 * program.
 *
 * The execution digest binds the program, the challenge context and the
 * trace:
 *
 *     digest = HMAC-SHA256(program_bytes,
 *         "kiwi-execution-v1|" . nonce . "|" . scope . "|" . action . "|"
 *         . version . "|" . canonical_op_trace), hex-encoded
 *
 * The digest key is the program blob itself, a content-derived key. The
 * browser holds only the program, so it can compute the digest, while
 * the secret execution_key never leaves the server; it is only ever
 * used for program generation. The digest is never sent to the client.
 * The driver computes it from the program and presents it with the
 * solution token, and the verifier recomputes the expected digest from
 * the stored record's program. Substituting the program changes both
 * the key and the expected trace, so a tampered program cannot verify
 * against a digest computed from the original program. A digest from
 * another challenge fails because the nonce, scope, action and version
 * context differs. The comparison is constant-time (hash_equals).
 *
 * The execution dimension is supplementary evidence only. It is never
 * the sole acceptance boundary. The PoW proof and the record state
 * machinery still gate, and an armed challenge without a valid digest
 * fails with the deterministic ExecutionMismatch outcome.
 */
final class ExecutionChallengeGenerator
{
    /** The protocol label of the ExecutionChallengeV1 dimension. */
    public const LABEL = 'kiwi-execution-v1';

    /** The program blob format version. */
    public const FORMAT_VERSION = 1;

    /** The op-version byte stamped into the program (bumped on op-semantics changes). */
    public const PROTOCOL_VERSION = 1;

    /** The deterministic op-count bounds of every issued program. */
    public const MIN_OPS = 8;
    public const MAX_OPS = 24;

    /** The fixed attribute-name list of the DOM ops (never contains 'id'). */
    public const ATTR_NAMES = ['data-kiwi', 'data-a', 'data-b', 'title', 'data-x'];

    /** The fixed tag-name list of DOM_CREATE. */
    public const TAG_NAMES = ['div', 'span', 'section', 'p'];

    /** The id alphabet (standard base64 alphabet; valid inside an HTML id). */
    public const ID_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

    /** The class-name alphabet (no space — classList.add can never throw). */
    public const CLASS_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';

    /** Wire ceiling for the base64 program a record/challenge may carry. */
    public const MAX_PROGRAM_BASE64 = 4096;

    public const OP_ADD = 0;
    public const OP_SUB = 1;
    public const OP_MUL = 2;
    public const OP_XOR = 3;
    public const OP_AND = 4;
    public const OP_OR = 5;
    public const OP_SHL = 6;
    public const OP_SHR = 7;
    public const OP_U8_CREATE = 8;
    public const OP_U8_WRITE = 9;
    public const OP_U8_READ = 10;
    public const OP_U8_ROTATE = 11;
    public const OP_STR_LEN = 12;
    public const OP_STR_CHARCODE = 13;
    public const OP_STR_CODEPOINT = 14;
    public const OP_STR_SLICE = 15;
    public const OP_DOM_CREATE = 16;
    public const OP_DOM_SET_ATTR = 17;
    public const OP_DOM_APPEND = 18;
    public const OP_DOM_QUERY = 19;
    public const OP_DOM_GET_ATTR = 20;
    public const OP_DOM_DATASET_SET = 21;
    public const OP_DOM_DATASET_GET = 22;
    public const OP_DOM_CLASS_ADD = 23;
    public const OP_DOM_CLASS_CONTAINS = 24;
    public const OP_DOM_PARENT = 25;
    public const OP_DOM_DISPATCH = 26;
    public const OP_DOM_SERIALIZE = 27;
    public const OP_COUNT = 28;

    /** The trace entry names, one per opcode (index = opcode). */
    private const TRACE_NAMES = [
        'add', 'sub', 'mul', 'xor', 'and', 'or', 'shl', 'shr',
        'u8c', 'u8w', 'u8r', 'u8rot',
        'slen', 'schar', 'scode', 'sslice',
        'dcreate', 'dattr', 'dappend', 'dqsel', 'dget', 'dset', 'dgetd',
        'cadd', 'ccont', 'dparent', 'ddispatch', 'dserialize',
    ];

    private function __construct()
    {
    }

    /**
     * Generate the execution program for a challenge context: base64 of
     * the self-describing bytecode blob, deterministic per
     * (execution_key, nonce, scope, action, version).
     *
     * @throws \InvalidArgumentException when the execution key is not
     *                                   configured, or the context
     *                                   identifiers violate the bounded
     *                                   shapes
     */
    public static function generate(
        string $executionKey,
        string $nonce,
        string $scope,
        string $action,
        string $version,
    ): string {
        self::validateKey($executionKey);
        if ($action === '' || \strlen($action) > 32 || preg_match('/^[A-Za-z0-9._:-]+$/D', $action) !== 1) {
            throw new \InvalidArgumentException(
                'execution action must be 1-32 characters of [A-Za-z0-9._:-]'
            );
        }
        if ($version === '' || \strlen($version) > 8 || preg_match('/^[A-Za-z0-9._:-]+$/D', $version) !== 1) {
            throw new \InvalidArgumentException(
                'execution version must be 1-8 characters of [A-Za-z0-9._:-]'
            );
        }
        $stream = self::prfStream($executionKey, $nonce, $scope, $action, $version);

        $program = '';
        $program .= \chr(self::FORMAT_VERSION);
        $program .= \chr(\strlen($scope));
        $program .= $scope;
        $program .= \chr(\strlen($action));
        $program .= $action;
        $program .= \chr((int) $version);
        $opCount = 8 + (self::nextByte($stream) % 17);
        $program .= \chr($opCount);

        for ($i = 0; $i < $opCount; $i++) {
            $opcode = self::nextByte($stream) % self::OP_COUNT;
            $program .= \chr($opcode);
            $program .= self::drawOperands($stream, $opcode);
        }

        return base64_encode($program);
    }

    /**
     * Whether $programB64 is a well-formed ExecutionChallengeV1 program:
     * canonical standard base64, at most {@see self::MAX_PROGRAM_BASE64}
     * bytes, and a fully parseable blob (format version 1, bounded
     * scope/action, op count 8..24, every opcode and operand shape
     * valid).
     */
    public static function isValidProgram(string $programB64): bool
    {
        return self::decode($programB64) !== null;
    }

    /**
     * Parse a program blob into its canonical structure, or null when the
     * blob is malformed.
     *
     * @return array{format: int, scope: string, action: string, op_version: int, ops: list<array{op: int, operands: array<string, mixed>}>}|null
     */
    public static function decode(string $programB64): ?array
    {
        if (\strlen($programB64) > self::MAX_PROGRAM_BASE64) {
            return null;
        }
        $bytes = base64_decode($programB64, true);
        if ($bytes === false) {
            return null;
        }
        if (base64_encode($bytes) !== $programB64) {
            return null;
        }
        $pos = 0;
        $len = \strlen($bytes);
        $read = static function (int $n) use (&$pos, $bytes, $len): ?string {
            if ($pos + $n > $len) {
                return null;
            }
            $chunk = substr($bytes, $pos, $n);
            $pos += $n;

            return $chunk;
        };

        $format = $read(1);
        if ($format === null || \ord($format) !== self::FORMAT_VERSION) {
            return null;
        }
        $scopeLen = $read(1);
        if ($scopeLen === null) {
            return null;
        }
        $scope = $read(\ord($scopeLen));
        if ($scope === null || $scope === '' || \strlen($scope) > 128) {
            return null;
        }
        $actionLen = $read(1);
        if ($actionLen === null) {
            return null;
        }
        $action = $read(\ord($actionLen));
        if ($action === null || $action === '' || \strlen($action) > 32) {
            return null;
        }
        $opVersion = $read(1);
        if ($opVersion === null) {
            return null;
        }
        $opCount = $read(1);
        if ($opCount === null) {
            return null;
        }
        $opCount = \ord($opCount);
        if ($opCount < self::MIN_OPS || $opCount > self::MAX_OPS) {
            return null;
        }

        $ops = [];
        for ($i = 0; $i < $opCount; $i++) {
            $opcode = $read(1);
            if ($opcode === null) {
                return null;
            }
            $opcode = \ord($opcode);
            if ($opcode >= self::OP_COUNT) {
                return null;
            }
            $operands = self::readOperands($read, $opcode);
            if ($operands === null) {
                return null;
            }
            $ops[] = ['op' => $opcode, 'operands' => $operands];
        }

        return [
            'format' => self::FORMAT_VERSION,
            'scope' => $scope,
            'action' => $action,
            'op_version' => \ord($opVersion),
            'ops' => $ops,
        ];
    }

    /**
     * The expected execution digest of a program for a challenge nonce:
     * hex HMAC-SHA256 keyed by the program bytes (the content-derived
     * digest key) over the label + context + canonical op trace. Null
     * when the program is malformed.
     */
    public static function expectedDigest(string $programB64, string $nonce): ?string
    {
        $bytes = base64_decode($programB64, true);
        if ($bytes === false || base64_encode($bytes) !== $programB64) {
            return null;
        }
        $program = self::decode($programB64);
        if ($program === null) {
            return null;
        }
        $trace = self::canonicalTrace($program);

        return hash_hmac(
            'sha256',
            self::LABEL.'|'.$nonce.'|'.$program['scope'].'|'.$program['action'].'|'.$program['op_version'].'|'.$trace,
            $bytes,
        );
    }

    /**
     * The deterministic canonical op trace of a program: the joined
     * `opname(result)` entries of every op, simulated against the shared
     * state machine (u8 array, current DOM node, appended-id set).
     * A pure function of the program — the browser interpreter computes
     * the identical string.
     *
     * @param array{format: int, scope: string, action: string, op_version: int, ops: list<array{op: int, operands: array<string, mixed>}>} $program
     */
    public static function canonicalTrace(array $program): string
    {
        $u8 = [];
        $cur = null; // ['id', 'attrs' map, 'dataset' map, 'classes' set, 'appended' bool]
        $docIds = [];
        $entries = [];

        foreach ($program['ops'] as $record) {
            $op = $record['op'];
            $operands = $record['operands'];
            $entries[] = self::TRACE_NAMES[$op].'('.self::simulateOp($op, $operands, $u8, $cur, $docIds).')';
        }

        return implode(';', $entries);
    }

    private static function validateKey(string $executionKey): void
    {
        if (\strlen($executionKey) < 16) {
            throw new \InvalidArgumentException(
                'KiwiCaptcha execution key must be at least 16 bytes'
            );
        }
    }

    /**
     * The keyed PRF stream: successive 32-byte HMAC-SHA256 blocks keyed
     * by execution_key over the label+context+u32be(counter), served as
     * one byte string.
     */
    private static function prfStream(string $key, string $nonce, string $scope, string $action, string $version): string
    {
        $base = self::LABEL.'|'.$nonce.'|'.$scope.'|'.$action.'|'.$version;
        $stream = '';
        // The op count + 24 ops with their operand bytes needs at most a
        // few hundred bytes; 16 blocks (512 bytes) always suffices, and
        // the bound makes the stream length deterministic.
        for ($i = 0; $i < 16; $i++) {
            $stream .= hash_hmac('sha256', $base.pack('N', $i), $key, true);
        }

        return $stream;
    }

    /**
     * @param resource|string $stream a byte string consumed from position 0
     */
    private static function nextByte(string &$stream): int
    {
        $byte = \ord($stream[0] ?? "\x00");
        $stream = (string) substr($stream, 1);

        return $byte;
    }

    private static function drawOperands(string &$stream, int $opcode): string
    {
        return match ($opcode) {
            self::OP_ADD, self::OP_SUB, self::OP_MUL, self::OP_XOR,
            self::OP_AND, self::OP_OR, self::OP_SHL, self::OP_SHR => self::drawBytes($stream, 8),
            self::OP_U8_CREATE, self::OP_U8_READ, self::OP_U8_ROTATE => self::drawBytes($stream, 1),
            self::OP_U8_WRITE => self::drawBytes($stream, 2),
            self::OP_STR_LEN => self::drawStringOperand($stream, 0),
            self::OP_STR_CHARCODE, self::OP_STR_CODEPOINT => self::drawStringOperand($stream, 1),
            self::OP_STR_SLICE => self::drawStringOperand($stream, 2),
            self::OP_DOM_CREATE => self::drawBytes($stream, 1).self::drawIdOperand($stream),
            self::OP_DOM_SET_ATTR => self::drawBytes($stream, 1).self::drawPrintableOperand($stream, 32),
            self::OP_DOM_QUERY => self::drawIdOperand($stream),
            self::OP_DOM_GET_ATTR => self::drawBytes($stream, 1),
            self::OP_DOM_DATASET_SET => self::drawDatasetOperand($stream),
            self::OP_DOM_DATASET_GET => self::drawStringOperand($stream, 0),
            self::OP_DOM_CLASS_ADD, self::OP_DOM_CLASS_CONTAINS => self::drawClassOperand($stream),
            default => '',
        };
    }

    /**
     * @param callable(int): ?string $read
     *
     * @return array<string, mixed>|null
     */
    private static function readOperands(callable $read, int $opcode): ?array
    {
        $readByte = static function () use ($read): ?int {
            $b = $read(1);
            if ($b === null) {
                return null;
            }

            return \ord($b);
        };
        // Every string-shaped operand reader mirrors the generator's
        // draw function: the draw writes the real length value as the
        // length byte, never the raw PRF byte, so the reader takes the
        // length byte verbatim and validates its bound. Re-applying the
        // draw's modulus to the written value would wrap at the modulus
        // boundary. The readers do not re-validate the alphabets. The
        // verifier recomputes the trace; a foreign blob with out-of-
        // alphabet bytes simply yields its own deterministic trace, and
        // the canonical re-encode of the blob must still hold.
        $readString = static function () use ($read, $readByte): ?array {
            $lenByte = $readByte();
            if ($lenByte === null) {
                return null;
            }
            $len = $lenByte;
            if ($len < 1 || $len > 16) {
                return null;
            }
            $s = $read($len);
            if ($s === null) {
                return null;
            }

            return ['len' => $len, 's' => $s];
        };
        $readId = static function () use ($read, $readByte): ?array {
            $lenByte = $readByte();
            if ($lenByte === null) {
                return null;
            }
            $len = $lenByte;
            if ($len < 4 || $len > 16) {
                return null;
            }
            $s = $read($len);
            if ($s === null) {
                return null;
            }

            return ['len' => $len, 's' => $s];
        };
        $readValue = static function () use ($read, $readByte): ?array {
            $lenByte = $readByte();
            if ($lenByte === null) {
                return null;
            }
            $len = $lenByte;
            if ($len < 1 || $len > 32) {
                return null;
            }
            $s = $read($len);
            if ($s === null) {
                return null;
            }

            return ['len' => $len, 's' => $s];
        };
        $readClass = static function () use ($read, $readByte): ?array {
            $lenByte = $readByte();
            if ($lenByte === null) {
                return null;
            }
            $len = $lenByte;
            if ($len < 1 || $len > 12) {
                return null;
            }
            $s = $read($len);
            if ($s === null) {
                return null;
            }

            return ['len' => $len, 's' => $s];
        };

        return match ($opcode) {
            self::OP_ADD, self::OP_SUB, self::OP_MUL, self::OP_XOR,
            self::OP_AND, self::OP_OR, self::OP_SHL, self::OP_SHR => self::readU32Pair($read),
            self::OP_U8_CREATE => self::readU8Create($read, $readByte),
            self::OP_U8_WRITE => ['idx' => ($readByte() ?? 0) % 64, 'val' => $readByte() ?? 0],
            self::OP_U8_READ => ['idx' => ($readByte() ?? 0) % 64],
            self::OP_U8_ROTATE => ['k' => ($readByte() ?? 0) % 8],
            self::OP_STR_LEN => $readString(),
            self::OP_STR_CHARCODE, self::OP_STR_CODEPOINT => self::readStringWithByte($read, $readString),
            self::OP_STR_SLICE => self::readStringWithBytes($read, $readString, 2),
            self::OP_DOM_CREATE => self::readCreate($read, $readByte, $readId),
            self::OP_DOM_SET_ATTR => self::readSetAttr($read, $readByte, $readValue),
            self::OP_DOM_QUERY => $readId(),
            self::OP_DOM_GET_ATTR => ['name' => ($readByte() ?? 0) % 5],
            self::OP_DOM_DATASET_SET => self::readDatasetSet($read, $readByte, $readValue),
            self::OP_DOM_DATASET_GET => $readString(),
            self::OP_DOM_CLASS_ADD, self::OP_DOM_CLASS_CONTAINS => $readClass(),
            self::OP_DOM_APPEND, self::OP_DOM_PARENT, self::OP_DOM_DISPATCH,
            self::OP_DOM_SERIALIZE => [],
            default => null,
        };
    }

    /**
     * @param callable(int): ?string $read
     *
     * @return array{a: int, b: int}|null
     */
    private static function readU32Pair(callable $read): ?array
    {
        $a = self::readFixed($read, 4);
        $b = self::readFixed($read, 4);
        if ($a === null || $b === null) {
            return null;
        }

        return ['a' => $a, 'b' => $b];
    }

    /**
     * @param callable(int): ?string $read
     * @param callable(): ?int $readByte
     *
     * @return array{len: int}|null
     */
    private static function readU8Create(callable $read, callable $readByte): ?array
    {
        // U8_CREATE is a raw-byte operand, unlike the string operands
        // whose length byte carries the actual length. Both the
        // generator and the interpreter derive the array length with
        // 8 + (byte % 57), so the parse re-derives the same value.
        $lenByte = $readByte();
        if ($lenByte === null) {
            return null;
        }

        return ['len' => 8 + ($lenByte % 57)];
    }

    /**
     * @param callable(int): ?string $read
     * @param callable(): ?array{len: int, s: string} $readValue
     *
     * @return array<string, mixed>|null
     */
    private static function readDatasetSet(callable $read, callable $readByte, callable $readValue): ?array
    {
        $keyByte = $readByte();
        if ($keyByte === null) {
            return null;
        }
        $keyLen = $keyByte;
        if ($keyLen < 1 || $keyLen > 16) {
            return null;
        }
        $key = $read($keyLen);
        if ($key === null) {
            return null;
        }
        $val = $readValue();
        if ($val === null) {
            return null;
        }

        return ['s' => $key, 'val' => $val['s']];
    }

    /**
     * @param callable(int): ?string $read
     * @param callable(): ?array{len: int, s: string} $readString
     *
     * @return array<string, mixed>|null
     */
    private static function readStringWithByte(callable $read, callable $readString): ?array
    {
        $str = $readString();
        if ($str === null) {
            return null;
        }
        $b = $read(1);
        if ($b === null) {
            return null;
        }

        return ['len' => $str['len'], 's' => $str['s'], 'idx' => \ord($b)];
    }

    /**
     * @param callable(int): ?string $read
     * @param callable(): ?array{len: int, s: string} $readString
     *
     * @return array<string, mixed>|null
     */
    private static function readStringWithBytes(callable $read, callable $readString, int $extra): ?array
    {
        $str = $readString();
        if ($str === null) {
            return null;
        }
        $tail = $read($extra);
        if ($tail === null) {
            return null;
        }
        $start = \ord($tail[0]) % ($str['len'] + 1);
        $count = \ord($tail[1]) % 32;

        return ['len' => $str['len'], 's' => $str['s'], 'start' => $start, 'count' => $count];
    }

    /**
     * @param callable(int): ?string $read
     * @param callable(): ?int $readByte
     * @param callable(): ?array{len: int, s: string} $readId
     *
     * @return array<string, mixed>|null
     */
    private static function readCreate(callable $read, callable $readByte, callable $readId): ?array
    {
        $tagByte = $readByte();
        if ($tagByte === null) {
            return null;
        }
        $id = $readId();
        if ($id === null) {
            return null;
        }

        return ['tag' => $tagByte % 4, 'id' => $id['s']];
    }

    /**
     * @param callable(int): ?string $read
     * @param callable(): ?int $readByte
     * @param callable(): ?array{len: int, s: string} $readString
     *
     * @return array<string, mixed>|null
     */
    private static function readSetAttr(callable $read, callable $readByte, callable $readString): ?array
    {
        $nameByte = $readByte();
        if ($nameByte === null) {
            return null;
        }
        $str = $readString();
        if ($str === null) {
            return null;
        }

        return ['name' => $nameByte % 5, 'val' => $str['s']];
    }

    private static function readFixed(callable $read, int $n): ?int
    {
        $bytes = $read($n);
        if ($bytes === null) {
            return null;
        }
        $value = 0;
        for ($i = 0; $i < $n; $i++) {
            $value = ($value << 8) | \ord($bytes[$i]);
        }

        return $value;
    }

    private static function drawBytes(string &$stream, int $n): string
    {
        $bytes = substr($stream, 0, $n);
        $stream = (string) substr($stream, $n);

        return $bytes;
    }

    /** 1 byte length + L printable-ASCII bytes (+ $extra trailing bytes). */
    private static function drawStringOperand(string &$stream, int $extra): string
    {
        $len = (self::nextByte($stream) % 16) + 1;
        $out = \chr($len);
        for ($i = 0; $i < $len; $i++) {
            $out .= \chr(0x20 + (self::nextByte($stream) % 0x5F));
        }

        return $out.self::drawBytes($stream, $extra);
    }

    /** 1 byte length + L base64-alphabet id bytes. */
    private static function drawIdOperand(string &$stream): string
    {
        $len = 4 + (self::nextByte($stream) % 13);
        $out = \chr($len);
        for ($i = 0; $i < $len; $i++) {
            $out .= self::ID_ALPHABET[self::nextByte($stream) % 64];
        }

        return $out;
    }

    /** 1 byte length + L printable-ASCII bytes. */
    private static function drawPrintableOperand(string &$stream, int $maxLen): string
    {
        $len = (self::nextByte($stream) % $maxLen) + 1;
        $out = \chr($len);
        for ($i = 0; $i < $len; $i++) {
            $out .= \chr(0x20 + (self::nextByte($stream) % 0x5F));
        }

        return $out;
    }

    /** 1 byte length + K digit-first key bytes + 1 byte length + V value bytes. */
    private static function drawDatasetOperand(string &$stream): string
    {
        $len = (self::nextByte($stream) % 16) + 1;
        $out = \chr($len);
        $out .= \chr(0x30 + (self::nextByte($stream) % 10));
        for ($i = 1; $i < $len; $i++) {
            $out .= \chr(0x20 + (self::nextByte($stream) % 0x5F));
        }

        return $out.self::drawPrintableOperand($stream, 32);
    }

    /** 1 byte length + C class-alphabet bytes. */
    private static function drawClassOperand(string &$stream): string
    {
        $len = (self::nextByte($stream) % 12) + 1;
        $out = \chr($len);
        for ($i = 0; $i < $len; $i++) {
            $out .= self::CLASS_ALPHABET[self::nextByte($stream) % 64];
        }

        return $out;
    }

    /**
     * The deterministic state-machine execution of one op; returns the
     * op's canonical trace value (decimal, "1"/"0", or standard base64).
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
            self::OP_ADD => (string) $u32($operands['a'] + $operands['b']),
            self::OP_SUB => (string) $u32($operands['a'] - $operands['b']),
            self::OP_MUL => (string) self::mul32($operands['a'], $operands['b']),
            self::OP_XOR => (string) ($operands['a'] ^ $operands['b']),
            self::OP_AND => (string) ($operands['a'] & $operands['b']),
            self::OP_OR => (string) ($operands['a'] | $operands['b']),
            self::OP_SHL => (string) $u32($operands['a'] << ($operands['b'] & 31)),
            self::OP_SHR => (string) $u32($operands['a'] >> ($operands['b'] & 31)),
            self::OP_U8_CREATE => self::opU8Create($operands, $u8, $checksum),
            self::OP_U8_WRITE => self::opU8Write($operands, $u8, $checksum),
            self::OP_U8_READ => (string) ((($operands['idx'] < \count($u8)) ? $u8[$operands['idx']] : 0) & 0xFF),
            self::OP_U8_ROTATE => self::opU8Rotate($operands, $u8, $checksum),
            self::OP_STR_LEN => (string) \strlen($operands['s']),
            self::OP_STR_CHARCODE, self::OP_STR_CODEPOINT => (string) (($operands['idx'] < \strlen($operands['s']))
                ? \ord($operands['s'][$operands['idx']])
                : 0),
            self::OP_STR_SLICE => base64_encode(substr($operands['s'], $operands['start'], $operands['count'])),
            self::OP_DOM_CREATE => self::opDomCreate($operands, $cur),
            self::OP_DOM_SET_ATTR => self::opDomSetAttr($operands, $cur),
            self::OP_DOM_APPEND => self::opDomAppend($cur, $docIds),
            self::OP_DOM_QUERY => isset($docIds[$operands['s']]) ? '1' : '0',
            self::OP_DOM_GET_ATTR => self::opDomGetAttr($operands, $cur),
            self::OP_DOM_DATASET_SET => self::opDatasetSet($operands, $cur),
            self::OP_DOM_DATASET_GET => self::opDatasetGet($operands, $cur),
            self::OP_DOM_CLASS_ADD => self::opClassAdd($operands, $cur),
            self::OP_DOM_CLASS_CONTAINS => self::opClassContains($operands, $cur),
            self::OP_DOM_PARENT => $cur !== null && $cur['appended'] ? '1' : '0',
            self::OP_DOM_DISPATCH => '1',
            self::OP_DOM_SERIALIZE => self::opDomSerialize($cur, $docIds),
            default => '0',
        };
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
        $name = self::ATTR_NAMES[$operands['name']];
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
        $name = self::ATTR_NAMES[$operands['name']];

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
