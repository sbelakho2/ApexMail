<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * The client-submitted solution, decoded from the `kiwi__token` hidden input.
 *
 * Wire format: `base64(nonce "." counter "." duration_ms "." telemetry_json
 * ["." execution_digest])`.
 * The telemetry segment may itself contain dots, so decoding splits only on
 * the first four dots (an armed challenge appends the execution digest as
 * a fifth segment; an unarmed token keeps the exact four-segment shape).
 */
final class SolutionToken
{
    private function __construct(
        public readonly string $nonce,
        public readonly int $counter,
        public readonly int $durationMs,
        public readonly array $telemetry,
        // The ExecutionChallengeV1 execution digest (64 lowercase hex
        // characters) presented for an execution-armed challenge; null
        // on the unarmed shape. The digest is computed by the browser
        // interpreter from the issued program and binds the submission
        // to the challenge context; the verifier recomputes the expected
        // digest from the stored program and rejects a mismatch with the
        // deterministic ExecutionMismatch outcome.
        public readonly ?string $executionDigest = null,
    ) {
    }

    /**
     * The browser/wasm solver caps at 5,000,000 hashes, so a counter
     * above it cannot come from a legit solve. 5,000,000 is 7 digits;
     * the length bound rejects absurdly long digit strings before the
     * integer cast could hide them.
     */
    private const MAX_SOLVER_COUNTER = 5_000_000;

    /** The solver-cap ceiling (5M), exposed for tests. */
    public static function maxSolverCounter(): int
    {
        return self::MAX_SOLVER_COUNTER;
    }

    /** Hard ceiling for the client-reported duration (telemetry only): 1 hour. */
    public const MAX_DURATION_MS = 3_600_000;

    /**
     * @param array<string, mixed> $telemetry
     * @param string|null          $executionDigest 64-lowercase-hex execution
     *                                              digest, or null for the
     *                                              legacy four-segment shape
     */
    public static function create(string $nonce, int $counter, int $durationMs, array $telemetry, ?string $executionDigest = null): self
    {
        return new self($nonce, $counter, $durationMs, $telemetry, $executionDigest);
    }

    public function encode(): string
    {
        $plain = sprintf(
            '%s.%d.%d.%s',
            $this->nonce,
            $this->counter,
            $this->durationMs,
            // The telemetry segment must always be a JSON object (decode
            // requires it): the (object) cast makes an empty array encode
            // as {} and an assoc array as {"k":v,...}, never [].
            (string) json_encode((object) $this->telemetry, JSON_UNESCAPED_SLASHES)
        );
        // The execution digest is an optional fifth segment: an unarmed
        // token stays byte-identical to the four-segment shape.
        if ($this->executionDigest !== null) {
            $plain .= '.'.$this->executionDigest;
        }

        return base64_encode($plain);
    }

    /**
     * @throws DecodeError
     */
    public static function decode(string $raw): self
    {
        // Early size cap: legitimately encoded tokens are a few hundred bytes;
        // anything larger is an abuse probe, not a solution.
        if (\strlen($raw) > 32_768) {
            throw DecodeError::malformed();
        }

        // Strict canonical base64: base64_decode in strict mode rejects
        // every character outside the standard alphabet (including
        // base64url '-'/'_' and whitespace), and the canonical re-encode
        // check rejects any non-canonical padding (unpadded, over-padded,
        // or non-zero trailing bits). Exactly one canonical byte
        // representation of the plaintext can decode.
        $plain = base64_decode($raw, true);
        if ($plain === false) {
            throw DecodeError::invalidBase64();
        }
        $plain = (string) $plain;
        if (base64_encode($plain) !== $raw) {
            throw DecodeError::invalidBase64();
        }
        // The regex engine is always available in PHP 8.1 (no undeclared
        // mbstring dependency); /u makes the match fail on invalid UTF-8.
        if (preg_match('//u', $plain) !== 1) {
            throw DecodeError::invalidUtf8();
        }

        // The wire grammar splits on ALL dots: the first three segments
        // are nonce/counter/duration, and the final segment is the
        // execution digest exactly when it is 64 lowercase hex characters
        // (the shape the driver's interpreter produces) — the telemetry
        // is everything between. A JSON telemetry object can never end
        // with a 64-hex tail (it must close with '}'), so the
        // discriminator is unambiguous, and a malformed digest tail on
        // an armed token fails the telemetry JSON parse below (fail
        // closed).
        $parts = explode('.', $plain);
        if (\count($parts) < 4) {
            throw DecodeError::malformed();
        }
        $last = $parts[\count($parts) - 1];
        $executionDigest = null;
        if (\count($parts) >= 5 && preg_match('/^[0-9a-f]{64}$/D', $last) === 1) {
            $executionDigest = $last;
            $telemetryStr = implode('.', \array_slice($parts, 3, -1));
        } else {
            $telemetryStr = implode('.', \array_slice($parts, 3));
        }
        [$nonce, $counterStr, $durationStr] = $parts;

        // The nonce is base64(32 random bytes): exactly 44 chars, standard
        // alphabet with one padding '='. Anything else cannot come from
        // Issuer::issue().
        if (\strlen($nonce) !== 44 || preg_match('/^[A-Za-z0-9+\/]{43}=$/', $nonce) !== 1) {
            throw DecodeError::malformed();
        }

        // Rust's `u64::from_str` accepts leading zeros ("007" -> 7) and
        // rejects empty/"+1"/"1.5". ctype_digit mirrors that exactly.
        if ($counterStr === '' || !ctype_digit($counterStr)) {
            throw DecodeError::invalidCounter();
        }
        // Counter bound: the JS solver searches counter < 5,000,000
        // attempts, so the largest counter it can ever produce is
        // 4,999,999; anything >= 5,000,000 was not minted by a real
        // solve.
        if (\strlen($counterStr) > 7 || (int) $counterStr >= self::MAX_SOLVER_COUNTER) {
            throw DecodeError::counterExceedsSolverMaximum();
        }
        $counter = (int) $counterStr;

        if ($durationStr === '' || !ctype_digit($durationStr)) {
            throw DecodeError::invalidDuration();
        }
        // Duration is client telemetry only, but the wire protocol still
        // bounds it (0 .. 3_600_000 ms = 1 hour) so both implementations
        // accept exactly the same language.
        if ((int) $durationStr > self::MAX_DURATION_MS) {
            throw DecodeError::invalidDuration();
        }
        $durationMs = (int) $durationStr;

        // Telemetry must be a JSON object in both implementations ({} for
        // an off widget, {v,mode,me,ke,...} otherwise). json_decode in
        // object mode distinguishes {} from []/"x"/123/null; array mode
        // cannot.
        $telemetry = json_decode($telemetryStr, false);
        if (!\is_object($telemetry)) {
            throw DecodeError::malformed();
        }

        // The optional execution digest must be exactly 64 lowercase hex
        // characters (the hex HMAC-SHA256 shape the driver's interpreter
        // produces); any other shape is not part of the wire language.
        if ($executionDigest !== null && preg_match('/^[0-9a-f]{64}$/D', $executionDigest) !== 1) {
            throw DecodeError::malformed();
        }

        return new self($nonce, $counter, $durationMs, (array) $telemetry, $executionDigest);
    }
}
