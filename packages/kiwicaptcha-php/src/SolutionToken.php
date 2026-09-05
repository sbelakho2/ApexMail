<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * The client-submitted solution, decoded from the `kiwi__token` hidden input.
 *
 * Wire format: `base64(nonce "." counter "." duration_ms "." telemetry_json
 * ["." execution_digest[":" execution_trace]] ["." rsw_proof])`.
 * The telemetry segment may itself contain dots, so decoding splits on
 * all dots and peels the optional suffix segments right-to-left,
 * independently. The rsw final value is peeled first, exactly when the
 * last segment is 512 lowercase hex. The execution-evidence segment
 * that precedes it (digest or digest:trace) is peeled next. The
 * unarmed token keeps the exact four-segment shape.
 *
 * An rsw token carries the client's final value as an optional final
 * segment: exactly 512 lowercase hex characters (the 256-byte
 * big-endian residue, zero-padded). The counter segment then holds 0,
 * since a time-lock proof has no search counter. The rsw and execution
 * dimensions compose: the issuer may arm an execution challenge with
 * the rsw algorithm, and the wire then carries both the
 * execution-evidence segment and the rsw final value. The shapes are
 * unambiguous because JSON telemetry always ends with '}', never with a
 * hex tail, and the execution evidence is a distinct 64-hex shape, so
 * an rsw proof can never be mistaken for either.
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
        public readonly ?string $executionTrace = null,
        // The rsw final value (512 lowercase hex) presented for an rsw
        // challenge; null on every other shape. The verifier compares it
        // constant-time against the trapdoor expectation.
        public readonly ?string $rswProof = null,
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
     * @param string|null          $rswProof         512-lowercase-hex rsw final
     *                                              value, or null for every
     *                                              other shape
     */
    public static function create(string $nonce, int $counter, int $durationMs, array $telemetry, ?string $executionDigest = null, ?string $executionTrace = null, ?string $rswProof = null): self
    {
        return new self($nonce, $counter, $durationMs, $telemetry, $executionDigest, $executionTrace, $rswProof);
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
            // The trace travels on the wire as base64url, unpadded — the
            // driver's format (btoa + url-safe translation): the field
            // already holds the standard base64 of the plain trace, so
            // only the alphabet/padding translation applies ('+'/'-',
            // '/'/'_', '=' stripped) — never a second encode.
            $plain .= '.'.$this->executionDigest.($this->executionTrace !== null ? ':'.rtrim(strtr($this->executionTrace, '+/', '-_'), '=') : '');
        }
        // The rsw final value rides as the final segment, after the
        // execution evidence: an armed rsw challenge carries both, and
        // the 512-hex discriminator reads the last part.
        if ($this->rswProof !== null) {
            $plain .= '.'.$this->rswProof;
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
        // are nonce/counter/duration, and everything from the fourth
        // segment onward is telemetry plus — at the tail — the optional
        // execution-evidence segment and the optional rsw final value.
        // The suffix peels run independently, right-to-left: the rsw
        // final value is peeled first exactly when the last segment is
        // 512 lowercase hex (the shape the sequential solver produces),
        // then the execution-evidence segment (`digest` or
        // `digest:trace`) is peeled from the segment that precedes it,
        // so an armed rsw challenge carrying both stays one
        // unambiguous grammar. A JSON telemetry object can never end
        // with a hex tail (it must close with '}'), so each
        // discriminator is unambiguous, and a tail matching neither
        // stays part of the telemetry and fails the JSON parse below
        // (fail closed).
        $parts = explode('.', $plain);
        if (\count($parts) < 4) {
            throw DecodeError::malformed();
        }
        $end = \count($parts);
        $executionDigest = null;
        $executionTrace = null;
        $rswProof = null;
        if ($end >= 5 && preg_match('/^[0-9a-f]{512}$/D', $parts[$end - 1]) === 1) {
            // The rsw final value: exactly 512 lowercase hex, the
            // 256-byte big-endian residue the sequential solver
            // produces. The counter segment above then holds 0 (an
            // rsw proof has no search counter).
            $rswProof = $parts[$end - 1];
            --$end;
        }
        if ($end >= 5) {
            // The segment preceding the (optional) rsw final value is
            // `digest` or `digest:trace`: the digest is exactly 64
            // lowercase hex and the trace is canonical base64url (whose
            // alphabet carries neither '.' nor ':'), so the split is
            // total and the discriminator unambiguous. A segment whose
            // digest part is not 64 lowercase hex is not
            // execution-evidence and stays in the telemetry (fail
            // closed); a 64-hex digest with a malformed trace rejects
            // outright, exactly like a lone execution tail.
            $segment = $parts[$end - 1];
            $colon = strpos($segment, ':');
            $digestPart = $colon === false ? $segment : substr($segment, 0, $colon);
            if (preg_match('/^[0-9a-f]{64}$/D', $digestPart) === 1) {
                $executionDigest = $digestPart;
                if ($colon !== false) {
                    $executionTrace = substr($segment, $colon + 1);
                    // The driver emits base64url, unpadded; translate
                    // back to canonical standard base64 (re-pad) before
                    // the strict decode + re-encode check.
                    $standard = strtr($executionTrace, '-_', '+/');
                    $standard = str_pad($standard, (int) ceil(\strlen($standard) / 4) * 4, '=');
                    if ($executionTrace === '' || \strlen($executionTrace) > 10924
                        || base64_decode($standard, true) === false
                        || rtrim(strtr(base64_encode((string) base64_decode($standard, true)), '+/', '-_'), '=') !== $executionTrace) {
                        throw DecodeError::malformed();
                    }
                }
                --$end;
            }
        }
        $telemetryStr = implode('.', \array_slice($parts, 3, $end - 3));
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

        return new self($nonce, $counter, $durationMs, (array) $telemetry, $executionDigest, $executionTrace, $rswProof);
    }
}
