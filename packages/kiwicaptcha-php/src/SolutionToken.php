<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * The client-submitted solution, decoded from the `kiwi__token` hidden input.
 *
 * Wire format: `base64(nonce "." counter "." duration_ms "." telemetry_json)`.
 * The telemetry segment may itself contain dots, so decoding splits only on
 * the first three dots.
 */
final class SolutionToken
{
    private function __construct(
        public readonly string $nonce,
        public readonly int $counter,
        public readonly int $durationMs,
        public readonly array $telemetry,
    ) {
    }

    /**
     * The browser/wasm solver caps at 5,000,000 hashes (Rust
     * SOLVER_MAX_TARGET_BITS / MAX_SHA_HASHES), so a counter above it cannot
     * come from a legit solve. 5,000,000 is 7 digits — the length bound
     * rejects absurdly long digit strings before the (PHP_INT_MAX-clamped)
     * integer cast could hide them.
     */
    private const MAX_SOLVER_COUNTER = 5_000_000;

    /**
     * @param array<string, mixed> $telemetry
     */
    public static function create(string $nonce, int $counter, int $durationMs, array $telemetry): self
    {
        return new self($nonce, $counter, $durationMs, $telemetry);
    }

    public function encode(): string
    {
        $plain = sprintf(
            '%s.%d.%d.%s',
            $this->nonce,
            $this->counter,
            $this->durationMs,
            (string) json_encode($this->telemetry, JSON_UNESCAPED_SLASHES)
        );

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

        $plain = base64_decode(trim($raw), true);
        if ($plain === false) {
            throw DecodeError::invalidBase64();
        }
        $plain = (string) $plain;
        // PCRE is always available in PHP 8.1 (no undeclared mbstring
        // dependency): /u makes the match fail on invalid UTF-8.
        if (preg_match('//u', $plain) !== 1) {
            throw DecodeError::invalidUtf8();
        }

        $parts = explode('.', $plain, 4);
        if (\count($parts) !== 4) {
            throw DecodeError::malformed();
        }
        [$nonce, $counterStr, $durationStr, $telemetryStr] = $parts;

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
        // Counter bound: the solver caps at 5,000,000 hashes, so larger
        // values are abuse probes, not solutions.
        if (\strlen($counterStr) > 7 || (int) $counterStr > self::MAX_SOLVER_COUNTER) {
            throw DecodeError::counterExceedsSolverMaximum();
        }
        $counter = (int) $counterStr;

        if ($durationStr === '' || !ctype_digit($durationStr)) {
            throw DecodeError::invalidDuration();
        }
        $durationMs = (int) $durationStr;

        $telemetry = json_decode($telemetryStr, true);
        if (!\is_array($telemetry)) {
            throw DecodeError::malformed();
        }

        return new self($nonce, $counter, $durationMs, $telemetry);
    }
}
