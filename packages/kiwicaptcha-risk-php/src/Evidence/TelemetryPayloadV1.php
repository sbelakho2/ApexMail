<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Evidence;

/**
 * The parsed telemetry-v1 payload (protocol/telemetry-v1/payload.json),
 * mirror of the Rust `TelemetryPayloadV1`.
 *
 * Constructed only through parse(), which accepts exactly the published
 * schema and rejects everything else, so a valid value can never carry
 * an out-of-range count, an unknown field or a broken collector
 * invariant.
 */
final class TelemetryPayloadV1
{
    /** The schema version this parser accepts. */
    public const VERSION = 1;

    /** The wire bound on the payload text (bytes); shared with Rust. */
    public const MAX_PAYLOAD_BYTES = 512;

    /**
     * @param array{fo: int, ke: int, pa: int, po: int, fm: int} $ec
     */
    private function __construct(
        public readonly int $v,
        public readonly array $ec,
        public readonly int $qe,
        public readonly int $ft,
        public readonly int $pt,
        public readonly int $n,
    ) {
    }

    /**
     * Parses one payload from its JSON text against the published
     * schema. Every violation (wrong version, missing field,
     * out-of-range value, unknown field, wrong JSON shape) is a reject;
     * the caller treats a reject exactly like an absent payload
     * (neutral-unknown, never negative).
     */
    public static function parse(string $raw): ?self
    {
        if (strlen($raw) > self::MAX_PAYLOAD_BYTES) {
            return null;
        }
        try {
            $decoded = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
        if (!is_array($decoded) || array_is_list($decoded)) {
            return null;
        }
        $known = ['v', 'ec', 'qe', 'ft', 'pt', 'n'];
        foreach (array_keys($decoded) as $key) {
            if (!in_array($key, $known, true)) {
                return null;
            }
        }
        foreach ($known as $key) {
            if (!array_key_exists($key, $decoded)) {
                return null;
            }
        }
        $v = $decoded['v'];
        $qe = $decoded['qe'];
        $ft = $decoded['ft'];
        $pt = $decoded['pt'];
        $n = $decoded['n'];
        $ec = $decoded['ec'];
        if (!is_int($v) || !is_int($qe) || !is_int($ft) || !is_int($pt) || !is_int($n)) {
            return null;
        }
        if (!is_array($ec) || array_is_list($ec)) {
            return null;
        }
        $counts = [];
        foreach (['fo', 'ke', 'pa', 'po', 'fm'] as $class) {
            if (!array_key_exists($class, $ec) || !is_int($ec[$class])) {
                return null;
            }
            $counts[$class] = $ec[$class];
        }
        foreach (array_keys($ec) as $key) {
            if (!in_array($key, ['fo', 'ke', 'pa', 'po', 'fm'], true)) {
                return null;
            }
        }
        $payload = new self($v, $counts, $qe, $ft, $pt, $n);
        return $payload->validate() ? $payload : null;
    }

    private function validate(): bool
    {
        $consts = EvidenceModel::CONSTS;
        if ($this->v !== self::VERSION) {
            return false;
        }
        $cap = $consts['sample_cap'];
        if ($this->qe < 0 || $this->qe > $consts['entropy_max']) {
            return false;
        }
        if ($this->ft < 0 || $this->ft > $cap) {
            return false;
        }
        if ($this->pt < 0 || $this->pt > $consts['score_saturation']) {
            return false;
        }
        if ($this->n < 0 || $this->n > $cap) {
            return false;
        }
        $sum = 0;
        foreach ($this->ec as $count) {
            if ($count < 0 || $count > $cap) {
                return false;
            }
            $sum += $count;
        }
        // The collector invariant: every counted event increments
        // exactly one class and the sample count.
        return $sum === $this->n;
    }
}
