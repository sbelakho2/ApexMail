<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * A verification result committed to a consumed challenge record.
 *
 * The storage layer stores this as the record's optional `consumed_result`
 * JSON field — `{"valid": bool, "binding": string|null}` — so a retry on an
 * already-consumed record returns the SAME deterministic outcome as the
 * attempt that consumed it, without re-deriving the proof.
 *
 * This is a storage-layer runtime field: it is NEVER part of the canonical
 * `ChallengeRecord` wire schema (the 21 base keys). The storage wraps the
 * record JSON with `state`/`consumed_result` and strips them again before
 * parsing.
 */
final class ConsumedResult
{
    public function __construct(
        public readonly bool $valid,
        public readonly ?string $binding,
    ) {
    }

    /** @return array{valid: bool, binding: string|null} */
    public function toArray(): array
    {
        return ['valid' => $this->valid, 'binding' => $this->binding];
    }

    /**
     * Rebuild a stored consumed_result. Lenient on structure (the value is
     * written by {@see StorageInterface::commitResult()} — a corrupt value
     * is treated as absent by the storages, degrading to ConsumeIndeterminate
     * rather than crashing the verify path).
     *
     * @param array<string, mixed> $data
     *
     * @throws \InvalidArgumentException on a structurally invalid value
     */
    public static function fromArray(array $data): self
    {
        $valid = $data['valid'] ?? null;
        if (!\is_bool($valid)) {
            throw new \InvalidArgumentException('consumed_result.valid must be a boolean');
        }
        $binding = $data['binding'] ?? null;
        if ($binding !== null && !\is_string($binding)) {
            throw new \InvalidArgumentException('consumed_result.binding must be a string or null');
        }

        return new self($valid, $binding);
    }
}
