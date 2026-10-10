<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * A verification result committed to a consumed challenge record.
 *
 * The storage layer stores this as the record's optional `consumed_result`
 * JSON field, `{"valid": bool, "binding": string|null, "mac"?: hex}`, so
 * a retry on an already-consumed record returns the same deterministic
 * outcome as the attempt that consumed it, without re-deriving the proof.
 *
 * `mac` is the server-state MAC the verifier computes when it commits
 * through {@see AuthenticatedResultCommitInterface}, see
 * {@see ServerStateMac::consumedResult()}. It binds the verdict, the
 * binding and the recorded operation identity to the record's
 * challenge, so a storage writer without the master secret cannot
 * forge a stored success. The key is omitted when null, which is the
 * shape of results committed through the plain
 * {@see StorageInterface::commitResult()}.
 *
 * This is a storage-layer runtime field; it is never part of the
 * canonical `ChallengeRecord` wire schema. The storage wraps the record
 * JSON with `state`/`consumed_result` and strips them again before
 * parsing.
 */
final class ConsumedResult
{
    public function __construct(
        public readonly bool $valid,
        public readonly ?string $binding,
        public readonly ?string $mac = null,
    ) {
        if ($mac !== null && preg_match(ServerStateMac::PATTERN, $mac) !== 1) {
            throw new \InvalidArgumentException('consumed_result.mac must be 64 lowercase hex characters');
        }
    }

    /** @return array{valid: bool, binding: string|null, mac?: string} */
    public function toArray(): array
    {
        $data = ['valid' => $this->valid, 'binding' => $this->binding];
        if ($this->mac !== null) {
            $data['mac'] = $this->mac;
        }

        return $data;
    }

    /**
     * Rebuild a stored consumed_result. Lenient on structure: the value
     * is written by {@see StorageInterface::commitResult()}, and a
     * corrupt value is treated as absent by the storages, degrading to
     * ConsumeIndeterminate rather than crashing the verify path.
     *
     * @param array<string, mixed> $data
     *
     * @throws \InvalidArgumentException on a structurally invalid value
     */
    public static function fromArray(array $data): self
    {
        // The exact supported key set: a result object carrying any other
        // key is corrupt persisted state and is rejected here, mirroring
        // the Rust StoredConsumedResult's deny_unknown_fields boundary.
        $unknown = array_diff(array_keys($data), ['valid', 'binding', 'mac']);
        if ($unknown !== []) {
            throw new \InvalidArgumentException(
                'consumed_result carries unsupported keys: '.implode(',', array_map(strval(...), $unknown))
            );
        }
        $valid = $data['valid'] ?? null;
        // The production Lua now writes a real JSON boolean; legacy records
        // from earlier commits store 1/0 — both forms decode here.
        if (\is_int($valid) && ($valid === 1 || $valid === 0)) {
            $valid = $valid === 1;
        }
        if (!\is_bool($valid)) {
            throw new \InvalidArgumentException('consumed_result.valid must be a boolean');
        }
        $binding = $data['binding'] ?? null;
        if ($binding !== null && !\is_string($binding)) {
            throw new \InvalidArgumentException('consumed_result.binding must be a string or null');
        }
        $mac = $data['mac'] ?? null;
        if ($mac !== null && !\is_string($mac)) {
            throw new \InvalidArgumentException('consumed_result.mac must be a string or null');
        }

        return new self($valid, $binding, $mac);
    }
}
