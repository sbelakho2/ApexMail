<?php

declare(strict_types=1);

namespace ApexMail\DTOs;

/**
 * Base class for all API response DTOs.
 *
 * Each DTO wraps a decoded JSON array from the ApexMail API and provides
 * typed, readonly access to known fields while preserving access to any
 * unexpected fields via ArrayAccess semantics.
 *
 * @phpstan-consistent-constructor
 */
abstract class DTO implements \ArrayAccess, \JsonSerializable
{
    /** @var array<string, mixed> Raw API response data */
    protected array $data;

    /**
     * @param array<string, mixed> $data Raw response from the ApexMail API
     */
    public function __construct(array $data)
    {
        $this->data = $data;
    }

    /** Return the underlying raw data. */
    public function toArray(): array
    {
        return $this->data;
    }

    /** Return the DTO as a JSON string. */
    public function toJson(int $flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE): string
    {
        return json_encode($this->data, $flags);
    }

    /** Re-create from a JSON string. */
    public static function fromJson(string $json, string $class = self::class): static
    {
        $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($data)) {
            throw new \InvalidArgumentException('JSON must decode to an object');
        }
        return new $class($data);
    }

    // ── ArrayAccess ─────────────────────────────────────────────────────────

    public function offsetExists(mixed $offset): bool
    {
        return isset($this->data[$offset]);
    }

    public function offsetGet(mixed $offset): mixed
    {
        return $this->data[$offset] ?? null;
    }

    /** @throws \BadMethodCallException — DTOs are immutable */
    public function offsetSet(mixed $offset, mixed $value): void
    {
        throw new \BadMethodCallException('DTOs are immutable');
    }

    /** @throws \BadMethodCallException — DTOs are immutable */
    public function offsetUnset(mixed $offset): void
    {
        throw new \BadMethodCallException('DTOs are immutable');
    }

    // ── JsonSerializable ────────────────────────────────────────────────────

    public function jsonSerialize(): array
    {
        return $this->data;
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    protected function string(string $key): ?string
    {
        $v = $this->data[$key] ?? null;
        return is_string($v) ? $v : null;
    }

    protected function int(string $key): ?int
    {
        $v = $this->data[$key] ?? null;
        return is_int($v) ? $v : (is_numeric($v) ? (int) $v : null);
    }

    protected function float(string $key): ?float
    {
        $v = $this->data[$key] ?? null;
        return is_float($v) ? $v : (is_numeric($v) ? (float) $v : null);
    }

    protected function bool(string $key): ?bool
    {
        $v = $this->data[$key] ?? null;
        return is_bool($v) ? $v : null;
    }

    /** @return array<string, mixed>|null */
    protected function map(string $key): ?array
    {
        $v = $this->data[$key] ?? null;
        return is_array($v) ? $v : null;
    }

    /** @return list<mixed>|null */
    protected function list(string $key): ?array
    {
        $v = $this->data[$key] ?? null;
        return is_array($v) ? array_values($v) : null;
    }
}
