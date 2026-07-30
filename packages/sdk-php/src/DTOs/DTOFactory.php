<?php

declare(strict_types=1);

namespace ApexMail\DTOs;

/**
 * Helper trait for DTOs that need to construct sub-DTOs from array data.
 *
 * @internal
 */
trait DTOFactory
{
    /**
     * Build a list of DTOs from a raw array key.
     *
     * @template T of DTO
     * @param  string $key   Raw data key
     * @param  class-string<T> $class  DTO class name
     * @return list<T>|null
     */
    private function dtoList(string $key, string $class): ?array
    {
        $raw = $this->data[$key] ?? null;
        if (!is_array($raw)) {
            return null;
        }
        return array_map(static fn (mixed $item): DTO => new $class(
            is_array($item) ? $item : ['email' => (string) $item]
        ), array_values($raw));
    }

    /**
     * Build a single sub-DTO from a raw array key.
     *
     * @template T of DTO
     * @param  string $key   Raw data key
     * @param  class-string<T> $class  DTO class name
     * @return T|null
     */
    private function dto(string $key, string $class): ?DTO
    {
        $raw = $this->data[$key] ?? null;
        if (!is_array($raw)) {
            return null;
        }
        return new $class($raw);
    }
}
