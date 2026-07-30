<?php

declare(strict_types=1);

namespace ApexMail\DTOs;

/**
 * A paginated API response containing items and optional cursor/offset metadata.
 *
 * @immutable
 *
 * @template T of DTO
 *
 * @property-read T[]         $items
 * @property-read string|null $next_cursor
 * @property-read int|null    $total
 */
class PaginatedResponse extends DTO
{
    /** @var class-string<T> */
    private string $itemClass;

    /**
     * @param array<string, mixed> $data
     * @param class-string<T>      $itemClass
     */
    public function __construct(array $data, string $itemClass = DTO::class)
    {
        parent::__construct($data);
        $this->itemClass = $itemClass;
    }

    /** @return T[] */
    public function getItems(): array
    {
        $raw = $this->data['items'] ?? $this->data['data'] ?? $this->data['messages'] ?? [];
        if (!is_array($raw)) {
            return [];
        }
        $class = $this->itemClass;
        return array_map(static fn (mixed $item): DTO => new $class(
            is_array($item) ? $item : []
        ), array_values($raw));
    }

    public function getNextCursor(): ?string
    {
        return $this->string('next_cursor') ?? $this->string('nextCursor');
    }

    public function getTotal(): ?int
    {
        return $this->int('total');
    }
}
