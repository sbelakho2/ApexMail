<?php

declare(strict_types=1);

namespace ApexMail\DTOs;

/**
 * An email template with versioning.
 *
 * @immutable
 *
 * @property-read string      $id
 * @property-read string      $name
 * @property-read string|null $slug
 * @property-read string|null $subject
 * @property-read string|null $html
 * @property-read string|null $text
 * @property-read string      $engine
 * @property-read int         $version
 * @property-read array|null  $schema
 * @property-read string|null $created_at
 * @property-read string|null $updated_at
 */
class Template extends DTO
{
    public function getId(): string
    {
        return $this->data['id'] ?? '';
    }

    public function getName(): string
    {
        return $this->data['name'] ?? '';
    }

    public function getSlug(): ?string
    {
        return $this->string('slug');
    }

    public function getSubject(): ?string
    {
        return $this->string('subject');
    }

    public function getHtml(): ?string
    {
        return $this->string('html');
    }

    public function getText(): ?string
    {
        return $this->string('text');
    }

    public function getEngine(): string
    {
        return $this->string('engine') ?? 'handlebars';
    }

    public function getVersion(): int
    {
        return $this->int('version') ?? 1;
    }

    /** @return array<string, mixed>|null */
    public function getSchema(): ?array
    {
        $schema = $this->data['schema'] ?? null;
        return is_array($schema) ? $schema : null;
    }

    public function getCreatedAt(): ?string
    {
        return $this->string('created_at') ?? $this->string('createdAt');
    }

    public function getUpdatedAt(): ?string
    {
        return $this->string('updated_at') ?? $this->string('updatedAt');
    }
}
