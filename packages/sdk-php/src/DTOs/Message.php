<?php

declare(strict_types=1);

namespace ApexMail\DTOs;

/**
 * Represents a sent (or retrieved) email message.
 *
 * @immutable
 *
 * @property-read string          $id
 * @property-read string|null     $status
 * @property-read Address|null    $from
 * @property-read Address[]|null  $to
 * @property-read Address[]|null  $cc
 * @property-read Address[]|null  $bcc
 * @property-read string|null     $subject
 * @property-read string|null     $html
 * @property-read string|null     $text
 * @property-read string|null     $template_id
 * @property-read string|null     $priority
 * @property-read string|null     $scheduled_at
 * @property-read string[]|null   $tags
 * @property-read Attachment[]|null $attachments
 * @property-read string|null     $error
 * @property-read string|null     $created_at
 * @property-read string|null     $updated_at
 */
class Message extends DTO
{
    use DTOFactory;

    public function getId(): string
    {
        return $this->data['id'] ?? '';
    }

    public function getStatus(): ?string
    {
        return $this->string('status');
    }

    public function getFrom(): ?Address
    {
        return Address::from($this->data['from'] ?? []);
    }

    /** @return Address[]|null */
    public function getTo(): ?array
    {
        return $this->dtoList('to', Address::class);
    }

    /** @return Address[]|null */
    public function getCc(): ?array
    {
        return $this->dtoList('cc', Address::class);
    }

    /** @return Address[]|null */
    public function getBcc(): ?array
    {
        return $this->dtoList('bcc', Address::class);
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

    public function getTemplateId(): ?string
    {
        return $this->string('template_id') ?? $this->string('templateId');
    }

    public function getPriority(): ?string
    {
        return $this->string('priority');
    }

    public function getScheduledAt(): ?string
    {
        return $this->string('scheduled_at') ?? $this->string('scheduledAt');
    }

    /** @return string[]|null */
    public function getTags(): ?array
    {
        return $this->list('tags');
    }

    /** @return Attachment[]|null */
    public function getAttachments(): ?array
    {
        return $this->dtoList('attachments', Attachment::class);
    }

    public function getError(): ?string
    {
        return $this->string('error');
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
