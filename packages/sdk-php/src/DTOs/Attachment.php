<?php

declare(strict_types=1);

namespace ApexMail\DTOs;

/**
 * An email attachment.
 *
 * @immutable
 *
 * @property-read string      $filename
 * @property-read string      $content    Base64-encoded content
 * @property-read string      $mime_type
 * @property-read string|null $content_id For inline images (CID)
 */
class Attachment extends DTO
{
    public function getFilename(): string
    {
        return $this->data['filename'] ?? '';
    }

    public function getContent(): string
    {
        return $this->data['content'] ?? '';
    }

    public function getMimeType(): string
    {
        return $this->string('mime_type') ?? $this->data['mimeType'] ?? 'application/octet-stream';
    }

    public function getContentId(): ?string
    {
        return $this->string('content_id') ?? $this->string('contentId');
    }
}
