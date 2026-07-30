<?php

declare(strict_types=1);

namespace ApexMail\DTOs;

/**
 * A delivery / engagement event.
 *
 * @immutable
 *
 * @property-read string        $id
 * @property-read string        $type           message.delivered | message.bounced | …
 * @property-read string        $message_id
 * @property-read string|null   $status
 * @property-read string|null   $timestamp
 * @property-read string|null   $domain_id
 * @property-read Envelope|null $envelope
 */
class Event extends DTO
{
    use DTOFactory;

    public function getId(): string
    {
        return $this->data['id'] ?? '';
    }

    public function getType(): string
    {
        return $this->data['type'] ?? '';
    }

    public function getMessageId(): string
    {
        return $this->string('message_id') ?? $this->string('messageId') ?? '';
    }

    public function getStatus(): ?string
    {
        return $this->string('status');
    }

    public function getTimestamp(): ?string
    {
        return $this->string('timestamp');
    }

    public function getDomainId(): ?string
    {
        return $this->string('domain_id') ?? $this->string('domainId');
    }

    public function getEnvelope(): ?Envelope
    {
        return $this->dto('envelope', Envelope::class);
    }
}
