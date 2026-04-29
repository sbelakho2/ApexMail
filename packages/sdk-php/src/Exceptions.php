<?php

declare(strict_types=1);

namespace ApexMail\Exceptions;

class ApexMailException extends \RuntimeException
{
    public function __construct(
        string           $message,
        private readonly int    $statusCode,
        private readonly ?string $apiCode   = null,
        private readonly array $metadata = [],
    ) {
        parent::__construct($message, $statusCode);
    }

    public function getStatusCode(): int     { return $this->statusCode; }
    public function getApiCode(): ?string    { return $this->apiCode; }
    public function getMetadata(): array     { return $this->metadata; }
}

class NetworkException       extends ApexMailException {}
class AuthenticationException extends ApexMailException {}
class ForbiddenException      extends ApexMailException {}
class ConflictException       extends ApexMailException {}
class NotFoundException       extends ApexMailException {}
class ValidationException     extends ApexMailException {}
class RateLimitException extends ApexMailException
{
    public function getLimit(): ?int
    {
        return isset($this->getMetadata()['limit']) ? (int) $this->getMetadata()['limit'] : null;
    }

    public function getRemaining(): ?int
    {
        return isset($this->getMetadata()['remaining']) ? (int) $this->getMetadata()['remaining'] : null;
    }

    public function getReset(): ?int
    {
        return isset($this->getMetadata()['reset']) ? (int) $this->getMetadata()['reset'] : null;
    }

    public function getRetryAfter(): ?string
    {
        return isset($this->getMetadata()['retryAfter']) ? (string) $this->getMetadata()['retryAfter'] : null;
    }
}
class ApiException            extends ApexMailException {}
