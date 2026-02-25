<?php

declare(strict_types=1);

namespace ApexMail\Exceptions;

class ApexMailException extends \RuntimeException
{
    public function __construct(
        string           $message,
        private readonly int    $statusCode = 0,
        private readonly ?string $apiCode   = null,
    ) {
        parent::__construct($message, $statusCode);
    }

    public function getStatusCode(): int     { return $this->statusCode; }
    public function getApiCode(): ?string    { return $this->apiCode; }
}

class NetworkException       extends ApexMailException {}
class AuthenticationException extends ApexMailException {}
class NotFoundException       extends ApexMailException {}
class ValidationException     extends ApexMailException {}
class RateLimitException      extends ApexMailException {}
class ApiException            extends ApexMailException {}
