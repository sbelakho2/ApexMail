<?php

declare(strict_types=1);

namespace ApexMail;

/**
 * Official PHP SDK for the ApexMail transactional email API.
 *
 * Usage:
 *   $client = new ApexMail\Client('am_live_xxxx');
 *
 *   $response = $client->emails->send([
 *       'from'    => 'hello@example.com',
 *       'to'      => 'user@example.com',
 *       'subject' => 'Hello!',
 *       'html'    => '<h1>Hello World</h1>',
 *   ]);
 *   echo $response['message']['id'];
 *
 * @package ApexMail
 */

class Client
{
    public const SDK_VERSION     = '1.0.0';
    public const DEFAULT_URL     = 'https://api.apexmail.ee';
    public const DEFAULT_MAX_RESPONSE_BYTES = 20971520;
    private const API_KEY_REGEX  = '/^am_(live|test)_[A-Za-z0-9]{16,}$/';

    private string $apiKey;
    private string $baseUrl;
    private int    $timeout;
    private int    $maxRetries;
    private int    $maxResponseBytes;
    private ?array $lastRateLimit = null;

    public Resources\Emails      $emails;
    public Resources\Domains     $domains;
    public Resources\Webhooks    $webhooks;
    public Resources\Templates   $templates;
    public Resources\Suppressions $suppressions;
    public Resources\Events      $events;
    public Resources\Analytics   $analytics;
    public Resources\ApiKeys     $apiKeys;

    /**
     * @param string $apiKey  API key (starts with am_live_ or am_test_)
    * @param array  $options Optional: ['baseUrl' => '...', 'timeout' => 30, 'maxResponseBytes' => 20971520]
     */
    public function __construct(string $apiKey, array $options = [])
    {
        if (!preg_match(self::API_KEY_REGEX, $apiKey)) {
            throw new \InvalidArgumentException('Invalid API key format');
        }

        $this->apiKey  = $apiKey;
        $this->baseUrl = rtrim($options['baseUrl'] ?? self::DEFAULT_URL, '/');
        if (!str_starts_with($this->baseUrl, 'https://')) {
            throw new \InvalidArgumentException('baseUrl must use HTTPS');
        }
        $this->timeout = (int) ($options['timeout'] ?? 30);
        $this->maxRetries = (int) ($options['maxRetries'] ?? 3);
        $this->maxResponseBytes = (int) ($options['maxResponseBytes'] ?? self::DEFAULT_MAX_RESPONSE_BYTES);

        $this->emails       = new Resources\Emails($this);
        $this->domains      = new Resources\Domains($this);
        $this->webhooks     = new Resources\Webhooks($this);
        $this->templates    = new Resources\Templates($this);
        $this->suppressions = new Resources\Suppressions($this);
        $this->events       = new Resources\Events($this);
        $this->analytics    = new Resources\Analytics($this);
        $this->apiKeys      = new Resources\ApiKeys($this);
    }

    /**
     * Make an API request.
     *
     * @param string      $method          HTTP method (GET, POST, PATCH, DELETE)
     * @param string      $path            Relative API path (e.g. /v1/messages)
     * @param array|null  $body            Request body (will be JSON-encoded)
     * @param string|null $idempotencyKey  Optional idempotency key
     * @return array                       Decoded JSON response
     * @throws ApexMailException
     */
    public function request(
        string  $method,
        string  $path,
        ?array  $body = null,
        ?string $idempotencyKey = null,
    ): array {
        $url = $this->baseUrl . $path;

        $attempt = 0;
        while (true) {
            $retryAfter = null;
            $rateLimit = [
                'limit' => null,
                'remaining' => null,
                'reset' => null,
                'retryAfter' => null,
            ];
            $headers = [
                'X-API-Key: ' . $this->apiKey,
                'Accept: application/json',
                'Content-Type: application/json',
                'User-Agent: apexmail-php/' . self::SDK_VERSION,
            ];
            if ($idempotencyKey !== null) {
                $headers[] = 'X-Idempotency-Key: ' . $idempotencyKey;
            }

            $responseBody = '';
            $responseTooLarge = false;
            $maxBytes = $this->maxResponseBytes;

            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_CUSTOMREQUEST  => strtoupper($method),
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HTTPHEADER     => $headers,
                CURLOPT_TIMEOUT        => $this->timeout,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_HEADERFUNCTION => static function ($curl, $header) use (&$retryAfter, &$rateLimit) {
                    $len = strlen($header);
                    $trimmed = trim($header);
                    if ($trimmed === '' || !str_contains($trimmed, ':')) {
                        return $len;
                    }

                    [$name, $value] = explode(':', $trimmed, 2);
                    $value = trim($value);
                    switch (strtolower($name)) {
                        case 'retry-after':
                            $retryAfter = $value;
                            $rateLimit['retryAfter'] = $value;
                            break;
                        case 'x-ratelimit-limit':
                            $rateLimit['limit'] = $value;
                            break;
                        case 'x-ratelimit-remaining':
                            $rateLimit['remaining'] = $value;
                            break;
                        case 'x-ratelimit-reset':
                            $rateLimit['reset'] = $value;
                            break;
                    }
                    return $len;
                },
                CURLOPT_WRITEFUNCTION => static function ($curl, string $chunk) use (&$responseBody, &$responseTooLarge, $maxBytes): int {
                    if ((strlen($responseBody) + strlen($chunk)) > $maxBytes) {
                        $responseTooLarge = true;
                        return 0;
                    }
                    $responseBody .= $chunk;
                    return strlen($chunk);
                },
            ]);

            if ($body !== null) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body, JSON_THROW_ON_ERROR));
            }

            curl_exec($ch);
            $statusCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $curlError  = curl_error($ch);
            curl_close($ch);

            if ($responseTooLarge) {
                throw new Exceptions\NetworkException('Response body exceeds maxResponseBytes', 0);
            }

            if ($curlError) {
                if ($attempt < $this->maxRetries) {
                    $this->sleepBackoff($attempt);
                    $attempt++;
                    continue;
                }
                throw new Exceptions\NetworkException('cURL error: ' . $curlError, 0);
            }

            $this->lastRateLimit = $this->normalizeRateLimit($rateLimit);

            if (in_array($statusCode, [429, 500, 502, 503, 504], true) && $attempt < $this->maxRetries) {
                $this->sleepRetryAfter($retryAfter, $attempt);
                $attempt++;
                continue;
            }

            $decoded = $responseBody !== ''
                ? $this->decodeResponseBody($responseBody)
                : [];

            if ($statusCode >= 400) {
                $this->throwApiError($statusCode, $decoded, $this->lastRateLimit);
            }

            return $decoded;
        }
    }

    public function getLastRateLimit(): ?array
    {
        return $this->lastRateLimit;
    }

    /**
     * Sleep for max(retryAfter, baseDelay * attempt²) seconds, capped at 5s.
     *
     * Honors the server's Retry-After header (integer seconds or HTTP-date)
     * while providing quadratic backoff growth as attempts increase.
     */
    private function sleepRetryAfter(?string $retryAfter, int $attempt): void
    {
        // Compute quadratic backoff: baseDelay * attempt²
        $backoff = $this->calculateBackoff($attempt);

        if ($retryAfter !== null && $retryAfter !== '') {
            $retryAfterSeconds = -1;

            // Try integer seconds (most common)
            if (ctype_digit($retryAfter)) {
                $retryAfterSeconds = (int) $retryAfter;
            } else {
                // Try HTTP-date format
                $parsed = strtotime($retryAfter);
                if ($parsed !== false) {
                    $retryAfterSeconds = max(0, $parsed - time());
                }
            }

            if ($retryAfterSeconds >= 0) {
                $backoff = max($backoff, $retryAfterSeconds);
            }
        }

        $backoff = min($backoff, 5.0);
        usleep((int) ($backoff * 1_000_000));
    }

    /**
     * Quadratic backoff: baseDelay * attempt², used when no Retry-After header.
     */
    private function calculateBackoff(int $attempt): float
    {
        return 0.5 * ($attempt * $attempt);
    }

    public static function verifyWebhookSignature(
        string $payload,
        string|array|null $signatureHeader,
        string $secret,
        int $toleranceSeconds = 300,
        ?int $timestamp = null,
    ): bool {
        if ($signatureHeader === null || $signatureHeader === '' || $secret === '') {
            return false;
        }

        if (is_array($signatureHeader)) {
            $signatureHeader = $signatureHeader[0] ?? null;
        }
        if ($signatureHeader === null || $signatureHeader === '') {
            return false;
        }

        $parsed = self::parseSignatureHeader($signatureHeader);
        $timestampValue = $timestamp ?? ($parsed['timestamp'] ?? null);
        $signature = $parsed['signature'] ?? null;
        if ($timestampValue === null || $signature === null || $signature === '') {
            return false;
        }
        if (!is_numeric($timestampValue)) {
            return false;
        }

        $timestampInt = (int) $timestampValue;
        $now = time();
        if (abs($now - $timestampInt) > $toleranceSeconds) {
            return false;
        }

        $signedPayload = $timestampInt . '.' . $payload;
        $expected = hash_hmac('sha256', $signedPayload, $secret);
        if (strlen($expected) !== strlen($signature)) {
            return false;
        }

        return hash_equals($expected, $signature);
    }

    private static function parseSignatureHeader(string $signatureHeader): array
    {
        $trimmed = trim($signatureHeader);
        if (str_contains($trimmed, 't=') && str_contains($trimmed, 'v1=')) {
            $parts = explode(',', $trimmed);
            $timestamp = null;
            $signature = null;
            foreach ($parts as $part) {
                $part = trim($part);
                $segments = explode('=', $part, 2);
                if (count($segments) !== 2) {
                    continue;
                }
                [$key, $value] = $segments;
                if ($key === 't' && $value !== '') {
                    $timestamp = $value;
                } elseif ($key === 'v1' && $value !== '') {
                    $signature = $value;
                }
            }
            return ['timestamp' => $timestamp, 'signature' => $signature];
        }

        if (str_starts_with($trimmed, 'sha256=')) {
            return ['signature' => substr($trimmed, strlen('sha256='))];
        }

        return ['signature' => $trimmed];
    }

    // ── Private ─────────────────────────────────────────────────────────────

    private function decodeResponseBody(string $responseBody): array
    {
        $decoded = json_decode($responseBody, true, 512, JSON_THROW_ON_ERROR);

        if (is_array($decoded)) {
            // SDK-111: Unwrap API envelope {"data": ..., "meta": ...}
            if (isset($decoded['data'])) {
                $data = $decoded['data'];
                if (is_array($data)) {
                    return $data;
                }
            }
            return $decoded;
        }

        return [];
    }

    private function normalizeRateLimit(array $rateLimit): ?array
    {
        $normalized = [];

        foreach (['limit', 'remaining', 'reset'] as $key) {
            if ($rateLimit[$key] !== null && ctype_digit((string) $rateLimit[$key])) {
                $normalized[$key] = (int) $rateLimit[$key];
            }
        }

        if ($rateLimit['retryAfter'] !== null && $rateLimit['retryAfter'] !== '') {
            $normalized['retryAfter'] = $rateLimit['retryAfter'];
        }

        return $normalized === [] ? null : $normalized;
    }

    /** @throws ApexMailException */
    private function throwApiError(int $statusCode, array $body, ?array $rateLimit = null): void
    {
        // The ApexMail error envelope is nested: {"error":{"code":"...","message":"..."}}
        $message = "HTTP {$statusCode}";
        $code    = null;
        if (isset($body['error']) && \is_array($body['error'])) {
            $message = $body['error']['message'] ?? "HTTP {$statusCode}";
            $code    = $body['error']['code']    ?? null;
        } elseif (isset($body['error'])) {
            $message = $body['error'];
        }
        $metadata = $rateLimit ?? [];

        $exception = match (true) {
            $statusCode === 401 => new Exceptions\AuthenticationException($message, $statusCode, $code, $metadata),
            $statusCode === 403 => new Exceptions\ForbiddenException($message, $statusCode, $code, $metadata),
            $statusCode === 409 => new Exceptions\ConflictException($message, $statusCode, $code, $metadata),
            $statusCode === 404 => new Exceptions\NotFoundException($message, $statusCode, $code, $metadata),
            $statusCode === 400 => new Exceptions\ValidationException($message, $statusCode, $code, $metadata),
            $statusCode === 429 => new Exceptions\RateLimitException($message, $statusCode, $code, $metadata),
            default             => new Exceptions\ApiException($message, $statusCode, $code, $metadata),
        };

        throw $exception;
    }

    /**
     * Returns a redacted string representation for safe logging.
     * Shows only the first 4 and last 4 characters of the API key.
     */
    public function __toString(): string
    {
        $key = $this->apiKey;
        $masked = strlen($key) > 8
            ? substr($key, 0, 4) . "\u2026\u2026" . substr($key, -4)
            : '[REDACTED]';
        return "ApexMail\Client{apiKey={$masked}, baseUrl={$this->baseUrl}}";
    }
}
