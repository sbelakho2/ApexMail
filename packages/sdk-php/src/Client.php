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
 *   echo $response['id'];
 *
 * @package ApexMail
 */

class Client
{
    public const SDK_VERSION     = '1.0.1';
    public const DEFAULT_URL     = 'https://api.apexmail.ee';
    public const DEFAULT_MAX_RESPONSE_BYTES = 20971520;
    /** Upper bound for retry delays; the server's Retry-After is honored in full up to this cap. */
    public const MAX_RETRY_AFTER_SECONDS = 120.0;
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
        if (!str_starts_with($this->baseUrl, 'https://')
            && !preg_match('#^http://(localhost|127\.0\.0\.1)(:\d+)?/?$#', $this->baseUrl)) {
            // HTTP is only permitted for loopback addresses (local testing);
            // production URLs must use HTTPS.
            throw new \InvalidArgumentException('baseUrl must use HTTPS');
        }
        // Numeric options are validated, not silently coerced: a 0/negative
        // timeout means "no timeout" in cURL (an infinite hang), a 0
        // maxResponseBytes makes the write callback reject the first chunk
        // of every response, and negative retries silently mean "no
        // retries". Fail fast with a clear message instead.
        $timeout = $options['timeout'] ?? 30;
        if (!is_numeric($timeout) || (int) $timeout < 1) {
            throw new \InvalidArgumentException('timeout must be an integer of at least 1 second');
        }
        $this->timeout = (int) $timeout;

        $maxRetries = $options['maxRetries'] ?? 3;
        if (!is_numeric($maxRetries) || (int) $maxRetries < 0) {
            throw new \InvalidArgumentException('maxRetries must be an integer of at least 0');
        }
        $this->maxRetries = (int) $maxRetries;

        $maxResponseBytes = $options['maxResponseBytes'] ?? self::DEFAULT_MAX_RESPONSE_BYTES;
        if (!is_numeric($maxResponseBytes) || (int) $maxResponseBytes < 1) {
            throw new \InvalidArgumentException('maxResponseBytes must be an integer of at least 1');
        }
        $this->maxResponseBytes = (int) $maxResponseBytes;

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

        // Duplicate-side-effect protection (SDK-B, extended beyond send): a
        // POST that times out AFTER the server processed it retries blind —
        // creating a second webhook/template/API key. Every non-idempotent
        // request without a caller-supplied key gets one generated here,
        // BEFORE the retry loop, so all attempts of this call present the
        // same key and the server deduplicates.
        $methodUpper = strtoupper($method);
        if ($idempotencyKey === null && $body !== null && $methodUpper === 'POST') {
            $idempotencyKey = self::uuid4();
        }

        // SDK-G L4: serialize the body BEFORE opening the cURL handle so a
        // JsonException can never leak an open handle, and so each retry
        // attempt reuses the same pre-computed payload.
        $jsonBody = null;
        if ($body !== null) {
            try {
                $jsonBody = json_encode($body, JSON_THROW_ON_ERROR);
            } catch (\JsonException $e) {
                throw new Exceptions\ApexMailException(
                    'Failed to encode request body as JSON: ' . $e->getMessage(),
                    0,
                    'JSON_ENCODE_ERROR',
                    []
                );
            }
        }

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
                // Header injection: the caller-supplied key flows into a raw
                // cURL header. Strip control bytes (CR/LF/NUL) and cap the
                // length; printable-token validation happens where the key
                // is generated (uuid4) and any hostile input collapses to a
                // harmless value here rather than splitting the request.
                $safeKey = preg_replace('/[\x00-\x1F\x7F]/', '', $idempotencyKey) ?? '';
                $headers[] = 'X-Idempotency-Key: ' . substr($safeKey, 0, 128);
            }

            $responseBody = '';
            $responseTooLarge = false;
            $maxBytes = $this->maxResponseBytes;

            $ch = curl_init($url);
            try {
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

                if ($jsonBody !== null) {
                    curl_setopt($ch, CURLOPT_POSTFIELDS, $jsonBody);
                }

                curl_exec($ch);
                $statusCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $curlError  = curl_error($ch);
            } finally {
                // SDK-G L4: deterministically drop the last reference to the
                // handle so it is released even on write aborts (e.g.
                // response-too-large) or exceptions. curl_close() is a no-op
                // since PHP 8.0 (deprecated in 8.5), so unset() is the
                // correct release mechanism.
                unset($ch);
            }

            if ($responseTooLarge) {
                // Deterministic application failure: callers that treat
                // NetworkException as "transport error, safe to retry" must
                // not re-attempt (and for non-idempotent POSTs, duplicate)
                // a request that will fail identically on every retry.
                throw new Exceptions\ApiException(
                    'Response body exceeds maxResponseBytes',
                    $statusCode > 0 ? $statusCode : 0,
                    'RESPONSE_TOO_LARGE',
                    []
                );
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

            try {
                $decoded = $responseBody !== ''
                    ? $this->decodeResponseBody($responseBody)
                    : [];
            } catch (\JsonException $e) {
                // Non-JSON body (e.g. an HTML 502 page from a proxy): raise a
                // proper SDK exception instead of leaking a JsonException.
                throw new Exceptions\ApiException(
                    'Invalid JSON response from API (HTTP ' . $statusCode . '): ' . $e->getMessage(),
                    $statusCode,
                    'PARSE_ERROR',
                    $this->lastRateLimit ?? []
                );
            }

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
     * Sleep for max(retryAfter, baseDelay * attempt²) seconds.
     *
     * Honors the server's Retry-After header (integer seconds or HTTP-date)
     * in full, capped at a sane maximum of 120s (SDK-F: was silently capped
     * at 5s, truncating long rate-limit windows).
     */
    private function sleepRetryAfter(?string $retryAfter, int $attempt): void
    {
        $delay = self::computeRetryDelay($retryAfter, $attempt + 1);
        self::sleepWithJitter($delay);
    }

    private function sleepBackoff(int $attempt): void
    {
        self::sleepWithJitter(self::computeRetryDelay(null, $attempt + 1));
    }

    /**
     * Sleep delay seconds with up to ±20% jitter: without jitter every
     * client that received the same 429 retries in lockstep (thundering
     * herd). Jitter is applied symmetrically so the honored Retry-After
     * window is never shortened by more than 20%.
     */
    private static function sleepWithJitter(float $delay): void
    {
        $jitter = $delay * 0.2;
        $actual = $delay + (random_int(-1, 1) * $jitter * (random_int(0, 100) / 100));
        usleep((int) (max(0.0, $actual) * 1_000_000));
    }

    /**
     * Pure delay computation (unit-testable, no sleeping):
     * delay = min(max(quadraticBackoff, retryAfterSeconds), 120.0).
     *
     * $attempt is the retry NUMBER about to run (1 = first retry): the
     * pre-fix code passed 0 for the first retry, producing a 0s delay — an
     * immediate hammer at a server that had just said "slow down" — and
     * burned a retry against the still-warm failure.
     */
    public static function computeRetryDelay(?string $retryAfter, int $attempt): float
    {
        $backoff = self::calculateBackoff(max(1, $attempt));

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
                $backoff = max($backoff, (float) $retryAfterSeconds);
            }
        }

        return min($backoff, self::MAX_RETRY_AFTER_SECONDS);
    }

    /**
     * Quadratic backoff: baseDelay * attempt², used when no Retry-After header.
     */
    private static function calculateBackoff(int $attempt): float
    {
        return 0.5 * ($attempt * $attempt);
    }

    /**
     * Generate a random UUID v4 (RFC 4122) without external dependencies.
     * Used for automatic idempotency keys on send endpoints (SDK-B).
     */
    public static function uuid4(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
        $hex = bin2hex($bytes);
        return sprintf(
            '%s-%s-%s-%s-%s',
            substr($hex, 0, 8),
            substr($hex, 8, 4),
            substr($hex, 12, 4),
            substr($hex, 16, 4),
            substr($hex, 20, 12)
        );
    }

    /**
     * Verify an ApexMail webhook signature.
     *
     * The platform delivers (see worker-processors/src/webhook/processor.rs):
     *   X-ApexMail-Signature: sha256=<hex hmac>
     *   X-ApexMail-Timestamp: <milliseconds since epoch>
     * and signs the message "{timestamp_millis}.{payload}" with HMAC-SHA256.
     *
     * Pass BOTH headers; the timestamp may be milliseconds (platform) or
     * seconds and is auto-detected. The legacy Stripe-style single header
     * "t=<seconds>,v1=<hex>" is still accepted for backwards compatibility,
     * as is an explicit $timestamp override (seconds or milliseconds).
     */
    public static function verifyWebhookSignature(
        string $payload,
        string|array|null $signatureHeader,
        string $secret,
        int $toleranceSeconds = 300,
        ?int $timestamp = null,
        ?string $timestampHeader = null,
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
        $signature = $parsed['signature'] ?? null;
        if ($signature === null || $signature === '') {
            return false;
        }

        // Timestamp resolution order: explicit argument, the platform's
        // X-ApexMail-Timestamp header, then the legacy t= header field.
        $timestampValue = $timestamp ?? $timestampHeader ?? ($parsed['timestamp'] ?? null);
        if ($timestampValue === null || !is_numeric($timestampValue)) {
            return false;
        }

        // Auto-detect seconds vs milliseconds: anything past 2001-09-09 in
        // integer terms cannot be seconds and anything before 2001 cannot be
        // milliseconds. 1e12 = 2001-09-09T01:46:40Z.
        $timestampString = (string) $timestampValue;
        $asInt = (int) $timestampValue;
        $isMilliseconds = strlen(preg_replace('/\D/', '', $timestampString) ?? '') > 11
            || $asInt > 1_000_000_000_000;
        $timestampSeconds = $isMilliseconds ? intdiv($asInt, 1000) : $asInt;

        if (abs(time() - $timestampSeconds) > $toleranceSeconds) {
            return false;
        }

        // The signature input uses the timestamp EXACTLY as delivered
        // (milliseconds on the platform path) — never a normalized form.
        $signedPayload = $timestampString . '.' . $payload;
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

    /** @var array|null Envelope metadata (has_more, next_cursor, ...) of the last list response. */
    private ?array $lastResponseMeta = null;

    /**
     * Pagination metadata of the last list response: the API envelope is
     * {"data": [...], "meta": {"has_more": bool, "next_cursor": "..."}} and
     * the SDK unwraps `data` for the resource methods. Without this
     * accessor, cursor pagination was unusable — the next cursor was
     * decoded and then silently discarded.
     */
    public function getLastResponseMeta(): ?array
    {
        return $this->lastResponseMeta;
    }

    /** Convenience: the next-page cursor of the last list response, if any. */
    public function getNextCursor(): ?string
    {
        $cursor = $this->lastResponseMeta['next_cursor'] ?? null;
        return \is_string($cursor) && $cursor !== '' ? $cursor : null;
    }

    private function decodeResponseBody(string $responseBody): array
    {
        $decoded = json_decode($responseBody, true, 512, JSON_THROW_ON_ERROR);

        if (is_array($decoded)) {
            // SDK-111: Unwrap API envelope {"data": ..., "meta": ...}.
            // Only unwrap when the envelope shape is unambiguous: a `data`
            // key holding an array, optionally alongside `error`/`meta`.
            // A lone `data` array (no envelope siblings) is also an array
            // payload — return it as-is so nested resources keep their shape.
            if (isset($decoded['data']) && is_array($decoded['data'])
                && (isset($decoded['meta']) || isset($decoded['error']) || array_keys($decoded) === ['data'])) {
                $this->lastResponseMeta = isset($decoded['meta']) && is_array($decoded['meta'])
                    ? $decoded['meta']
                    : null;
                return $decoded['data'];
            }
        }

        return is_array($decoded) ? $decoded : [];
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
