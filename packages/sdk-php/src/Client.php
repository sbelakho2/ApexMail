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

// ── Autoload sub-classes ──
require_once __DIR__ . '/Exceptions.php';
require_once __DIR__ . '/Resources/Emails.php';
require_once __DIR__ . '/Resources/Domains.php';
require_once __DIR__ . '/Resources/Webhooks.php';
require_once __DIR__ . '/Resources/Templates.php';
require_once __DIR__ . '/Resources/Suppressions.php';
require_once __DIR__ . '/Resources/Events.php';

class Client
{
    public const SDK_VERSION     = '1.0.0';
    public const DEFAULT_URL     = 'https://api.apexmail.ee';

    private string $apiKey;
    private string $baseUrl;
    private int    $timeout;

    public Resources\Emails      $emails;
    public Resources\Domains     $domains;
    public Resources\Webhooks    $webhooks;
    public Resources\Templates   $templates;
    public Resources\Suppressions $suppressions;
    public Resources\Events      $events;

    /**
     * @param string $apiKey  API key (starts with am_live_ or am_test_)
     * @param array  $options Optional: ['baseUrl' => '...', 'timeout' => 30]
     */
    public function __construct(string $apiKey, array $options = [])
    {
        $this->apiKey  = $apiKey;
        $this->baseUrl = rtrim($options['baseUrl'] ?? self::DEFAULT_URL, '/');
        $this->timeout = (int) ($options['timeout'] ?? 30);

        $this->emails       = new Resources\Emails($this);
        $this->domains      = new Resources\Domains($this);
        $this->webhooks     = new Resources\Webhooks($this);
        $this->templates    = new Resources\Templates($this);
        $this->suppressions = new Resources\Suppressions($this);
        $this->events       = new Resources\Events($this);
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

        $headers = [
            'Authorization: Bearer ' . $this->apiKey,
            'Content-Type: application/json',
            'Accept: application/json',
            'User-Agent: apexmail-php/' . self::SDK_VERSION,
        ];
        if ($idempotencyKey !== null) {
            $headers[] = 'X-Idempotency-Key: ' . $idempotencyKey;
        }

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST  => strtoupper($method),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_TIMEOUT        => $this->timeout,
            CURLOPT_FOLLOWLOCATION => true,
        ]);

        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body, JSON_THROW_ON_ERROR));
        }

        $response   = curl_exec($ch);
        $statusCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError  = curl_error($ch);
        curl_close($ch);

        if ($curlError) {
            throw new Exceptions\NetworkException('cURL error: ' . $curlError);
        }

        $decoded = $response ? (array) json_decode((string) $response, true, 512, JSON_THROW_ON_ERROR) : [];

        if ($statusCode >= 400) {
            $this->throwApiError($statusCode, $decoded);
        }

        return $decoded;
    }

    // ── Private ─────────────────────────────────────────────────────────────

    /** @throws ApexMailException */
    private function throwApiError(int $statusCode, array $body): void
    {
        $message = $body['error'] ?? "HTTP {$statusCode}";
        $code    = $body['code']  ?? null;

        $exception = match (true) {
            $statusCode === 401 => new Exceptions\AuthenticationException($message, $statusCode, $code),
            $statusCode === 404 => new Exceptions\NotFoundException($message, $statusCode, $code),
            $statusCode === 422 => new Exceptions\ValidationException($message, $statusCode, $code),
            $statusCode === 429 => new Exceptions\RateLimitException($message, $statusCode, $code),
            default             => new Exceptions\ApiException($message, $statusCode, $code),
        };

        throw $exception;
    }
}
