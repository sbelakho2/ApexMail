<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

use Symfony\Component\HttpFoundation\Request;

/**
 * Request factory for tests that POST to the challenge endpoint: the widget
 * always sends `Content-Type: application/json` (the narrow-HTTP
 * contract — anything else is 415). Symfony's Request::create() forces
 * `application/x-www-form-urlencoded` onto every POST, which would make
 * every fixture request look like a smuggling attempt.
 *
 * Identical to Request::create() except that a POST without an explicit
 * content type is declared application/json.
 */
final class JsonRequest
{
    /**
     * @param array<string, mixed> $parameters
     * @param array<string, mixed> $cookies
     * @param array<string, mixed> $files
     * @param array<string, mixed> $server
     */
    public static function create(
        string $uri,
        string $method = 'GET',
        array $parameters = [],
        array $cookies = [],
        array $files = [],
        array $server = [],
        ?string $content = null,
    ): Request {
        if ($method === 'POST' && !isset($server['CONTENT_TYPE']) && !isset($server['HTTP_CONTENT_TYPE'])) {
            $server['CONTENT_TYPE'] = 'application/json';
        }

        return Request::create($uri, $method, $parameters, $cookies, $files, $server, $content);
    }
}
