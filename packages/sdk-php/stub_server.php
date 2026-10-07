<?php
/**
 * Stub HTTP server router for the ApexMail PHP SDK functional tests.
 *
 * Started by test.php via the PHP built-in server:
 *   php -S 127.0.0.1:18099 stub_server.php
 *
 * Serves canned responses (including non-happy-path ones) and records the
 * Idempotency-Key header of every request into a JSONL file so tests can
 * assert retry/idempotency behavior end-to-end.
 *
 * @phpstan-ignore-next-line
 */

$recordFile = sys_get_temp_dir() . '/apexmail_php_sdk_stub_headers.jsonl';
$counterFile = sys_get_temp_dir() . '/apexmail_php_sdk_stub_counter';

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$method = $_SERVER['REQUEST_METHOD'];

// Record the request for test assertions. The server contract reads
// `Idempotency-Key` (not X-Idempotency-Key) — keep recording both so a
// regression is visible.
file_put_contents(
    $recordFile,
    json_encode([
        'path'        => $path,
        'method'      => $method,
        'idempotency' => $_SERVER['HTTP_IDEMPOTENCY_KEY'] ?? null,
        'legacy_idempotency' => $_SERVER['HTTP_X_IDEMPOTENCY_KEY'] ?? null,
    ]) . "\n",
    FILE_APPEND
);

function respond(int $status, string $body, array $headers = []): void
{
    http_response_code($status);
    foreach ($headers as $name => $value) {
        header("$name: $value");
    }
    header('Content-Length: ' . strlen($body));
    echo $body;
    exit;
}

switch ($path) {
    case '/v1/messages':
        if ($method === 'POST') {
            // Real API single-send shape (after envelope unwrap):
            // {id, status, created_at}. The LIVE envelope always carries
            // "error": null — omitting it here hid the PHP-1 unwrap defect.
            respond(200, '{"data":{"id":"msg_live_1","status":"queued","created_at":"2026-08-21T12:00:00Z"},"error":null}',
                ['Content-Type' => 'application/json']);
        }
        respond(200, '{"data":[],"error":null,"meta":{"total":0}}', ['Content-Type' => 'application/json']);

    case '/v1/messages/batch':
        // Real API batch shape: {accepted, rejected, results: [{index, id?, status, error?}]}
        respond(200, '{"data":{"accepted":2,"rejected":1,"results":['
            . '{"index":0,"id":"msg_b1","status":"queued"},'
            . '{"index":1,"status":"rejected","error":"invalid recipient"}'
            . ']},"error":null}', ['Content-Type' => 'application/json']);

    case '/html502':
        respond(502, '<html><head><title>502 Bad Gateway</title></head><body>nginx</body></html>',
            ['Content-Type' => 'text/html']);

    case '/422':
        // Real API validation/deserialization shape (docs/api/errors.md).
        respond(422, '{"error":{"code":"VALIDATION_ERROR","message":"missing field `html_body`"}}',
            ['Content-Type' => 'application/json']);

    case '/paginated':
        // Real pagination envelope (routes/pagination.rs pagination_meta):
        // camelCase hasMore/nextCursor inside meta.
        respond(200, '{"data":[{"id":"msg_p1","status":"queued","created_at":"2026-08-21T12:00:00Z"}],'
            . '"error":null,"meta":{"hasMore":true,"nextCursor":"cur_abc123"}}',
            ['Content-Type' => 'application/json']);

    case '/json302':
        // A redirect carrying a JSON body (proxy/CDN shape) must NOT be
        // returned as a successful payload.
        respond(302, '{"data":{"id":"redirected"}}',
            ['Content-Type' => 'application/json', 'Location' => '/elsewhere']);

    case '/nonjson200':
        respond(200, '<html>not json</html>', ['Content-Type' => 'text/html']);

    case '/retryafter':
        respond(429, '{"error":{"code":"RATE_LIMIT_EXCEEDED","message":"Slow down"}}',
            ['Content-Type' => 'application/json', 'Retry-After' => '60']);

    case '/huge':
        respond(200, str_repeat('x', 64 * 1024), ['Content-Type' => 'application/json']);

    case '/flaky500':
        $count = (int) (@file_get_contents($counterFile) ?: '0');
        file_put_contents($counterFile, (string) ($count + 1));
        if ($count === 0) {
            respond(500, '{"error":{"code":"INTERNAL","message":"transient boom"}}',
                ['Content-Type' => 'application/json']);
        }
        respond(200, '{"data":{"id":"msg_after_retry","status":"queued","created_at":"2026-08-21T12:00:01Z"},"error":null}',
            ['Content-Type' => 'application/json']);

    case '/v1/messages/msg_live_1/cancel':
        // Real cancellation payload (enveloped, flat data).
        respond(200, '{"data":{"id":"msg_live_1","status":"cancelled","created_at":"2026-08-21T12:00:00Z"},"error":null}',
            ['Content-Type' => 'application/json']);

    case '/v1/webhooks/wh_live_1/rotate-secret':
        // Real rotate response: the new secret is returned once.
        respond(200, '{"data":{"id":"wh_live_1","url":"https://example.com/hook","events":["message.delivered"],'
            . '"secret":"whsec_rotated","status":"active","created_at":"2026-08-21T12:00:00Z",'
            . '"updated_at":"2026-08-21T12:00:05Z"},"error":null}',
            ['Content-Type' => 'application/json']);

    case '/v1/analytics/dashboard':
        respond(200, '{"data":{"total_sent":3,"total_delivered":2},"error":null}',
            ['Content-Type' => 'application/json']);

    default:
        respond(404, '{"error":{"code":"NOT_FOUND","message":"unknown stub path"}}',
            ['Content-Type' => 'application/json']);
}
