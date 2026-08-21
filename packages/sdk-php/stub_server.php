<?php
/**
 * Stub HTTP server router for the ApexMail PHP SDK functional tests.
 *
 * Started by test.php via the PHP built-in server:
 *   php -S 127.0.0.1:18099 stub_server.php
 *
 * Serves canned responses (including non-happy-path ones) and records the
 * X-Idempotency-Key header of every request into a JSONL file so tests can
 * assert retry/idempotency behavior end-to-end.
 *
 * @phpstan-ignore-next-line
 */

$recordFile = sys_get_temp_dir() . '/apexmail_php_sdk_stub_headers.jsonl';
$counterFile = sys_get_temp_dir() . '/apexmail_php_sdk_stub_counter';

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$method = $_SERVER['REQUEST_METHOD'];

// Record the request for test assertions.
file_put_contents(
    $recordFile,
    json_encode([
        'path'        => $path,
        'method'      => $method,
        'idempotency' => $_SERVER['HTTP_X_IDEMPOTENCY_KEY'] ?? null,
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
            // {id, status, created_at}
            respond(200, '{"data":{"id":"msg_live_1","status":"queued","created_at":"2026-08-21T12:00:00Z"}}',
                ['Content-Type' => 'application/json']);
        }
        respond(200, '{"data":[],"meta":{"total":0}}', ['Content-Type' => 'application/json']);

    case '/v1/messages/batch':
        // Real API batch shape: {accepted, rejected, results: [{index, id?, status, error?}]}
        respond(200, '{"data":{"accepted":2,"rejected":1,"results":['
            . '{"index":0,"id":"msg_b1","status":"queued"},'
            . '{"index":1,"status":"rejected","error":"invalid recipient"}'
            . ']}}', ['Content-Type' => 'application/json']);

    case '/html502':
        respond(502, '<html><head><title>502 Bad Gateway</title></head><body>nginx</body></html>',
            ['Content-Type' => 'text/html']);

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
        respond(200, '{"data":{"id":"msg_after_retry","status":"queued","created_at":"2026-08-21T12:00:01Z"}}',
            ['Content-Type' => 'application/json']);

    default:
        respond(404, '{"error":{"code":"NOT_FOUND","message":"unknown stub path"}}',
            ['Content-Type' => 'application/json']);
}
