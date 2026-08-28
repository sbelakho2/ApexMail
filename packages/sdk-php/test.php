<?php
/**
 * Functional simulation tests for the ApexMail PHP SDK.
 * Uses a mock subclass to intercept HTTP calls without a live server.
 *
 * Run: php test.php
 */

declare(strict_types=1);

require_once __DIR__ . '/src/Client.php';

// Load the resource classes (PSR-4 ApexMail\ → src/) via the Composer
// autoloader when available, otherwise require them explicitly.
if (is_file(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
} else {
    foreach (glob(__DIR__ . '/src/Resources/*.php') ?: [] as $resourceFile) {
        require_once $resourceFile;
    }
}

// ── Test harness ──────────────────────────────────────────────────────────

$passed = 0;
$failed = 0;

function assert_pass(string $name): void {
    global $passed;
    $passed++;
    echo "\033[32m  PASS\033[0m  $name\n";
}

function assert_fail(string $name, string $reason): void {
    global $failed;
    $failed++;
    echo "\033[31m  FAIL\033[0m  $name: $reason\n";
}

function expect(string $name, bool $condition, string $failMsg = ''): void {
    $condition ? assert_pass($name) : assert_fail($name, $failMsg ?: 'assertion failed');
}

// ── Mock client ───────────────────────────────────────────────────────────

class MockClient extends \ApexMail\Client
{
    /** @var array Recorded calls: [method, path, body, idempotencyKey][] */
    public array $calls = [];

    /** Preset response queue: each element returned for next call */
    private array $responses = [];

    /** Preset errors: each element thrown for next call */
    private array $errors = [];

    public function __construct(string $apiKey = 'am_test_mockclient000000')
    {
        parent::__construct($apiKey, ['baseUrl' => 'https://mock.local']);
    }

    /** Queue a successful response for the next request */
    public function queueResponse(array $response): void
    {
        $this->responses[] = $response;
    }

    /** Queue an exception to be thrown on the next request */
    public function queueException(\ApexMail\Exceptions\ApexMailException $e): void
    {
        $this->errors[] = $e;
    }

    public function request(
        string  $method,
        string  $path,
        ?array  $body = null,
        ?string $idempotencyKey = null,
    ): array {
        $this->calls[] = compact('method', 'path', 'body', 'idempotencyKey');

        if (!empty($this->errors)) {
            throw array_shift($this->errors);
        }
        if (!empty($this->responses)) {
            return array_shift($this->responses);
        }
        return [];
    }
}

// ── Email resource tests ──────────────────────────────────────────────────

echo "\nEmails\n";

// send()
$client = new MockClient();
$client->queueResponse([
    'id' => 'msg_123', 'status' => 'queued', 'created_at' => '2025-01-01T00:00:00Z',
]);
$resp = $client->emails->send([
    'from'    => 'a@example.com',
    'to'      => 'b@example.com',
    'subject' => 'Hello',
    'html'    => '<p>hi</p>',
]);
expect('send() calls POST /v1/messages', $client->calls[0]['method'] === 'POST' && $client->calls[0]['path'] === '/v1/messages');
expect('send() returns flat id (real API shape)', $resp['id'] === 'msg_123');
expect('send() returns status', $resp['status'] === 'queued');

// send() with idempotency key
$client = new MockClient();
$client->queueResponse(['id' => 'msg_456', 'status' => 'queued', 'created_at' => '2025-01-01T00:00:00Z']);
$client->emails->send([
    'from' => 'a@b.c', 'to' => 'x@y.z', 'subject' => 'Hi', 'text' => 'Hi',
    'idempotency_key' => 'key-001',
]);
expect('send() forwards idempotencyKey', $client->calls[0]['idempotencyKey'] === 'key-001');

// SDK-B: automatic idempotency keys (caller key wins; unique per logical send)
$client = new MockClient();
$client->queueResponse(['id' => 'm1', 'status' => 'queued']);
$client->queueResponse(['id' => 'm2', 'status' => 'queued']);
$client->emails->send(['from' => 'a@b.c', 'to' => 'x@y.z', 'subject' => 'Hi', 'text' => 'Hi']);
$client->emails->send(['from' => 'a@b.c', 'to' => 'x@y.z', 'subject' => 'Hi again', 'text' => 'Hi']);
expect('send() auto-generates idempotencyKey', !empty($client->calls[0]['idempotencyKey']));
expect('send() generates different keys per logical send', $client->calls[0]['idempotencyKey'] !== $client->calls[1]['idempotencyKey']);

// SDK-B: batch auto-generates an idempotency key
$client = new MockClient();
$client->queueResponse(['accepted' => 1, 'rejected' => 0, 'results' => []]);
$client->emails->batch([
    ['from' => 'a@b.c', 'to' => 'x@y.z', 'subject' => 'msg 1', 'text' => 'x'],
]);
expect('batch() auto-generates idempotencyKey', !empty($client->calls[0]['idempotencyKey']));
$client->emails->batch(
    [['from' => 'a@b.c', 'to' => 'x@y.z', 'subject' => 'msg 2', 'text' => 'x']],
    'batch-key-1'
);
expect('batch() forwards caller idempotencyKey', $client->calls[1]['idempotencyKey'] === 'batch-key-1');

// batch()
$client = new MockClient();
$client->queueResponse([
    'accepted' => 2,
    'rejected' => 1,
    'results' => [
        ['index' => 0, 'id' => 'm1', 'status' => 'queued'],
        ['index' => 1, 'status' => 'rejected', 'error' => 'invalid recipient'],
    ],
]);
$resp = $client->emails->batch([
    ['from' => 'a@b.c', 'to' => 'x@y.z', 'subject' => 'msg 1', 'text' => 'x'],
    ['from' => 'a@b.c', 'to' => 'p@q.r', 'subject' => 'msg 2', 'text' => 'x'],
]);
expect('batch() calls POST /v1/messages/batch', $client->calls[0]['path'] === '/v1/messages/batch');
expect('batch() accepted count (real API shape)', $resp['accepted'] === 2);
expect('batch() rejected count', $resp['rejected'] === 1);
expect('batch() rejected items map error', $resp['results'][1]['error'] === 'invalid recipient');

// get()
$client = new MockClient();
$client->queueResponse(['id' => 'msg_789', 'status' => 'delivered', 'subject' => 'Hi']);
$resp = $client->emails->get('msg_789');
expect('get() calls GET /v1/messages/{id}',
    $client->calls[0]['method'] === 'GET' && $client->calls[0]['path'] === '/v1/messages/msg_789');
expect('get() returns flat message (real API shape)', $resp['id'] === 'msg_789');

// list()
$client = new MockClient();
$client->queueResponse(['messages' => [], 'pagination' => ['total' => 0, 'limit' => 20, 'offset' => 0]]);
$resp = $client->emails->list();
expect('list() calls GET /v1/messages', str_starts_with($client->calls[0]['path'], '/v1/messages'));
expect('list() returns pagination', isset($resp['pagination']));

// ── Domain resource tests ─────────────────────────────────────────────────

echo "\nDomains\n";

$client = new MockClient();
$client->queueResponse(['domain' => ['id' => 'dom_1', 'domain' => 'mail.example.com', 'status' => 'pending'], 'dnsRecords' => []]);
$resp = $client->domains->create('mail.example.com');
expect('domains.create() POST /v1/domains', $client->calls[0]['method'] === 'POST' && $client->calls[0]['path'] === '/v1/domains');
expect('domains.create() returns domain', $resp['domain']['domain'] === 'mail.example.com');

$client = new MockClient();
$client->queueResponse(['domains' => [], 'pagination' => ['total' => 0]]);
$client->domains->list();
expect('domains.list() GET /v1/domains', $client->calls[0]['method'] === 'GET' && $client->calls[0]['path'] === '/v1/domains');

$client = new MockClient();
$client->queueResponse(['domain' => ['id' => 'dom_1', 'domain' => 'mail.example.com']]);
$client->domains->get('dom_1');
expect('domains.get() GET /v1/domains/{id}', $client->calls[0]['path'] === '/v1/domains/dom_1');

$client = new MockClient();
$client->queueResponse(['verified' => false, 'message' => 'DNS not propagated']);
$resp = $client->domains->verify('dom_1');
expect('domains.verify() POST /v1/domains/{id}/verify', 
    $client->calls[0]['path'] === '/v1/domains/dom_1/verify' && $client->calls[0]['method'] === 'POST');
expect('domains.verify() returns verified field', array_key_exists('verified', $resp));

$client = new MockClient();
$client->queueResponse([]);
$client->domains->delete('dom_1');
expect('domains.delete() DELETE /v1/domains/{id}', 
    $client->calls[0]['method'] === 'DELETE' && $client->calls[0]['path'] === '/v1/domains/dom_1');

$client = new MockClient();
$client->queueResponse(['healthy' => true, 'spf' => 'pass', 'dkim' => 'pass', 'dmarc' => 'pass']);
$resp = $client->domains->health('dom_1');
expect('domains.health() GET /v1/domains/{id}/health',
    $client->calls[0]['method'] === 'GET' && $client->calls[0]['path'] === '/v1/domains/dom_1/health');
expect('domains.health() returns healthy field', array_key_exists('healthy', $resp));

// ── Webhook resource tests ────────────────────────────────────────────────

echo "\nWebhooks\n";

$client = new MockClient();
$client->queueResponse(['webhook' => ['id' => 'wh_1', 'url' => 'https://ex.com/hook', 'events' => ['message.delivered']]]);
$resp = $client->webhooks->create(['url' => 'https://ex.com/hook', 'events' => ['message.delivered']]);
expect('webhooks.create() POST /v1/webhooks', 
    $client->calls[0]['method'] === 'POST' && $client->calls[0]['path'] === '/v1/webhooks');
expect('webhooks.create() returns webhook id', $resp['webhook']['id'] === 'wh_1');

$client = new MockClient();
$client->queueResponse(['webhooks' => [['id' => 'wh_1'], ['id' => 'wh_2']]]);
$resp = $client->webhooks->list();
expect('webhooks.list() GET /v1/webhooks',
    $client->calls[0]['method'] === 'GET' && $client->calls[0]['path'] === '/v1/webhooks');
expect('webhooks.list() returns webhooks', count($resp['webhooks']) === 2);

$client = new MockClient();
$client->queueResponse(['webhook' => ['id' => 'wh_1', 'url' => 'https://ex.com/hook']]);
$resp = $client->webhooks->get('wh_1');
expect('webhooks.get() GET /v1/webhooks/{id}',
    $client->calls[0]['method'] === 'GET' && $client->calls[0]['path'] === '/v1/webhooks/wh_1');
expect('webhooks.get() returns webhook', $resp['webhook']['id'] === 'wh_1');

$client = new MockClient();
$client->queueResponse(['webhook' => ['id' => 'wh_1', 'url' => 'https://new.com/hook', 'events' => ['message.bounced']]]);
$resp = $client->webhooks->update('wh_1', ['url' => 'https://new.com/hook', 'events' => ['message.bounced']]);
expect('webhooks.update() PUT /v1/webhooks/{id}',
    $client->calls[0]['method'] === 'PUT' && $client->calls[0]['path'] === '/v1/webhooks/wh_1');
expect('webhooks.update() body has url', $client->calls[0]['body']['url'] === 'https://new.com/hook');
expect('webhooks.update() body has events', $client->calls[0]['body']['events'] === ['message.bounced']);

$client = new MockClient();
$client->queueResponse([]);
$client->webhooks->delete('wh_1');
expect('webhooks.delete() DELETE /v1/webhooks/{id}',
    $client->calls[0]['method'] === 'DELETE' && $client->calls[0]['path'] === '/v1/webhooks/wh_1');

echo "\nRate limiting\n";

$rateLimitException = new \ApexMail\Exceptions\RateLimitException(
    'Too many requests',
    429,
    'rate_limit',
    ['limit' => 100, 'remaining' => 0, 'reset' => 1_900_000_000, 'retryAfter' => '60']
);
expect('RateLimitException exposes limit', $rateLimitException->getLimit() === 100);
expect('RateLimitException exposes remaining', $rateLimitException->getRemaining() === 0);
expect('RateLimitException exposes reset', $rateLimitException->getReset() === 1_900_000_000);
expect('RateLimitException exposes retryAfter', $rateLimitException->getRetryAfter() === '60');

// ── Template resource tests ───────────────────────────────────────────────

echo "\nTemplates\n";

$client = new MockClient();
$client->queueResponse(['template' => ['id' => 'tpl_1', 'name' => 'Welcome', 'slug' => 'welcome']]);
$resp = $client->templates->create(['name' => 'Welcome', 'subject' => 'Hi', 'html' => '<p>Hello {{name}}</p>']);
expect('templates.create() POST /v1/templates', 
    $client->calls[0]['method'] === 'POST' && $client->calls[0]['path'] === '/v1/templates');
expect('templates.create() returns template', $resp['template']['id'] === 'tpl_1');

$client = new MockClient();
$client->queueResponse(['template' => ['id' => 'tpl_1', 'name' => 'Welcome']]);
$client->templates->get('tpl_1');
expect('templates.get() GET /v1/templates/{id}', $client->calls[0]['path'] === '/v1/templates/tpl_1');

$client = new MockClient();
$client->queueResponse(['template' => ['id' => 'tpl_1', 'slug' => 'welcome']]);
$resp = $client->templates->getBySlug('welcome');
expect('templates.getBySlug() GET /v1/templates/slug/{slug}',
    $client->calls[0]['method'] === 'GET' && $client->calls[0]['path'] === '/v1/templates/slug/welcome');
expect('templates.getBySlug() returns template', $resp['template']['slug'] === 'welcome');

$client = new MockClient();
$client->queueResponse(['templates' => [['id' => 'tpl_1'], ['id' => 'tpl_2']], 'pagination' => ['total' => 2]]);
$resp = $client->templates->list(['limit' => 10]);
expect('templates.list() GET /v1/templates?...',
    $client->calls[0]['method'] === 'GET' && str_starts_with($client->calls[0]['path'], '/v1/templates'));
expect('templates.list() has limit param', str_contains($client->calls[0]['path'], 'limit=10'));
expect('templates.list() returns templates', count($resp['templates']) === 2);

$client = new MockClient();
$client->queueResponse(['template' => ['id' => 'tpl_1', 'name' => 'Updated']]);
$resp = $client->templates->update('tpl_1', ['name' => 'Updated', 'html' => '<p>new</p>']);
expect('templates.update() PUT /v1/templates/{id}',
    $client->calls[0]['method'] === 'PUT' && $client->calls[0]['path'] === '/v1/templates/tpl_1');
expect('templates.update() body has name', $client->calls[0]['body']['name'] === 'Updated');

$client = new MockClient();
$client->queueResponse([]);
$client->templates->delete('tpl_1');
expect('templates.delete() DELETE /v1/templates/{id}',
    $client->calls[0]['method'] === 'DELETE' && $client->calls[0]['path'] === '/v1/templates/tpl_1');

$client = new MockClient();
$client->queueResponse(['html' => '<p>Hello Alice</p>', 'text' => 'Hello Alice']);
$resp = $client->templates->render('tpl_1', ['name' => 'Alice']);
expect('templates.render() POST /v1/templates/{id}/render',
    $client->calls[0]['method'] === 'POST' && $client->calls[0]['path'] === '/v1/templates/tpl_1/render');
expect('templates.render() body has variables', $client->calls[0]['body']['variables']['name'] === 'Alice');
expect('templates.render() returns html', $resp['html'] === '<p>Hello Alice</p>');

// ── Suppression resource tests ────────────────────────────────────────────

echo "\nSuppressions\n";

$client = new MockClient();
$client->queueResponse([]);
$client->suppressions->add('bad@example.com', 'bounce');
expect('suppressions.add() POST /v1/suppressions', 
    $client->calls[0]['method'] === 'POST' && $client->calls[0]['path'] === '/v1/suppressions');
expect('suppressions.add() sets email in body', $client->calls[0]['body']['emails'][0] === 'bad@example.com');
expect('suppressions.add() sets reason in body', $client->calls[0]['body']['reason'] === 'bounce');

$client = new MockClient();
$client->queueResponse([]);
$client->suppressions->add(['a@b.com', 'c@d.com'], 'manual');
expect('suppressions.add() bulk sends array', count($client->calls[0]['body']['emails']) === 2);

$client = new MockClient();
$client->queueResponse(['suppressions' => [['email' => 'bad@example.com']], 'pagination' => ['total' => 1]]);
$resp = $client->suppressions->list(['reason' => 'bounce', 'limit' => 10]);
expect('suppressions.list() GET /v1/suppressions?...',
    $client->calls[0]['method'] === 'GET' && str_starts_with($client->calls[0]['path'], '/v1/suppressions'));
expect('suppressions.list() has reason param', str_contains($client->calls[0]['path'], 'reason=bounce'));

$client = new MockClient();
$client->queueResponse(['suppressed' => true, 'reason' => 'bounce']);
$resp = $client->suppressions->check('bad@example.com');
expect('suppressions.check() GET /v1/suppressions/check/{email}',
    $client->calls[0]['method'] === 'GET' && $client->calls[0]['path'] === '/v1/suppressions/check/bad%40example.com');
expect('suppressions.check() returns suppressed', $resp['suppressed'] === true);

$client = new MockClient();
$client->queueResponse([]);
$client->suppressions->delete('bad@example.com');
expect('suppressions.delete() DELETE /v1/suppressions/{email}',
    $client->calls[0]['method'] === 'DELETE' && str_contains($client->calls[0]['path'], 'bad'));

// ── Events resource tests ─────────────────────────────────────────────────

echo "\nEvents\n";

$client = new MockClient();
$client->queueResponse(['events' => [], 'pagination' => ['total' => 0]]);
$client->events->list(['messageId' => 'msg_123']);
expect('events.list() GET /v1/events', str_starts_with($client->calls[0]['path'], '/v1/events'));
expect('events.list() includes messageId', str_contains($client->calls[0]['path'], 'messageId=msg_123'));

$client = new MockClient();
$client->queueResponse(['events' => [['type' => 'message.delivered']]]);
$resp = $client->events->getByMessage('msg_123');
expect('events.getByMessage() GET /v1/events?messageId=msg_123',
    $client->calls[0]['method'] === 'GET' && str_contains($client->calls[0]['path'], 'messageId=msg_123'));
expect('events.getByMessage() has limit=100', str_contains($client->calls[0]['path'], 'limit=100'));
expect('events.getByMessage() returns events', count($resp['events']) === 1);

$client = new MockClient();
$client->queueResponse(['event' => ['id' => 'evt_42', 'type' => 'message.opened']]);
$resp = $client->events->get('evt_42');
expect('events.get() GET /v1/events/{id}',
    $client->calls[0]['method'] === 'GET' && $client->calls[0]['path'] === '/v1/events/evt_42');
expect('events.get() returns event', $resp['event']['id'] === 'evt_42');

// ── Exception mapping tests ───────────────────────────────────────────────

echo "\nError handling\n";

$client = new MockClient();
$client->queueException(new \ApexMail\Exceptions\AuthenticationException('Invalid API key', 401));
try {
    $client->emails->send(['from' => 'a@b.c', 'to' => 'x@y.z', 'subject' => 'Hi', 'text' => 'Hi']);
    assert_fail('401 throws AuthenticationException', 'no exception thrown');
} catch (\ApexMail\Exceptions\AuthenticationException $e) {
    expect('401 throws AuthenticationException', true);
    expect('exception has correct message', str_contains($e->getMessage(), 'Invalid API key'));
}

$client = new MockClient();
$client->queueException(new \ApexMail\Exceptions\NotFoundException('Not found', 404));
try {
    $client->emails->get('nonexistent');
    assert_fail('404 throws NotFoundException', 'no exception thrown');
} catch (\ApexMail\Exceptions\NotFoundException $e) {
    expect('404 throws NotFoundException', true);
}

$client = new MockClient();
$client->queueException(new \ApexMail\Exceptions\RateLimitException('Rate limit exceeded', 429));
try {
    $client->emails->send(['from' => 'a@b.c', 'to' => 'x@y.z', 'subject' => 'Hi', 'text' => 'Hi']);
    assert_fail('429 throws RateLimitException', 'no exception thrown');
} catch (\ApexMail\Exceptions\RateLimitException $e) {
    expect('429 throws RateLimitException', true);
}

$client = new MockClient();
$client->queueException(new \ApexMail\Exceptions\ValidationException('Invalid params', 422));
try {
    $client->emails->send(['from' => 'a@b.c', 'to' => 'x@y.z', 'subject' => 'Hi', 'text' => 'Hi']);
    assert_fail('422 throws ValidationException', 'no exception thrown');
} catch (\ApexMail\Exceptions\ValidationException $e) {
    expect('422 throws ValidationException', true);
    expect('ValidationException has status code', $e->getStatusCode() === 422);
}

$client = new MockClient();
$client->queueException(new \ApexMail\Exceptions\NetworkException('Connection timed out', 0));
try {
    $client->emails->send(['from' => 'a@b.c', 'to' => 'x@y.z', 'subject' => 'Hi', 'text' => 'Hi']);
    assert_fail('NetworkException on transport failure', 'no exception thrown');
} catch (\ApexMail\Exceptions\NetworkException $e) {
    expect('NetworkException raised on transport failure', true);
    expect('NetworkException message', str_contains($e->getMessage(), 'timed out'));
}

// ── Retry delay computation (SDK-F) ───────────────────────────────────────

echo "\nRetry delay computation\n";

expect('Retry-After 60 → 60s delay (not capped at 5)', \ApexMail\Client::computeRetryDelay('60', 1) === 60.0);
expect('Retry-After 300 → capped at 120s', \ApexMail\Client::computeRetryDelay('300', 1) === 120.0);
// The argument is the retry NUMBER about to run: the first retry delays
// 0.5s (the pre-fix 0s fired immediately at a server that said slow down).
expect('no Retry-After, first retry → 0.5s backoff', \ApexMail\Client::computeRetryDelay(null, 1) === 0.5);
expect('no Retry-After, third retry → 4.5s backoff', \ApexMail\Client::computeRetryDelay(null, 3) === 4.5);
expect('garbage Retry-After falls back to backoff', \ApexMail\Client::computeRetryDelay('not-a-date', 2) === 2.0);
expect('uuid4() shape', (bool) preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', \ApexMail\Client::uuid4()));
expect('uuid4() uniqueness', \ApexMail\Client::uuid4() !== \ApexMail\Client::uuid4());

// ── Live stub-server tests (non-happy-path + idempotency) ─────────────────

echo "\nStub server integration\n";

$stubPort = 18123;
$recordFile = sys_get_temp_dir() . '/apexmail_php_sdk_stub_headers.jsonl';
$counterFile = sys_get_temp_dir() . '/apexmail_php_sdk_stub_counter';
@unlink($recordFile);
@unlink($counterFile);

$proc = proc_open(
    [PHP_BINARY, '-S', "127.0.0.1:{$stubPort}", __DIR__ . '/stub_server.php'],
    [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
    $pipes
);
$stubReady = false;
for ($i = 0; $i < 50; $i++) {
    $sock = @fsockopen('127.0.0.1', $stubPort, $errno, $errstr, 0.2);
    if ($sock) {
        fclose($sock);
        $stubReady = true;
        break;
    }
    usleep(50_000);
}

function stub_client(int $maxRetries, int $maxBytes = 20971520): \ApexMail\Client
{
    global $stubPort;
    return new \ApexMail\Client('am_test_stubserver000001', [
        'baseUrl' => "http://127.0.0.1:{$stubPort}",
        'maxRetries' => $maxRetries,
        'maxResponseBytes' => $maxBytes,
        'timeout' => 10,
    ]);
}

function recorded_stub_requests(): array
{
    global $recordFile;
    if (!is_file($recordFile)) {
        return [];
    }
    return array_filter(array_map(
        static fn (string $line) => json_decode($line, true),
        file($recordFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: []
    ));
}

if ($stubReady) {
    try {
        // Real API shapes through the full HTTP stack (envelope unwrapped).
        $client = stub_client(0);
        $resp = $client->emails->send([
            'from' => 'a@example.com', 'to' => 'b@example.com',
            'subject' => 'Hi', 'text' => 'Hello',
        ]);
        expect('live send returns flat {id,status,created_at}',
            $resp['id'] === 'msg_live_1' && $resp['status'] === 'queued' && isset($resp['created_at']));

        $resp = $client->emails->batch([
            ['from' => 'a@example.com', 'to' => 'b@example.com', 'subject' => 'Hi', 'text' => 'x'],
        ]);
        expect('live batch returns {accepted,rejected,results}', $resp['accepted'] === 2 && $resp['rejected'] === 1);
        expect('live batch rejected item has error, no id',
            $resp['results'][1]['error'] === 'invalid recipient' && !isset($resp['results'][1]['id']));

        // SDK-B: same idempotency key across retries of one send.
        @unlink($recordFile);
        $client = stub_client(2);
        $resp = $client->request('POST', '/flaky500', ['from' => 'a@example.com'], 'stub-fixed-key');
        expect('flaky send succeeds after retry', $resp['id'] === 'msg_after_retry');
        $messages = array_values(array_filter(recorded_stub_requests(), static fn ($r) => $r['path'] === '/flaky500'));
        expect('flaky send issued exactly 2 requests', count($messages) === 2);
        expect('same X-Idempotency-Key across both attempts',
            $messages[0]['idempotency'] === 'stub-fixed-key' && $messages[1]['idempotency'] === 'stub-fixed-key');

        // SDK-B: two logical sends get different auto keys.
        @unlink($recordFile);
        $client = stub_client(0);
        $client->request('POST', '/v1/messages', ['a' => 1], \ApexMail\Client::uuid4());
        $client->request('POST', '/v1/messages', ['a' => 2], \ApexMail\Client::uuid4());
        $messages = array_values(array_filter(recorded_stub_requests(), static fn ($r) => $r['path'] === '/v1/messages' && $r['method'] === 'POST'));
        expect('two sends carry different idempotency keys',
            count($messages) >= 2 && $messages[0]['idempotency'] !== $messages[1]['idempotency']);

        // Non-happy-path: 502 with an HTML body must throw, not return a hash.
        $client = stub_client(0);
        try {
            $client->request('GET', '/html502');
            assert_fail('502 HTML throws ApiException', 'no exception thrown');
        } catch (\ApexMail\Exceptions\ApiException $e) {
            expect('502 HTML throws ApiException', true);
            expect('502 HTML keeps status 502', $e->getStatusCode() === 502);
            expect('502 HTML apiCode is PARSE_ERROR', $e->getApiCode() === 'PARSE_ERROR');
        }

        // Non-happy-path: non-JSON 200 is an invalid response.
        $client = stub_client(0);
        try {
            $client->request('GET', '/nonjson200');
            assert_fail('non-JSON 200 throws ApiException', 'no exception thrown');
        } catch (\ApexMail\Exceptions\ApiException $e) {
            expect('non-JSON 200 throws ApiException', true);
            expect('non-JSON 200 apiCode is PARSE_ERROR', $e->getApiCode() === 'PARSE_ERROR');
        }

        // Non-happy-path: 429 with Retry-After surfaces the header.
        $client = stub_client(0);
        try {
            $client->request('GET', '/retryafter');
            assert_fail('429 throws RateLimitException', 'no exception thrown');
        } catch (\ApexMail\Exceptions\RateLimitException $e) {
            expect('429 throws RateLimitException', true);
            expect('429 exposes Retry-After header', $e->getRetryAfter() === '60');
        }

        // Non-happy-path: huge body rejected by the streaming cap. This is a
        // DETERMINISTIC failure (RESPONSE_TOO_LARGE ApiException), not a
        // transport error — callers must not treat it as retryable.
        $client = stub_client(0, 1024);
        try {
            $client->request('GET', '/huge');
            assert_fail('oversized body throws', 'no exception thrown');
        } catch (\ApexMail\Exceptions\ApiException $e) {
            expect('oversized body throws ApiException', str_contains($e->getMessage(), 'maxResponseBytes'));
            expect('oversized body carries RESPONSE_TOO_LARGE', $e->getApiCode() === 'RESPONSE_TOO_LARGE');
        }
    } finally {
        proc_terminate($proc);
        proc_close($proc);
    }
} else {
    assert_fail('stub server started', 'could not start php -S stub server');
    proc_terminate($proc);
}

// ── Summary ───────────────────────────────────────────────────────────────

echo "\n";
if ($failed === 0) {
    echo "\033[32mAll {$passed} tests passed.\033[0m\n\n";
    exit(0);
} else {
    echo "\033[31m{$failed} test(s) FAILED, {$passed} passed.\033[0m\n\n";
    exit(1);
}
