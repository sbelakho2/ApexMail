# Functional simulation tests for the ApexMail Ruby SDK
# Run: ruby test.rb

require_relative 'lib/apexmail'

# ── Harness ───────────────────────────────────────────────────────────────

$passed = 0
$failed = 0

def assert_pass(name)
  $passed += 1
  puts "\e[32m  PASS\e[0m  #{name}"
end

def assert_fail(name, reason = 'assertion failed')
  $failed += 1
  puts "\e[31m  FAIL\e[0m  #{name}: #{reason}"
end

def expect(name, condition, reason = 'condition was false')
  condition ? assert_pass(name) : assert_fail(name, reason)
end

# ── Mock transport ────────────────────────────────────────────────────────

class FakeTransport
  attr_reader :calls

  def initialize
    @calls     = []
    @responses = []
    @errors    = []
  end

  def queue_response(r)       = @responses << r
  def queue_error(e)          = @errors    << e

  def request(method, path, body: nil, idempotency_key: nil)
    @calls << { method: method, path: path, body: body, idempotency_key: idempotency_key }
    raise @errors.shift unless @errors.empty?
    @responses.shift || {}
  end
end

def mk_transport(response = nil)
  t = FakeTransport.new
  t.queue_response(response) if response
  t
end

# ── Email tests ───────────────────────────────────────────────────────────

puts "\nEmails"

t = FakeTransport.new
t.queue_response({ 'id' => 'msg_123', 'status' => 'queued', 'created_at' => '2026-01-01T00:00:00Z' })
api = ApexMail::EmailsAPI.new(t)
resp = api.send_email(from: 'a@b.com', to: 'x@y.com', subject: 'Hi', html: '<p>Hi</p>')
expect('send() POST /v1/messages',  t.calls[0][:method] == 'POST' && t.calls[0][:path] == '/v1/messages')
expect('send() returns flat id (real API shape)', resp['id'] == 'msg_123')
expect('send() returns status', resp['status'] == 'queued')
expect('send() body has from key',  t.calls[0][:body].key?(:from))
expect('send() body has subject',   t.calls[0][:body][:subject] == 'Hi')

t = FakeTransport.new
t.queue_response({ 'id' => 'msg_456' })
api = ApexMail::EmailsAPI.new(t)
api.send_email(from: 'a@b.com', to: 'x@y.com', subject: 'Hi', html: '<p>Hi</p>', idempotency_key: 'ik-001')
expect('send() forwards idempotency_key', t.calls[0][:idempotency_key] == 'ik-001')

# SDK-B: automatic idempotency key for send
t = FakeTransport.new
api = ApexMail::EmailsAPI.new(t)
api.send_email(from: 'a@b.com', to: 'x@y.com', subject: 'Hi', html: '<p>Hi</p>')
api.send_email(from: 'a@b.com', to: 'x@y.com', subject: 'Hi again', html: '<p>Hi</p>')
key1 = t.calls[0][:idempotency_key]
key2 = t.calls[1][:idempotency_key]
expect('send() auto-generates idempotency key', !key1.nil? && !key1.to_s.empty?)
expect('send() generates different keys per logical send', key1 != key2)

# SDK-B: automatic idempotency key for batch
t = FakeTransport.new
api = ApexMail::EmailsAPI.new(t)
api.batch(messages: [{ from: 'a@b.com', to: 'x@y.com', subject: 'msg1', text: 'msg1' }])
expect('batch() auto-generates idempotency key', !t.calls[0][:idempotency_key].to_s.empty?)
api.batch(messages: [{ from: 'a@b.com', to: 'x@y.com', subject: 'msg2', text: 'msg2' }], idempotency_key: 'batch-ik')
expect('batch() forwards caller idempotency key', t.calls[1][:idempotency_key] == 'batch-ik')

t = FakeTransport.new
t.queue_response({ 'accepted' => 2, 'rejected' => 0,
                   'results' => [{ 'index' => 0, 'id' => 'm1', 'status' => 'queued' },
                                 { 'index' => 1, 'id' => 'm2', 'status' => 'queued' }] })
api = ApexMail::EmailsAPI.new(t)
resp = api.batch(messages: [
  { from: 'a@b.com', to: 'x@y.com', subject: 'msg1', text: 'msg1' },
  { from: 'a@b.com', to: 'p@q.com', subject: 'msg2', text: 'msg2' },
])
expect('batch() POST /v1/messages/batch', t.calls[0][:path] == '/v1/messages/batch')
expect('batch() sends 2 items',           t.calls[0][:body][:messages].length == 2)
expect('batch() accepted count (real API shape)', resp['accepted'] == 2)
expect('batch() results map by index',    resp['results'][1]['id'] == 'm2')

t = FakeTransport.new
t.queue_response({ 'id' => 'msg_789', 'status' => 'delivered' })
api = ApexMail::EmailsAPI.new(t)
resp = api.get('msg_789')
expect('get() GET /v1/messages/msg_789', t.calls[0][:method] == 'GET' && t.calls[0][:path] == '/v1/messages/msg_789')

t = FakeTransport.new
t.queue_response({ 'messages' => [], 'pagination' => { 'total' => 0, 'limit' => 20 } })
api = ApexMail::EmailsAPI.new(t)
resp = api.list
expect('list() path starts with /v1/messages', t.calls[0][:path].start_with?('/v1/messages'))
expect('list() default limit',                  t.calls[0][:path].include?('limit=20'))

# ── Domain tests ──────────────────────────────────────────────────────────

puts "\nDomains"

t = FakeTransport.new
t.queue_response({ 'domain' => { 'id' => 'dom_1', 'domain' => 'mail.example.com' }, 'dnsRecords' => [] })
api = ApexMail::DomainsAPI.new(t)
resp = api.create(domain: 'mail.example.com')
expect('create() POST /v1/domains',        t.calls[0][:method] == 'POST' && t.calls[0][:path] == '/v1/domains')
expect('create() body has name field (CreateDomainRequest takes {name})', t.calls[0][:body][:name] == 'mail.example.com')
expect('create() sends no domain key',            t.calls[0][:body].key?(:domain) == false)
expect('create() returns domain id',       resp.dig('domain', 'domain') == 'mail.example.com')

t = FakeTransport.new
t.queue_response({ 'domains' => [], 'pagination' => { 'total' => 0 } })
api = ApexMail::DomainsAPI.new(t)
api.list
expect('list() GET /v1/domains', t.calls[0][:method] == 'GET' && t.calls[0][:path] == '/v1/domains')

t = FakeTransport.new
t.queue_response({ 'domain' => { 'id' => 'dom_1' } })
api = ApexMail::DomainsAPI.new(t)
api.get('dom_1')
expect('get() GET /v1/domains/dom_1', t.calls[0][:path] == '/v1/domains/dom_1')

t = FakeTransport.new
t.queue_response({ 'verified' => false, 'message' => 'DNS not propagated' })
api = ApexMail::DomainsAPI.new(t)
resp = api.verify('dom_1')
expect('verify() POST /v1/domains/dom_1/verify', t.calls[0][:path] == '/v1/domains/dom_1/verify')
expect('verify() returns verified field',        resp.key?('verified'))

t = FakeTransport.new
t.queue_response({})
api = ApexMail::DomainsAPI.new(t)
api.delete('dom_1')
expect('delete() DELETE /v1/domains/dom_1', t.calls[0][:method] == 'DELETE' && t.calls[0][:path] == '/v1/domains/dom_1')

t = FakeTransport.new
t.queue_response({ 'spf' => 'pass', 'dkim' => 'pass', 'dmarc' => 'pass', 'healthy' => true })
api = ApexMail::DomainsAPI.new(t)
resp = api.health('dom_1')
expect('health() maps to GET /v1/domains/:id (no /health endpoint)', t.calls[0][:method] == 'GET' && t.calls[0][:path] == '/v1/domains/dom_1')
expect('health() returns healthy field',        resp.key?('healthy'))

# ── Webhook tests ─────────────────────────────────────────────────────────

puts "\nWebhooks"

t = FakeTransport.new
t.queue_response({ 'webhook' => { 'id' => 'wh_1', 'url' => 'https://ex.com/hook' } })
api = ApexMail::WebhooksAPI.new(t)
resp = api.create(url: 'https://ex.com/hook', events: ['message.delivered'])
expect('create() POST /v1/webhooks',      t.calls[0][:method] == 'POST' && t.calls[0][:path] == '/v1/webhooks')
expect('create() returns webhook id',     resp.dig('webhook', 'id') == 'wh_1')
expect('create() body has url',           t.calls[0][:body][:url] == 'https://ex.com/hook')
expect('create() body has events array',  t.calls[0][:body][:events] == ['message.delivered'])

t = FakeTransport.new
t.queue_response({ 'webhooks' => [] })
api = ApexMail::WebhooksAPI.new(t)
api.list
expect('list() GET /v1/webhooks',          t.calls[0][:method] == 'GET' && t.calls[0][:path] == '/v1/webhooks')

t = FakeTransport.new
t.queue_response({ 'webhook' => { 'id' => 'wh_1', 'url' => 'https://ex.com/hook' } })
api = ApexMail::WebhooksAPI.new(t)
resp = api.get('wh_1')
expect('get() GET /v1/webhooks/wh_1',      t.calls[0][:method] == 'GET' && t.calls[0][:path] == '/v1/webhooks/wh_1')
expect('get() returns webhook id',         resp.dig('webhook', 'id') == 'wh_1')

t = FakeTransport.new
t.queue_response({ 'webhook' => { 'id' => 'wh_1', 'url' => 'https://new.com/hook' } })
api = ApexMail::WebhooksAPI.new(t)
resp = api.update('wh_1', url: 'https://new.com/hook', events: ['message.bounced'])
expect('update() PUT /v1/webhooks/wh_1',   t.calls[0][:method] == 'PUT' && t.calls[0][:path] == '/v1/webhooks/wh_1')
expect('update() body has url',             t.calls[0][:body][:url] == 'https://new.com/hook')
expect('update() body has events',          t.calls[0][:body][:events] == ['message.bounced'])

t = FakeTransport.new
t.queue_response({})
api = ApexMail::WebhooksAPI.new(t)
api.delete('wh_1')
expect('delete() DELETE /v1/webhooks/wh_1', t.calls[0][:method] == 'DELETE' && t.calls[0][:path] == '/v1/webhooks/wh_1')

# ── Template tests ────────────────────────────────────────────────────────

puts "\nTemplates"

t = FakeTransport.new
t.queue_response({ 'template' => { 'id' => 'tpl_1', 'name' => 'Welcome' } })
api = ApexMail::TemplatesAPI.new(t)
resp = api.create(name: 'Welcome', subject: 'Hi', html: '<p>Hi</p>')
expect('create() POST /v1/templates',   t.calls[0][:path] == '/v1/templates')
expect('create() returns template id',  resp.dig('template', 'id') == 'tpl_1')

t = FakeTransport.new
t.queue_response({ 'template' => { 'id' => 'tpl_1' } })
api = ApexMail::TemplatesAPI.new(t)
api.get('tpl_1')
expect('get() GET /v1/templates/tpl_1', t.calls[0][:path] == '/v1/templates/tpl_1')

t = FakeTransport.new
t.queue_response({ 'template' => { 'id' => 'tpl_1', 'slug' => 'welcome' } })
api = ApexMail::TemplatesAPI.new(t)
resp = api.get_by_slug('welcome')
expect('get_by_slug() GET /v1/templates/slug/welcome', t.calls[0][:path] == '/v1/templates/slug/welcome')

t = FakeTransport.new
t.queue_response({ 'templates' => [], 'pagination' => { 'total' => 0 } })
api = ApexMail::TemplatesAPI.new(t)
api.list
expect('list() GET /v1/templates?...',  t.calls[0][:path].start_with?('/v1/templates'))
expect('list() has limit param',        t.calls[0][:path].include?('limit='))

t = FakeTransport.new
t.queue_response({ 'template' => { 'id' => 'tpl_1', 'name' => 'Updated' } })
api = ApexMail::TemplatesAPI.new(t)
resp = api.update('tpl_1', name: 'Updated', subject: 'New subject')
expect('update() PUT /v1/templates/tpl_1', t.calls[0][:method] == 'PUT' && t.calls[0][:path] == '/v1/templates/tpl_1')
expect('update() body has name',             t.calls[0][:body][:name] == 'Updated')

t = FakeTransport.new
t.queue_response({})
api = ApexMail::TemplatesAPI.new(t)
api.delete('tpl_1')
expect('delete() DELETE /v1/templates/tpl_1', t.calls[0][:method] == 'DELETE' && t.calls[0][:path] == '/v1/templates/tpl_1')

t = FakeTransport.new
t.queue_response({ 'html' => '<h1>Hello Alice</h1>', 'subject' => 'Welcome' })
api = ApexMail::TemplatesAPI.new(t)
resp = api.render('tpl_1', { name: 'Alice' })
expect('render() POST /v1/templates/tpl_1/render', t.calls[0][:method] == 'POST' && t.calls[0][:path] == '/v1/templates/tpl_1/render')
expect('render() body has variables',               t.calls[0][:body][:variables][:name] == 'Alice')
expect('render() returns html',                     resp.key?('html'))

# ── Suppression tests ─────────────────────────────────────────────────────

puts "\nSuppressions"

t = FakeTransport.new
t.queue_response({})
api = ApexMail::SuppressionsAPI.new(t)
api.add(emails: 'bad@example.com', reason: 'bounce')
expect('add() POST /v1/suppressions',        t.calls[0][:path] == '/v1/suppressions')
expect('add() body has emails array',        t.calls[0][:body][:emails] == ['bad@example.com'])
expect('add() body has reason',              t.calls[0][:body][:reason] == 'bounce')

t = FakeTransport.new
t.queue_response({})
api = ApexMail::SuppressionsAPI.new(t)
api.add(emails: ['a@b.com', 'c@d.com'], reason: 'manual')
expect('add() bulk sends array of emails',   t.calls[0][:body][:emails] == ['a@b.com', 'c@d.com'])

t = FakeTransport.new
t.queue_response({ 'suppressions' => [], 'pagination' => { 'total' => 0 } })
api = ApexMail::SuppressionsAPI.new(t)
api.list
expect('list() GET /v1/suppressions',        t.calls[0][:method] == 'GET' && t.calls[0][:path].start_with?('/v1/suppressions'))

t = FakeTransport.new
t.queue_response({ 'suppressed' => true, 'reason' => 'bounce' })
api = ApexMail::SuppressionsAPI.new(t)
resp = api.check('bad@example.com')
expect('check() GET /v1/suppressions/check/{email}', t.calls[0][:method] == 'GET' && t.calls[0][:path] == '/v1/suppressions/check/bad%40example.com')
expect('check() returns suppressed field',     resp.key?('suppressed'))

t = FakeTransport.new
t.queue_response({})
api = ApexMail::SuppressionsAPI.new(t)
api.delete('bad@example.com')
expect('delete() DELETE /v1/suppressions/…', t.calls[0][:method] == 'DELETE' && t.calls[0][:path].include?('bad'))

# ── Events tests ──────────────────────────────────────────────────────────

puts "\nEvents"

t = FakeTransport.new
t.queue_response({ 'events' => [], 'pagination' => { 'total' => 0 } })
api = ApexMail::EventsAPI.new(t)
api.list(message_id: 'msg_123')
expect('list() GET /v1/events',              t.calls[0][:path].start_with?('/v1/events'))
expect('list() includes messageId param',    t.calls[0][:path].include?('messageId=msg_123'))

t = FakeTransport.new
t.queue_response({ 'events' => [{ 'id' => 'evt_1', 'eventType' => 'delivered' }] })
api = ApexMail::EventsAPI.new(t)
resp = api.get_by_message('msg_123')
expect('get_by_message() GET /v1/events?messageId=msg_123', t.calls[0][:path].include?('messageId=msg_123'))
expect('get_by_message() returns events',                    resp.key?('events'))

t = FakeTransport.new
t.queue_response({ 'event' => { 'id' => 'evt_42', 'eventType' => 'bounced' } })
api = ApexMail::EventsAPI.new(t)
resp = api.get('evt_42')
expect('get() GET /v1/events/evt_42',      t.calls[0][:method] == 'GET' && t.calls[0][:path] == '/v1/events/evt_42')
expect('get() returns event',              resp.dig('event', 'id') == 'evt_42')

# ── API key tests ─────────────────────────────────────────────────────────

puts "\nAPI Keys"

t = FakeTransport.new
t.queue_response({ 'apiKey' => { 'id' => 'key_1', 'name' => 'Deploy key' } })
api = ApexMail::ApiKeysAPI.new(t)
resp = api.create(name: 'Deploy key', expires_at: '2026-12-31T00:00:00Z')
expect('create() POST /v1/auth/api-keys', t.calls[0][:method] == 'POST' && t.calls[0][:path] == '/v1/auth/api-keys')
expect('create() body has name',          t.calls[0][:body][:name] == 'Deploy key')
expect('create() forwards expiresAt',     t.calls[0][:body][:expiresAt] == '2026-12-31T00:00:00Z')
expect('create() returns api key',        resp.dig('apiKey', 'id') == 'key_1')

t = FakeTransport.new
t.queue_response({ 'apiKeys' => [] })
api = ApexMail::ApiKeysAPI.new(t)
api.list(limit: 25, offset: 5)
expect('list() GET /v1/auth/api-keys', t.calls[0][:method] == 'GET' && t.calls[0][:path].start_with?('/v1/auth/api-keys'))
expect('list() forwards pagination',   t.calls[0][:path].include?('limit=25') && t.calls[0][:path].include?('offset=5'))

t = FakeTransport.new
t.queue_response({})
api = ApexMail::ApiKeysAPI.new(t)
api.revoke('key_1')
expect('revoke() DELETE /v1/auth/api-keys/key_1', t.calls[0][:method] == 'DELETE' && t.calls[0][:path] == '/v1/auth/api-keys/key_1')

# ── Analytics tests ───────────────────────────────────────────────────────

puts "\nAnalytics"

t = FakeTransport.new
t.queue_response({ 'stats' => { 'sent' => 10 } })
api = ApexMail::AnalyticsAPI.new(t)
resp = api.get(from: '2026-01-01', to: '2026-01-31', group_by: 'day', tag: 'welcome')
expect('get() GET /v1/analytics',       t.calls[0][:method] == 'GET' && t.calls[0][:path].start_with?('/v1/analytics'))
expect('get() forwards groupBy filter', t.calls[0][:path].include?('groupBy=day'))
expect('get() returns stats',           resp.key?('stats'))

# ── Error handling ────────────────────────────────────────────────────────

puts "\nError handling"

t = FakeTransport.new
t.queue_error(ApexMail::AuthenticationError.new('Invalid API key', status_code: 401))
api = ApexMail::EmailsAPI.new(t)
begin
  api.send_email(from: 'a@b.com', to: 'x@y.com', subject: 'Hi', html: '<p>Hi</p>')
  assert_fail('401 raises AuthenticationError', 'no exception raised')
rescue ApexMail::AuthenticationError => e
  expect('401 raises AuthenticationError', true)
  expect('error has status_code 401',      e.status_code == 401)
end

t = FakeTransport.new
t.queue_error(ApexMail::NotFoundError.new('Not found', status_code: 404))
api = ApexMail::EmailsAPI.new(t)
begin
  api.get('missing')
  assert_fail('404 raises NotFoundError', 'no exception raised')
rescue ApexMail::NotFoundError => e
  expect('404 raises NotFoundError', true)
end

t = FakeTransport.new
t.queue_error(ApexMail::RateLimitError.new('Rate limit exceeded', status_code: 429))
api = ApexMail::EmailsAPI.new(t)
begin
  api.send_email(from: 'a@b.com', to: 'x@y.com', subject: 'Hi', html: '<p>Hi</p>')
  assert_fail('429 raises RateLimitError', 'no exception raised')
rescue ApexMail::RateLimitError => e
  expect('429 raises RateLimitError', true)
end

t = FakeTransport.new
t.queue_error(ApexMail::ValidationError.new('Invalid params', status_code: 422))
api = ApexMail::EmailsAPI.new(t)
begin
  api.send_email(from: 'a@b.com', to: 'x@y.com', subject: 'Hi', html: '<p>Hi</p>')
  assert_fail('422 raises ValidationError', 'no exception raised')
rescue ApexMail::ValidationError => e
  expect('422 raises ValidationError', true)
  expect('ValidationError has status_code', e.status_code == 422)
end

t = FakeTransport.new
t.queue_error(ApexMail::NetworkError.new('Connection refused'))
api = ApexMail::EmailsAPI.new(t)
begin
  api.send_email(from: 'a@b.com', to: 'x@y.com', subject: 'Hi', html: '<p>Hi</p>')
  assert_fail('NetworkError raised on transport failure', 'no exception raised')
rescue ApexMail::NetworkError => e
  expect('NetworkError raised on transport failure', true)
  expect('NetworkError message', e.message.include?('Connection refused'))
end

# ── Client integration test ───────────────────────────────────────────────

puts "\nClient integration"

client = ApexMail::Client.new('am_test_0123456789abcdef')
expect('Client has emails API',       client.emails.is_a?(ApexMail::EmailsAPI))
expect('Client has domains API',      client.domains.is_a?(ApexMail::DomainsAPI))
expect('Client has webhooks API',     client.webhooks.is_a?(ApexMail::WebhooksAPI))
expect('Client has templates API',    client.templates.is_a?(ApexMail::TemplatesAPI))
expect('Client has suppressions API', client.suppressions.is_a?(ApexMail::SuppressionsAPI))
expect('Client has events API',       client.events.is_a?(ApexMail::EventsAPI))
expect('Client has API keys API',     client.api_keys.is_a?(ApexMail::ApiKeysAPI))
expect('Client has analytics API',    client.analytics.is_a?(ApexMail::AnalyticsAPI))

# ── Transport tests (SDK-A/B/F, G L9) ─────────────────────────────────────

puts "\nTransport"

# Fakes that quack like Net::HTTP / Net::HTTPResponse, injected via the
# Transport test seams (http_factory / sleeper) so the real retry loop,
# header building, and response handling run without a network.
class FakeHTTPResponse
  attr_reader :code, :headers

  def initialize(code, body, headers = {})
    @code   = code.to_s
    @headers = headers
    @chunks = Array(body)
  end

  def read_body
    return enum_for(:read_body) unless block_given?
    @chunks.each { |c| yield c.is_a?(String) ? c : c.to_s }
  end

  def []=(key, value)
    @headers[key] = value
  end

  def [](key)
    @headers[key]
  end
end

class FakeHTTP
  attr_reader :requests

  def initialize(responses)
    @responses = responses.dup
    @requests  = []
  end

  def start
    block_given? ? yield(self) : self
  end

  def finish; end

  def request(req, &block)
    @requests << req
    resp = @responses.shift || (@responses.empty? ? nil : @responses.last)
    raise IOError, 'no more canned responses' if resp.nil?

    block.call(resp) if block
    resp
  end
end

def mk_transport(responses, sleeper = nil)
  fake = FakeHTTP.new(responses)
  ApexMail::Transport.new(
    api_key: 'am_test_0123456789abcdef',
    base_url: 'https://api.example.com',
    open_timeout: 1, read_timeout: 1, max_response_bytes: 1024 * 1024,
    sleeper: sleeper, http_factory: -> { fake }
  ).tap { |_t| fake }
end

html_502 = "<html><head><title>502 Bad Gateway</title></head><body>nginx</body></html>"

# SDK-A: 502 with an HTML body must raise, never return a success hash.
t, _ = mk_transport([FakeHTTPResponse.new(502, html_502)] * 10)
begin
  result = t.request('POST', '/v1/messages', body: { from: 'a@b.com' })
  assert_fail('502 HTML raises (not a success hash)', "returned #{result.inspect}")
rescue ApexMail::Error => e
  expect('502 HTML raises ApexMail::Error',        e.is_a?(ApexMail::Error))
  expect('502 HTML error carries status_code 502', e.status_code == 502)
  expect('502 HTML error code is PARSE_ERROR',     e.code == 'PARSE_ERROR')
end

# SDK-A: non-JSON 200 is an invalid response and must raise too.
t, _ = mk_transport([FakeHTTPResponse.new(200, '<html>hi</html>')])
begin
  t.request('GET', '/v1/anything')
  assert_fail('non-JSON 200 raises', 'no exception raised')
rescue ApexMail::Error => e
  expect('non-JSON 200 raises ApexMail::Error',  true)
  expect('non-JSON 200 code is PARSE_ERROR',     e.code == 'PARSE_ERROR')
  expect('non-JSON 200 keeps status_code 200',   e.status_code == 200)
end

# SDK-A: JSON error envelope on a 503 still maps through the normal path.
t, _ = mk_transport([FakeHTTPResponse.new(503, '{"error":{"code":"SERVICE_UNAVAILABLE","message":"down"}}')] * 10)
begin
  t.request('GET', '/v1/anything')
  assert_fail('JSON 503 raises', 'no exception raised')
rescue ApexMail::Error => e
  expect('JSON 503 raises with server message', e.message.include?('down'))
end

# SDK-B: the same X-Idempotency-Key is replayed across retries of one call.
fake = FakeHTTP.new([
  FakeHTTPResponse.new(500, '{"error":{"message":"boom"}}'),
  FakeHTTPResponse.new(200, '{"data":{"id":"msg_retry","status":"queued","created_at":"2026-01-01T00:00:00Z"}}'),
])
t2 = ApexMail::Transport.new(
  api_key: 'am_test_0123456789abcdef', base_url: 'https://api.example.com',
  open_timeout: 1, read_timeout: 1, max_response_bytes: 1024 * 1024,
  sleeper: ->(_d) {}, http_factory: -> { fake }
)
resp = t2.request('POST', '/v1/messages', body: { a: 1 }, idempotency_key: 'sdk-b-key')
expect('retried send succeeds and unwraps envelope', resp[:id] == 'msg_retry')
req_keys = fake.requests.map { |r| r['X-Idempotency-Key'] }
expect('retry replays the same X-Idempotency-Key', req_keys == ['sdk-b-key', 'sdk-b-key'])

# Retry only on retryable statuses: a 422 must raise immediately (1 request).
fake = FakeHTTP.new([FakeHTTPResponse.new(422, '{"error":{"code":"VALIDATION_ERROR","message":"nope"}}')] * 10)
t3 = ApexMail::Transport.new(
  api_key: 'am_test_0123456789abcdef', base_url: 'https://api.example.com',
  open_timeout: 1, read_timeout: 1, max_response_bytes: 1024 * 1024,
  sleeper: ->(_d) { raise 'should not sleep' }, http_factory: -> { fake }
)
begin
  t3.request('POST', '/v1/messages', body: { a: 1 })
  assert_fail('422 raises immediately', 'no exception raised')
rescue ApexMail::ValidationError => e
  expect('422 raises ValidationError', true)
  expect('422 is not retried (single request)', fake.requests.length == 1)
end

# SDK-F: Retry-After is honored in full, capped at 120s (not 5s).
resp_hdr = FakeHTTPResponse.new(429, '{}', { 'Retry-After' => '60' })
t4, _ = mk_transport([])
expect('Retry-After 60 → delay 60.0 (not capped at 5)', (t4.send(:retry_delay, resp_hdr, 0) - 60.0).abs < 0.01)
resp_hdr = FakeHTTPResponse.new(429, '{}', { 'Retry-After' => '300' })
expect('Retry-After 300 → capped at 120.0', (t4.send(:retry_delay, resp_hdr, 0) - 120.0).abs < 0.01)
resp_hdr = FakeHTTPResponse.new(503, '{}')
expect('no Retry-After → backoff stays ≤ MAX_BACKOFF+jitter', t4.send(:retry_delay, resp_hdr, 2) <= ApexMail::Transport::MAX_BACKOFF + 1.0)

# SDK-F end-to-end: the injected sleeper receives the server's full value.
slept = []
fake = FakeHTTP.new([
  FakeHTTPResponse.new(429, '{}', { 'Retry-After' => '60' }),
  FakeHTTPResponse.new(200, '{"data":{"id":"m1","status":"queued","created_at":"now"}}'),
])
t5 = ApexMail::Transport.new(
  api_key: 'am_test_0123456789abcdef', base_url: 'https://api.example.com',
  open_timeout: 1, read_timeout: 1, max_response_bytes: 1024 * 1024,
  sleeper: ->(d) { slept << d }, http_factory: -> { fake }
)
t5.request('POST', '/v1/messages', body: { a: 1 }, idempotency_key: 'k')
expect('sleeper called with full 60s Retry-After', slept.length == 1 && (slept[0] - 60.0).abs < 0.01)

# G L9: top-level JSON array body on a 200 is returned as an array.
t6, _ = mk_transport([FakeHTTPResponse.new(200, '[1,2,3]')])
resp = t6.request('GET', '/v1/things')
expect('array body returned as array', resp == [1, 2, 3])

# Envelope unwrap still works for hash bodies.
t7, _ = mk_transport([FakeHTTPResponse.new(200, '{"data":{"id":"x"},"meta":{"total":1}}')])
resp = t7.request('GET', '/v1/things')
expect('envelope body unwrapped to data', resp[:id] == 'x')

# ── Summary ───────────────────────────────────────────────────────────────

puts ""
if $failed == 0
  puts "\e[32mAll #{$passed} tests passed.\e[0m\n\n"
  exit 0
else
  puts "\e[31m#{$failed} FAILED, #{$passed} passed.\e[0m\n\n"
  exit 1
end
