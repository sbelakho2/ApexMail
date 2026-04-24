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
t.queue_response({ 'message' => { 'id' => 'msg_123', 'status' => 'queued' } })
api = ApexMail::EmailsAPI.new(t)
resp = api.send(from: 'a@b.com', to: 'x@y.com', subject: 'Hi', html: '<p>Hi</p>')
expect('send() POST /v1/messages',  t.calls[0][:method] == 'POST' && t.calls[0][:path] == '/v1/messages')
expect('send() returns message id', resp.dig('message', 'id') == 'msg_123')
expect('send() body has from key',  t.calls[0][:body].key?(:from))
expect('send() body has subject',   t.calls[0][:body][:subject] == 'Hi')

t = FakeTransport.new
t.queue_response({ 'message' => { 'id' => 'msg_456' } })
api = ApexMail::EmailsAPI.new(t)
api.send(from: 'a@b.com', to: 'x@y.com', subject: 'Hi', idempotency_key: 'ik-001')
expect('send() forwards idempotency_key', t.calls[0][:idempotency_key] == 'ik-001')

t = FakeTransport.new
t.queue_response({ 'results' => [{ 'index' => 0, 'success' => true }, { 'index' => 1, 'success' => true }],
                   'summary' => { 'total' => 2, 'success' => 2, 'failed' => 0 } })
api = ApexMail::EmailsAPI.new(t)
resp = api.batch(messages: [
  { from: 'a@b.com', to: 'x@y.com', subject: 'msg1' },
  { from: 'a@b.com', to: 'p@q.com', subject: 'msg2' },
])
expect('batch() POST /v1/messages/batch', t.calls[0][:path] == '/v1/messages/batch')
expect('batch() sends 2 items',           t.calls[0][:body][:messages].length == 2)
expect('batch() summary total',           resp.dig('summary', 'total') == 2)

t = FakeTransport.new
t.queue_response({ 'message' => { 'id' => 'msg_789', 'status' => 'delivered' } })
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
expect('create() body has domain field',   t.calls[0][:body][:domain] == 'mail.example.com')
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
expect('health() GET /v1/domains/dom_1/health', t.calls[0][:method] == 'GET' && t.calls[0][:path] == '/v1/domains/dom_1/health')
expect('health() returns healthy field',        resp.key?('healthy'))

# ── Webhook tests ─────────────────────────────────────────────────────────

puts "\nWebhooks"

t = FakeTransport.new
t.queue_response({ 'webhook' => { 'id' => 'wh_1', 'url' => 'https://ex.com/hook' } })
api = ApexMail::WebhooksAPI.new(t)
resp = api.create(url: 'https://ex.com/hook', events: ['email.delivered'])
expect('create() POST /v1/webhooks',      t.calls[0][:method] == 'POST' && t.calls[0][:path] == '/v1/webhooks')
expect('create() returns webhook id',     resp.dig('webhook', 'id') == 'wh_1')
expect('create() body has url',           t.calls[0][:body][:url] == 'https://ex.com/hook')
expect('create() body has events array',  t.calls[0][:body][:events] == ['email.delivered'])

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
resp = api.update('wh_1', url: 'https://new.com/hook', events: ['email.bounced'])
expect('update() PATCH /v1/webhooks/wh_1',  t.calls[0][:method] == 'PATCH' && t.calls[0][:path] == '/v1/webhooks/wh_1')
expect('update() body has url',             t.calls[0][:body][:url] == 'https://new.com/hook')
expect('update() body has events',          t.calls[0][:body][:events] == ['email.bounced'])

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
expect('update() PATCH /v1/templates/tpl_1', t.calls[0][:method] == 'PATCH' && t.calls[0][:path] == '/v1/templates/tpl_1')
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
expect('render() body has data',                    t.calls[0][:body][:data][:name] == 'Alice')
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
expect('check() GET /v1/suppressions/{email}', t.calls[0][:method] == 'GET' && t.calls[0][:path].include?('bad'))
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

# ── Error handling ────────────────────────────────────────────────────────

puts "\nError handling"

t = FakeTransport.new
t.queue_error(ApexMail::AuthenticationError.new('Invalid API key', status_code: 401))
api = ApexMail::EmailsAPI.new(t)
begin
  api.send(from: 'a@b.com', to: 'x@y.com', subject: 'Hi')
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
  api.send(from: 'a@b.com', to: 'x@y.com', subject: 'Hi')
  assert_fail('429 raises RateLimitError', 'no exception raised')
rescue ApexMail::RateLimitError => e
  expect('429 raises RateLimitError', true)
end

t = FakeTransport.new
t.queue_error(ApexMail::ValidationError.new('Invalid params', status_code: 422))
api = ApexMail::EmailsAPI.new(t)
begin
  api.send(from: 'a@b.com', to: 'x@y.com', subject: 'Hi')
  assert_fail('422 raises ValidationError', 'no exception raised')
rescue ApexMail::ValidationError => e
  expect('422 raises ValidationError', true)
  expect('ValidationError has status_code', e.status_code == 422)
end

t = FakeTransport.new
t.queue_error(ApexMail::NetworkError.new('Connection refused'))
api = ApexMail::EmailsAPI.new(t)
begin
  api.send(from: 'a@b.com', to: 'x@y.com', subject: 'Hi')
  assert_fail('NetworkError raised on transport failure', 'no exception raised')
rescue ApexMail::NetworkError => e
  expect('NetworkError raised on transport failure', true)
  expect('NetworkError message', e.message.include?('Connection refused'))
end

# ── Client integration test ───────────────────────────────────────────────

puts "\nClient integration"

client = ApexMail::Client.new('test_key')
expect('Client has emails API',       client.emails.is_a?(ApexMail::EmailsAPI))
expect('Client has domains API',      client.domains.is_a?(ApexMail::DomainsAPI))
expect('Client has webhooks API',     client.webhooks.is_a?(ApexMail::WebhooksAPI))
expect('Client has templates API',    client.templates.is_a?(ApexMail::TemplatesAPI))
expect('Client has suppressions API', client.suppressions.is_a?(ApexMail::SuppressionsAPI))
expect('Client has events API',       client.events.is_a?(ApexMail::EventsAPI))

# ── Summary ───────────────────────────────────────────────────────────────

puts ""
if $failed == 0
  puts "\e[32mAll #{$passed} tests passed.\e[0m\n\n"
  exit 0
else
  puts "\e[31m#{$failed} FAILED, #{$passed} passed.\e[0m\n\n"
  exit 1
end
