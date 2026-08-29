# frozen_string_literal: true

# Payload contract tests for the ApexMail Ruby SDK.
#
# Run: ruby test/payload_contract_test.rb
#
# The wire bodies this SDK emits must match the server DTOs in
# api-server/src/routes/*.rs exactly (most use serde(deny_unknown_fields),
# so any extra key is a 422):
#
#   messages.rs    SendMessageRequest
#   webhooks.rs    CreateWebhookRequest / UpdateWebhookRequest
#   templates.rs   CreateTemplateRequest
#   suppressions.rs CreateSuppressionRequest
#   domains.rs     CreateDomainRequest
#   auth.rs        CreateApiKeyRequest
#
# Plus the platform webhook-signature format
# (worker-processors/src/webhook/processor.rs):
#
#   X-ApexMail-Signature: sha256=<hex hmac-sha256>
#   X-ApexMail-Timestamp: <milliseconds since epoch>
#   signed message: "{timestamp_millis}.{payload}"

require_relative "../lib/apexmail"

$passed = 0
$failed = 0

def expect(name, condition, reason = "condition was false")
  if condition
    $passed += 1
  else
    $failed += 1
    puts "  FAIL  #{name}: #{reason}"
  end
end

# ── Recording transport (same interface Transport exposes) ─────────────────

class RecordingTransport
  attr_reader :calls

  def initialize
    @calls = []
  end

  def request(method, path, body: nil, idempotency_key: nil)
    @calls << { method: method, path: path, body: body, idempotency_key: idempotency_key }
    {}
  end
end

def transport
  RecordingTransport.new
end

# ── F1: send wire shape vs messages.rs SendMessageRequest ──────────────────

t = transport
emails = ApexMail::EmailsAPI.new(t)
emails.send_email(
  from: { email: "hello@example.com", name: "Ignored" },
  to: ["user@example.com", { email: "second@example.com", name: "Dropped" }],
  subject: "Hello!",
  html: "<h1>Hello World</h1>",
  cc: ["cc@example.com"],
  bcc: "bcc@example.com",
  tags: ["welcome", { name: "campaign", value: "spring" }],
  scheduled_at: "2026-09-01T09:00:00Z",
  metadata: { source: "ruby-sdk-test" },
  # Inputs the API rejects — must NOT be sent:
  reply_to: "reply@example.com",
  template_id: "tpl_1",
  attachments: [{ filename: "a.txt", content: "eHg=" }],
  priority: "high",
)

body = t.calls[0][:body]
expect("send posts to /v1/messages", t.calls[0][:method] == "POST" && t.calls[0][:path] == "/v1/messages")
expect("send from is a bare address string", body[:from] == "hello@example.com")
expect("send to is a bare string list", body[:to] == ["user@example.com", "second@example.com"])
expect("send cc/bcc coerced to string lists", body[:cc] == ["cc@example.com"] && body[:bcc] == ["bcc@example.com"])
expect("send tags flattened to strings", body[:tags] == ["welcome", "campaign=spring"])
expect("send scheduled_at is snake_case", body[:scheduled_at] == "2026-09-01T09:00:00Z")
%w[replyTo reply_to templateId templateData attachments priority scheduledAt name].each do |forbidden|
  expect("send does not serialize #{forbidden}", !body.key?(forbidden.to_sym) && !body.key?(forbidden))
end

# batch uses the same coercion
t = transport
ApexMail::EmailsAPI.new(t).batch(messages: [
  { from: "hello@example.com", to: "user@example.com", subject: "Hi", text: "Hello", priority: "high" },
])
message = t.calls[0][:body][:messages][0]
expect("batch message to coerced to list", message[:to] == ["user@example.com"])
expect("batch message from bare string", message[:from] == "hello@example.com")
expect("batch drops priority", !message.key?(:priority))

# ── F2: webhook wire shapes vs webhooks.rs ─────────────────────────────────

t = transport
webhooks = ApexMail::WebhooksAPI.new(t)
webhooks.create(
  url: "https://example.com/hook",
  events: ["message.delivered", "email.bounced", "*"],
  secret: "whsec_legacy", # must NOT be sent
)
expect("webhook create sends exactly {url, events}",
       t.calls[0][:body] == { url: "https://example.com/hook", events: ["message.delivered", "email.bounced", "*"] })

rejected = false
begin
  webhooks.create(url: "https://example.com/hook", events: ["delivered"])
rescue ArgumentError
  rejected = true
end
expect("webhook create rejects unknown event names", rejected)

t = transport
webhooks = ApexMail::WebhooksAPI.new(t)
webhooks.update("wh_1", url: "https://example.com/hook2", events: ["message.opened"], active: false)
expect("webhook update maps active=false to status=paused",
       t.calls[0][:body] == { url: "https://example.com/hook2", events: ["message.opened"], status: "paused" })

expect("KNOWN_WEBHOOK_EVENTS matches the server list",
       ApexMail::KNOWN_WEBHOOK_EVENTS == %w[
         email.delivered email.bounced email.complained
         message.sent message.delivered message.bounced
         message.complained message.opened message.clicked
         recipient.unsubscribed placement_test.completed
         bounce complaint inbound *
       ])

# ── F4: template wire shape vs templates.rs ────────────────────────────────

t = transport
templates = ApexMail::TemplatesAPI.new(t)
templates.create(name: "welcome", subject: "Welcome!", html: "<p>Hi</p>", text: "Hi",
                 slug: "welcome-v1", engine: "handlebars")
expect("template create sends {name, subject, html_body, text_body}",
       t.calls[0][:body] == { name: "welcome", subject: "Welcome!", html_body: "<p>Hi</p>", text_body: "Hi" })

t = transport
templates = ApexMail::TemplatesAPI.new(t)
templates.update("tpl_1", subject: "New", html: "<p>New</p>", schema: { type: "object" })
expect("template update sends only server fields",
       t.calls[0][:body] == { subject: "New", html_body: "<p>New</p>" })
expect("templates API has no get_by_slug", !templates.respond_to?(:get_by_slug))

# ── F5: suppression wire shape vs suppressions.rs ──────────────────────────

t = transport
suppressions = ApexMail::SuppressionsAPI.new(t)
suppressions.add(emails: "blocked@example.com", reason: "bounce")
expect("suppression single email sends {email, reason}",
       t.calls[0][:path] == "/v1/suppressions" &&
       t.calls[0][:body] == { email: "blocked@example.com", reason: "bounce" })

t = transport
suppressions = ApexMail::SuppressionsAPI.new(t)
suppressions.add(emails: %w[a@example.com b@example.com], reason: "unsubscribe")
expect("suppression multiple emails use the bulk endpoint",
       t.calls[0][:path] == "/v1/suppressions/bulk" &&
       t.calls[0][:body] == { entries: [
         { email: "a@example.com", reason: "unsubscribe" },
         { email: "b@example.com", reason: "unsubscribe" },
       ] })

# ── F6: domain + analytics endpoints ───────────────────────────────────────

t = transport
domains = ApexMail::DomainsAPI.new(t)
domains.create(domain: "mail.example.com")
expect("domain create sends {name}", t.calls[0][:body] == { name: "mail.example.com" })

t = transport
domains = ApexMail::DomainsAPI.new(t)
domains.health("dom_1")
expect("domain health maps to GET /v1/domains/:id",
       t.calls[0][:method] == "GET" && t.calls[0][:path] == "/v1/domains/dom_1")

t = transport
analytics = ApexMail::AnalyticsAPI.new(t)
analytics.dashboard(from: "2026-01-01", to: "2026-02-01")
analytics.volume(interval: "week")
analytics.engagement
analytics.deliverability
analytics.analyze_subject_line("Open me")
expect("analytics dashboard subpath",
       t.calls[0][:method] == "GET" && t.calls[0][:path] == "/v1/analytics/dashboard?from=2026-01-01&to=2026-02-01")
expect("analytics volume interval param",
       t.calls[1][:path] == "/v1/analytics/volume?interval=week")
expect("analytics engagement bare subpath", t.calls[2][:path] == "/v1/analytics/engagement")
expect("analytics deliverability bare subpath", t.calls[3][:path] == "/v1/analytics/deliverability")
expect("subject-line posts {subject}",
       t.calls[4][:method] == "POST" && t.calls[4][:path] == "/v1/analytics/subject-line" &&
       t.calls[4][:body] == { subject: "Open me" })

# ── API keys: {name, scopes, expires_in_days} ──────────────────────────────

t = transport
api_keys = ApexMail::ApiKeysAPI.new(t)
api_keys.create(name: "deploy", scopes: ["messages:send"], expires_in_days: 30, expires_at: "2030-01-01T00:00:00Z")
expect("api key create sends {name, scopes, expires_in_days}",
       t.calls[0][:body] == { name: "deploy", scopes: ["messages:send"], expires_in_days: 30 })

t = transport
api_keys = ApexMail::ApiKeysAPI.new(t)
api_keys.create(name: "minimal")
expect("api key scopes always present", t.calls[0][:body] == { name: "minimal", scopes: [] })

# ── F3: platform webhook signature (ms timestamps) ─────────────────────────

payload = '{"test":true}'
secret = "whsec_test"

vector = OpenSSL::HMAC.hexdigest("sha256", secret, "1750000000000.#{payload}")
expect("known vector pins the signed string",
       vector == "31d18ff09cab4d0547ab1c518ffc67124406e128598a7ecfa5dbcc520e4996b2")

fresh_ms = ((Time.now.to_f - 1.0) * 1000).to_i.to_s
signature = "sha256=" + OpenSSL::HMAC.hexdigest("sha256", secret, "#{fresh_ms}.#{payload}")
expect("fresh millisecond signature verifies with both headers",
       ApexMail.verify_signature(payload, signature, secret, timestamp_header: fresh_ms))
expect("sha256= header without timestamp is rejected",
       !ApexMail.verify_signature(payload, signature, secret))
expect("stale millisecond timestamp is rejected",
       !ApexMail.verify_signature(payload, signature, secret,
                                  timestamp_header: "1750000000000", tolerance_seconds: 300))
stale_sig = "sha256=" + OpenSSL::HMAC.hexdigest("sha256", secret, "1750000000000.#{payload}")
expect("stale vector signature is rejected",
       !ApexMail.verify_signature(payload, stale_sig, secret,
                                  timestamp_header: "1750000000000", tolerance_seconds: 300))
wrong_order = "sha256=" + OpenSSL::HMAC.hexdigest("sha256", secret, "#{payload}.#{fresh_ms}")
expect("wrong signing order is rejected",
       !ApexMail.verify_signature(payload, wrong_order, secret, timestamp_header: fresh_ms))

# ── F10: X-Idempotency-Key control characters are stripped ─────────────────

transport = ApexMail::Transport.new(
  api_key: "am_live_1234567890abcdef",
  base_url: "https://api.apexmail.ee",
  open_timeout: 1,
  read_timeout: 1,
  max_response_bytes: 1024
)

# Build a request through the real transport and inspect the header.
request = transport.send(:build_request, "POST", URI.parse("https://api.apexmail.ee/v1/messages"),
                         { a: 1 }, "key\r\n injected")
expect("idempotency key control characters stripped", request["X-Idempotency-Key"] == "key injected")

# ── Summary ────────────────────────────────────────────────────────────────

if $failed.zero?
  puts "payload contract: #{$passed} checks passed"
else
  puts "payload contract: #{$passed} passed, #{$failed} FAILED"
  exit 1
end
