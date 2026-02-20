# frozen_string_literal: true

# apexmail.rb — Official Ruby SDK for the ApexMail transactional email API
#
# Usage:
#   require "apexmail"
#
#   client = ApexMail::Client.new("am_live_xxxx")
#
#   response = client.emails.send(
#     from:    "hello@example.com",
#     to:      "user@example.com",
#     subject: "Hello!",
#     html:    "<h1>Hello World</h1>"
#   )
#   puts response[:message][:id]

require "net/http"
require "uri"
require "json"

module ApexMail
  DEFAULT_BASE_URL = "https://api.apexmail.ee"
  SDK_VERSION      = "1.0.0"

  # ── Errors ─────────────────────────────────────────────────────────────────

  class Error < StandardError
    attr_reader :status_code, :code

    def initialize(message, status_code: nil, code: nil)
      super(message)
      @status_code = status_code
      @code        = code
    end
  end

  class AuthenticationError < Error; end
  class NotFoundError       < Error; end
  class ValidationError     < Error; end
  class RateLimitError      < Error; end
  class NetworkError        < Error; end

  # ── HTTP transport ─────────────────────────────────────────────────────────

  # @api private
  class Transport
    def initialize(api_key:, base_url:, open_timeout:, read_timeout:)
      @api_key      = api_key
      @base_url     = base_url
      @open_timeout = open_timeout
      @read_timeout = read_timeout
    end

    def request(method, path, body: nil, idempotency_key: nil)
      uri  = URI.parse("#{@base_url}#{path}")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl     = uri.scheme == "https"
      http.open_timeout = @open_timeout
      http.read_timeout = @read_timeout

      req = build_request(method, uri, body, idempotency_key)
      resp = http.request(req)
      handle_response(resp)
    end

    private

    def build_request(method, uri, body, idempotency_key)
      klass = {
        "GET"    => Net::HTTP::Get,
        "POST"   => Net::HTTP::Post,
        "PATCH"  => Net::HTTP::Patch,
        "DELETE" => Net::HTTP::Delete,
      }.fetch(method.upcase) { raise ArgumentError, "Unsupported HTTP method: #{method}" }

      req = klass.new(uri.path.empty? ? "/" : uri.full_path)
      req["Authorization"]   = "Bearer #{@api_key}"
      req["Content-Type"]    = "application/json"
      req["User-Agent"]      = "apexmail-ruby/#{SDK_VERSION}"
      req["X-Idempotency-Key"] = idempotency_key if idempotency_key
      req.body = JSON.generate(body) if body
      req
    end

    def handle_response(resp)
      body = resp.body.to_s.strip
      parsed = body.empty? ? {} : JSON.parse(body, symbolize_names: true)

      case resp.code.to_i
      when 200..299
        parsed
      when 401
        raise AuthenticationError.new(parsed[:error] || "Unauthorized", status_code: 401, code: parsed[:code])
      when 404
        raise NotFoundError.new(parsed[:error] || "Not found", status_code: 404, code: parsed[:code])
      when 422
        raise ValidationError.new(parsed[:error] || "Unprocessable entity", status_code: 422, code: parsed[:code])
      when 429
        raise RateLimitError.new(parsed[:error] || "Rate limit exceeded", status_code: 429, code: parsed[:code])
      else
        raise Error.new(parsed[:error] || "HTTP #{resp.code}", status_code: resp.code.to_i, code: parsed[:code])
      end
    end
  end

  # ── Client ─────────────────────────────────────────────────────────────────

  class Client
    attr_reader :emails, :domains, :webhooks, :templates, :suppressions, :events

    # @param api_key      [String]  Your ApexMail API key (starts with am_live_ or am_test_)
    # @param base_url     [String]  Override the base URL (useful for self-hosted)
    # @param open_timeout [Integer] TCP connect timeout in seconds (default: 10)
    # @param read_timeout [Integer] Read timeout in seconds (default: 30)
    def initialize(api_key, base_url: DEFAULT_BASE_URL, open_timeout: 10, read_timeout: 30)
      @transport   = Transport.new(api_key: api_key, base_url: base_url,
                                   open_timeout: open_timeout, read_timeout: read_timeout)
      @emails      = EmailsAPI.new(@transport)
      @domains     = DomainsAPI.new(@transport)
      @webhooks    = WebhooksAPI.new(@transport)
      @templates   = TemplatesAPI.new(@transport)
      @suppressions = SuppressionsAPI.new(@transport)
      @events      = EventsAPI.new(@transport)
    end
  end

  # ── Emails ──────────────────────────────────────────────────────────────────

  class EmailsAPI
    def initialize(transport) = @t = transport

    # Send a single transactional email.
    #
    # @param from    [String, Hash]        Sender ("addr" or { email:, name: })
    # @param to      [String, Array<String, Hash>] Recipients
    # @param subject [String]
    # @param html    [String, nil]         HTML body
    # @param text    [String, nil]         Plain-text body
    # @param options [Hash]                Additional options
    # @option options [String]  :template_id
    # @option options [Hash]    :template_data
    # @option options [String]  :reply_to
    # @option options [Array]   :attachments
    # @option options [Array]   :tags
    # @option options [String]  :priority  ("high" | "normal" | "low")
    # @option options [String]  :scheduled_at  ISO 8601 datetime
    # @option options [String]  :idempotency_key
    # @return [Hash]
    def send(from:, to:, subject:, html: nil, text: nil, **options)
      idempotency_key = options.delete(:idempotency_key)
      body = compact({
        from:         normalize_address(from),
        to:           normalize_recipients(to),
        cc:           normalize_recipients(options[:cc]),
        bcc:          normalize_recipients(options[:bcc]),
        replyTo:      options[:reply_to],
        subject:      subject,
        html:         html,
        text:         text,
        templateId:   options[:template_id],
        templateData: options[:template_data],
        attachments:  options[:attachments],
        tags:         options[:tags],
        priority:     options[:priority],
        scheduledAt:  options[:scheduled_at],
        metadata:     options[:metadata],
      })
      @t.request("POST", "/v1/messages", body: body, idempotency_key: idempotency_key)
    end

    # Send up to 1,000 emails in one request.
    #
    # @param messages [Array<Hash>] Array of send parameters (same keys as #send)
    # @return [Hash]
    def batch(messages:)
      @t.request("POST", "/v1/messages/batch", body: {
        messages: messages.map { |m| normalize_send_params(m) },
      })
    end

    # Retrieve an email by ID.
    # @param id [String]
    def get(id)
      @t.request("GET", "/v1/messages/#{id}")
    end

    # List emails with optional filters.
    # @param status [String, nil]
    # @param limit  [Integer]
    # @param offset [Integer]
    def list(status: nil, limit: 20, offset: 0, tag: nil)
      query = "?limit=#{limit}&offset=#{offset}"
      query += "&status=#{status}" if status
      query += "&tag=#{tag}"       if tag
      @t.request("GET", "/v1/messages#{query}")
    end

    private

    def normalize_address(addr)
      addr.is_a?(Hash) ? addr : { email: addr }
    end

    def normalize_recipients(recips)
      return nil if recips.nil?
      Array(recips).map { |r| normalize_address(r) }
    end

    def normalize_send_params(params)
      from    = normalize_address(params[:from] || params["from"])
      to      = normalize_recipients(params[:to] || params["to"])
      compact(params.merge(from: from, to: to))
    end

    def compact(hash)
      hash.reject { |_, v| v.nil? }
    end
  end

  # ── Domains ─────────────────────────────────────────────────────────────────

  class DomainsAPI
    def initialize(transport) = @t = transport

    # Add a domain and retrieve DNS records.
    # @param domain [String]
    def create(domain:)
      @t.request("POST", "/v1/domains", body: { domain: domain })
    end

    # List all domains.
    def list
      @t.request("GET", "/v1/domains")
    end

    # Get a domain by ID.
    def get(id)
      @t.request("GET", "/v1/domains/#{id}")
    end

    # Trigger DNS verification.
    def verify(id)
      @t.request("POST", "/v1/domains/#{id}/verify")
    end

    # Delete a domain.
    def delete(id)
      @t.request("DELETE", "/v1/domains/#{id}")
    end

    # Get DNS health for a domain.
    def health(id)
      @t.request("GET", "/v1/domains/#{id}/health")
    end
  end

  # ── Webhooks ────────────────────────────────────────────────────────────────

  class WebhooksAPI
    def initialize(transport) = @t = transport

    # @param url    [String]
    # @param events [Array<String>] e.g. ["delivered", "bounced"]
    # @param secret [String, nil]
    def create(url:, events:, secret: nil)
      body = { url: url, events: events }
      body[:secret] = secret if secret
      @t.request("POST", "/v1/webhooks", body: body)
    end

    def list
      @t.request("GET", "/v1/webhooks")
    end

    def get(id)
      @t.request("GET", "/v1/webhooks/#{id}")
    end

    # Update a webhook (URL, events, secret, or active status).
    # @param id     [String]
    # @param params [Hash] { url:, events:, secret:, active: }
    def update(id, **params)
      @t.request("PATCH", "/v1/webhooks/#{id}", body: params)
    end

    def delete(id)
      @t.request("DELETE", "/v1/webhooks/#{id}")
    end
  end

  # ── Templates ───────────────────────────────────────────────────────────────

  class TemplatesAPI
    def initialize(transport) = @t = transport

    # @param name    [String]
    # @param subject [String]
    # @param html    [String, nil]
    # @param engine  [String] "handlebars" | "mjml" | "liquid" | "ejs" | "react"
    def create(name:, subject:, html: nil, text: nil, engine: "handlebars", **opts)
      @t.request("POST", "/v1/templates", body: {
        name: name, subject: subject, html: html, text: text,
        engine: engine, **opts,
      }.compact)
    end

    def list(limit: 50, offset: 0)
      @t.request("GET", "/v1/templates?limit=#{limit}&offset=#{offset}")
    end

    def get(id)
      @t.request("GET", "/v1/templates/#{id}")
    end

    def get_by_slug(slug)
      @t.request("GET", "/v1/templates/slug/#{slug}")
    end

    # Update a template (creates a new version automatically).
    # @param id     [String]
    # @param params [Hash] { name:, subject:, html:, text:, engine:, schema: }
    def update(id, **params)
      @t.request("PATCH", "/v1/templates/#{id}", body: params)
    end

    def delete(id)
      @t.request("DELETE", "/v1/templates/#{id}")
    end

    # Render a template with given data (dry-run, does not send).
    # @param id   [String]
    # @param data [Hash]
    def render(id, data = {})
      @t.request("POST", "/v1/templates/#{id}/render", body: { data: data })
    end

    # Validate a React Email JSX source string without saving it.
    # @param source [String]  Raw JSX source
    def validate_react_email(source)
      @t.request("POST", "/v1/templates/react-email/validate", body: { source: source })
    end

    # Get a React Email JSX starter template.
    # @param component_name [String]
    def react_email_starter(component_name = "EmailTemplate")
      @t.request("GET", "/v1/templates/react-email/starter?name=#{URI.encode_www_form_component(component_name)}")
    end
  end

  # ── Suppressions ────────────────────────────────────────────────────────────

  class SuppressionsAPI
    def initialize(transport) = @t = transport

    # Add one or more email addresses to the suppression list.
    # @param emails [String, Array<String>] Single email or array of emails
    # @param reason [String] "bounce" | "complaint" | "unsubscribe" | "manual"
    def add(emails:, reason: "manual")
      email_list = Array(emails)
      @t.request("POST", "/v1/suppressions", body: { emails: email_list, reason: reason })
    end

    def list(limit: 50, offset: 0)
      @t.request("GET", "/v1/suppressions?limit=#{limit}&offset=#{offset}")
    end

    def check(email)
      @t.request("GET", "/v1/suppressions/#{URI.encode_www_form_component(email)}")
    end

    def delete(email)
      @t.request("DELETE", "/v1/suppressions/#{URI.encode_www_form_component(email)}")
    end
  end

  # ── Events ──────────────────────────────────────────────────────────────────

  class EventsAPI
    def initialize(transport) = @t = transport

    def list(message_id: nil, limit: 50, offset: 0)
      query = "?limit=#{limit}&offset=#{offset}"
      query += "&messageId=#{message_id}" if message_id
      @t.request("GET", "/v1/events#{query}")
    end

    def get_by_message(message_id)
      @t.request("GET", "/v1/events?messageId=#{message_id}&limit=100")
    end

    # Get a single event by its ID.
    # @param event_id [String]
    def get(event_id)
      @t.request("GET", "/v1/events/#{event_id}")
    end
  end
end
