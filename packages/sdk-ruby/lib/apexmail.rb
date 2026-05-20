# frozen_string_literal: true

# apexmail.rb — Official Ruby SDK for the ApexMail transactional email API
#
# Usage:
#   require "apexmail"
#
#   client = ApexMail::Client.new("am_live_xxxx")
#
#   response = client.emails.send_email(
#     from:    "hello@example.com",
#     to:      "user@example.com",
#     subject: "Hello!",
#     html:    "<h1>Hello World</h1>"
#   )
#   puts response[:message][:id]

require "net/http"
require "uri"
require "json"
require "openssl"
require "time"

module ApexMail
  DEFAULT_BASE_URL = "https://api.apexmail.ee"
  SDK_VERSION      = "1.0.0"
  DEFAULT_MAX_RESPONSE_BYTES = 20 * 1024 * 1024
  API_KEY_REGEX    = /\Aam_(live|test)_[A-Za-z0-9]{16,}\z/

  def self.encode_path(value)
    URI.encode_www_form_component(value.to_s)
  end

  def self.build_query(params)
    filtered = params.reject { |_, v| v.nil? }
    return "" if filtered.empty?

    "?" + URI.encode_www_form(filtered)
  end

  def self.verify_signature(payload, signature_header, secret, tolerance_seconds: 300, timestamp: nil)
    raise ArgumentError, "payload must not be nil" if payload.nil?
    raise ArgumentError, "signature header must not be blank" if signature_header.to_s.empty?
    raise ArgumentError, "secret must not be blank" if secret.to_s.empty?

    parsed = parse_signature_header(signature_header.to_s)
    timestamp_value = timestamp || parsed[:timestamp]
    signature = parsed[:signature]
    return false if timestamp_value.nil? || signature.to_s.empty?

    timestamp_int = Integer(timestamp_value, exception: false)
    return false unless timestamp_int
    return false if (Time.now.to_i - timestamp_int).abs > tolerance_seconds

    signed_payload = "#{timestamp_int}.#{payload}"
    expected = OpenSSL::HMAC.hexdigest("sha256", secret, signed_payload)
    return false unless expected.bytesize == signature.bytesize

    OpenSSL.fixed_length_secure_compare(expected, signature)
  end

  def self.parse_signature_header(header)
    values = header.split(",").filter_map do |part|
      key, value = part.strip.split("=", 2)
      [key, value] if key && value
    end.to_h
    signature = values["v1"] || header.delete_prefix("sha256=").strip
    { timestamp: values["t"], signature: signature }
  end

  # ── Errors ─────────────────────────────────────────────────────────────────

  class Error < StandardError
    attr_reader :status_code, :code, :details

    def initialize(message, status_code: nil, code: nil, details: nil)
      super(message)
      @status_code = status_code
      @code        = code
      @details     = details
    end
  end

  class AuthenticationError < Error; end
  class ForbiddenError      < Error; end
  class ConflictError       < Error; end
  class NotFoundError       < Error; end
  class ValidationError     < Error; end
  class RateLimitError < Error
    attr_reader :retry_after

    def initialize(message, status_code: nil, code: nil, details: nil, retry_after: nil)
      super(message, status_code: status_code, code: code, details: details)
      @retry_after = retry_after
    end
  end
  class NetworkError        < Error; end

  # ── HTTP transport ─────────────────────────────────────────────────────────

  # @api private
  class Transport
    MAX_RETRIES = 3
    INITIAL_BACKOFF = 0.5
    MAX_BACKOFF = 5.0
    JITTER_MAX = 1.0

    def initialize(api_key:, base_url:, open_timeout:, read_timeout:, max_response_bytes:)
      @api_key      = api_key
      @base_uri     = URI.parse(base_url)
      raise ArgumentError, "baseUrl must use HTTPS" unless @base_uri.scheme == "https"
      @open_timeout = open_timeout
      @read_timeout = read_timeout
      @max_response_bytes = max_response_bytes
      @mutex = Mutex.new
      @http = Net::HTTP.new(@base_uri.host, @base_uri.port)
      @http.use_ssl = @base_uri.scheme == "https"
      @http.verify_mode = OpenSSL::SSL::VERIFY_PEER if @http.use_ssl?
      @http.open_timeout = @open_timeout
      @http.read_timeout = @read_timeout
      @keep_alive_timeout = 30
      @http.keep_alive_timeout = @keep_alive_timeout
      @last_used_at = nil
    end

    def request(method, path, body: nil, idempotency_key: nil)
      attempt = 0

      loop do
        begin
          resp = @mutex.synchronize do
            ensure_connection
            uri = URI.parse("#{@base_uri}#{path}")
            req = build_request(method, uri, body, idempotency_key)
            response_body = +""
            resp = @http.request(req) do |response|
              response.read_body do |chunk|
                response_body << chunk
                if response_body.bytesize > @max_response_bytes
                  reset_connection
                  raise Error.new("Response body exceeds max_response_bytes",
                                  status_code: response.code.to_i)
                end
              end
            end
            @last_used_at = Time.now
            [resp, response_body]
          end

          resp, response_body = resp

          if retryable_status?(resp.code.to_i) && attempt < MAX_RETRIES
            sleep(retry_delay(resp, attempt))
            attempt += 1
            next
          end

          return handle_response(resp, response_body)
        rescue IOError, EOFError, Timeout::Error, Errno::ECONNRESET, Errno::ECONNREFUSED, SocketError, OpenSSL::SSL::SSLError => e
          @mutex.synchronize { reset_connection }
          if attempt < MAX_RETRIES
            sleep(backoff(attempt))
            attempt += 1
            next
          end
          raise NetworkError, e.message
        end
      end
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
      req["X-API-Key"]      = @api_key
      req["Content-Type"]    = "application/json"
      req["User-Agent"]      = "apexmail-ruby/#{SDK_VERSION}"
      req["X-Idempotency-Key"] = idempotency_key if idempotency_key
      req.body = JSON.generate(body) if body
      req
    end

    def ensure_connection
      if @http.started? && @last_used_at && (Time.now - @last_used_at) > @keep_alive_timeout
        reset_connection
      end
      @http.start unless @http.started?
    end

    def reset_connection
      @http.finish if @http.started?
    end

    def retryable_status?(status)
      status == 429 || status >= 500
    end

    def retry_delay(resp, attempt)
      retry_after = resp["Retry-After"]
      delay = backoff(attempt)

      if retry_after
        seconds = Integer(retry_after, exception: false)
        if seconds
          retry_after_delay = seconds.to_f
          delay = retry_after_delay if retry_after_delay > delay
          return [delay, MAX_BACKOFF].min
        end

        begin
          date = Time.httpdate(retry_after)
          retry_after_delay = [date - Time.now, 0].max
          delay = retry_after_delay if retry_after_delay > delay
        rescue ArgumentError, TypeError
        end
      end

      [delay, MAX_BACKOFF].min
    end

    def backoff(attempt)
      delay = INITIAL_BACKOFF * (attempt * attempt)
      capped = [delay, MAX_BACKOFF].min
      capped + rand(0.0..JITTER_MAX)
    end

    def handle_response(resp, body)
      body_text = body.to_s.strip
      parsed = if body_text.empty?
                 {}
               else
                 JSON.parse(body_text, symbolize_names: true)
               end

      error = parsed[:error]
      if error.is_a?(Hash)
        message = error[:message] || body_text
        code = error[:code]
        details = error[:details]
      else
        message = error || parsed[:message] || body_text
        code = parsed[:code]
        details = parsed[:errors]
      end
      message = "HTTP #{resp.code}" if message.to_s.empty?

      # SDK-111: Unwrap API envelope {"data": ..., "meta": ...}
      if parsed.is_a?(Hash) && parsed.key?(:data)
        parsed = parsed[:data]
      end

      case resp.code.to_i
      when 200..299
        parsed
      when 401
        raise AuthenticationError.new(message || "Unauthorized",
                                      status_code: 401, code: code, details: details)
      when 403
        raise ForbiddenError.new(message || "Forbidden",
                                 status_code: 403, code: code, details: details)
      when 404
        raise NotFoundError.new(message || "Not found",
                                status_code: 404, code: code, details: details)
      when 409
        raise ConflictError.new(message || "Conflict",
                                status_code: 409, code: code, details: details)
      when 400, 422
        raise ValidationError.new(message || "Bad request",
                                  status_code: resp.code.to_i, code: code, details: details)
      when 429
        raise RateLimitError.new(message || "Rate limit exceeded",
                                 status_code: 429, code: code, details: details,
                                 retry_after: resp["Retry-After"])
      else
        raise Error.new(message,
                        status_code: resp.code.to_i, code: code, details: details)
      end
    rescue JSON::ParserError => e
      { raw: body_text, parse_error: e.message }
    end
  end

  # ── Client ─────────────────────────────────────────────────────────────────

  class Client
    attr_reader :emails, :domains, :webhooks, :templates, :suppressions, :events, :analytics, :api_keys

    # @param api_key      [String]  Your ApexMail API key (starts with am_live_ or am_test_)
    # @param base_url     [String]  Override the base URL (useful for self-hosted)
    # @param open_timeout [Integer] TCP connect timeout in seconds (default: 10)
    # @param read_timeout [Integer] Read timeout in seconds (default: 30)
    # @param max_response_bytes [Integer] Max response size in bytes (default: 20MB)
    def initialize(api_key, base_url: DEFAULT_BASE_URL, open_timeout: 10, read_timeout: 30,
                   max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES)
      validate_api_key!(api_key)
      @api_key     = api_key
      @transport   = Transport.new(api_key: api_key, base_url: base_url,
                                   open_timeout: open_timeout, read_timeout: read_timeout,
                                   max_response_bytes: max_response_bytes)
      @emails      = EmailsAPI.new(@transport)
      @domains     = DomainsAPI.new(@transport)
      @webhooks    = WebhooksAPI.new(@transport)
      @templates   = TemplatesAPI.new(@transport)
      @suppressions = SuppressionsAPI.new(@transport)
      @events      = EventsAPI.new(@transport)
      @analytics   = AnalyticsAPI.new(@transport)
      @api_keys    = ApiKeysAPI.new(@transport)
    end

    # Returns a redacted string representation showing metadata only.
    def to_s
      masked = @api_key.length > 8 \
        ? @api_key[0, 4] + "\u2026\u2026" + @api_key[-4, 4] \
        : "[REDACTED]"
      "#<#{self.class} api_key=#{masked}>"
    end

    # Redacted inspect to prevent credential leakage in logs or console output.
    def inspect
      to_s
    end

    def validate_api_key!(api_key)
      return if API_KEY_REGEX.match?(api_key)

      raise ValidationError.new("Invalid API key format", status_code: nil, code: "INVALID_API_KEY")
    end
  end

  # ── Emails ──────────────────────────────────────────────────────────────────

  class EmailsAPI
    def initialize(transport) = @t = transport

    EMAIL_REGEX = /\A[^@\s]+@[^@\s]+\.[^@\s]+\z/

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
    def send_email(from:, to:, subject:, html: nil, text: nil, **options)
      raise ArgumentError, '"from" is required' if from.nil?
      raise ArgumentError, '"to" is required' if to.nil?
      raise ArgumentError, '"subject" is required' if subject.to_s.strip.empty?
      if (html.nil? || html.to_s.strip.empty?) && (text.nil? || text.to_s.strip.empty?)
        raise ArgumentError, 'Either "html" or "text" body is required'
      end

      validate_recipients(from, 'from')
      validate_recipients(to, 'to')
      validate_recipients(options[:cc], 'cc') if options[:cc]
      validate_recipients(options[:bcc], 'bcc') if options[:bcc]

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
      list = Array(messages)
      raise ArgumentError, 'messages must include at least one item' if list.empty?

      list.each_with_index do |message, index|
        unless message.is_a?(Hash)
          raise ArgumentError, "message at index #{index} must be a hash"
        end
        validate_send_params(message, index)
      end
      @t.request("POST", "/v1/messages/batch", body: {
        messages: list.map { |m| normalize_send_params(m) },
      })
    end

    # Retrieve an email by ID.
    # @param id [String]
    def get(id)
      @t.request("GET", "/v1/messages/#{ApexMail.encode_path(id)}")
    end

    # List emails with optional filters.
    # @param status [String, nil]
    # @param limit  [Integer]
    # @param offset [Integer]
    # @param cursor [String, nil]
    # @param tag    [String, nil]
    def list(status: nil, limit: 20, offset: 0, cursor: nil, tag: nil)
      query = ApexMail.build_query(limit: limit, offset: offset, cursor: cursor, status: status, tag: tag)
      @t.request("GET", "/v1/messages#{query}")
    end

    # Cancel a queued or scheduled email by ID.
    # @param id [String] The message ID to cancel
    # @return [Hash] Queue cancellation result with +id+ and +status+ keys
    def cancel(id)
      @t.request("POST", "/v1/messages/#{ApexMail.encode_path(id)}/cancel", body: {})
    end

    private

    def normalize_address(addr)
      addr.is_a?(Hash) ? addr : { email: addr }
    end

    def normalize_recipients(recips)
      return nil if recips.nil?
      Array(recips).map { |r| normalize_address(r) }
    end

    def validate_recipients(recips, field)
      list = Array(recips)
      raise ArgumentError, "\"#{field}\" must include at least one recipient" if list.empty?

      list.each do |recipient|
        email = extract_email(recipient)
        unless email && EMAIL_REGEX.match?(email)
          raise ArgumentError, "Invalid \"#{field}\" email format: #{email}"
        end
      end
    end

    def extract_email(recipient)
      recipient.is_a?(Hash) ? recipient[:email] || recipient['email'] : recipient
    end

    def normalize_send_params(params)
      from    = normalize_address(params[:from] || params["from"])
      to      = normalize_recipients(params[:to] || params["to"])
      compact(params.merge(from: from, to: to))
    end

    def validate_send_params(params, index = nil)
      label = index.nil? ? 'message' : "message at index #{index}"
      from = params[:from] || params["from"]
      to = params[:to] || params["to"]
      subject = params[:subject] || params["subject"]
      html = params[:html] || params["html"]
      text = params[:text] || params["text"]
      template_id = params[:template_id] || params["template_id"] || params[:templateId] || params["templateId"]

      raise ArgumentError, "#{label} missing \"from\"" if from.nil?
      raise ArgumentError, "#{label} missing \"to\"" if to.nil?
      raise ArgumentError, "#{label} missing \"subject\"" if subject.to_s.strip.empty?
      if (html.nil? || html.to_s.strip.empty?) && (text.nil? || text.to_s.strip.empty?) && template_id.nil?
        raise ArgumentError, "#{label} missing html, text, or template_id"
      end

      validate_recipients(from, 'from')
      validate_recipients(to, 'to')
      validate_recipients(params[:cc] || params["cc"], 'cc') if params[:cc] || params["cc"]
      validate_recipients(params[:bcc] || params["bcc"], 'bcc') if params[:bcc] || params["bcc"]
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
      @t.request("GET", "/v1/domains/#{ApexMail.encode_path(id)}")
    end

    # Trigger DNS verification.
    def verify(id)
      @t.request("POST", "/v1/domains/#{ApexMail.encode_path(id)}/verify")
    end

    # Delete a domain.
    def delete(id)
      @t.request("DELETE", "/v1/domains/#{ApexMail.encode_path(id)}")
    end

    # Get DNS health for a domain.
    def health(id)
      @t.request("GET", "/v1/domains/#{ApexMail.encode_path(id)}/health")
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
      @t.request("GET", "/v1/webhooks/#{ApexMail.encode_path(id)}")
    end

    # Update a webhook (URL, events, secret, or active status).
    # @param id     [String]
    # @param params [Hash] { url:, events:, secret:, active: }
    def update(id, **params)
      @t.request("PUT", "/v1/webhooks/#{ApexMail.encode_path(id)}", body: params)
    end

    def delete(id)
      @t.request("DELETE", "/v1/webhooks/#{ApexMail.encode_path(id)}")
    end

    def test(id)
      @t.request("POST", "/v1/webhooks/#{ApexMail.encode_path(id)}/test")
    end
  end

  # ── Templates ───────────────────────────────────────────────────────────────

  class TemplatesAPI
    def initialize(transport) = @t = transport

    # @param name    [String]
    # @param subject [String]
    # @param html    [String, nil]
    # @param engine  [String] template engine name
    def create(name:, subject:, html: nil, text: nil, engine: "handlebars", **opts)
      @t.request("POST", "/v1/templates", body: {
        name: name, subject: subject, html: html, text: text,
        engine: engine, **opts,
      }.compact)
    end

    def list(limit: 50, offset: 0, cursor: nil)
      query = ApexMail.build_query(limit: limit, offset: offset, cursor: cursor)
      @t.request("GET", "/v1/templates#{query}")
    end

    def get(id)
      @t.request("GET", "/v1/templates/#{ApexMail.encode_path(id)}")
    end

    def get_by_slug(slug)
      @t.request("GET", "/v1/templates/slug/#{ApexMail.encode_path(slug)}")
    end

    # Update a template (creates a new version automatically).
    # @param id     [String]
    # @param params [Hash] { name:, subject:, html:, text:, engine:, schema: }
    def update(id, **params)
      @t.request("PUT", "/v1/templates/#{ApexMail.encode_path(id)}", body: params)
    end

    def delete(id)
      @t.request("DELETE", "/v1/templates/#{ApexMail.encode_path(id)}")
    end

    # Duplicate a template (creates a copy with a new ID).
    # @param id [String]
    def duplicate(id)
      @t.request("POST", "/v1/templates/#{ApexMail.encode_path(id)}/duplicate")
    end

    # Rollback a template to a previous version.
    # @param id [String]
    # @param version [Integer] The version number to roll back to
    def rollback(id, version:)
      @t.request("POST", "/v1/templates/#{ApexMail.encode_path(id)}/rollback", body: { version: version })
    end

    # Render a template with given variables (dry-run, does not send).
    # @param id   [String]
    # @param data [Hash]
    def render(id, data = {})
      @t.request("POST", "/v1/templates/#{ApexMail.encode_path(id)}/render", body: { variables: data })
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

    def list(limit: 50, offset: 0, cursor: nil, reason: nil, tag: nil)
      query = ApexMail.build_query(limit: limit, offset: offset, cursor: cursor, reason: reason, tag: tag)
      @t.request("GET", "/v1/suppressions#{query}")
    end

    def check(email)
      @t.request("GET", "/v1/suppressions/check/#{ApexMail.encode_path(email)}")
    end

    def delete(id)
      @t.request("DELETE", "/v1/suppressions/#{ApexMail.encode_path(id)}")
    end

    def bulk(entries:)
      @t.request("POST", "/v1/suppressions/bulk", body: { entries: entries })
    end
  end

  # ── Events ──────────────────────────────────────────────────────────────────

  class EventsAPI
    def initialize(transport) = @t = transport

    # List events with optional filters.
    #
    # Each event in the response may include an +envelope+ hash with:
    #   from::      [String, nil]  Envelope MAIL FROM address
    #   to::        [Array<String>] Envelope RCPT TO addresses
    #   dkim::      [String]  Authentication result: +pass+, +fail+, +neutral+, +none+
    #   spf::       [String]  Authentication result: +pass+, +fail+, +neutral+, +none+
    #   dmarc::     [String]  Authentication result: +pass+, +fail+, +neutral+, +none+
    #   timestamp:: [String]  ISO 8601 delivery event timestamp
    def list(message_id: nil, limit: 50, offset: 0, cursor: nil, type: nil, status: nil,
             date_from: nil, date_to: nil, domain_id: nil)
      query = ApexMail.build_query(
        limit: limit, offset: offset, cursor: cursor, messageId: message_id,
        type: type, status: status, dateFrom: date_from,
        dateTo: date_to, domainId: domain_id
      )
      @t.request("GET", "/v1/events#{query}")
    end

    def get_by_message(message_id)
      query = ApexMail.build_query(messageId: message_id, limit: 100)
      @t.request("GET", "/v1/events#{query}")
    end

    # Get a single event by its ID.
    # @param event_id [String]
    def get(event_id)
      @t.request("GET", "/v1/events/#{ApexMail.encode_path(event_id)}")
    end

    def stats(**filters)
      query = ApexMail.build_query(filters)
      @t.request("GET", "/v1/events/stats#{query}")
    end

    def timeseries(**filters)
      query = ApexMail.build_query(filters)
      @t.request("GET", "/v1/events/timeseries#{query}")
    end
  end

  # ── API Keys ───────────────────────────────────────────────────────────────

  class ApiKeysAPI
    def initialize(transport) = @t = transport

    def create(name:, expires_at: nil)
      body = { name: name }
      body[:expiresAt] = expires_at if expires_at
      @t.request("POST", "/v1/auth/api-keys", body: body)
    end

    def list(limit: 50, offset: 0, cursor: nil)
      query = ApexMail.build_query(limit: limit, offset: offset, cursor: cursor)
      @t.request("GET", "/v1/auth/api-keys#{query}")
    end

    def revoke(id)
      @t.request("DELETE", "/v1/auth/api-keys/#{ApexMail.encode_path(id)}")
    end
  end

  # ── Analytics ──────────────────────────────────────────────────────────────

  class AnalyticsAPI
    def initialize(transport) = @t = transport

    # Fetch analytics with required date range and optional filters.
    # @param from     [String] ISO 8601 start date (required)
    # @param to       [String] ISO 8601 end date (required)
    # @param group_by [String] Grouping dimension
    # @param tag      [String] Filter by tag name
    # @param domain   [String] Filter by sending domain
    def get(from:, to:, group_by: nil, tag: nil, domain: nil)
      query = ApexMail.build_query(from: from, to: to, groupBy: group_by, tag: tag, domain: domain)
      @t.request("GET", "/v1/analytics#{query}")
    end
  end
end
